//! Serveur IPC : socket Unix `SOCK_STREAM`, messages NDJSON.
//!
//! Sécurité :
//! - le répertoire du socket est créé en 0750 ;
//! - le socket appartient à `root:<socket_group>` en mode 0660 — seuls root
//!   et les membres du groupe peuvent s'y connecter (le noyau applique les
//!   permissions du fichier socket lors du `connect(2)`) ;
//! - les identifiants du pair (`SO_PEERCRED`) sont journalisés pour
//!   traçabilité ;
//! - les requêtes sont limitées en taille et désérialisées avec `serde`
//!   (jamais d'évaluation dynamique).

use crate::state::DaemonState;
use anyhow::{Context, Result};
use owlsentry_common::{Alert, ClientRequest, DaemonMessage, IPC_PROTOCOL_VERSION};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

/// Taille maximale d'une requête client (anti-DoS mémoire).
const MAX_REQUEST_BYTES: usize = 4096;

pub struct IpcServer {
    pub socket_path: PathBuf,
    pub socket_group: String,
    pub language: String,
    pub state: Arc<DaemonState>,
    pub broadcast_tx: broadcast::Sender<Alert>,
}

impl IpcServer {
    /// Prépare le socket (répertoire, permissions, propriétaire) et sert les
    /// clients jusqu'à annulation de la tâche.
    pub async fn serve(self) -> Result<()> {
        if let Some(dir) = self.socket_path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("création de {}", dir.display()))?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))
                .with_context(|| format!("permissions de {}", dir.display()))?;
        }
        // Supprimer un socket périmé d'une exécution précédente.
        match std::fs::remove_file(&self.socket_path) {
            Ok(()) => debug!("ancien socket supprimé"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("suppression de {}", self.socket_path.display()))
            }
        }

        let listener = UnixListener::bind(&self.socket_path)
            .with_context(|| format!("bind sur {}", self.socket_path.display()))?;

        self.apply_socket_permissions()?;
        info!(path = %self.socket_path.display(), "serveur IPC en écoute");

        loop {
            let (stream, _addr) = listener.accept().await.context("accept IPC")?;
            let state = Arc::clone(&self.state);
            let rx = self.broadcast_tx.subscribe();
            let language = self.language.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client(stream, state, rx, language).await {
                    debug!(error = %e, "client IPC terminé avec erreur");
                }
            });
        }
    }

    /// 0660 root:<groupe>. Si le groupe n'existe pas, on retombe sur 0600
    /// (root uniquement) plutôt que d'ouvrir l'accès.
    fn apply_socket_permissions(&self) -> Result<()> {
        let path: &Path = &self.socket_path;
        match nix::unistd::Group::from_name(&self.socket_group) {
            Ok(Some(group)) => {
                nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(0)), Some(group.gid))
                    .with_context(|| format!("chown du socket {}", path.display()))?;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
                    .context("chmod 0660 du socket")?;
            }
            Ok(None) => {
                warn!(
                    group = %self.socket_group,
                    "groupe introuvable — socket restreint à root (0600)"
                );
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                    .context("chmod 0600 du socket")?;
            }
            Err(e) => {
                warn!(error = %e, "résolution du groupe impossible — socket 0600");
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                    .context("chmod 0600 du socket")?;
            }
        }
        Ok(())
    }
}

async fn send(stream: &mut (impl AsyncWriteExt + Unpin), msg: &DaemonMessage) -> Result<()> {
    let mut buf = serde_json::to_vec(msg).context("sérialisation IPC")?;
    buf.push(b'\n');
    stream.write_all(&buf).await.context("écriture IPC")?;
    Ok(())
}

async fn handle_client(
    stream: UnixStream,
    state: Arc<DaemonState>,
    mut alerts_rx: broadcast::Receiver<Alert>,
    language: String,
) -> Result<()> {
    // Traçabilité : qui se connecte ? (le contrôle d'accès effectif est
    // assuré par les permissions du fichier socket).
    if let Ok(cred) = stream.peer_cred() {
        info!(uid = cred.uid(), gid = cred.gid(), pid = ?cred.pid(), "client IPC connecté");
    }

    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    let mut subscribed = false;

    send(
        &mut write_half,
        &DaemonMessage::Hello {
            version: crate::VERSION.to_string(),
            protocol: IPC_PROTOCOL_VERSION,
            language,
        },
    )
    .await?;

    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line.context("lecture IPC")? else {
                    break; // client déconnecté
                };
                if line.len() > MAX_REQUEST_BYTES {
                    send(&mut write_half, &DaemonMessage::Error {
                        message: "requête trop longue".into(),
                    }).await?;
                    continue;
                }
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<ClientRequest>(&line) {
                    Ok(ClientRequest::Subscribe) => {
                        subscribed = true;
                    }
                    Ok(ClientRequest::GetRecent { limit }) => {
                        let alerts = state.recent(limit.min(10_000)).await;
                        send(&mut write_half, &DaemonMessage::Recent { alerts }).await?;
                    }
                    Ok(ClientRequest::GetStats) => {
                        let stats = state.stats().await;
                        send(&mut write_half, &DaemonMessage::Stats { stats }).await?;
                    }
                    Ok(ClientRequest::Ping) => {
                        send(&mut write_half, &DaemonMessage::Pong).await?;
                    }
                    Err(e) => {
                        send(&mut write_half, &DaemonMessage::Error {
                            message: format!("requête invalide: {e}"),
                        }).await?;
                    }
                }
            }
            result = alerts_rx.recv(), if subscribed => {
                match result {
                    Ok(alert) => {
                        send(&mut write_half, &DaemonMessage::Alert { alert }).await?;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(missed = n, "client IPC trop lent, alertes manquées");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
    Ok(())
}
