//! Journalisation structurée (`tracing`) avec rotation quotidienne.
//!
//! Deux flux distincts dans le répertoire de logs (par défaut
//! `/var/log/owlsentry/`) :
//! - `daemon.log.YYYY-MM-DD` : journal technique du démon ;
//! - `alerts.jsonl.YYYY-MM-DD` : une alerte JSON par ligne (exploitable
//!   par `jq`, SIEM, etc.).
//!
//! La rotation quotidienne est assurée par `tracing-appender` ; la purge et
//! la compression sont déléguées à `logrotate` (voir `packaging/`).

use anyhow::{Context, Result};
use owlsentry_common::Alert;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Garde à conserver vivante pendant toute la durée du processus
/// (sinon les derniers logs sont perdus à l'arrêt).
pub struct LogGuard {
    _daemon: WorkerGuard,
}

/// Écrivain d'alertes NDJSON avec rotation quotidienne.
#[derive(Clone)]
pub struct AlertWriter {
    inner: Arc<Mutex<rolling::RollingFileAppender>>,
}

impl AlertWriter {
    pub fn write(&self, alert: &Alert) -> Result<()> {
        let line = serde_json::to_vec(alert).context("sérialisation d'une alerte")?;
        let mut w = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("verrou du journal d'alertes empoisonné"))?;
        w.write_all(&line)
            .and_then(|_| w.write_all(b"\n"))
            .and_then(|_| w.flush())
            .context("écriture dans alerts.jsonl")?;
        Ok(())
    }
}

/// Initialise `tracing` (fichier + stderr pour journald) et retourne
/// l'écrivain d'alertes.
pub fn init(log_dir: &Path, level: &str) -> Result<(LogGuard, AlertWriter)> {
    std::fs::create_dir_all(log_dir)
        .with_context(|| format!("création de {}", log_dir.display()))?;
    // Journaux lisibles par root et le groupe seulement.
    let perms = std::fs::Permissions::from_mode(0o750);
    std::fs::set_permissions(log_dir, perms)
        .with_context(|| format!("permissions de {}", log_dir.display()))?;

    let daemon_appender = rolling::daily(log_dir, "daemon.log");
    let (daemon_writer, guard) = tracing_appender::non_blocking(daemon_appender);

    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .with_ansi(false)
                .with_target(true)
                .with_writer(daemon_writer),
        )
        .with(fmt::layer().with_ansi(false).with_writer(std::io::stderr))
        .try_init()
        .map_err(|e| anyhow::anyhow!("initialisation de tracing: {e}"))?;

    let alerts = AlertWriter {
        inner: Arc::new(Mutex::new(rolling::daily(log_dir, "alerts.jsonl"))),
    };
    Ok((LogGuard { _daemon: guard }, alerts))
}
