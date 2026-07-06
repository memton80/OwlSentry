//! Dispatcher central : reçoit les alertes des moniteurs, attribue un
//! identifiant, journalise, met à jour l'état partagé et diffuse aux
//! clients IPC abonnés.

use crate::logging::AlertWriter;
use crate::state::DaemonState;
use owlsentry_common::Alert;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Boucle du dispatcher. Se termine quand tous les moniteurs ont fermé
/// leur émetteur.
pub async fn run(
    mut rx: mpsc::Receiver<Alert>,
    state: Arc<DaemonState>,
    broadcast_tx: broadcast::Sender<Alert>,
    writer: AlertWriter,
) {
    while let Some(mut alert) = rx.recv().await {
        alert.id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

        info!(
            target: "owlsentry::alert",
            id = alert.id,
            severity = %alert.severity,
            category = %alert.category,
            title = %alert.title,
            what = %alert.what,
            "alerte"
        );

        if let Err(e) = writer.write(&alert) {
            error!(error = %e, "échec d'écriture du journal d'alertes");
        }

        state.record(&alert).await;
        // Ignorer l'erreur « aucun abonné » : c'est un cas normal.
        let _ = broadcast_tx.send(alert);
    }
}
