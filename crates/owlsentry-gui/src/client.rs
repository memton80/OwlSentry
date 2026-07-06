//! Client IPC de la GUI : thread dédié qui maintient la connexion au démon,
//! relaie les messages vers l'interface et émet les notifications bureau
//! pour les alertes critiques.

use owlsentry_common::{Alert, ClientRequest, DaemonMessage, Severity};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

/// Événements transmis du thread réseau vers l'interface.
#[derive(Debug)]
pub enum GuiEvent {
    Connected { language: String },
    Disconnected,
    Alert(Alert),
    Recent(Vec<Alert>),
}

fn send_request(stream: &mut UnixStream, req: &ClientRequest) -> std::io::Result<()> {
    let mut buf = serde_json::to_vec(req)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    buf.push(b'\n');
    stream.write_all(&buf)
}

fn desktop_notify(alert: &Alert) {
    let urgency = if alert.severity >= Severity::Critical {
        notify_rust::Urgency::Critical
    } else {
        notify_rust::Urgency::Normal
    };
    // Échec non bloquant : pas de session D-Bus, pas de notification.
    let _ = notify_rust::Notification::new()
        .appname("OwlSentry")
        .summary(&alert.title)
        .body(&alert.what)
        .urgency(urgency)
        .show();
}

/// Lance le thread de connexion. `notify_enabled` est partagé avec la GUI
/// (case à cocher « notifications »).
pub fn spawn(
    socket_path: PathBuf,
    tx: Sender<GuiEvent>,
    repaint: impl Fn() + Send + 'static,
    notify_enabled: Arc<AtomicBool>,
) {
    std::thread::Builder::new()
        .name("owlsentry-ipc".into())
        .spawn(move || loop {
            match UnixStream::connect(&socket_path) {
                Ok(mut stream) => {
                    let ok = send_request(&mut stream, &ClientRequest::Subscribe)
                        .and_then(|_| {
                            send_request(&mut stream, &ClientRequest::GetRecent { limit: 500 })
                        })
                        .is_ok();
                    if !ok {
                        let _ = tx.send(GuiEvent::Disconnected);
                        repaint();
                        std::thread::sleep(Duration::from_secs(3));
                        continue;
                    }
                    let reader = BufReader::new(match stream.try_clone() {
                        Ok(s) => s,
                        Err(_) => {
                            std::thread::sleep(Duration::from_secs(3));
                            continue;
                        }
                    });
                    for line in reader.lines() {
                        let Ok(line) = line else { break };
                        if line.trim().is_empty() {
                            continue;
                        }
                        match serde_json::from_str::<DaemonMessage>(&line) {
                            Ok(DaemonMessage::Hello { language, .. }) => {
                                let _ = tx.send(GuiEvent::Connected { language });
                            }
                            Ok(DaemonMessage::Alert { alert }) => {
                                if alert.severity >= Severity::High
                                    && notify_enabled.load(Ordering::Relaxed)
                                {
                                    desktop_notify(&alert);
                                }
                                let _ = tx.send(GuiEvent::Alert(alert));
                            }
                            Ok(DaemonMessage::Recent { alerts }) => {
                                let _ = tx.send(GuiEvent::Recent(alerts));
                            }
                            Ok(_) => {}
                            Err(_) => {
                                // Message inconnu : on l'ignore (compatibilité
                                // ascendante du protocole).
                            }
                        }
                        repaint();
                    }
                    let _ = tx.send(GuiEvent::Disconnected);
                    repaint();
                }
                Err(_) => {
                    let _ = tx.send(GuiEvent::Disconnected);
                    repaint();
                }
            }
            std::thread::sleep(Duration::from_secs(3));
        })
        .expect("création du thread IPC");
}
