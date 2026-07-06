//! Test d'intégration : un client se connecte au serveur IPC, s'abonne,
//! et reçoit une alerte simulée (scénario « intrusion détectée »).

use owlsentry_common::{Alert, Category, ClientRequest, DaemonMessage, Severity};
use owlsentry_daemon::ipc_server::IpcServer;
use owlsentry_daemon::state::DaemonState;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};

async fn send_request(stream: &mut UnixStream, req: &ClientRequest) {
    let mut buf = serde_json::to_vec(req).expect("serialize");
    buf.push(b'\n');
    stream.write_all(&buf).await.expect("write");
}

#[tokio::test]
async fn client_receives_broadcast_alert() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("owlsentry-test.sock");

    let state = Arc::new(DaemonState::new(100));
    let (broadcast_tx, _) = broadcast::channel::<Alert>(16);

    // Une alerte pré-existante dans le tampon, pour GetRecent.
    let old_alert = Alert::new(Severity::Medium, Category::Filesystem, "old", "w", "y", "h");
    state.record(&old_alert).await;

    let server = IpcServer {
        socket_path: socket_path.clone(),
        // Groupe volontairement inexistant : le serveur doit retomber sur 0600
        // sans échouer (on ne tourne pas root dans les tests).
        socket_group: "owlsentry-test-nonexistent".into(),
        language: "fr".into(),
        state: Arc::clone(&state),
        broadcast_tx: broadcast_tx.clone(),
    };
    let server_task = tokio::spawn(server.serve());

    // Attendre que le socket apparaisse.
    let mut connected = None;
    for _ in 0..50 {
        match UnixStream::connect(&socket_path).await {
            Ok(s) => {
                connected = Some(s);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    let mut stream = connected.expect("connexion au socket");

    let (read_half, write_half) = stream.split();
    let mut lines = BufReader::new(read_half).lines();
    let mut write_half = write_half;

    // 1. Hello à la connexion.
    let hello = timeout(Duration::from_secs(5), lines.next_line())
        .await
        .expect("timeout hello")
        .expect("read")
        .expect("line");
    let msg: DaemonMessage = serde_json::from_str(&hello).expect("parse hello");
    assert!(matches!(msg, DaemonMessage::Hello { protocol: 1, .. }));

    // 2. GetRecent retourne l'alerte pré-existante.
    let req = serde_json::to_vec(&ClientRequest::GetRecent { limit: 10 }).expect("ser");
    write_half.write_all(&req).await.expect("write");
    write_half.write_all(b"\n").await.expect("write");
    let recent = timeout(Duration::from_secs(5), lines.next_line())
        .await
        .expect("timeout recent")
        .expect("read")
        .expect("line");
    let msg: DaemonMessage = serde_json::from_str(&recent).expect("parse recent");
    match msg {
        DaemonMessage::Recent { alerts } => {
            assert_eq!(alerts.len(), 1);
            assert_eq!(alerts[0].title, "old");
        }
        other => panic!("attendu Recent, reçu {other:?}"),
    }

    // 3. Subscribe puis diffusion d'une alerte simulée (« touch /etc/shadow »).
    let req = serde_json::to_vec(&ClientRequest::Subscribe).expect("ser");
    write_half.write_all(&req).await.expect("write");
    write_half.write_all(b"\n").await.expect("write");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let intrusion = Alert::new(
        Severity::High,
        Category::Filesystem,
        "Fichier sensible modifié : /etc/shadow",
        "what",
        "why",
        "how",
    );
    broadcast_tx.send(intrusion).expect("broadcast");

    let line = timeout(Duration::from_secs(5), lines.next_line())
        .await
        .expect("timeout alert")
        .expect("read")
        .expect("line");
    let msg: DaemonMessage = serde_json::from_str(&line).expect("parse alert");
    match msg {
        DaemonMessage::Alert { alert } => {
            assert_eq!(alert.severity, Severity::High);
            assert!(alert.title.contains("/etc/shadow"));
        }
        other => panic!("attendu Alert, reçu {other:?}"),
    }

    // 4. Ping/Pong sur une seconde connexion.
    let mut stream2 = UnixStream::connect(&socket_path).await.expect("reconnect");
    send_request(&mut stream2, &ClientRequest::Ping).await;
    let (r2, _w2) = stream2.split();
    let mut lines2 = BufReader::new(r2).lines();
    // Hello puis Pong.
    let _hello = lines2.next_line().await.expect("read").expect("line");
    let pong = timeout(Duration::from_secs(5), lines2.next_line())
        .await
        .expect("timeout pong")
        .expect("read")
        .expect("line");
    let msg: DaemonMessage = serde_json::from_str(&pong).expect("parse pong");
    assert!(matches!(msg, DaemonMessage::Pong));

    server_task.abort();
}
