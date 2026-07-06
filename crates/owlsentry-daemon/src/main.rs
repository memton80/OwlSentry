//! Point d'entrée du démon OwlSentry.

use anyhow::{Context, Result};
use clap::Parser;
use owlsentry_common::{Alert, DaemonConfig, Lang, Rules};
use owlsentry_daemon::{dispatcher, ipc_server::IpcServer, logging, monitors, state::DaemonState};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "owlsentry-daemon",
    about = "Démon de détection d'intrusion OwlSentry (Fedora, SELinux, firewalld)",
    version
)]
struct Args {
    /// Chemin du fichier de configuration TOML.
    #[arg(short, long, default_value = owlsentry_common::DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Valide la configuration et les règles puis quitte.
    #[arg(long)]
    check_config: bool,
}

fn load_config(args: &Args) -> Result<(DaemonConfig, Rules)> {
    let config = if args.config.exists() {
        DaemonConfig::load(&args.config)
            .with_context(|| format!("chargement de {}", args.config.display()))?
    } else {
        eprintln!(
            "configuration {} absente : valeurs par défaut utilisées",
            args.config.display()
        );
        DaemonConfig::default()
    };
    let rules = Rules::load_or_default(&config.general.rules_path)
        .with_context(|| format!("chargement de {}", config.general.rules_path.display()))?;
    Ok((config, rules))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let (config, rules) = load_config(&args)?;

    if args.check_config {
        println!("Configuration et règles valides.");
        return Ok(());
    }

    let (_log_guard, alert_writer) =
        logging::init(&config.general.log_dir, &config.general.log_level)?;
    let lang = Lang::from_code(&config.general.language);
    info!(
        version = owlsentry_daemon::VERSION,
        lang = lang.code(),
        "démarrage d'OwlSentry"
    );

    let state = Arc::new(DaemonState::new(config.general.recent_buffer));
    let (alert_tx, alert_rx) = mpsc::channel::<Alert>(1024);
    let (broadcast_tx, _) = broadcast::channel::<Alert>(512);

    // Dispatcher central.
    tokio::spawn(dispatcher::run(
        alert_rx,
        Arc::clone(&state),
        broadcast_tx.clone(),
        alert_writer,
    ));

    // Moniteurs.
    if config.audit.enabled {
        let cfg = config.audit.clone();
        let selinux_rules = rules.selinux.clone();
        let tx = alert_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = monitors::audit::run(cfg, selinux_rules, lang, tx).await {
                error!("moniteur audit arrêté: {e:#}");
            }
        });
    } else {
        warn!("moniteur audit désactivé par configuration");
    }

    if config.filesystem.enabled {
        let cfg = config.filesystem.clone();
        let mut fs_rules = rules.filesystem.clone();
        // Ne jamais boucler sur nos propres journaux.
        if !fs_rules.ignore_paths.contains(&config.general.log_dir) {
            fs_rules.ignore_paths.push(config.general.log_dir.clone());
        }
        let tx = alert_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = monitors::fs::run(cfg, fs_rules, lang, tx).await {
                error!("moniteur fichiers arrêté: {e:#}");
            }
        });
    }

    if config.network.enabled {
        let cfg = config.network.clone();
        let net_rules = rules.network.clone();
        let tx = alert_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = monitors::net::run(cfg, net_rules, lang, tx).await {
                error!("moniteur réseau arrêté: {e:#}");
            }
        });
    }

    if config.process.enabled {
        let interval = config.process.scan_interval_secs;
        let tx = alert_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = monitors::process::run(interval, lang, tx).await {
                error!("moniteur processus arrêté: {e:#}");
            }
        });
    }

    // Serveur IPC.
    let socket_path = config.general.socket_path.clone();
    let ipc = IpcServer {
        socket_path: socket_path.clone(),
        socket_group: config.general.socket_group.clone(),
        language: config.general.language.clone(),
        state: Arc::clone(&state),
        broadcast_tx,
    };
    let ipc_task = tokio::spawn(async move {
        if let Err(e) = ipc.serve().await {
            error!("serveur IPC arrêté: {e:#}");
        }
    });

    // Attente d'un signal d'arrêt.
    let mut sigterm = signal(SignalKind::terminate()).context("installation de SIGTERM")?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("SIGINT reçu, arrêt"),
        _ = sigterm.recv() => info!("SIGTERM reçu, arrêt"),
    }

    ipc_task.abort();
    if let Err(e) = std::fs::remove_file(&socket_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(error = %e, "nettoyage du socket impossible");
        }
    }
    info!("OwlSentry arrêté proprement");
    Ok(())
}
