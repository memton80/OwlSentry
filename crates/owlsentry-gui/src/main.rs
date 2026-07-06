//! Point d'entrée de l'interface graphique OwlSentry.
//!
//! Tourne en espace utilisateur non privilégié ; l'utilisateur doit être
//! membre du groupe `owlsentry` pour se connecter au socket du démon.

mod app;
mod client;

use clap::Parser;
use owlsentry_common::Lang;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

#[derive(Parser, Debug)]
#[command(
    name = "owlsentry-gui",
    about = "Interface graphique d'OwlSentry (alertes en temps réel, tableau de bord)",
    version
)]
struct Args {
    /// Chemin du socket Unix du démon.
    #[arg(short, long, default_value = owlsentry_common::DEFAULT_SOCKET_PATH)]
    socket: PathBuf,

    /// Langue de l'interface au démarrage ("fr" ou "en").
    #[arg(short, long, default_value = "fr")]
    lang: String,
}

fn main() -> eframe::Result<()> {
    let args = Args::parse();
    let lang = Lang::from_code(&args.lang);

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 700.0])
            .with_min_inner_size([700.0, 400.0])
            .with_app_id("org.owlsentry.gui"),
        ..Default::default()
    };

    eframe::run_native(
        "OwlSentry",
        options,
        Box::new(move |cc| {
            let (tx, rx) = mpsc::channel();
            let notify_enabled = Arc::new(AtomicBool::new(true));
            let ctx = cc.egui_ctx.clone();
            client::spawn(
                args.socket.clone(),
                tx,
                move || ctx.request_repaint(),
                Arc::clone(&notify_enabled),
            );
            Ok(Box::new(app::OwlSentryApp::new(rx, notify_enabled, lang)))
        }),
    )
}
