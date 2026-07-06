//! Bibliothèque interne du démon OwlSentry.
//!
//! Le binaire (`main.rs`) est une fine couche au-dessus de cette
//! bibliothèque ; l'exposer permet d'écrire des tests d'intégration
//! (voir `tests/`).

pub mod dispatcher;
pub mod ipc_server;
pub mod logging;
pub mod messages;
pub mod monitors;
pub mod state;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
