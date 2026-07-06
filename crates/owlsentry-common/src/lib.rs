//! Types partagés entre le démon OwlSentry et l'interface graphique.
//!
//! Shared types between the OwlSentry daemon and the GUI.

pub mod alert;
pub mod config;
pub mod i18n;
pub mod ipc;

pub use alert::{Alert, Category, Severity};
pub use config::{DaemonConfig, Rules};
pub use i18n::Lang;
pub use ipc::{ClientRequest, DaemonMessage, HourBucket, Stats};

/// Version du protocole IPC. Incrémentée à chaque changement incompatible.
pub const IPC_PROTOCOL_VERSION: u32 = 1;

/// Chemin par défaut du socket Unix du démon.
pub const DEFAULT_SOCKET_PATH: &str = "/run/owlsentry/owlsentry.sock";

/// Chemin par défaut de la configuration du démon.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/owlsentry/owlsentry.conf";
