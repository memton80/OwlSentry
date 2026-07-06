//! Configuration du démon (`/etc/owlsentry/owlsentry.conf`, format TOML)
//! et règles de détection personnalisables (`/etc/owlsentry/rules.toml`).
//!
//! Toute la désérialisation passe par `serde` puis par une étape de
//! validation explicite (`validate()`), conformément au principe
//! « désérialiser puis valider ».

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("lecture impossible de {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("TOML invalide dans {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("configuration invalide: {0}")]
    Invalid(String),
}

/// Configuration principale du démon.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DaemonConfig {
    pub general: GeneralCfg,
    pub audit: AuditCfg,
    pub filesystem: FsCfg,
    pub network: NetCfg,
    pub process: ProcCfg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralCfg {
    /// Langue des messages d'alerte: "fr" ou "en".
    pub language: String,
    /// Répertoire des journaux du démon (rotation quotidienne).
    pub log_dir: PathBuf,
    /// Niveau de log: trace|debug|info|warn|error (syntaxe EnvFilter acceptée).
    pub log_level: String,
    /// Chemin du socket Unix.
    pub socket_path: PathBuf,
    /// Groupe autorisé à se connecter au socket.
    pub socket_group: String,
    /// Chemin du fichier de règles.
    pub rules_path: PathBuf,
    /// Nombre d'alertes conservées en mémoire pour `GetRecent`.
    pub recent_buffer: usize,
}

impl Default for GeneralCfg {
    fn default() -> Self {
        GeneralCfg {
            language: "fr".into(),
            log_dir: PathBuf::from("/var/log/owlsentry"),
            log_level: "info".into(),
            socket_path: PathBuf::from(crate::DEFAULT_SOCKET_PATH),
            socket_group: "owlsentry".into(),
            rules_path: PathBuf::from("/etc/owlsentry/rules.toml"),
            recent_buffer: 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditCfg {
    pub enabled: bool,
    /// Journal auditd à suivre (AVC SELinux, syscalls audités).
    pub audit_log: PathBuf,
    /// Intervalle de relecture quand aucune donnée n'est disponible (ms).
    pub poll_interval_ms: u64,
}

impl Default for AuditCfg {
    fn default() -> Self {
        AuditCfg {
            enabled: true,
            audit_log: PathBuf::from("/var/log/audit/audit.log"),
            poll_interval_ms: 500,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FsCfg {
    pub enabled: bool,
    /// Répertoires surveillés récursivement via inotify.
    pub watch_paths: Vec<PathBuf>,
    /// Anti-rafale : délai minimal entre deux alertes pour un même chemin (s).
    pub debounce_secs: u64,
}

impl Default for FsCfg {
    fn default() -> Self {
        FsCfg {
            enabled: true,
            watch_paths: vec![
                PathBuf::from("/etc"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/usr/sbin"),
                PathBuf::from("/usr/local/bin"),
                PathBuf::from("/var/log"),
                PathBuf::from("/tmp"),
                PathBuf::from("/dev/shm"),
            ],
            debounce_secs: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetCfg {
    pub enabled: bool,
    /// Intervalle d'échantillonnage de /proc/net (s).
    pub poll_interval_secs: u64,
    /// Nombre de ports distincts sondés par une même IP avant alerte.
    pub port_scan_threshold: usize,
    /// Fenêtre glissante de détection de scan (s).
    pub port_scan_window_secs: u64,
    /// Alerter quand un nouveau port se met en écoute.
    pub alert_new_listener: bool,
    /// Blocage automatique des IP de scan via firewalld (règle riche temporaire).
    pub firewalld_block: bool,
    /// Durée du blocage temporaire (s).
    pub block_duration_secs: u64,
}

impl Default for NetCfg {
    fn default() -> Self {
        NetCfg {
            enabled: true,
            poll_interval_secs: 5,
            port_scan_threshold: 15,
            port_scan_window_secs: 30,
            alert_new_listener: true,
            firewalld_block: false,
            block_duration_secs: 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcCfg {
    pub enabled: bool,
    /// Intervalle entre deux balayages de /proc (s).
    pub scan_interval_secs: u64,
}

impl Default for ProcCfg {
    fn default() -> Self {
        ProcCfg {
            enabled: true,
            scan_interval_secs: 30,
        }
    }
}

impl DaemonConfig {
    /// Charge la configuration depuis un fichier TOML puis la valide.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let cfg: DaemonConfig = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Vérifie la cohérence des valeurs (chemins absolus, seuils non nuls...).
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !matches!(self.general.language.as_str(), "fr" | "en") {
            return Err(ConfigError::Invalid(format!(
                "general.language doit être \"fr\" ou \"en\" (reçu: {:?})",
                self.general.language
            )));
        }
        for (name, p) in [
            ("general.log_dir", &self.general.log_dir),
            ("general.socket_path", &self.general.socket_path),
            ("general.rules_path", &self.general.rules_path),
            ("audit.audit_log", &self.audit.audit_log),
        ] {
            if !p.is_absolute() {
                return Err(ConfigError::Invalid(format!(
                    "{name} doit être un chemin absolu (reçu: {})",
                    p.display()
                )));
            }
        }
        for p in &self.filesystem.watch_paths {
            if !p.is_absolute() {
                return Err(ConfigError::Invalid(format!(
                    "filesystem.watch_paths contient un chemin relatif: {}",
                    p.display()
                )));
            }
        }
        if self.general.recent_buffer == 0 {
            return Err(ConfigError::Invalid(
                "general.recent_buffer doit être > 0".into(),
            ));
        }
        if self.network.port_scan_threshold == 0 {
            return Err(ConfigError::Invalid(
                "network.port_scan_threshold doit être > 0".into(),
            ));
        }
        if self.network.poll_interval_secs == 0
            || self.process.scan_interval_secs == 0
            || self.audit.poll_interval_ms == 0
        {
            return Err(ConfigError::Invalid(
                "les intervalles de scrutation doivent être > 0".into(),
            ));
        }
        Ok(())
    }
}

/// Règles de détection personnalisables (`rules.toml`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Rules {
    pub filesystem: FsRules,
    pub network: NetRules,
    pub selinux: SelinuxRules,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FsRules {
    /// Fichiers/répertoires critiques : toute modification déclenche une alerte élevée.
    pub sensitive_paths: Vec<PathBuf>,
    /// Extensions considérées suspectes dans les répertoires temporaires.
    pub suspicious_extensions: Vec<String>,
    /// Répertoires où la création de scripts est suspecte.
    pub suspicious_dirs: Vec<PathBuf>,
    /// Chemins ignorés (préfixe) — évite les boucles avec nos propres journaux.
    pub ignore_paths: Vec<PathBuf>,
}

impl Default for FsRules {
    fn default() -> Self {
        FsRules {
            sensitive_paths: [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/gshadow",
                "/etc/group",
                "/etc/sudoers",
                "/etc/sudoers.d",
                "/etc/ssh/sshd_config",
                "/etc/pam.d",
                "/etc/crontab",
                "/etc/cron.d",
                "/etc/ld.so.preload",
                "/etc/ld.so.conf",
                "/etc/selinux/config",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
            suspicious_extensions: ["sh", "py", "pl", "so", "elf", "bin"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            suspicious_dirs: ["/tmp", "/var/tmp", "/dev/shm"]
                .iter()
                .map(PathBuf::from)
                .collect(),
            ignore_paths: vec![PathBuf::from("/var/log/owlsentry")],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetRules {
    /// IP jamais bloquées automatiquement.
    pub never_block: Vec<String>,
    /// Ports distants notoirement associés à des portes dérobées.
    pub suspicious_ports: Vec<u16>,
    /// Interpréteurs dont une connexion sortante est suspecte.
    pub shell_processes: Vec<String>,
}

impl Default for NetRules {
    fn default() -> Self {
        NetRules {
            never_block: vec!["127.0.0.1".into(), "::1".into()],
            suspicious_ports: vec![1337, 4444, 6667, 9001, 31337],
            shell_processes: ["bash", "sh", "zsh", "dash", "nc", "ncat", "socat"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SelinuxRules {
    /// Types SELinux cibles dont un refus d'accès est critique.
    pub critical_types: Vec<String>,
    /// Commandes de manipulation SELinux à signaler quand elles apparaissent
    /// dans les événements d'audit.
    pub watched_commands: Vec<String>,
}

impl Default for SelinuxRules {
    fn default() -> Self {
        SelinuxRules {
            critical_types: [
                "shadow_t",
                "passwd_file_t",
                "sshd_key_t",
                "security_t",
                "auditd_log_t",
                "boot_t",
                "modules_object_t",
                "selinux_config_t",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            watched_commands: [
                "chcon",
                "restorecon",
                "setenforce",
                "setsebool",
                "semodule",
                "semanage",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }
}

impl Rules {
    /// Charge les règles ; si le fichier n'existe pas, retourne les valeurs
    /// par défaut (le démon reste fonctionnel sans `rules.toml`).
    pub fn load_or_default(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(raw) => {
                let rules: Rules = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
                    path: path.to_path_buf(),
                    source,
                })?;
                Ok(rules)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Rules::default()),
            Err(source) => Err(ConfigError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        DaemonConfig::default().validate().expect("valid");
    }

    #[test]
    fn empty_toml_gives_defaults() {
        let cfg: DaemonConfig = toml::from_str("").expect("parse");
        assert_eq!(cfg.general.language, "fr");
        assert!(cfg.audit.enabled);
        cfg.validate().expect("valid");
    }

    #[test]
    fn invalid_language_rejected() {
        let cfg: DaemonConfig = toml::from_str("[general]\nlanguage = \"de\"").expect("parse");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn relative_path_rejected() {
        let cfg: DaemonConfig = toml::from_str("[general]\nlog_dir = \"logs\"").expect("parse");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn partial_rules_merge_with_defaults() {
        let rules: Rules = toml::from_str("[network]\nsuspicious_ports = [4444]").expect("parse");
        assert_eq!(rules.network.suspicious_ports, vec![4444]);
        // Les autres sections gardent leurs valeurs par défaut.
        assert!(!rules.filesystem.sensitive_paths.is_empty());
    }
}
