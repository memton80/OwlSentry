//! Modèle d'alerte : quoi / pourquoi / comment.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Gravité d'une alerte, ordonnée de la moins à la plus grave.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Catégorie fonctionnelle d'une alerte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Selinux,
    Filesystem,
    Network,
    Process,
    Audit,
    System,
}

impl Category {
    pub const ALL: [Category; 6] = [
        Category::Selinux,
        Category::Filesystem,
        Category::Network,
        Category::Process,
        Category::Audit,
        Category::System,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Category::Selinux => "selinux",
            Category::Filesystem => "filesystem",
            Category::Network => "network",
            Category::Process => "process",
            Category::Audit => "audit",
            Category::System => "system",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Une alerte de détection d'intrusion.
///
/// Les champs `what` / `why` / `how` sont déjà localisés par le démon
/// (langue configurée dans `/etc/owlsentry/owlsentry.conf`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Identifiant monotone attribué par le dispatcher du démon (0 = non attribué).
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub category: Category,
    /// Titre court de la détection.
    pub title: String,
    /// Quoi : processus, fichier, connexion, règle SELinux concernée.
    pub what: String,
    /// Pourquoi : explication de la menace.
    pub why: String,
    /// Comment : actions recommandées pour remédier.
    pub how: String,
    /// Métadonnées structurées (pid, chemin, ip, contexte SELinux, ...).
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl Alert {
    pub fn new(
        severity: Severity,
        category: Category,
        title: impl Into<String>,
        what: impl Into<String>,
        why: impl Into<String>,
        how: impl Into<String>,
    ) -> Self {
        Alert {
            id: 0,
            timestamp: Utc::now(),
            severity,
            category,
            title: title.into(),
            what: what.into(),
            why: why.into(),
            how: how.into(),
            metadata: BTreeMap::new(),
        }
    }

    /// Ajoute une métadonnée (chaînable).
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Info < Severity::Low);
    }

    #[test]
    fn alert_serde_roundtrip() {
        let a = Alert::new(
            Severity::High,
            Category::Selinux,
            "AVC denial",
            "what",
            "why",
            "how",
        )
        .with_meta("pid", "1234");
        let json = serde_json::to_string(&a).expect("serialize");
        let back: Alert = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.severity, Severity::High);
        assert_eq!(back.category, Category::Selinux);
        assert_eq!(back.metadata.get("pid").map(String::as_str), Some("1234"));
    }
}
