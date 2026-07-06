//! Protocole IPC entre le démon et l'interface graphique.
//!
//! Transport : socket Unix (`SOCK_STREAM`), messages JSON délimités par `\n`
//! (NDJSON). Chaque ligne est un objet JSON avec un champ `type`.
//! Le contrôle d'accès repose sur les permissions du fichier socket
//! (0660, root:owlsentry) — voir la documentation.

use crate::alert::Alert;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn default_recent_limit() -> usize {
    500
}

/// Requêtes envoyées par un client (GUI ou CLI) au démon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientRequest {
    /// S'abonner au flux d'alertes en temps réel.
    Subscribe,
    /// Récupérer les dernières alertes conservées en mémoire.
    GetRecent {
        #[serde(default = "default_recent_limit")]
        limit: usize,
    },
    /// Récupérer les statistiques agrégées.
    GetStats,
    /// Test de vie.
    Ping,
}

/// Messages envoyés par le démon à un client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonMessage {
    /// Envoyé à la connexion.
    Hello {
        version: String,
        protocol: u32,
        language: String,
    },
    /// Une alerte en temps réel (après `Subscribe`).
    Alert { alert: Alert },
    /// Réponse à `GetRecent`.
    Recent { alerts: Vec<Alert> },
    /// Réponse à `GetStats`.
    Stats { stats: Stats },
    /// Réponse à `Ping`.
    Pong,
    /// Erreur de protocole (requête invalide, ...).
    Error { message: String },
}

/// Compteur d'alertes pour une heure donnée (tableau de bord).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourBucket {
    /// Début de l'heure (UTC, minutes/secondes à zéro).
    pub hour: DateTime<Utc>,
    pub count: u64,
}

/// Statistiques agrégées depuis le démarrage du démon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    pub started_at: DateTime<Utc>,
    pub total: u64,
    /// Clés : `info`, `low`, `medium`, `high`, `critical`.
    pub by_severity: BTreeMap<String, u64>,
    /// Clés : `selinux`, `filesystem`, `network`, `process`, `audit`, `system`.
    pub by_category: BTreeMap<String, u64>,
    /// Alertes par heure (48 dernières heures au maximum).
    pub hourly: Vec<HourBucket>,
}

impl Stats {
    pub fn new(started_at: DateTime<Utc>) -> Self {
        Stats {
            started_at,
            total: 0,
            by_severity: BTreeMap::new(),
            by_category: BTreeMap::new(),
            hourly: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let req: ClientRequest =
            serde_json::from_str(r#"{"type":"get_recent","limit":10}"#).expect("parse");
        match req {
            ClientRequest::GetRecent { limit } => assert_eq!(limit, 10),
            other => panic!("unexpected: {other:?}"),
        }
        // Limite par défaut si absente.
        let req: ClientRequest = serde_json::from_str(r#"{"type":"get_recent"}"#).expect("parse");
        match req {
            ClientRequest::GetRecent { limit } => assert_eq!(limit, 500),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn message_roundtrip() {
        let msg = DaemonMessage::Hello {
            version: "0.1.0".into(),
            protocol: 1,
            language: "fr".into(),
        };
        let json = serde_json::to_string(&msg).expect("serialize");
        assert!(json.contains(r#""type":"hello""#));
        let back: DaemonMessage = serde_json::from_str(&json).expect("deserialize");
        matches!(back, DaemonMessage::Hello { .. });
    }
}
