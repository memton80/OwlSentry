//! Internationalisation minimale (français / anglais) pour les libellés de
//! l'interface. Les messages d'alerte eux-mêmes sont localisés côté démon
//! (voir `owlsentry-daemon/src/messages.rs`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    Fr,
    En,
}

impl Lang {
    pub fn from_code(code: &str) -> Lang {
        match code.trim().to_ascii_lowercase().as_str() {
            "en" | "en_us" | "en_gb" => Lang::En,
            _ => Lang::Fr,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Lang::Fr => "fr",
            Lang::En => "en",
        }
    }
}

/// Traduit une clé de libellé d'interface. Retourne la clé telle quelle si
/// elle est inconnue (comportement sûr, jamais de panique).
pub fn tr(lang: Lang, key: &'static str) -> &'static str {
    let fr = matches!(lang, Lang::Fr);
    match key {
        "app_title" => {
            if fr {
                "OwlSentry — Détection d'intrusion"
            } else {
                "OwlSentry — Intrusion Detection"
            }
        }
        "alerts" => {
            if fr {
                "Alertes"
            } else {
                "Alerts"
            }
        }
        "dashboard" => {
            if fr {
                "Tableau de bord"
            } else {
                "Dashboard"
            }
        }
        "connected" => {
            if fr {
                "Connecté au démon"
            } else {
                "Connected to daemon"
            }
        }
        "disconnected" => {
            if fr {
                "Démon injoignable — reconnexion…"
            } else {
                "Daemon unreachable — reconnecting…"
            }
        }
        "severity" => {
            if fr {
                "Gravité"
            } else {
                "Severity"
            }
        }
        "min_severity" => {
            if fr {
                "Gravité min."
            } else {
                "Min severity"
            }
        }
        "category" => {
            if fr {
                "Catégorie"
            } else {
                "Category"
            }
        }
        "all" => {
            if fr {
                "Toutes"
            } else {
                "All"
            }
        }
        "search" => {
            if fr {
                "Recherche"
            } else {
                "Search"
            }
        }
        "time" => {
            if fr {
                "Heure"
            } else {
                "Time"
            }
        }
        "title" => {
            if fr {
                "Titre"
            } else {
                "Title"
            }
        }
        "what" => {
            if fr {
                "Quoi"
            } else {
                "What"
            }
        }
        "why" => {
            if fr {
                "Pourquoi"
            } else {
                "Why"
            }
        }
        "how" => {
            if fr {
                "Comment (actions recommandées)"
            } else {
                "How (recommended actions)"
            }
        }
        "details" => {
            if fr {
                "Détails"
            } else {
                "Details"
            }
        }
        "metadata" => {
            if fr {
                "Métadonnées"
            } else {
                "Metadata"
            }
        }
        "no_alert_selected" => {
            if fr {
                "Sélectionnez une alerte pour voir les détails."
            } else {
                "Select an alert to see details."
            }
        }
        "notifications" => {
            if fr {
                "Notifications bureau"
            } else {
                "Desktop notifications"
            }
        }
        "language" => {
            if fr {
                "Langue"
            } else {
                "Language"
            }
        }
        "total_alerts" => {
            if fr {
                "Alertes au total"
            } else {
                "Total alerts"
            }
        }
        "alerts_last_24h" => {
            if fr {
                "Alertes par heure (24 h)"
            } else {
                "Alerts per hour (24 h)"
            }
        }
        "by_severity" => {
            if fr {
                "Par gravité"
            } else {
                "By severity"
            }
        }
        "by_category" => {
            if fr {
                "Par catégorie"
            } else {
                "By category"
            }
        }
        "clear" => {
            if fr {
                "Effacer"
            } else {
                "Clear"
            }
        }
        _ => key,
    }
}

/// Libellé localisé d'une gravité.
pub fn severity_label(lang: Lang, sev: crate::Severity) -> &'static str {
    use crate::Severity::*;
    match (lang, sev) {
        (Lang::Fr, Info) => "Info",
        (Lang::Fr, Low) => "Faible",
        (Lang::Fr, Medium) => "Moyenne",
        (Lang::Fr, High) => "Élevée",
        (Lang::Fr, Critical) => "Critique",
        (Lang::En, Info) => "Info",
        (Lang::En, Low) => "Low",
        (Lang::En, Medium) => "Medium",
        (Lang::En, High) => "High",
        (Lang::En, Critical) => "Critical",
    }
}

/// Libellé localisé d'une catégorie.
pub fn category_label(lang: Lang, cat: crate::Category) -> &'static str {
    use crate::Category::*;
    match (lang, cat) {
        (Lang::Fr, Selinux) => "SELinux",
        (Lang::Fr, Filesystem) => "Fichiers",
        (Lang::Fr, Network) => "Réseau",
        (Lang::Fr, Process) => "Processus",
        (Lang::Fr, Audit) => "Audit",
        (Lang::Fr, System) => "Système",
        (Lang::En, Selinux) => "SELinux",
        (Lang::En, Filesystem) => "Filesystem",
        (Lang::En, Network) => "Network",
        (Lang::En, Process) => "Process",
        (Lang::En, Audit) => "Audit",
        (Lang::En, System) => "System",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_key_returns_key() {
        assert_eq!(tr(Lang::Fr, "does_not_exist"), "does_not_exist");
    }

    #[test]
    fn lang_from_code() {
        assert_eq!(Lang::from_code("EN"), Lang::En);
        assert_eq!(Lang::from_code("fr"), Lang::Fr);
        assert_eq!(Lang::from_code("xx"), Lang::Fr);
    }
}
