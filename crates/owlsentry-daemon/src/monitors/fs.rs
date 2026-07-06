//! Moniteur système de fichiers : inotify (via la crate `notify`) sur les
//! répertoires sensibles. Détecte :
//! - modifications / changements de permissions sur les fichiers critiques ;
//! - création de scripts/binaires dans les répertoires temporaires ;
//! - suppression de journaux dans /var/log.

use crate::messages;
use anyhow::{Context, Result};
use notify::event::{ModifyKind, RemoveKind};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use owlsentry_common::config::{FsCfg, FsRules};
use owlsentry_common::{Alert, Category, Lang, Severity};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Type d'événement simplifié, indépendant de la crate `notify`
/// (facilite les tests unitaires).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsAction {
    Create,
    Modify,
    MetadataChange,
    Remove,
}

impl FsAction {
    fn describe(self, lang: Lang) -> &'static str {
        match (lang, self) {
            (Lang::Fr, FsAction::Create) => "création",
            (Lang::Fr, FsAction::Modify) => "modification du contenu",
            (Lang::Fr, FsAction::MetadataChange) => {
                "changement de permissions/propriétaire/contexte"
            }
            (Lang::Fr, FsAction::Remove) => "suppression",
            (Lang::En, FsAction::Create) => "creation",
            (Lang::En, FsAction::Modify) => "content modification",
            (Lang::En, FsAction::MetadataChange) => "permissions/owner/context change",
            (Lang::En, FsAction::Remove) => "removal",
        }
    }
}

fn path_starts_with_any(path: &Path, prefixes: &[PathBuf]) -> bool {
    prefixes.iter().any(|p| path.starts_with(p))
}

/// Vrai pour les artefacts de rotation de journaux (logrotate) :
/// `messages-20260101`, `secure.1`, `*.gz`, `*.xz`, `*.old`…
fn looks_like_rotated_log(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if let Some(ext) = name.rsplit('.').next() {
        if matches!(ext, "gz" | "xz" | "zst" | "bz2" | "old") {
            return true;
        }
        if !ext.is_empty() && ext.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    // suffixe -YYYYMMDD
    name.rsplit('-')
        .next()
        .map(|s| s.len() == 8 && s.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false)
}

/// Classifie un événement de fichier en alerte éventuelle.
pub fn classify(action: FsAction, path: &Path, rules: &FsRules, lang: Lang) -> Option<Alert> {
    if path_starts_with_any(path, &rules.ignore_paths) {
        return None;
    }
    let path_str = path.to_string_lossy();

    // 1. Fichiers/répertoires critiques.
    if path_starts_with_any(path, &rules.sensitive_paths) {
        let severity = match action {
            FsAction::Remove => Severity::Critical,
            FsAction::Modify | FsAction::MetadataChange => Severity::High,
            FsAction::Create => Severity::Medium,
        };
        let m = messages::sensitive_file_changed(lang, &path_str, action.describe(lang));
        return Some(
            Alert::new(
                severity,
                Category::Filesystem,
                m.title,
                m.what,
                m.why,
                m.how,
            )
            .with_meta("path", path_str.to_string())
            .with_meta("action", format!("{action:?}")),
        );
    }

    // 2. Suppression de journaux (hors artefacts de rotation).
    if action == FsAction::Remove && path.starts_with("/var/log") && !looks_like_rotated_log(path) {
        let m = messages::log_deleted(lang, &path_str);
        return Some(
            Alert::new(
                Severity::High,
                Category::Filesystem,
                m.title,
                m.what,
                m.why,
                m.how,
            )
            .with_meta("path", path_str.to_string()),
        );
    }

    // 3. Scripts/binaires créés dans les répertoires temporaires.
    if action == FsAction::Create && path_starts_with_any(path, &rules.suspicious_dirs) {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if rules.suspicious_extensions.iter().any(|e| e == &ext) {
            let m = messages::suspicious_file_created(lang, &path_str);
            return Some(
                Alert::new(
                    Severity::Medium,
                    Category::Filesystem,
                    m.title,
                    m.what,
                    m.why,
                    m.how,
                )
                .with_meta("path", path_str.to_string()),
            );
        }
    }

    None
}

fn simplify_kind(kind: &EventKind) -> Option<FsAction> {
    match kind {
        EventKind::Create(_) => Some(FsAction::Create),
        EventKind::Modify(ModifyKind::Metadata(_)) => Some(FsAction::MetadataChange),
        EventKind::Modify(ModifyKind::Data(_)) | EventKind::Modify(ModifyKind::Any) => {
            Some(FsAction::Modify)
        }
        EventKind::Remove(RemoveKind::File)
        | EventKind::Remove(RemoveKind::Any)
        | EventKind::Remove(RemoveKind::Folder) => Some(FsAction::Remove),
        _ => None,
    }
}

/// Boucle du moniteur : installe les watchers inotify et classifie les
/// événements reçus.
pub async fn run(cfg: FsCfg, rules: FsRules, lang: Lang, tx: mpsc::Sender<Alert>) -> Result<()> {
    let (raw_tx, mut raw_rx) = mpsc::channel::<Event>(1024);

    // Le callback de `notify` tourne dans un thread dédié : `blocking_send`
    // y est autorisé (jamais appelé depuis le runtime tokio).
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
        if let Ok(event) = res {
            let _ = raw_tx.blocking_send(event);
        }
    })
    .context("création du watcher inotify")?;

    for path in &cfg.watch_paths {
        match watcher.watch(path, RecursiveMode::Recursive) {
            Ok(()) => info!(path = %path.display(), "surveillance inotify active"),
            Err(e) => warn!(path = %path.display(), error = %e, "surveillance impossible"),
        }
    }

    // Anti-rafale : au plus une alerte par chemin par fenêtre de debounce.
    let debounce = Duration::from_secs(cfg.debounce_secs.max(1));
    let mut last_alert: HashMap<PathBuf, Instant> = HashMap::new();

    while let Some(event) = raw_rx.recv().await {
        let Some(action) = simplify_kind(&event.kind) else {
            continue;
        };
        for path in &event.paths {
            let now = Instant::now();
            if let Some(prev) = last_alert.get(path) {
                if now.duration_since(*prev) < debounce {
                    continue;
                }
            }
            if let Some(alert) = classify(action, path, &rules, lang) {
                last_alert.insert(path.clone(), now);
                if last_alert.len() > 10_000 {
                    last_alert.retain(|_, t| now.duration_since(*t) < debounce);
                }
                if tx.send(alert).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> FsRules {
        FsRules::default()
    }

    #[test]
    fn sensitive_file_modification_is_high() {
        let alert = classify(
            FsAction::Modify,
            Path::new("/etc/shadow"),
            &rules(),
            Lang::Fr,
        )
        .expect("alert");
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.category, Category::Filesystem);
        assert!(alert.what.contains("/etc/shadow"));
    }

    #[test]
    fn sensitive_dir_children_covered() {
        // /etc/sudoers.d est un préfixe sensible : ses enfants comptent aussi.
        let alert = classify(
            FsAction::Create,
            Path::new("/etc/sudoers.d/evil"),
            &rules(),
            Lang::En,
        );
        assert!(alert.is_some());
    }

    #[test]
    fn script_in_tmp_is_flagged() {
        let alert = classify(
            FsAction::Create,
            Path::new("/tmp/payload.sh"),
            &rules(),
            Lang::Fr,
        )
        .expect("alert");
        assert_eq!(alert.severity, Severity::Medium);
    }

    #[test]
    fn regular_file_in_tmp_ignored() {
        assert!(classify(
            FsAction::Create,
            Path::new("/tmp/notes.txt"),
            &rules(),
            Lang::Fr
        )
        .is_none());
    }

    #[test]
    fn log_removal_alerts_but_rotation_does_not() {
        assert!(classify(
            FsAction::Remove,
            Path::new("/var/log/secure"),
            &rules(),
            Lang::Fr
        )
        .is_some());
        for rotated in [
            "/var/log/messages-20260101",
            "/var/log/secure.1",
            "/var/log/dnf.log.gz",
            "/var/log/old.xz",
        ] {
            assert!(
                classify(FsAction::Remove, Path::new(rotated), &rules(), Lang::Fr).is_none(),
                "{rotated} ne devrait pas alerter"
            );
        }
    }

    #[test]
    fn ignored_paths_are_silent() {
        assert!(classify(
            FsAction::Remove,
            Path::new("/var/log/owlsentry/alerts.jsonl.2026-07-06"),
            &rules(),
            Lang::Fr
        )
        .is_none());
    }

    #[test]
    fn log_modification_is_normal() {
        // Les journaux sont modifiés en permanence : seul Remove alerte.
        assert!(classify(
            FsAction::Modify,
            Path::new("/var/log/audit/audit.log"),
            &rules(),
            Lang::Fr
        )
        .is_none());
    }
}
