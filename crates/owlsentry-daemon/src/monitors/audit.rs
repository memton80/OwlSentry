//! Moniteur auditd/SELinux : suit `/var/log/audit/audit.log` en temps réel
//! (équivalent `tail -F`, avec gestion de la rotation) et convertit les
//! événements pertinents en alertes.
//!
//! Choix d'implémentation : parsing direct du journal plutôt que la crate
//! `audit` ou la libaudit — le format `key=value` est stable, cela évite une
//! dépendance C et fonctionne même si auditd est configuré différemment.
//! Une évolution possible est de lire le multicast netlink
//! (`AUDIT_NLGRP_READONLY`, capacité CAP_AUDIT_READ) sans passer par le
//! fichier ; le point d'entrée est isolé ici pour permettre ce changement.

use crate::messages;
use anyhow::{Context, Result};
use owlsentry_common::config::{AuditCfg, SelinuxRules};
use owlsentry_common::{Alert, Category, Lang, Severity};
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Événement d'audit décodé (sous-ensemble utile).
#[derive(Debug, Clone, PartialEq)]
pub enum AuditEvent {
    /// Refus SELinux.
    AvcDenial {
        perms: String,
        pid: Option<i32>,
        comm: String,
        target: String,
        tclass: String,
        scontext: String,
        tcontext: String,
        permissive: bool,
    },
    /// Exécution consignée par auditd (type=SYSCALL avec exe=).
    Exec { exe: String, auid: String },
    /// setenforce 0.
    EnforcingDisabled,
    /// Chargement de politique/module SELinux.
    PolicyLoad,
}

/// Découpe une ligne d'audit en paires clé→valeur. Les valeurs entre
/// guillemets peuvent contenir des espaces.
fn parse_kv(line: &str) -> HashMap<&str, &str> {
    let mut map = HashMap::new();
    let mut rest = line;
    while let Some(eq) = rest.find('=') {
        // La clé est le dernier token avant '='.
        let key_start = rest[..eq]
            .rfind(|c: char| c.is_whitespace())
            .map(|i| i + 1)
            .unwrap_or(0);
        let key = &rest[key_start..eq];
        let after = &rest[eq + 1..];
        let (value, consumed) = if let Some(stripped) = after.strip_prefix('"') {
            match stripped.find('"') {
                Some(end) => (&stripped[..end], eq + 1 + 1 + end + 1),
                None => (stripped, rest.len()),
            }
        } else {
            let end = after
                .find(|c: char| c.is_whitespace())
                .unwrap_or(after.len());
            (&after[..end], eq + 1 + end)
        };
        if !key.is_empty() {
            map.insert(key, value);
        }
        if consumed >= rest.len() {
            break;
        }
        rest = &rest[consumed..];
    }
    map
}

/// Extrait le type d'enregistrement (`type=XXX`).
fn record_type(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("type=")?;
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Analyse une ligne du journal d'audit.
pub fn parse_line(line: &str) -> Option<AuditEvent> {
    let rtype = record_type(line)?;
    match rtype {
        "AVC" | "USER_AVC" => {
            if !line.contains("denied") {
                return None;
            }
            // Permissions entre accolades : avc:  denied  { read write } for ...
            let perms = line
                .split_once('{')
                .and_then(|(_, rest)| rest.split_once('}'))
                .map(|(inside, _)| inside.trim().to_string())?;
            let kv = parse_kv(line);
            Some(AuditEvent::AvcDenial {
                perms,
                pid: kv.get("pid").and_then(|v| v.parse().ok()),
                comm: kv.get("comm").unwrap_or(&"?").to_string(),
                target: kv
                    .get("name")
                    .or_else(|| kv.get("path"))
                    .or_else(|| kv.get("laddr"))
                    .unwrap_or(&"?")
                    .to_string(),
                tclass: kv.get("tclass").unwrap_or(&"?").to_string(),
                scontext: kv.get("scontext").unwrap_or(&"?").to_string(),
                tcontext: kv.get("tcontext").unwrap_or(&"?").to_string(),
                permissive: kv.get("permissive").map(|v| *v == "1").unwrap_or(false),
            })
        }
        "SYSCALL" => {
            let kv = parse_kv(line);
            let exe = kv.get("exe")?.to_string();
            Some(AuditEvent::Exec {
                exe,
                auid: kv.get("auid").unwrap_or(&"?").to_string(),
            })
        }
        "MAC_STATUS" => {
            let kv = parse_kv(line);
            if kv.get("enforcing").map(|v| *v == "0").unwrap_or(false) {
                Some(AuditEvent::EnforcingDisabled)
            } else {
                None
            }
        }
        "MAC_POLICY_LOAD" => Some(AuditEvent::PolicyLoad),
        _ => None,
    }
}

/// Convertit un événement d'audit en alerte, selon les règles.
pub fn event_to_alert(event: &AuditEvent, rules: &SelinuxRules, lang: Lang) -> Option<Alert> {
    match event {
        AuditEvent::AvcDenial {
            perms,
            pid,
            comm,
            target,
            tclass,
            scontext,
            tcontext,
            permissive,
        } => {
            let critical = rules
                .critical_types
                .iter()
                .any(|t| tcontext.contains(t.as_str()));
            let severity = if critical {
                Severity::Critical
            } else if *permissive {
                Severity::Medium
            } else {
                Severity::High
            };
            let m = messages::avc_denial(lang, comm, perms, target, tclass, scontext, tcontext);
            let mut alert = Alert::new(severity, Category::Selinux, m.title, m.what, m.why, m.how)
                .with_meta("comm", comm.clone())
                .with_meta("perms", perms.clone())
                .with_meta("scontext", scontext.clone())
                .with_meta("tcontext", tcontext.clone())
                .with_meta("tclass", tclass.clone());
            if let Some(pid) = pid {
                alert = alert.with_meta("pid", pid.to_string());
            }
            Some(alert)
        }
        AuditEvent::Exec { exe, auid } => {
            let basename = exe.rsplit('/').next().unwrap_or(exe.as_str());
            if !rules.watched_commands.iter().any(|c| c == basename) {
                return None;
            }
            let m = messages::selinux_tool_used(lang, basename, auid);
            Some(
                Alert::new(
                    Severity::Medium,
                    Category::Selinux,
                    m.title,
                    m.what,
                    m.why,
                    m.how,
                )
                .with_meta("exe", exe.clone())
                .with_meta("auid", auid.clone()),
            )
        }
        AuditEvent::EnforcingDisabled => {
            let m = messages::enforcing_disabled(lang);
            Some(Alert::new(
                Severity::Critical,
                Category::Selinux,
                m.title,
                m.what,
                m.why,
                m.how,
            ))
        }
        AuditEvent::PolicyLoad => {
            let m = messages::policy_loaded(lang);
            Some(Alert::new(
                Severity::Medium,
                Category::Selinux,
                m.title,
                m.what,
                m.why,
                m.how,
            ))
        }
    }
}

/// Boucle principale du moniteur : suit le fichier d'audit et pousse les
/// alertes dans `tx`.
pub async fn run(
    cfg: AuditCfg,
    rules: SelinuxRules,
    lang: Lang,
    tx: mpsc::Sender<Alert>,
) -> Result<()> {
    let path = cfg.audit_log.clone();
    let poll = Duration::from_millis(cfg.poll_interval_ms);

    let mut file = File::open(&path)
        .await
        .with_context(|| format!("ouverture de {}", path.display()))?;
    let mut ino = file.metadata().await?.ino();
    // Démarrer à la fin : on ne rejoue pas l'historique.
    file.seek(SeekFrom::End(0)).await?;
    let mut reader = BufReader::new(file);
    info!(path = %path.display(), "suivi du journal d'audit démarré");

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            tokio::time::sleep(poll).await;
            // Rotation ? (inode différent ou fichier tronqué)
            match tokio::fs::metadata(&path).await {
                Ok(meta) => {
                    let pos = reader.stream_position().await.unwrap_or(0);
                    if meta.ino() != ino || meta.len() < pos {
                        debug!("rotation du journal d'audit détectée, réouverture");
                        match File::open(&path).await {
                            Ok(f) => {
                                ino = meta.ino();
                                reader = BufReader::new(f);
                            }
                            Err(e) => warn!(error = %e, "réouverture du journal impossible"),
                        }
                    }
                }
                Err(e) => debug!(error = %e, "stat du journal d'audit impossible"),
            }
            continue;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(event) = parse_line(trimmed) {
            if let Some(alert) = event_to_alert(&event, &rules, lang) {
                if tx.send(alert).await.is_err() {
                    // Dispatcher arrêté : fin propre.
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AVC_LINE: &str = r#"type=AVC msg=audit(1720000000.123:456): avc:  denied  { read } for  pid=1234 comm="cat" name="shadow" dev="dm-0" ino=131842 scontext=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0"#;

    #[test]
    fn parse_avc_denial() {
        let event = parse_line(AVC_LINE).expect("event");
        match &event {
            AuditEvent::AvcDenial {
                perms,
                pid,
                comm,
                target,
                tclass,
                tcontext,
                permissive,
                ..
            } => {
                assert_eq!(perms, "read");
                assert_eq!(*pid, Some(1234));
                assert_eq!(comm, "cat");
                assert_eq!(target, "shadow");
                assert_eq!(tclass, "file");
                assert!(tcontext.contains("shadow_t"));
                assert!(!permissive);
            }
            other => panic!("unexpected: {other:?}"),
        }
        // shadow_t est dans les types critiques par défaut → Critical.
        let alert = event_to_alert(&event, &SelinuxRules::default(), Lang::Fr).expect("alert");
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.category, Category::Selinux);
        assert!(alert.what.contains("cat"));
    }

    #[test]
    fn parse_syscall_watched_command() {
        let line = r#"type=SYSCALL msg=audit(1720000000.200:457): arch=c000003e syscall=59 success=yes exit=0 a0=1 items=2 pid=999 auid=1000 uid=0 gid=0 comm="setenforce" exe="/usr/sbin/setenforce" subj=unconfined_u:unconfined_r:unconfined_t:s0 key=(null)"#;
        let event = parse_line(line).expect("event");
        match &event {
            AuditEvent::Exec { exe, auid } => {
                assert_eq!(exe, "/usr/sbin/setenforce");
                assert_eq!(auid, "1000");
            }
            other => panic!("unexpected: {other:?}"),
        }
        let alert = event_to_alert(&event, &SelinuxRules::default(), Lang::En).expect("alert");
        assert_eq!(alert.severity, Severity::Medium);
    }

    #[test]
    fn parse_syscall_unwatched_command_no_alert() {
        let line = r#"type=SYSCALL msg=audit(1.2:3): syscall=59 exe="/usr/bin/ls" auid=1000"#;
        let event = parse_line(line).expect("event");
        assert!(event_to_alert(&event, &SelinuxRules::default(), Lang::Fr).is_none());
    }

    #[test]
    fn parse_mac_status_disable() {
        let line =
            r#"type=MAC_STATUS msg=audit(1.2:4): enforcing=0 old_enforcing=1 auid=1000 ses=2"#;
        assert_eq!(parse_line(line), Some(AuditEvent::EnforcingDisabled));
        let line_enable =
            r#"type=MAC_STATUS msg=audit(1.2:5): enforcing=1 old_enforcing=0 auid=1000"#;
        assert_eq!(parse_line(line_enable), None);
    }

    #[test]
    fn parse_policy_load() {
        let line = r#"type=MAC_POLICY_LOAD msg=audit(1.2:6): auid=1000 ses=2 lsm=selinux res=1"#;
        assert_eq!(parse_line(line), Some(AuditEvent::PolicyLoad));
    }

    #[test]
    fn irrelevant_lines_ignored() {
        assert_eq!(parse_line("type=CRED_ACQ msg=audit(1.2:7): pid=1"), None);
        assert_eq!(parse_line("garbage without type"), None);
        assert_eq!(parse_line(""), None);
    }

    #[test]
    fn kv_parser_handles_quotes() {
        let kv = parse_kv(r#"comm="my prog" exe="/usr/bin/x" pid=42"#);
        assert_eq!(kv.get("comm"), Some(&"my prog"));
        assert_eq!(kv.get("exe"), Some(&"/usr/bin/x"));
        assert_eq!(kv.get("pid"), Some(&"42"));
    }
}
