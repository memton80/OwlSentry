//! Moniteur de processus : balayage périodique de /proc pour détecter
//! - les injections via LD_PRELOAD ;
//! - les binaires supprimés encore en cours d'exécution ;
//! - les exécutables lancés depuis /tmp, /var/tmp ou /dev/shm ;
//! - les processus cachés (présents dans /proc mais absents de
//!   l'énumération du répertoire — comportement de rootkit).

use crate::messages;
use anyhow::Result;
use owlsentry_common::{Alert, Category, Lang, Severity};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::info;

const TMP_EXEC_PREFIXES: [&str; 3] = ["/tmp", "/var/tmp", "/dev/shm"];

fn list_proc_pids() -> HashSet<i32> {
    let mut pids = HashSet::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
            {
                pids.insert(pid);
            }
        }
    }
    pids
}

fn read_comm(pid: i32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".to_string())
}

/// Extrait la valeur de LD_PRELOAD de l'environnement d'un processus,
/// si elle est non vide.
pub fn ld_preload_of(environ: &[u8]) -> Option<String> {
    for var in environ.split(|b| *b == 0) {
        let var = String::from_utf8_lossy(var);
        if let Some(value) = var.strip_prefix("LD_PRELOAD=") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Lit le PPid depuis /proc/<pid>/status.
fn ppid_of(pid: i32) -> Option<i32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Vrai si le chemin d'exécutable pointe dans un répertoire temporaire.
pub fn is_tmp_exec(exe: &Path) -> bool {
    TMP_EXEC_PREFIXES.iter().any(|p| exe.starts_with(p))
}

pub async fn run(scan_interval_secs: u64, lang: Lang, tx: mpsc::Sender<Alert>) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(scan_interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Déduplication : un pid n'est signalé qu'une fois par type de problème.
    let mut reported_preload: HashSet<i32> = HashSet::new();
    let mut reported_deleted: HashSet<i32> = HashSet::new();
    let mut reported_tmp: HashSet<i32> = HashSet::new();
    let mut reported_hidden: HashSet<i32> = HashSet::new();

    info!("moniteur de processus démarré");
    loop {
        interval.tick().await;
        let pids = list_proc_pids();
        let mut ppids: HashSet<i32> = HashSet::new();

        for &pid in &pids {
            if let Some(ppid) = ppid_of(pid) {
                ppids.insert(ppid);
            }

            // LD_PRELOAD (l'accès à environ échoue pour les processus
            // d'autres utilisateurs sans CAP_SYS_PTRACE : on ignore alors).
            if !reported_preload.contains(&pid) {
                if let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ")) {
                    if let Some(value) = ld_preload_of(&environ) {
                        reported_preload.insert(pid);
                        let comm = read_comm(pid);
                        let m = messages::ld_preload(lang, pid, &comm, &value);
                        let alert = Alert::new(
                            Severity::High,
                            Category::Process,
                            m.title,
                            m.what,
                            m.why,
                            m.how,
                        )
                        .with_meta("pid", pid.to_string())
                        .with_meta("comm", comm)
                        .with_meta("ld_preload", value);
                        if tx.send(alert).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }

            // Exécutable supprimé ou dans un répertoire temporaire.
            if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) {
                let exe_str = exe.to_string_lossy();
                if exe_str.ends_with(" (deleted)") && !reported_deleted.contains(&pid) {
                    reported_deleted.insert(pid);
                    let comm = read_comm(pid);
                    let m = messages::deleted_exe(lang, pid, &comm);
                    let alert = Alert::new(
                        Severity::High,
                        Category::Process,
                        m.title,
                        m.what,
                        m.why,
                        m.how,
                    )
                    .with_meta("pid", pid.to_string())
                    .with_meta("comm", comm)
                    .with_meta("exe", exe_str.to_string());
                    if tx.send(alert).await.is_err() {
                        return Ok(());
                    }
                } else if is_tmp_exec(&exe) && !reported_tmp.contains(&pid) {
                    reported_tmp.insert(pid);
                    let comm = read_comm(pid);
                    let m = messages::tmp_exec(lang, pid, &comm, &exe_str);
                    let alert = Alert::new(
                        Severity::High,
                        Category::Process,
                        m.title,
                        m.what,
                        m.why,
                        m.how,
                    )
                    .with_meta("pid", pid.to_string())
                    .with_meta("comm", comm)
                    .with_meta("exe", exe_str.to_string());
                    if tx.send(alert).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }

        // Processus cachés : un ppid référencé, accessible via stat(2) sur
        // /proc/<pid>, mais absent de l'énumération readdir de /proc.
        // Confirmation par une seconde énumération pour éliminer la course
        // « le processus vient de mourir ».
        for ppid in ppids {
            if ppid <= 2 || pids.contains(&ppid) || reported_hidden.contains(&ppid) {
                continue;
            }
            let proc_path = PathBuf::from(format!("/proc/{ppid}"));
            if proc_path.exists() && !list_proc_pids().contains(&ppid) {
                reported_hidden.insert(ppid);
                let m = messages::hidden_process(lang, ppid);
                let alert = Alert::new(
                    Severity::Critical,
                    Category::Process,
                    m.title,
                    m.what,
                    m.why,
                    m.how,
                )
                .with_meta("pid", ppid.to_string());
                if tx.send(alert).await.is_err() {
                    return Ok(());
                }
            }
        }

        // Nettoyage : oublier les pids disparus pour pouvoir re-signaler un
        // pid réutilisé.
        reported_preload.retain(|p| pids.contains(p));
        reported_deleted.retain(|p| pids.contains(p));
        reported_tmp.retain(|p| pids.contains(p));
        reported_hidden.retain(|p| Path::new(&format!("/proc/{p}")).exists());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ld_preload_extracted() {
        let environ = b"PATH=/usr/bin\0LD_PRELOAD=/tmp/evil.so\0HOME=/root\0";
        assert_eq!(ld_preload_of(environ), Some("/tmp/evil.so".to_string()));
    }

    #[test]
    fn empty_ld_preload_ignored() {
        let environ = b"PATH=/usr/bin\0LD_PRELOAD=\0HOME=/root\0";
        assert_eq!(ld_preload_of(environ), None);
        assert_eq!(ld_preload_of(b"PATH=/usr/bin\0"), None);
    }

    #[test]
    fn tmp_exec_detection() {
        assert!(is_tmp_exec(Path::new("/tmp/payload")));
        assert!(is_tmp_exec(Path::new("/dev/shm/x")));
        assert!(!is_tmp_exec(Path::new("/usr/bin/bash")));
        assert!(!is_tmp_exec(Path::new("/tmpfoo/bin"))); // préfixe strict
    }
}
