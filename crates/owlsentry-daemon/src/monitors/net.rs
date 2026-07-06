//! Moniteur réseau : échantillonne `/proc/net/tcp{,6}` pour détecter
//! - les scans de ports (nombre de ports distincts sondés par IP dans une
//!   fenêtre glissante, via les demi-connexions SYN_RECV) ;
//! - l'apparition de nouveaux ports en écoute ;
//! - les connexions sortantes d'interpréteurs (reverse shells) ;
//! - les connexions vers des ports notoirement malveillants.
//!
//! Le blocage automatique (optionnel, `network.firewalld_block = true`)
//! passe par `firewall-cmd` exécuté SANS shell (arguments fixes, IP validée
//! par `IpAddr::from_str`) et avec `--timeout` pour rester temporaire.

use crate::messages;
use anyhow::Result;
use owlsentry_common::config::{NetCfg, NetRules};
use owlsentry_common::{Alert, Category, Lang, Severity};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// États TCP de /proc/net/tcp.
pub const TCP_ESTABLISHED: u8 = 0x01;
pub const TCP_SYN_RECV: u8 = 0x03;
pub const TCP_LISTEN: u8 = 0x0A;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpConn {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub state: u8,
    pub inode: u64,
}

fn parse_hex_port(s: &str) -> Option<u16> {
    u16::from_str_radix(s, 16).ok()
}

fn parse_hex_addr(s: &str, v6: bool) -> Option<IpAddr> {
    if v6 {
        if s.len() != 32 {
            return None;
        }
        // /proc/net/tcp6 encode l'adresse comme 4 mots de 32 bits, chacun en
        // ordre little-endian.
        let mut bytes = [0u8; 16];
        for word in 0..4 {
            let chunk = &s[word * 8..word * 8 + 8];
            let value = u32::from_str_radix(chunk, 16).ok()?;
            bytes[word * 4..word * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        if s.len() != 8 {
            return None;
        }
        let value = u32::from_str_radix(s, 16).ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(value.to_le_bytes())))
    }
}

/// Analyse une ligne de `/proc/net/tcp` ou `/proc/net/tcp6`.
pub fn parse_proc_net_line(line: &str, v6: bool) -> Option<TcpConn> {
    let mut fields = line.split_whitespace();
    let first = fields.next()?;
    // Ignorer l'en-tête ("sl").
    if !first.ends_with(':') {
        return None;
    }
    let local = fields.next()?;
    let remote = fields.next()?;
    let state = u8::from_str_radix(fields.next()?, 16).ok()?;
    // tx_queue:rx_queue, tr:tm->when, retrnsmt, uid, timeout, inode
    let _txrx = fields.next()?;
    let _tr = fields.next()?;
    let _retr = fields.next()?;
    let _uid = fields.next()?;
    let _timeout = fields.next()?;
    let inode: u64 = fields.next()?.parse().ok()?;

    let (laddr, lport) = local.split_once(':')?;
    let (raddr, rport) = remote.split_once(':')?;
    Some(TcpConn {
        local_addr: parse_hex_addr(laddr, v6)?,
        local_port: parse_hex_port(lport)?,
        remote_addr: parse_hex_addr(raddr, v6)?,
        remote_port: parse_hex_port(rport)?,
        state,
        inode,
    })
}

fn read_proc_net() -> Vec<TcpConn> {
    let mut conns = Vec::new();
    for (path, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        if let Ok(content) = std::fs::read_to_string(path) {
            conns.extend(
                content
                    .lines()
                    .filter_map(|line| parse_proc_net_line(line, v6)),
            );
        }
    }
    conns
}

/// Table inode de socket → (pid, comm), construite en balayant /proc/*/fd.
fn socket_inode_owners() -> HashMap<u64, (i32, String)> {
    let mut map = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue; // processus terminé ou accès refusé
        };
        let comm = std::fs::read_to_string(entry.path().join("comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                let target = target.to_string_lossy();
                if let Some(inode) = target
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    map.insert(inode, (pid, comm.clone()));
                }
            }
        }
    }
    map
}

fn is_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// Bloque temporairement une IP via firewalld (règle riche + timeout).
async fn firewalld_block(ip: IpAddr, duration_secs: u64) -> Result<()> {
    let family = if ip.is_ipv4() { "ipv4" } else { "ipv6" };
    let rule = format!("rule family={family} source address={ip} drop");
    let status = tokio::process::Command::new("firewall-cmd")
        .arg(format!("--add-rich-rule={rule}"))
        .arg(format!("--timeout={duration_secs}"))
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("firewall-cmd a retourné {status}");
    }
    Ok(())
}

/// Suivi des ports sondés par IP dans une fenêtre glissante.
#[derive(Default)]
pub struct ScanTracker {
    probes: HashMap<IpAddr, Vec<(Instant, u16)>>,
}

impl ScanTracker {
    /// Enregistre une sonde et retourne le nombre de ports distincts vus par
    /// cette IP dans la fenêtre.
    pub fn record(&mut self, ip: IpAddr, port: u16, window: Duration) -> usize {
        let now = Instant::now();
        let entry = self.probes.entry(ip).or_default();
        entry.retain(|(t, _)| now.duration_since(*t) < window);
        if !entry.iter().any(|(_, p)| *p == port) {
            entry.push((now, port));
        }
        entry.len()
    }

    pub fn forget(&mut self, ip: &IpAddr) {
        self.probes.remove(ip);
    }
}

pub async fn run(cfg: NetCfg, rules: NetRules, lang: Lang, tx: mpsc::Sender<Alert>) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(cfg.poll_interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let window = Duration::from_secs(cfg.port_scan_window_secs.max(1));

    let never_block: HashSet<IpAddr> = rules
        .never_block
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    let mut known_listeners: HashSet<u16> = HashSet::new();
    let mut baseline_done = false;
    let mut tracker = ScanTracker::default();
    let mut reported_scans: HashSet<IpAddr> = HashSet::new();
    let mut reported_shell_conns: HashSet<(i32, u16)> = HashSet::new();
    let mut reported_susp_ports: HashSet<(IpAddr, u16)> = HashSet::new();

    info!("moniteur réseau démarré");
    loop {
        interval.tick().await;
        let conns = read_proc_net();

        // --- Nouveaux ports en écoute ---
        let listeners: HashSet<u16> = conns
            .iter()
            .filter(|c| c.state == TCP_LISTEN)
            .map(|c| c.local_port)
            .collect();
        if baseline_done && cfg.alert_new_listener {
            for port in listeners.difference(&known_listeners) {
                let m = messages::new_listener(lang, "tcp", *port);
                let alert = Alert::new(
                    Severity::Medium,
                    Category::Network,
                    m.title,
                    m.what,
                    m.why,
                    m.how,
                )
                .with_meta("port", port.to_string())
                .with_meta("proto", "tcp".to_string());
                if tx.send(alert).await.is_err() {
                    return Ok(());
                }
            }
        }
        known_listeners = listeners;
        baseline_done = true;

        // --- Détection de scan (SYN_RECV) ---
        for conn in conns.iter().filter(|c| c.state == TCP_SYN_RECV) {
            if is_local(conn.remote_addr) {
                continue;
            }
            let distinct = tracker.record(conn.remote_addr, conn.local_port, window);
            if distinct >= cfg.port_scan_threshold && !reported_scans.contains(&conn.remote_addr) {
                reported_scans.insert(conn.remote_addr);
                let mut blocked = false;
                if cfg.firewalld_block && !never_block.contains(&conn.remote_addr) {
                    match firewalld_block(conn.remote_addr, cfg.block_duration_secs).await {
                        Ok(()) => {
                            blocked = true;
                            info!(ip = %conn.remote_addr, "IP bloquée temporairement via firewalld");
                        }
                        Err(e) => {
                            warn!(ip = %conn.remote_addr, error = %e, "blocage firewalld impossible")
                        }
                    }
                }
                let m = messages::port_scan(lang, &conn.remote_addr.to_string(), distinct, blocked);
                let alert = Alert::new(
                    Severity::High,
                    Category::Network,
                    m.title,
                    m.what,
                    m.why,
                    m.how,
                )
                .with_meta("ip", conn.remote_addr.to_string())
                .with_meta("distinct_ports", distinct.to_string())
                .with_meta("blocked", blocked.to_string());
                tracker.forget(&conn.remote_addr);
                if tx.send(alert).await.is_err() {
                    return Ok(());
                }
            }
        }

        // --- Connexions établies suspectes ---
        let established: Vec<&TcpConn> = conns
            .iter()
            .filter(|c| c.state == TCP_ESTABLISHED && !is_local(c.remote_addr))
            .collect();
        if !established.is_empty() {
            let owners = socket_inode_owners();
            for conn in established {
                let remote = format!("{}:{}", conn.remote_addr, conn.remote_port);
                if rules.suspicious_ports.contains(&conn.remote_port)
                    && !reported_susp_ports.contains(&(conn.remote_addr, conn.remote_port))
                {
                    reported_susp_ports.insert((conn.remote_addr, conn.remote_port));
                    let m = messages::suspicious_port_connection(lang, &remote, conn.remote_port);
                    let alert = Alert::new(
                        Severity::High,
                        Category::Network,
                        m.title,
                        m.what,
                        m.why,
                        m.how,
                    )
                    .with_meta("remote", remote.clone());
                    if tx.send(alert).await.is_err() {
                        return Ok(());
                    }
                }
                if let Some((pid, comm)) = owners.get(&conn.inode) {
                    if rules.shell_processes.iter().any(|s| s == comm)
                        && !reported_shell_conns.contains(&(*pid, conn.remote_port))
                    {
                        reported_shell_conns.insert((*pid, conn.remote_port));
                        let m = messages::shell_connection(lang, comm, *pid, &remote);
                        let alert = Alert::new(
                            Severity::High,
                            Category::Network,
                            m.title,
                            m.what,
                            m.why,
                            m.how,
                        )
                        .with_meta("pid", pid.to_string())
                        .with_meta("comm", comm.clone())
                        .with_meta("remote", remote);
                        if tx.send(alert).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
        }

        // Bornes mémoire des ensembles de déduplication.
        if reported_scans.len() > 10_000 {
            reported_scans.clear();
        }
        if reported_shell_conns.len() > 10_000 {
            reported_shell_conns.clear();
        }
        if reported_susp_ports.len() > 10_000 {
            reported_susp_ports.clear();
        }
        debug!(connections = conns.len(), "échantillon réseau");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ligne réelle de /proc/net/tcp : 127.0.0.1:631 en LISTEN.
    const V4_LISTEN: &str =
        "   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0";

    #[test]
    fn parse_v4_listen_line() {
        let conn = parse_proc_net_line(V4_LISTEN, false).expect("conn");
        assert_eq!(conn.local_addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(conn.local_port, 0x0277); // 631
        assert_eq!(conn.state, TCP_LISTEN);
        assert_eq!(conn.inode, 12345);
    }

    #[test]
    fn parse_header_returns_none() {
        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        assert!(parse_proc_net_line(header, false).is_none());
    }

    #[test]
    fn parse_v6_loopback() {
        // ::1 → 00000000 00000000 00000000 01000000 (mots little-endian)
        let line = "   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1 0000000000000000 100 0 0 10 0";
        let conn = parse_proc_net_line(line, true).expect("conn");
        assert_eq!(conn.local_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(conn.local_port, 8080);
    }

    #[test]
    fn scan_tracker_counts_distinct_ports() {
        let mut tracker = ScanTracker::default();
        let ip: IpAddr = "203.0.113.7".parse().expect("ip");
        let window = Duration::from_secs(30);
        for port in 1000..1005 {
            tracker.record(ip, port, window);
        }
        // Port déjà vu : le compte ne change pas.
        assert_eq!(tracker.record(ip, 1000, window), 5);
        assert_eq!(tracker.record(ip, 1005, window), 6);
    }
}
