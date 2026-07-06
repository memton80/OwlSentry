//! État partagé du démon : tampon des alertes récentes + statistiques.

use chrono::{DateTime, Utc};
use owlsentry_common::{Alert, HourBucket, Stats};
use std::collections::{BTreeMap, VecDeque};
use tokio::sync::RwLock;

const MAX_HOUR_BUCKETS: usize = 48;

#[derive(Debug)]
struct Inner {
    recent: VecDeque<Alert>,
    total: u64,
    by_severity: BTreeMap<String, u64>,
    by_category: BTreeMap<String, u64>,
    hourly: VecDeque<HourBucket>,
}

/// État partagé entre le dispatcher et le serveur IPC.
#[derive(Debug)]
pub struct DaemonState {
    started_at: DateTime<Utc>,
    recent_capacity: usize,
    inner: RwLock<Inner>,
}

/// Tronque un instant au début de son heure (UTC).
fn truncate_to_hour(ts: DateTime<Utc>) -> DateTime<Utc> {
    let secs = ts.timestamp() - ts.timestamp().rem_euclid(3600);
    DateTime::<Utc>::from_timestamp(secs, 0).unwrap_or(ts)
}

impl DaemonState {
    pub fn new(recent_capacity: usize) -> Self {
        DaemonState {
            started_at: Utc::now(),
            recent_capacity: recent_capacity.max(1),
            inner: RwLock::new(Inner {
                recent: VecDeque::new(),
                total: 0,
                by_severity: BTreeMap::new(),
                by_category: BTreeMap::new(),
                hourly: VecDeque::new(),
            }),
        }
    }

    /// Enregistre une alerte dans le tampon et les statistiques.
    pub async fn record(&self, alert: &Alert) {
        let mut inner = self.inner.write().await;
        inner.total += 1;
        *inner
            .by_severity
            .entry(alert.severity.as_str().to_string())
            .or_insert(0) += 1;
        *inner
            .by_category
            .entry(alert.category.as_str().to_string())
            .or_insert(0) += 1;

        let hour = truncate_to_hour(alert.timestamp);
        match inner.hourly.back_mut() {
            Some(last) if last.hour == hour => last.count += 1,
            _ => {
                inner.hourly.push_back(HourBucket { hour, count: 1 });
                while inner.hourly.len() > MAX_HOUR_BUCKETS {
                    inner.hourly.pop_front();
                }
            }
        }

        inner.recent.push_back(alert.clone());
        while inner.recent.len() > self.recent_capacity {
            inner.recent.pop_front();
        }
    }

    /// Retourne les `limit` alertes les plus récentes (ordre chronologique).
    pub async fn recent(&self, limit: usize) -> Vec<Alert> {
        let inner = self.inner.read().await;
        let n = limit.min(inner.recent.len());
        inner
            .recent
            .iter()
            .skip(inner.recent.len() - n)
            .cloned()
            .collect()
    }

    pub async fn stats(&self) -> Stats {
        let inner = self.inner.read().await;
        Stats {
            started_at: self.started_at,
            total: inner.total,
            by_severity: inner.by_severity.clone(),
            by_category: inner.by_category.clone(),
            hourly: inner.hourly.iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use owlsentry_common::{Category, Severity};

    fn alert(sev: Severity) -> Alert {
        Alert::new(sev, Category::System, "t", "w", "y", "h")
    }

    #[tokio::test]
    async fn record_and_stats() {
        let state = DaemonState::new(2);
        state.record(&alert(Severity::High)).await;
        state.record(&alert(Severity::High)).await;
        state.record(&alert(Severity::Info)).await;

        let stats = state.stats().await;
        assert_eq!(stats.total, 3);
        assert_eq!(stats.by_severity.get("high"), Some(&2));
        assert_eq!(stats.by_severity.get("info"), Some(&1));
        assert!(!stats.hourly.is_empty());

        // Le tampon est borné à 2.
        let recent = state.recent(10).await;
        assert_eq!(recent.len(), 2);
    }
}
