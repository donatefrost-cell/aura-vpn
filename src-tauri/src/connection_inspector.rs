use crate::models::{
    AppSettings, ConnectionInspectorSnapshot, ConnectionMode, ConnectionSnapshot,
    ConnectionStageFlags, ConnectionStatus, ConnectionTimelineEvent, CoreDiagnostics,
    ServerProfile, ThroughputSummary, TrafficStats, TunnelHealthState,
};
use chrono::Utc;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

const TIMELINE_CAP: usize = 100;

pub struct SessionInspectorTracker {
    next_event_id: AtomicU64,
    timeline: Mutex<VecDeque<ConnectionTimelineEvent>>,
    sample_count: Mutex<u64>,
    sum_rx: Mutex<u128>,
    sum_tx: Mutex<u128>,
    peak_rx: Mutex<u64>,
    peak_tx: Mutex<u64>,
}

impl Default for SessionInspectorTracker {
    fn default() -> Self {
        Self {
            next_event_id: AtomicU64::new(1),
            timeline: Mutex::new(VecDeque::with_capacity(TIMELINE_CAP)),
            sample_count: Mutex::new(0),
            sum_rx: Mutex::new(0),
            sum_tx: Mutex::new(0),
            peak_rx: Mutex::new(0),
            peak_tx: Mutex::new(0),
        }
    }
}

impl SessionInspectorTracker {
    pub fn reset_throughput(&self) {
        *self.sample_count.lock().unwrap_or_else(|p| p.into_inner()) = 0;
        *self.sum_rx.lock().unwrap_or_else(|p| p.into_inner()) = 0;
        *self.sum_tx.lock().unwrap_or_else(|p| p.into_inner()) = 0;
        *self.peak_rx.lock().unwrap_or_else(|p| p.into_inner()) = 0;
        *self.peak_tx.lock().unwrap_or_else(|p| p.into_inner()) = 0;
    }

    pub fn record_traffic_sample(&self, t: &TrafficStats) {
        let mut sc = self.sample_count.lock().unwrap_or_else(|p| p.into_inner());
        *sc = sc.saturating_add(1);
        drop(sc);

        let mut sr = self.sum_rx.lock().unwrap_or_else(|p| p.into_inner());
        *sr = sr.saturating_add(t.rx_bytes_per_sec as u128);
        drop(sr);

        let mut st = self.sum_tx.lock().unwrap_or_else(|p| p.into_inner());
        *st = st.saturating_add(t.tx_bytes_per_sec as u128);
        drop(st);

        let mut pr = self.peak_rx.lock().unwrap_or_else(|p| p.into_inner());
        if t.rx_bytes_per_sec > *pr {
            *pr = t.rx_bytes_per_sec;
        }
        drop(pr);

        let mut pt = self.peak_tx.lock().unwrap_or_else(|p| p.into_inner());
        if t.tx_bytes_per_sec > *pt {
            *pt = t.tx_bytes_per_sec;
        }
    }

    pub fn push_event(
        &self,
        stage: &str,
        level: &str,
        message: &str,
        latency_ms: Option<u64>,
    ) -> ConnectionTimelineEvent {
        let ev = ConnectionTimelineEvent {
            id: self.next_event_id.fetch_add(1, Ordering::Relaxed),
            timestamp: Utc::now().to_rfc3339(),
            stage: stage.to_string(),
            level: level.to_string(),
            message: message.to_string(),
            latency_ms,
        };
        let mut guard = self.timeline.lock().unwrap_or_else(|p| p.into_inner());
        if guard.len() >= TIMELINE_CAP {
            guard.pop_front();
        }
        guard.push_back(ev.clone());
        ev
    }

    pub fn timeline_snapshot(&self) -> Vec<ConnectionTimelineEvent> {
        self.timeline
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    pub fn clear_timeline(&self) {
        self.timeline
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    pub fn throughput_summary(&self, latest: &TrafficStats) -> ThroughputSummary {
        let count = *self.sample_count.lock().unwrap_or_else(|p| p.into_inner());
        let sum_rx = *self.sum_rx.lock().unwrap_or_else(|p| p.into_inner());
        let sum_tx = *self.sum_tx.lock().unwrap_or_else(|p| p.into_inner());
        let peak_rx = *self.peak_rx.lock().unwrap_or_else(|p| p.into_inner());
        let peak_tx = *self.peak_tx.lock().unwrap_or_else(|p| p.into_inner());
        ThroughputSummary {
            current_rx_bps: latest.rx_bytes_per_sec,
            current_tx_bps: latest.tx_bytes_per_sec,
            avg_rx_bps: if count > 0 {
                (sum_rx / count as u128) as u64
            } else {
                0
            },
            avg_tx_bps: if count > 0 {
                (sum_tx / count as u128) as u64
            } else {
                0
            },
            peak_rx_bps: peak_rx,
            peak_tx_bps: peak_tx,
            total_rx_bytes: latest.total_rx_bytes,
            total_tx_bytes: latest.total_tx_bytes,
            sample_count: count,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_inspector_snapshot(
    snap: &ConnectionSnapshot,
    traffic: &TrafficStats,
    tracker: &SessionInspectorTracker,
    core_running: bool,
    aux_running: Option<bool>,
    reconnect_count: u32,
    active_profile: Option<&ServerProfile>,
    settings: &AppSettings,
    diag: &CoreDiagnostics,
) -> ConnectionInspectorSnapshot {
    let is_conn = snap.status == ConnectionStatus::Connected;
    let tun_mode = snap.mode == ConnectionMode::Tun;
    let proxy_listening = is_conn
        && snap.mode == ConnectionMode::SystemProxy
        && (snap.local_http_port.is_some() || snap.local_socks_port.is_some());
    let tun_up = is_conn && tun_mode;
    let tunnel_established = matches!(
        snap.health.state,
        TunnelHealthState::TunnelEstablished | TunnelHealthState::Verified
    ) || is_conn;
    let internet_verified =
        snap.health.state == TunnelHealthState::Verified && snap.health.last_probe_rtt_ms.is_some();

    let stages = ConnectionStageFlags {
        core_process_running: core_running,
        aux_process_running: aux_running,
        local_proxy_listening: proxy_listening,
        tun_adapter_up: tun_up,
        tunnel_established,
        internet_verified,
    };

    let uptime_secs = if is_conn {
        snap.connected_since
            .map(|ts| Utc::now().timestamp().saturating_sub(ts).max(0) as u64)
            .unwrap_or(0)
    } else {
        0
    };

    let (core_name, core_version) = match active_profile.map(|p| p.protocol) {
        Some(crate::models::ProtocolType::AmneziaWg) => (
            "wireproxy-awg + Xray-core".to_string(),
            format!("{} + wireproxy-awg v1.0.18", diag.core_version),
        ),
        _ => ("Xray-core".to_string(), diag.core_version.clone()),
    };

    ConnectionInspectorSnapshot {
        status: snap.status,
        stages,
        mode: snap.mode,
        active_server_id: snap.active_server_id.clone(),
        active_server_name: active_profile.map(|p| p.name.clone()),
        protocol: active_profile.map(|p| format!("{:?}", p.protocol).to_uppercase()),
        active_core_name: core_name,
        active_core_version: core_version,
        active_adapter_name: if tun_mode {
            Some(settings.tun.adapter_name.clone())
        } else {
            None
        },
        routing_profile: settings.routing.profile,
        dns_mode: settings.dns.mode.clone(),
        tcp_latency_ms: snap.latency_ms,
        http_rtt_ms: snap.health.last_probe_rtt_ms,
        uptime_secs,
        reconnect_count,
        kill_switch: snap.kill_switch.clone(),
        throughput: tracker.throughput_summary(traffic),
        timeline: tracker.timeline_snapshot(),
    }
}
