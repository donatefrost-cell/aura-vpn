use crate::config_gen::{
    generate_wireproxy_awg_config_with_dns, generate_xray_config_with_options, XrayGenOptions,
};
use crate::connection_inspector::{build_inspector_snapshot, SessionInspectorTracker};
use crate::core_registry::validate_core_for_profile;
use crate::elevation::is_elevated;
use crate::ip_monitor::{fetch_ip_info, load_ip_monitor, save_ip_monitor, StoredIpMonitor};
use crate::kill_switch::{
    firewall_rule_exists_in_os, remove_firewall_rule_verified, KillSwitchState,
};
use crate::logger::{redact_secrets, AppLogger};
use crate::models::{
    AmneziaWgDetails, AppSettings, ConnectionErrorInfo, ConnectionHistoryResponse,
    ConnectionInspectorSnapshot, ConnectionMode, ConnectionSnapshot, ConnectionStatus,
    CoreDiagnostics, CoreSelectionMode, DiagnosticsReport, EmergencyRecoveryReport, IpMonitorState,
    IpProviderId, KillSwitchConfig, KillSwitchEnforcement, KillSwitchMode, KillSwitchSnapshot,
    KillSwitchStatus, NetworkCheckItem, ProtectionCenterSnapshot, ProtectionItem,
    ProtectionItemStatus, ProtocolDetails, ProtocolType, ProxyProbeResult, RoutingConfig,
    RoutingProfile, ServerProfile, ServerQualityMetrics, SpeedTestResult, SplitTunnelMode,
    TrafficAggregateStats, TrafficStats, TunnelHealthSnapshot, TunnelHealthState,
};
use crate::proxy_meter::{
    pick_ephemeral_loopback_ports, start_proxy_meter, ProxyMeterHandle, TrafficCounters,
};
use crate::routing_rules::{load_rulepack, RulepackData};
use crate::storage::{secure_delete_file, AppStorage};
use crate::windows_proxy::{
    enable_system_proxy_with_override, inspect_system_proxy, restore_system_proxy,
};
use chrono::{DateTime, Duration as ChronoDuration, Local, Utc};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File};
use std::io::Read;
use std::net::IpAddr;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const STDERR_RING_CAPACITY: usize = 30;

pub(crate) const EMBEDDED_XRAY_SHA256: &str = env!("AURA_XRAY_SHA256");
pub(crate) const EMBEDDED_AWG_SHA256: &str = env!("AURA_AWG_SHA256");
pub(crate) const EMBEDDED_WINTUN_SHA256: &str = env!("AURA_WINTUN_SHA256");

#[derive(Debug, Error)]
pub enum CoreConnectError {
    #[error("{detail}")]
    BinaryMissing { detail: String },
    #[error("{detail}")]
    BinaryTampered { detail: String },
    #[error("{detail}")]
    AdminRequired { detail: String },
    #[error("{detail}")]
    PortConflict { detail: String },
    #[error("{detail}")]
    PortPermissionDenied { detail: String },
    #[error("{detail}")]
    InvalidConfig { detail: String },
    #[error("{detail}")]
    ServerUnreachable { detail: String },
    #[error("{detail}")]
    TunnelProbeFailed { detail: String },
    #[error("{detail}")]
    CoreCrashed { detail: String },
    #[error("{detail}")]
    KillSwitchEngaged { detail: String },
    #[error("{detail}")]
    SystemError { detail: String },
}

impl CoreConnectError {
    pub fn to_error_info(&self) -> ConnectionErrorInfo {
        match self {
            Self::BinaryMissing { detail } => ConnectionErrorInfo {
                code: "BINARY_MISSING".into(),
                category: "core".into(),
                title: "Не найден компонент ядра".into(),
                message: detail.clone(),
                hint: "Проверьте каталог приложения и при необходимости переустановите AURA VPN.".into(),
                action: Some("open_settings".into()),
            },
            Self::BinaryTampered { detail } => ConnectionErrorInfo {
                code: "BINARY_TAMPERED".into(),
                category: "security".into(),
                title: "Проверка целостности ядра не пройдена".into(),
                message: detail.clone(),
                hint: "Исполняемый файл ядра не соответствует контрольной сумме сборки. Переустановите приложение из доверенного источника.".into(),
                action: Some("open_settings".into()),
            },
            Self::AdminRequired { detail } => ConnectionErrorInfo {
                code: "ADMIN_REQUIRED".into(),
                category: "permissions".into(),
                title: "Требуются права администратора".into(),
                message: detail.clone(),
                hint: "Для создания системного TUN-интерфейса перезапустите AURA VPN от имени администратора или выберите режим «Системный прокси».".into(),
                action: Some("relaunch_admin".into()),
            },
            Self::PortConflict { detail } => ConnectionErrorInfo {
                code: "PORT_CONFLICT".into(),
                category: "network".into(),
                title: "Локальный порт занят".into(),
                message: detail.clone(),
                hint: "Закройте конфликтующую программу или измените локальные порты HTTP/SOCKS5 в Настройках → Прокси.".into(),
                action: Some("open_settings".into()),
            },
            Self::PortPermissionDenied { detail } => ConnectionErrorInfo {
                code: "PORT_PERMISSION_DENIED".into(),
                category: "network".into(),
                title: "Порт заблокирован Windows".into(),
                message: detail.clone(),
                hint: "Вероятно, порт входит в зарезервированный диапазон Hyper-V/WSL2. Выберите другой порт (например, 18080–18999) в Настройках → Прокси.".into(),
                action: Some("open_settings".into()),
            },
            Self::InvalidConfig { detail } => ConnectionErrorInfo {
                code: "INVALID_CONFIG".into(),
                category: "config".into(),
                title: "Ошибка конфигурации профиля".into(),
                message: detail.clone(),
                hint: "Проверьте корректность ключа, TLS/Reality-параметров или обновите подписку.".into(),
                action: Some("retry".into()),
            },
            Self::ServerUnreachable { detail } => ConnectionErrorInfo {
                code: "SERVER_UNREACHABLE".into(),
                category: "network".into(),
                title: "Сервер не отвечает".into(),
                message: detail.clone(),
                hint: "Проверьте интернет-соединение, обновите подписку или выберите другой узел.".into(),
                action: Some("retry".into()),
            },
            Self::TunnelProbeFailed { detail } => ConnectionErrorInfo {
                code: "TUNNEL_PROBE_FAILED".into(),
                category: "network".into(),
                title: "Туннель не пропускает трафик".into(),
                message: detail.clone(),
                hint: "TCP-порт узла открыт, но HTTPS 204-проба не прошла. Проверьте UUID/Reality-ключи, системное время или выберите другой сервер.".into(),
                action: Some("retry".into()),
            },
            Self::CoreCrashed { detail } => ConnectionErrorInfo {
                code: "CORE_CRASHED".into(),
                category: "core".into(),
                title: "Сетевое ядро неожиданно завершилось".into(),
                message: detail.clone(),
                hint: "Изучите журнал событий или повторите подключение.".into(),
                action: Some("retry".into()),
            },
            Self::KillSwitchEngaged { detail } => ConnectionErrorInfo {
                code: "KILL_SWITCH_ACTIVE".into(),
                category: "security".into(),
                title: "Активирована защита Kill Switch".into(),
                message: detail.clone(),
                hint: "Выход в интернет заблокирован для предотвращения утечек после разрыва VPN. Снимите блокировку вручную.".into(),
                action: Some("disengage_kill_switch".into()),
            },
            Self::SystemError { detail } => ConnectionErrorInfo {
                code: "SYSTEM_ERROR".into(),
                category: "system".into(),
                title: "Системная ошибка подключения".into(),
                message: detail.clone(),
                hint: "Попробуйте повторить подключение или проверьте диагностику сети.".into(),
                action: Some("retry".into()),
            },
        }
    }
}

fn classify_error_string(detail: &str) -> CoreConnectError {
    let clean = redact_secrets(detail);
    let lower = clean.to_ascii_lowercase();
    if lower.contains("binary_tampered") || lower.contains("контрольная сумма") {
        CoreConnectError::BinaryTampered { detail: clean }
    } else if lower.contains("не найден")
        && (lower.contains("xray") || lower.contains("wintun") || lower.contains("wireproxy"))
    {
        CoreConnectError::BinaryMissing { detail: clean }
    } else if lower.contains("права администратора") || lower.contains("администратора")
    {
        CoreConnectError::AdminRequired { detail: clean }
    } else if lower.contains("уже занят") {
        CoreConnectError::PortConflict { detail: clean }
    } else if lower.contains("hyper-v") || lower.contains("заблокировал доступ к")
    {
        CoreConnectError::PortPermissionDenied { detail: clean }
    } else if lower.contains("конфигурации") || lower.contains("prohibited") {
        CoreConnectError::InvalidConfig { detail: clean }
    } else if lower.contains("не отвечает") || lower.contains("таймаут tcp") {
        CoreConnectError::ServerUnreachable { detail: clean }
    } else if lower.contains("не удалось установить туннель") {
        CoreConnectError::TunnelProbeFailed { detail: clean }
    } else if lower.contains("kill switch") {
        CoreConnectError::KillSwitchEngaged { detail: clean }
    } else {
        CoreConnectError::SystemError { detail: clean }
    }
}

struct JobGuard {
    handle: HANDLE,
}

unsafe impl Send for JobGuard {}
unsafe impl Sync for JobGuard {}

impl JobGuard {
    fn new_kill_on_close() -> Option<Self> {
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 {
                CloseHandle(job);
                return None;
            }
            Some(Self { handle: job })
        }
    }

    fn assign_child(&self, child: &Child) -> Result<(), u32> {
        unsafe {
            let proc_handle = child.as_raw_handle() as HANDLE;
            if AssignProcessToJobObject(self.handle, proc_handle) == 0 {
                return Err(GetLastError());
            }
        }
        Ok(())
    }
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                CloseHandle(self.handle);
            }
        }
    }
}

struct ActiveSession {
    generation: u64,
    server_id: String,
    server_name: String,
    country_code: Option<String>,
    protocol: String,
    mode: ConnectionMode,
    started_at: DateTime<Utc>,
    reconnect_count: u32,
    history_enabled: bool,
    child: Arc<Mutex<Child>>,
    aux_child: Option<Arc<Mutex<Child>>>,
    proxy_meter: Option<ProxyMeterHandle>,
    _job: Option<JobGuard>,
    monitor_task: JoinHandle<()>,
    telemetry_task: JoinHandle<()>,
    intentional_stop: Arc<AtomicBool>,
    os_proxy_enabled: bool,
    config_path: PathBuf,
    aux_config_path: Option<PathBuf>,
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.intentional_stop.store(true, Ordering::SeqCst);
        self.telemetry_task.abort();
        self.monitor_task.abort();
        if let Some(m) = self.proxy_meter.take() {
            m.stop();
        }
        terminate_child(&self.child);
        if let Some(ref aux) = self.aux_child {
            terminate_child(aux);
        }
        secure_delete_file(&self.config_path);
        if let Some(ref aux_path) = self.aux_config_path {
            secure_delete_file(aux_path);
        }
    }
}

pub fn effective_kill_switch_config(settings: &AppSettings) -> KillSwitchConfig {
    let mut cfg = settings.kill_switch.clone();
    if cfg.mode == KillSwitchMode::Off && settings.kill_switch_enabled {
        cfg.mode = KillSwitchMode::OnDrop;
    }
    cfg.reconnect_attempts = cfg.reconnect_attempts.clamp(0, 10);
    cfg
}

pub struct CoreManager {
    storage: AppStorage,
    logger: Arc<AppLogger>,
    app_handle: Mutex<Option<AppHandle>>,
    snapshot: Mutex<ConnectionSnapshot>,
    counters: TrafficCounters,
    latest_traffic: Mutex<TrafficStats>,
    session: tokio::sync::Mutex<Option<ActiveSession>>,
    op_lock: tokio::sync::Mutex<()>,
    session_gen: Arc<AtomicU64>,
    cancel_tx: watch::Sender<u64>,
    kill_switch: tokio::sync::Mutex<KillSwitchState>,
    claude_guard: tokio::sync::Mutex<crate::kill_switch::ClaudeGuardManager>,
    kill_switch_cfg: std::sync::RwLock<KillSwitchConfig>,
    routing_cfg: std::sync::RwLock<RoutingConfig>,
    active_settings: std::sync::RwLock<AppSettings>,
    ip_monitor: Mutex<StoredIpMonitor>,
    exit_cleaned: AtomicBool,
    cached_core_path: Mutex<Option<PathBuf>>,
    cached_awg_path: Mutex<Option<PathBuf>>,
    cached_xray_version: Mutex<Option<(PathBuf, String)>>,
    verified_hashes: Mutex<HashMap<(PathBuf, u64, u64), bool>>,
    diagnostics_cache: Mutex<Option<(Instant, CoreDiagnostics)>>,
    pub inspector: SessionInspectorTracker,
    rulepack: std::sync::RwLock<Arc<RulepackData>>,
    server_quality: Mutex<HashMap<String, ServerQualityMetrics>>,
}

impl CoreManager {
    pub fn new(storage: AppStorage, logger: Arc<AppLogger>) -> Self {
        let ks_path = storage.kill_switch_state_path();
        let initial_pack = Arc::new(load_rulepack(storage.base_dir()));
        let initial_quality = storage.load_server_quality();
        let initial_ip = load_ip_monitor(&storage);
        let (cancel_tx, _) = watch::channel(0u64);
        Self {
            storage,
            logger,
            app_handle: Mutex::new(None),
            snapshot: Mutex::new(ConnectionSnapshot::default()),
            counters: TrafficCounters::new(),
            latest_traffic: Mutex::new(TrafficStats::default()),
            session: tokio::sync::Mutex::new(None),
            op_lock: tokio::sync::Mutex::new(()),
            session_gen: Arc::new(AtomicU64::new(0)),
            cancel_tx,
            kill_switch: tokio::sync::Mutex::new(KillSwitchState::new(ks_path)),
            claude_guard: tokio::sync::Mutex::new(crate::kill_switch::ClaudeGuardManager::new()),
            kill_switch_cfg: std::sync::RwLock::new(KillSwitchConfig::default()),
            routing_cfg: std::sync::RwLock::new(RoutingConfig::default()),
            active_settings: std::sync::RwLock::new(AppSettings::default()),
            ip_monitor: Mutex::new(initial_ip),
            exit_cleaned: AtomicBool::new(false),
            cached_core_path: Mutex::new(None),
            cached_awg_path: Mutex::new(None),
            cached_xray_version: Mutex::new(None),
            verified_hashes: Mutex::new(HashMap::new()),
            diagnostics_cache: Mutex::new(None),
            inspector: SessionInspectorTracker::default(),
            rulepack: std::sync::RwLock::new(initial_pack),
            server_quality: Mutex::new(initial_quality),
        }
    }

    pub fn reload_rulepack(&self) {
        let fresh = Arc::new(load_rulepack(self.storage.base_dir()));
        if let Ok(mut guard) = self.rulepack.write() {
            *guard = fresh;
        }
    }

    pub fn rulepack_snapshot(&self) -> Arc<RulepackData> {
        self.rulepack
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn xray_resource_dir(&self) -> Option<PathBuf> {
        let app = self.app_handle.lock().ok().and_then(|g| g.clone());
        resolve_xray_binary(app.as_ref())
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    }

    pub fn attach_app(&self, app: AppHandle) {
        if let Ok(mut guard) = self.app_handle.lock() {
            *guard = Some(app.clone());
        }
        if let Ok(path) = resolve_xray_binary(Some(&app)) {
            if let Ok(mut cached) = self.cached_core_path.lock() {
                *cached = Some(path);
            }
        }
        if let Ok(path) = resolve_awg_binary(Some(&app)) {
            if let Ok(mut cached) = self.cached_awg_path.lock() {
                *cached = Some(path);
            }
        }
    }

    pub fn snapshot(&self) -> ConnectionSnapshot {
        self.snapshot
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn traffic_snapshot(&self) -> TrafficStats {
        *self
            .latest_traffic
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    pub fn server_quality_snapshot(&self) -> HashMap<String, ServerQualityMetrics> {
        self.server_quality
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn clear_server_quality(&self) -> Result<(), String> {
        let mut map = self
            .server_quality
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        map.clear();
        self.storage.save_server_quality(&map)
    }

    pub fn record_server_tcp_ping(&self, server_id: &str, tcp_ms: Option<u64>) {
        self.record_server_tcp_pings_batch(&[(server_id.to_string(), tcp_ms)]);
    }

    pub fn record_server_tcp_pings_batch(&self, results: &[(String, Option<u64>)]) {
        if results.is_empty() {
            return;
        }
        let mut map = self
            .server_quality
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        for (server_id, tcp_ms) in results {
            let entry = map.entry(server_id.clone()).or_default();
            entry.last_tcp_ms = *tcp_ms;
            if let Some(ms) = tcp_ms {
                entry.success_count = entry.success_count.saturating_add(1);
                entry.consecutive_failures = 0;
                entry.last_success_at = Some(Utc::now().to_rfc3339());
                entry.last_error_code = None;
                recompute_quality_score(entry, Some(*ms));
            } else {
                entry.fail_count = entry.fail_count.saturating_add(1);
                entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
                entry.last_error_code = Some("SERVER_UNREACHABLE".to_string());
                recompute_quality_score(entry, None);
            }
        }
        let _ = self.storage.save_server_quality(&map);
    }

    pub async fn remap_active_server_id(&self, old_id: &str, new_id: &str) {
        if old_id == new_id {
            return;
        }
        {
            let mut guard = self.session.lock().await;
            if let Some(ref mut sess) = *guard {
                if sess.server_id == old_id {
                    sess.server_id = new_id.to_string();
                }
            }
        }
        self.update_snapshot(|s| {
            if s.active_server_id.as_deref() == Some(old_id) {
                s.active_server_id = Some(new_id.to_string());
            }
        });
    }

    fn resolve_core_exe_paths(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(p) = self.find_xray_path() {
            out.push(p);
        }
        if let Ok(p) = self.find_awg_path() {
            out.push(p);
        }
        out
    }

    fn resolve_routing_aware_exes(routing: &RoutingConfig) -> Vec<PathBuf> {
        if routing.split_tunnel_mode != SplitTunnelMode::BypassApps {
            return Vec::new();
        }
        let pf = std::env::var_os("ProgramFiles").map(PathBuf::from);
        let pf86 = std::env::var_os("ProgramFiles(x86)").map(PathBuf::from);
        let local_app = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);

        let mut out = Vec::new();
        for raw in &routing.split_apps {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let p = PathBuf::from(trimmed);
            if p.is_absolute() && p.exists() && p.is_file() {
                out.push(p);
                continue;
            }
            let file_name = if trimmed.to_ascii_lowercase().ends_with(".exe") {
                trimmed.to_string()
            } else {
                format!("{trimmed}.exe")
            };
            // Check explicit base directories and PATH for safe exe name resolution
            if let Some(path_var) = std::env::var_os("PATH") {
                if let Some(found) = std::env::split_paths(&path_var)
                    .map(|dir| dir.join(&file_name))
                    .find(|cand| cand.is_file())
                {
                    out.push(found);
                    continue;
                }
            }
            let stem = file_name.trim_end_matches(".exe").trim_end_matches(".EXE");
            let roots = [pf.as_ref(), pf86.as_ref(), local_app.as_ref()];
            for root in roots.into_iter().flatten() {
                let direct = root.join(stem).join(&file_name);
                if direct.is_file() {
                    out.push(direct);
                    break;
                }
            }
        }
        out
    }

    pub async fn kill_switch_snapshot_now(&self) -> KillSwitchSnapshot {
        self.kill_switch.lock().await.snapshot()
    }

    pub async fn sync_kill_switch_live(&self, settings: &AppSettings) {
        let ks_cfg = effective_kill_switch_config(settings);
        if let Ok(mut g) = self.kill_switch_cfg.write() {
            *g = ks_cfg.clone();
        }
        if let Ok(mut g) = self.routing_cfg.write() {
            *g = settings.routing.clone();
        }
        if let Ok(mut g) = self.active_settings.write() {
            *g = settings.clone();
        }

        let active_mode = { self.session.lock().await.as_ref().map(|s| s.mode) };
        let is_connected = active_mode.is_some();
        let effective_mode = active_mode.unwrap_or(settings.connection_mode);
        let core_exes = self.resolve_core_exe_paths();
        let extra_exes = Self::resolve_routing_aware_exes(&settings.routing);

        let ks_snap = if is_connected {
            let mut ks = self.kill_switch.lock().await;
            ks.sync_armed_tunnel_state(
                &ks_cfg,
                effective_mode == ConnectionMode::Tun,
                &core_exes,
                &extra_exes,
                (effective_mode == ConnectionMode::Tun)
                    .then_some(settings.tun.adapter_name.as_str()),
            );
            ks.snapshot()
        } else if ks_cfg.mode == KillSwitchMode::AlwaysOn {
            let mut ks = self.kill_switch.lock().await;
            let res = match settings.connection_mode {
                ConnectionMode::SystemProxy => {
                    let bypass = if settings.routing.bypass_ru_domains
                        || settings.routing.profile == RoutingProfile::RuDirect
                    {
                        vec!["*.ru".to_string(), "*.su".to_string(), "*.рф".to_string()]
                    } else {
                        Vec::new()
                    };
                    let _ = enable_system_proxy_with_override(
                        &self.storage.proxy_backup_path(),
                        settings.http_port,
                        &bypass,
                    );
                    ks.engage_proxy_guards(
                        settings.http_port,
                        Some(settings.socks_port),
                        ks_cfg.mode,
                        "Постоянный Kill Switch (Always-On) активен до подключения VPN."
                            .to_string(),
                    )
                    .await
                }
                ConnectionMode::Tun => {
                    ks.engage_tun_firewall_guard(
                        &ks_cfg,
                        &extra_exes,
                        "Постоянный Kill Switch (Always-On) удерживает блокировку вне VPN."
                            .to_string(),
                        false,
                    )
                    .await
                }
            };
            if let Err(err) = res {
                self.logger.warn("security", &err);
            }
            ks.snapshot()
        } else {
            let mut ks = self.kill_switch.lock().await;
            if ks.is_engaged() {
                let _ = ks.disengage_async().await;
                let _ = restore_system_proxy(&self.storage.proxy_backup_path());
            } else {
                ks.update_inactive_snapshot(&ks_cfg, None);
            }
            ks.snapshot()
        };

        let claude_status = {
            let mut cg = self.claude_guard.lock().await;
            cg.resolve_claude_ips_if_needed(
                settings.routing.claude_guard.enabled,
                settings.routing.claude_guard.block_without_vpn,
            )
            .await;
            cg.sync(&settings.routing.claude_guard, is_connected)
        };

        self.update_snapshot(|s| {
            s.kill_switch_engaged = ks_snap.blocking_active;
            s.kill_switch = ks_snap.clone();
            s.claude_guard = claude_status;
        });
        self.refresh_tray();
    }

    pub fn ip_monitor_snapshot(&self) -> IpMonitorState {
        let is_conn = self.snapshot().status == ConnectionStatus::Connected;
        self.ip_monitor
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .to_state(is_conn)
    }

    pub fn set_ip_mask(&self, mask_ip: bool) -> IpMonitorState {
        let is_conn = self.snapshot().status == ConnectionStatus::Connected;
        let mut guard = self.ip_monitor.lock().unwrap_or_else(|p| p.into_inner());
        guard.mask_ip = mask_ip;
        save_ip_monitor(&self.storage, &guard);
        guard.to_state(is_conn)
    }

    pub fn set_ip_provider(&self, provider: IpProviderId) -> IpMonitorState {
        let is_conn = self.snapshot().status == ConnectionStatus::Connected;
        let mut guard = self.ip_monitor.lock().unwrap_or_else(|p| p.into_inner());
        guard.provider = provider;
        save_ip_monitor(&self.storage, &guard);
        guard.to_state(is_conn)
    }

    pub fn clear_original_ip(&self) -> IpMonitorState {
        let is_conn = self.snapshot().status == ConnectionStatus::Connected;
        let mut guard = self.ip_monitor.lock().unwrap_or_else(|p| p.into_inner());
        guard.original_ip = None;
        save_ip_monitor(&self.storage, &guard);
        guard.to_state(is_conn)
    }

    pub fn clear_ip_monitor_cache(&self) -> IpMonitorState {
        let is_conn = self.snapshot().status == ConnectionStatus::Connected;
        let mut guard = self.ip_monitor.lock().unwrap_or_else(|p| p.into_inner());
        guard.original_ip = None;
        guard.vpn_ip = None;
        save_ip_monitor(&self.storage, &guard);
        guard.to_state(is_conn)
    }

    pub fn stored_ip_monitor_snapshot(&self) -> StoredIpMonitor {
        self.ip_monitor
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub async fn check_ip_monitor(
        &self,
        settings: &AppSettings,
        include_ipv6: bool,
        provider_override: Option<IpProviderId>,
    ) -> Result<IpMonitorState, String> {
        let snap = self.snapshot();
        if snap.kill_switch.blocking_active || snap.kill_switch_engaged {
            return Err("Проверка IP заблокирована активным Kill Switch. Снимите блокировку или подключитесь к VPN.".into());
        }
        if matches!(
            snap.status,
            ConnectionStatus::Connecting
                | ConnectionStatus::Verifying
                | ConnectionStatus::Reconnecting
                | ConnectionStatus::Switching
                | ConnectionStatus::Disconnecting
        ) {
            return Err(
                "Дождитесь завершения текущего переключения или подключения туннеля.".into(),
            );
        }

        let is_connected = snap.status == ConnectionStatus::Connected;
        let proxy_port = if is_connected && snap.mode == ConnectionMode::SystemProxy {
            snap.local_http_port.or(Some(settings.http_port))
        } else {
            None
        };
        let mode = if is_connected {
            snap.mode
        } else {
            settings.connection_mode
        };
        let provider = provider_override.unwrap_or(settings.preferred_ip_provider);

        let info = fetch_ip_info(proxy_port, include_ipv6, is_connected, mode, provider).await?;
        let mut guard = self.ip_monitor.lock().unwrap_or_else(|p| p.into_inner());
        guard.provider = provider;
        if is_connected {
            guard.vpn_ip = Some(info);
        } else {
            guard.original_ip = Some(info);
        }
        save_ip_monitor(&self.storage, &guard);
        Ok(guard.to_state(is_connected))
    }

    pub async fn build_protection_center(
        &self,
        settings: &AppSettings,
    ) -> ProtectionCenterSnapshot {
        let snap = self.snapshot();
        let diag = self.diagnostics();
        let ks_snap = self.kill_switch_snapshot_now().await;
        let ip_state = self.ip_monitor_snapshot();
        let mut items = Vec::new();

        items.push(ProtectionItem {
            id: "vpn_tunnel".into(),
            label: "Состояние VPN-туннеля".into(),
            status: match snap.status {
                ConnectionStatus::Connected => match snap.health.state {
                    TunnelHealthState::Verified => ProtectionItemStatus::Verified,
                    TunnelHealthState::Unstable | TunnelHealthState::Lost => {
                        ProtectionItemStatus::Issue
                    }
                    _ => ProtectionItemStatus::Limited,
                },
                ConnectionStatus::Error => ProtectionItemStatus::Issue,
                _ => ProtectionItemStatus::Unchecked,
            },
            value: match snap.status {
                ConnectionStatus::Connected => format!("Подключено ({:?})", snap.health.state),
                ConnectionStatus::Error => "Ошибка".into(),
                _ => "Отключено".into(),
            },
            detail: snap.health.reason.clone().unwrap_or_else(|| {
                "Состояние активной сессии ядра и подтверждение выхода трафика.".into()
            }),
            kind: "network".into(),
        });

        let ks_cfg = effective_kill_switch_config(settings);
        items.push(ProtectionItem {
            id: "kill_switch".into(),
            label: "Kill Switch 2.0".into(),
            status: match ks_snap.status {
                KillSwitchStatus::Inactive => ProtectionItemStatus::Unchecked,
                KillSwitchStatus::Armed => ProtectionItemStatus::Verified,
                KillSwitchStatus::Blocking => ProtectionItemStatus::Verified,
                KillSwitchStatus::Degraded => ProtectionItemStatus::Limited,
                KillSwitchStatus::RecoveryRequired => ProtectionItemStatus::Issue,
            },
            value: format!("{:?} • {:?}", ks_cfg.mode, ks_snap.enforcement),
            detail: ks_snap.last_reason.clone().unwrap_or_else(|| {
                if ks_cfg.mode == KillSwitchMode::Off {
                    "Kill Switch выключен в настройках безопасности.".into()
                } else if settings.connection_mode == ConnectionMode::SystemProxy {
                    "В «Системный прокси» защищаются проксируемые соединения (127.0.0.1). Для системного WFP-фильтра используйте TUN + UAC.".into()
                } else {
                    "Динамический WFP-фильтр ограничивает трафик уровнем ядра Windows.".into()
                }
            }),
            kind: "config".into(),
        });

        items.push(ProtectionItem {
            id: "ipv4_ip".into(),
            label: "Внешний IPv4".into(),
            status: match (&ip_state.vpn_ip, &ip_state.original_ip, ip_state.ip_changed) {
                (Some(_), Some(_), Some(true)) => ProtectionItemStatus::Verified,
                (Some(_), Some(_), Some(false)) if snap.status == ConnectionStatus::Connected => {
                    ProtectionItemStatus::Issue
                }
                (Some(_), None, _) => ProtectionItemStatus::Limited,
                _ => ProtectionItemStatus::Unchecked,
            },
            value: ip_state
                .vpn_ip
                .as_ref()
                .map(|_v| {
                    if ip_state.ip_changed == Some(true) {
                        "Изменён через VPN".into()
                    } else if ip_state.original_ip.is_some() {
                        "Совпадает с исходным!".into()
                    } else {
                        "Определён (исходный не проверен)".into()
                    }
                })
                .unwrap_or_else(|| "Не проверено".into()),
            detail: "Проверяется по явному запросу; без подключённого VPN исходный IP сравнивается с последней сохранённой проверкой.".into(),
            kind: "network".into(),
        });

        items.push(ProtectionItem {
            id: "ipv6_protection".into(),
            label: "Защита IPv6".into(),
            status: if !settings.ipv6_enabled && settings.connection_mode == ConnectionMode::Tun {
                ProtectionItemStatus::Verified
            } else if !settings.ipv6_enabled {
                ProtectionItemStatus::Limited
            } else {
                ProtectionItemStatus::Unchecked
            },
            value: if settings.ipv6_enabled {
                "Разрешён".into()
            } else {
                "Блокируется".into()
            },
            detail: if !settings.ipv6_enabled && settings.connection_mode == ConnectionMode::Tun {
                "В TUN-режиме весь внешний IPv6 блокируется правилами ядра и WFP.".into()
            } else {
                "В режиме «Системный прокси» системные IPv6-сокеты вне прокси не перехватываются."
                    .into()
            },
            kind: "config".into(),
        });

        items.push(ProtectionItem {
            id: "dns_mode".into(),
            label: "Конфигурация DNS".into(),
            status: if settings.dns.mode.eq_ignore_ascii_case("vpn")
                || settings.dns.mode.eq_ignore_ascii_case("hybrid")
            {
                ProtectionItemStatus::Verified
            } else {
                ProtectionItemStatus::Limited
            },
            value: format!("{} ({})", settings.dns.mode, settings.dns.primary_dns),
            detail: if settings.dns.mode.eq_ignore_ascii_case("direct") {
                "Используется прямой/системный DNS провайдера.".into()
            } else {
                "Конфигурация направляет зарубежные DNS-запросы через VPN.".into()
            },
            kind: "config".into(),
        });

        let has_direct_exceptions = settings.routing.bypass_ru_domains
            || settings.routing.profile != RoutingProfile::AllVpn
            || !settings.routing.custom_rules.is_empty();
        items.push(ProtectionItem {
            id: "routing_policy".into(),
            label: "Маршрутизация и исключения".into(),
            status: ProtectionItemStatus::Verified,
            value: format!("{:?}", settings.routing.profile),
            detail: if has_direct_exceptions {
                "Активны пользовательские или российские прямые исключения трафика.".into()
            } else {
                "Весь трафик направлен в туннель без прямых исключений.".into()
            },
            kind: "config".into(),
        });

        items.push(ProtectionItem {
            id: "core_integrity".into(),
            label: "Целостность сетевого ядра".into(),
            status: if diag.core_available && diag.core_integrity_ok {
                ProtectionItemStatus::Verified
            } else {
                ProtectionItemStatus::Issue
            },
            value: if diag.core_integrity_ok {
                diag.core_version.clone()
            } else {
                "Требуется проверка".into()
            },
            detail: diag
                .integrity_note
                .unwrap_or_else(|| "SHA-256 эталон сверяется перед каждым запуском.".into()),
            kind: "config".into(),
        });

        ProtectionCenterSnapshot {
            checked_at: Utc::now().to_rfc3339(),
            items,
            kill_switch: ks_snap,
            ip_monitor: ip_state,
        }
    }

    pub async fn emergency_recover_network(&self) -> EmergencyRecoveryReport {
        let mut report = EmergencyRecoveryReport::default();
        let _op_guard = self.op_lock.lock().await;
        let next_gen = self.session_gen.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.cancel_tx.send(next_gen);

        {
            let mut ks = self.kill_switch.lock().await;
            let had_fw_or_wfp = ks.is_engaged();
            match ks.disengage_async().await {
                Ok(()) => {
                    report.wfp_filters_removed = had_fw_or_wfp;
                }
                Err(e) => {
                    report.needs_elevation = true;
                    report.warnings.push(e);
                }
            }
        }

        if matches!(firewall_rule_exists_in_os(), Some(true)) {
            match remove_firewall_rule_verified() {
                Ok(()) => report.legacy_netsh_rule_removed = true,
                Err(e) => {
                    report.needs_elevation = true;
                    report.warnings.push(e);
                }
            }
        }

        let active = { self.session.lock().await.take() };
        if let Some(mut sess) = active {
            sess.intentional_stop.store(true, Ordering::SeqCst);
            sess.telemetry_task.abort();
            sess.monitor_task.abort();
            if let Some(m) = sess.proxy_meter.take() {
                m.stop_async().await;
            }
            terminate_child(&sess.child);
            report.orphaned_processes_killed += 1;
            if sess.aux_child.is_some() {
                report.orphaned_processes_killed += 1;
            }
            cleanup_aux(&sess.aux_child, &sess.aux_config_path);
            secure_delete_file(&sess.config_path);
        }

        match restore_system_proxy(&self.storage.proxy_backup_path()) {
            Ok(changed) => report.system_proxy_restored = changed,
            Err(e) => report.warnings.push(e),
        }

        report.stale_files_cleaned = self.storage.sweep_stale_runtime_files();
        self.counters.reset();
        self.emit_traffic(TrafficStats::default());
        self.update_snapshot(|s| {
            s.status = ConnectionStatus::Disconnected;
            s.connected_since = None;
            s.latency_ms = None;
            s.error_message = None;
            s.error_info = None;
            s.system_proxy_enabled = false;
            s.kill_switch_engaged = report.needs_elevation;
            s.local_http_port = None;
            s.local_socks_port = None;
            s.health = TunnelHealthSnapshot::default();
            s.kill_switch = KillSwitchSnapshot {
                mode: KillSwitchMode::Off,
                status: if report.needs_elevation {
                    KillSwitchStatus::RecoveryRequired
                } else {
                    KillSwitchStatus::Inactive
                },
                enforcement: KillSwitchEnforcement::None,
                blocking_active: false,
                needs_elevation: report.needs_elevation,
                allowed_exceptions: Vec::new(),
                last_reason: Some("Выполнено аварийное восстановление сети.".into()),
                updated_at: Some(Utc::now().to_rfc3339()),
            };
        });
        self.refresh_tray();
        report
    }

    fn record_server_connect_outcome(
        &self,
        server_id: &str,
        succeeded: bool,
        tcp_ms: Option<u64>,
        http_rtt_ms: Option<u64>,
        error_code: Option<&str>,
    ) {
        let mut map = self
            .server_quality
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let entry = map.entry(server_id.to_string()).or_default();
        if let Some(ms) = tcp_ms {
            entry.last_tcp_ms = Some(ms);
        }
        if let Some(rtt) = http_rtt_ms {
            entry.last_http_rtt_ms = Some(rtt);
        }
        if succeeded {
            entry.success_count = entry.success_count.saturating_add(1);
            entry.consecutive_failures = 0;
            entry.last_success_at = Some(Utc::now().to_rfc3339());
            entry.last_error_code = None;
            recompute_quality_score(entry, http_rtt_ms.or(entry.last_tcp_ms));
        } else {
            entry.fail_count = entry.fail_count.saturating_add(1);
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            entry.last_error_code = error_code.map(|s| s.to_string());
            recompute_quality_score(entry, None);
        }
        let _ = self.storage.save_server_quality(&map);
    }

    pub fn connection_history_response(&self) -> ConnectionHistoryResponse {
        let entries = self.storage.load_history();
        let now_local = Local::now();
        let today_date = now_local.date_naive();
        let week_cutoff = Utc::now() - ChronoDuration::days(7);
        let month_cutoff = Utc::now() - ChronoDuration::days(30);

        let mut agg = TrafficAggregateStats::default();
        for item in &entries {
            agg.total_duration_secs = agg.total_duration_secs.saturating_add(item.duration_secs);
            agg.total_sessions = agg.total_sessions.saturating_add(1);
            agg.total_reconnects = agg
                .total_reconnects
                .saturating_add(u64::from(item.reconnect_count));

            if let Ok(dt) = DateTime::parse_from_rfc3339(&item.ended_at) {
                let utc_dt = dt.with_timezone(&Utc);
                let local_dt = dt.with_timezone(&Local);
                if local_dt.date_naive() == today_date {
                    agg.today_rx_bytes = agg.today_rx_bytes.saturating_add(item.rx_bytes);
                    agg.today_tx_bytes = agg.today_tx_bytes.saturating_add(item.tx_bytes);
                }
                if utc_dt >= week_cutoff {
                    agg.week_rx_bytes = agg.week_rx_bytes.saturating_add(item.rx_bytes);
                    agg.week_tx_bytes = agg.week_tx_bytes.saturating_add(item.tx_bytes);
                }
                if utc_dt >= month_cutoff {
                    agg.month_rx_bytes = agg.month_rx_bytes.saturating_add(item.rx_bytes);
                    agg.month_tx_bytes = agg.month_tx_bytes.saturating_add(item.tx_bytes);
                }
            }
        }

        ConnectionHistoryResponse {
            entries,
            aggregates: agg,
            server_quality: self.server_quality_snapshot(),
        }
    }

    pub fn clear_connection_history(&self) -> Result<(), String> {
        self.storage.clear_history()
    }

    fn persist_session_history(&self, sess: &ActiveSession, end_reason: &str) {
        if !sess.history_enabled {
            return;
        }
        let ended = Utc::now();
        let duration_secs = (ended - sess.started_at).num_seconds().max(0) as u64;
        let traffic = self.traffic_snapshot();
        let entry = crate::models::ConnectionHistoryEntry {
            id: uuid::Uuid::new_v4().to_string(),
            server_id: Some(sess.server_id.clone()),
            server_name: sess.server_name.clone(),
            country_code: sess.country_code.clone(),
            protocol: sess.protocol.clone(),
            mode: sess.mode,
            started_at: sess.started_at.to_rfc3339(),
            ended_at: ended.to_rfc3339(),
            duration_secs,
            rx_bytes: traffic.total_rx_bytes,
            tx_bytes: traffic.total_tx_bytes,
            end_reason: end_reason.to_string(),
            reconnect_count: sess.reconnect_count,
        };
        if let Err(err) = self.storage.append_history_entry(entry) {
            self.logger.warn("storage", &err);
        }
    }

    fn update_snapshot<F>(&self, f: F)
    where
        F: FnOnce(&mut ConnectionSnapshot),
    {
        let next = {
            let mut guard = self.snapshot.lock().unwrap_or_else(|p| p.into_inner());
            f(&mut guard);
            guard.clone()
        };
        let app = self
            .app_handle
            .lock()
            .ok()
            .and_then(|g| g.as_ref().cloned());
        if let Some(app) = app {
            let _ = app.emit("connection-state", &next);
        }
    }

    fn refresh_tray(&self) {
        let app = self
            .app_handle
            .lock()
            .ok()
            .and_then(|g| g.as_ref().cloned());
        if let Some(app) = app {
            if let Some(st) = app.try_state::<crate::commands::AppState>() {
                st.tray.update_from_state(&app);
            }
        }
    }

    fn emit_traffic(&self, stats: TrafficStats) {
        self.inspector.record_traffic_sample(&stats);
        {
            let mut guard = self
                .latest_traffic
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            *guard = stats;
        }
        let app = self
            .app_handle
            .lock()
            .ok()
            .and_then(|g| g.as_ref().cloned());
        if let Some(app) = app {
            let _ = app.emit("traffic-stats", &stats);
        }
    }

    pub fn emit_timeline_event(
        &self,
        stage: &str,
        level: &str,
        message: &str,
        latency_ms: Option<u64>,
    ) {
        let ev = self.inspector.push_event(stage, level, message, latency_ms);
        let app = self
            .app_handle
            .lock()
            .ok()
            .and_then(|g| g.as_ref().cloned());
        if let Some(app) = app {
            let _ = app.emit("connection-timeline-event", &ev);
        }
    }

    pub fn diagnostics_cached(&self) -> CoreDiagnostics {
        if let Ok(guard) = self.diagnostics_cache.lock() {
            if let Some((ts, ref cached)) = *guard {
                if ts.elapsed() < Duration::from_secs(5) {
                    let mut out = cached.clone();
                    let (proxy_active, endpoint) = inspect_system_proxy();
                    out.system_proxy_active = proxy_active;
                    out.active_proxy_endpoint = endpoint;
                    out.kill_switch_engaged = self.snapshot().kill_switch_engaged;
                    return out;
                }
            }
        }
        let fresh = self.diagnostics();
        if let Ok(mut guard) = self.diagnostics_cache.lock() {
            *guard = Some((Instant::now(), fresh.clone()));
        }
        fresh
    }

    pub fn invalidate_diagnostics_cache(&self) {
        if let Ok(mut guard) = self.diagnostics_cache.lock() {
            *guard = None;
        }
    }

    pub async fn inspector_snapshot(
        &self,
        active_profile: Option<&ServerProfile>,
        settings: &AppSettings,
    ) -> ConnectionInspectorSnapshot {
        let snap = self.snapshot();
        let traffic = self.traffic_snapshot();
        let diag = self.diagnostics_cached();
        let (core_running, aux_running, reconnect_count) = {
            let mut sess = self.session.lock().await;
            if let Some(ref mut s) = *sess {
                let c_alive = s
                    .child
                    .lock()
                    .map(|mut g| matches!(g.try_wait(), Ok(None)))
                    .unwrap_or(false);
                let a_alive = s.aux_child.as_ref().map(|ac| {
                    ac.lock()
                        .map(|mut g| matches!(g.try_wait(), Ok(None)))
                        .unwrap_or(false)
                });
                (c_alive, a_alive, s.reconnect_count)
            } else {
                (false, None, 0)
            }
        };
        build_inspector_snapshot(
            &snap,
            &traffic,
            &self.inspector,
            core_running,
            aux_running,
            reconnect_count,
            active_profile,
            settings,
            &diag,
        )
    }

    pub fn verify_binary_integrity(
        &self,
        path: &Path,
        expected_hex: &str,
        label: &str,
    ) -> Result<bool, CoreConnectError> {
        let meta = fs::metadata(path).map_err(|e| CoreConnectError::BinaryMissing {
            detail: format!("Не удалось прочитать {label} ({}): {e}", path.display()),
        })?;
        let len = meta.len();
        let mtime_secs = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cache_key = (path.to_path_buf(), len, mtime_secs);

        if expected_hex.trim().is_empty() {
            #[cfg(not(debug_assertions))]
            return Err(CoreConnectError::BinaryTampered {
                detail: format!(
                    "Эталонный SHA-256 для {label} отсутствует в манифесте релизной сборки"
                ),
            });
            #[cfg(debug_assertions)]
            return Ok(false);
        }

        // Bypass mtime-only hash cache when running with elevated privileges (prevent TOCTOU/SetFileTime bypass).
        let skip_cache = crate::elevation::is_elevated();
        if !skip_cache {
            if let Some(&cached_ok) = self
                .verified_hashes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&cache_key)
            {
                if cached_ok {
                    return Ok(true);
                }
            }
        }

        let actual = compute_file_sha256(path).map_err(|e| CoreConnectError::BinaryMissing {
            detail: format!("Ошибка расчёта SHA-256 для {label}: {e}"),
        })?;
        let matches = actual.eq_ignore_ascii_case(expected_hex.trim());
        if matches {
            let mut cache = self
                .verified_hashes
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            cache.insert(cache_key, true);
            Ok(true)
        } else {
            Err(CoreConnectError::BinaryTampered {
                detail: format!(
                    "Контрольная сумма {label} не совпадает с манифестом сборки (ожидается {}..., получено {}...)",
                    &expected_hex[..12.min(expected_hex.len())],
                    &actual[..12.min(actual.len())]
                ),
            })
        }
    }

    fn get_cached_xray_version(&self, path: &Path) -> Option<String> {
        {
            let guard = self
                .cached_xray_version
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some((ref p, ref ver)) = *guard {
                if p == path {
                    return Some(ver.clone());
                }
            }
        }
        let queried = query_xray_version(path)?;
        let mut guard = self
            .cached_xray_version
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        *guard = Some((path.to_path_buf(), queried.clone()));
        Some(queried)
    }

    pub fn diagnostics(&self) -> CoreDiagnostics {
        let cached = self
            .cached_core_path
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let resolved = cached.or_else(|| {
            let app = self.app_handle.lock().ok().and_then(|g| g.clone());
            resolve_xray_binary(app.as_ref()).ok()
        });

        let mut integrity_notes = Vec::new();
        let (
            core_available,
            core_path,
            core_version,
            core_integrity_ok,
            wintun_available,
            wintun_integrity_ok,
        ) = match resolved {
            Some(p) if p.exists() => {
                let core_ok =
                    match self.verify_binary_integrity(&p, EMBEDDED_XRAY_SHA256, "xray.exe") {
                        Ok(v) => v,
                        Err(e) => {
                            integrity_notes.push(e.to_string());
                            false
                        }
                    };
                let ver = if core_ok || EMBEDDED_XRAY_SHA256.is_empty() {
                    self.get_cached_xray_version(&p)
                        .unwrap_or_else(|| "Xray-core (версия неизвестна)".into())
                } else {
                    "Отклонено проверкой SHA-256".into()
                };
                let wintun_path = p.parent().map(|dir| dir.join("wintun.dll"));
                let (wintun_avail, wintun_ok) = match wintun_path {
                    Some(ref wp) if wp.exists() => {
                        match self.verify_binary_integrity(wp, EMBEDDED_WINTUN_SHA256, "wintun.dll")
                        {
                            Ok(v) => (true, v),
                            Err(e) => {
                                integrity_notes.push(e.to_string());
                                (true, false)
                            }
                        }
                    }
                    _ => (false, false),
                };
                (
                    true,
                    p.to_string_lossy().to_string(),
                    ver,
                    core_ok,
                    wintun_avail,
                    wintun_ok,
                )
            }
            Some(p) => (
                false,
                p.to_string_lossy().to_string(),
                "Не найден".into(),
                false,
                false,
                false,
            ),
            None => (
                false,
                "resources/core/xray.exe".into(),
                "Не найден".into(),
                false,
                false,
                false,
            ),
        };

        let (awg_available, awg_integrity_ok) = match self.find_awg_path() {
            Ok(p) if p.exists() => {
                match self.verify_binary_integrity(&p, EMBEDDED_AWG_SHA256, "wireproxy-awg.exe") {
                    Ok(v) => (true, v),
                    Err(e) => {
                        integrity_notes.push(e.to_string());
                        (true, false)
                    }
                }
            }
            _ => (false, false),
        };

        let (system_proxy_active, active_proxy_endpoint) = inspect_system_proxy();
        let kill_switch_engaged = self.snapshot().kill_switch_engaged;
        let integrity_note = if integrity_notes.is_empty() {
            if core_integrity_ok && awg_integrity_ok && (!wintun_available || wintun_integrity_ok) {
                Some("Все компоненты ядра подтверждены SHA-256.".to_string())
            } else {
                None
            }
        } else {
            Some(integrity_notes.join("; "))
        };

        CoreDiagnostics {
            core_name: "Xray-core (MPL-2.0)".to_string(),
            core_version,
            core_path,
            core_available,
            wintun_available,
            awg_available,
            is_elevated: is_elevated(),
            always_run_as_admin: crate::elevation::is_always_admin_enabled(),
            kill_switch_engaged,
            system_proxy_active,
            active_proxy_endpoint,
            config_dir: self.storage.base_dir().to_string_lossy().to_string(),
            core_integrity_ok,
            awg_integrity_ok,
            wintun_integrity_ok,
            integrity_note,
        }
    }

    pub async fn ping_server(address: &str, port: u16) -> Option<u64> {
        let started = Instant::now();
        let target = if address.contains(':') && !address.starts_with('[') {
            format!("[{address}]:{port}")
        } else {
            format!("{address}:{port}")
        };
        let fut = TcpStream::connect(&target);
        match tokio::time::timeout(Duration::from_secs(4), fut).await {
            Ok(Ok(_stream)) => Some(started.elapsed().as_millis().max(1) as u64),
            _ => None,
        }
    }

    pub fn extract_profile_endpoints(profile: &ServerProfile) -> Vec<(String, u16)> {
        let mut endpoints: Vec<(String, u16)> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        if !profile.address.trim().is_empty() {
            let key = (profile.address.clone(), profile.port);
            if seen.insert(key.clone()) {
                endpoints.push(key);
            }
        }

        if let ProtocolDetails::RawXray(ref d) = profile.details {
            for ob in &d.extra_outbounds {
                if endpoints.len() >= 4 {
                    break;
                }
                let proto = ob
                    .get("protocol")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if matches!(
                    proto.as_str(),
                    "freedom" | "blackhole" | "dns" | "loopback" | ""
                ) {
                    continue;
                }
                let (addr, port) = crate::parser::raw_json::extract_endpoint(ob);
                if addr.trim().is_empty() || addr == "127.0.0.1" {
                    continue;
                }
                let key = (addr, port);
                if seen.insert(key.clone()) {
                    endpoints.push(key);
                }
            }
        }

        endpoints
    }

    pub async fn ping_profile(profile: &ServerProfile) -> Option<u64> {
        let endpoints = Self::extract_profile_endpoints(profile);
        if endpoints.is_empty() {
            return None;
        }
        if endpoints.len() == 1 {
            return Self::ping_server(&endpoints[0].0, endpoints[0].1).await;
        }

        let mut handles = Vec::with_capacity(endpoints.len());
        for (addr, port) in endpoints {
            handles.push(tokio::spawn(
                async move { Self::ping_server(&addr, port).await },
            ));
        }

        let mut best: Option<u64> = None;
        for handle in handles {
            if let Ok(Some(ms)) = handle.await {
                best = Some(match best {
                    Some(cur) => cur.min(ms),
                    None => ms,
                });
            }
        }
        best
    }

    pub async fn connect(
        self: &Arc<Self>,
        profile: ServerProfile,
        settings: AppSettings,
    ) -> Result<ConnectionSnapshot, String> {
        self.connect_internal(profile, settings, true, true, true)
            .await
    }

    pub async fn connect_internal(
        self: &Arc<Self>,
        profile: ServerProfile,
        settings: AppSettings,
        enable_os_proxy: bool,
        run_public_probe: bool,
        route_private_direct: bool,
    ) -> Result<ConnectionSnapshot, String> {
        let _op_guard = self.op_lock.lock().await;
        let my_gen = self.session_gen.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.cancel_tx.send(my_gen);
        self.connect_locked(
            profile,
            settings,
            enable_os_proxy,
            run_public_probe,
            route_private_direct,
            my_gen,
            0,
            false,
        )
        .await
    }

    async fn reengage_proxy_guard_on_abort(
        &self,
        keep_ks_guard: bool,
        mode: ConnectionMode,
        settings: &AppSettings,
        ks_cfg: &KillSwitchConfig,
        reason: &str,
    ) {
        if mode == ConnectionMode::SystemProxy {
            if keep_ks_guard && ks_cfg.mode != KillSwitchMode::Off {
                let mut ks = self.kill_switch.lock().await;
                let _ = ks
                    .engage_proxy_guards(
                        settings.http_port,
                        Some(settings.socks_port),
                        ks_cfg.mode,
                        reason.to_string(),
                    )
                    .await;
            }
        } else {
            let extra_exes = Self::resolve_routing_aware_exes(&settings.routing);
            let mut ks = self.kill_switch.lock().await;
            if keep_ks_guard && ks_cfg.mode != KillSwitchMode::Off {
                let _ = ks
                    .engage_tun_firewall_guard(ks_cfg, &extra_exes, reason.to_string(), false)
                    .await;
            } else {
                let _ = ks.disengage_async().await;
            }
        }
        let cg_status = {
            let mut cg = self.claude_guard.lock().await;
            cg.resolve_claude_ips_if_needed(
                settings.routing.claude_guard.enabled,
                settings.routing.claude_guard.block_without_vpn,
            )
            .await;
            cg.sync(&settings.routing.claude_guard, false)
        };
        self.update_snapshot(|s| {
            s.claude_guard = cg_status;
        });
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_locked(
        self: &Arc<Self>,
        profile: ServerProfile,
        settings: AppSettings,
        enable_os_proxy: bool,
        run_public_probe: bool,
        route_private_direct: bool,
        my_gen: u64,
        reconnect_count: u32,
        reconnecting_mode: bool,
    ) -> Result<ConnectionSnapshot, String> {
        let had_active = {
            let guard = self.session.lock().await;
            guard.is_some()
        };
        let ks_cfg = effective_kill_switch_config(&settings);
        if let Ok(mut g) = self.kill_switch_cfg.write() {
            *g = ks_cfg.clone();
        }
        if let Ok(mut g) = self.routing_cfg.write() {
            *g = settings.routing.clone();
        }
        if let Ok(mut g) = self.active_settings.write() {
            *g = settings.clone();
        }

        let keep_ks_guard = ks_cfg.mode != KillSwitchMode::Off
            && (had_active || reconnecting_mode || ks_cfg.mode == KillSwitchMode::AlwaysOn);

        if had_active && !reconnecting_mode {
            self.update_snapshot(|s| {
                s.status = ConnectionStatus::Switching;
                s.active_server_id = Some(profile.id.clone());
                s.error_message = None;
                s.error_info = None;
                s.health.state = TunnelHealthState::Starting;
            });
            self.refresh_tray();
        }

        self.disconnect_locked_with_ks(
            false,
            if had_active { "switch" } else { "restart" },
            keep_ks_guard,
            &settings,
        )
        .await?;

        let mode = profile
            .overrides
            .as_ref()
            .and_then(|o| o.preferred_mode)
            .unwrap_or(settings.connection_mode);
        let connect_timeout_secs = profile
            .overrides
            .as_ref()
            .and_then(|o| o.connect_timeout_secs)
            .unwrap_or(settings.connect_timeout_secs)
            .clamp(3, 60);
        self.counters.reset();
        self.inspector.reset_throughput();
        self.emit_traffic(TrafficStats::default());
        self.emit_timeline_event(
            "connect_start",
            "info",
            &format!("Инициализация подключения к «{}»", profile.name),
            None,
        );
        if !reconnecting_mode {
            self.update_snapshot(|s| {
                s.status = ConnectionStatus::Connecting;
                s.mode = mode;
                s.active_server_id = Some(profile.id.clone());
                s.connected_since = None;
                s.latency_ms = None;
                s.error_message = None;
                s.error_info = None;
                s.system_proxy_enabled = keep_ks_guard && mode == ConnectionMode::SystemProxy;
                s.kill_switch_engaged = keep_ks_guard;
                s.local_http_port = None;
                s.local_socks_port = None;
                s.health = TunnelHealthSnapshot {
                    state: TunnelHealthState::Starting,
                    consecutive_failures: 0,
                    last_probe_rtt_ms: None,
                    last_checked_at: Some(Utc::now().to_rfc3339()),
                    reason: None,
                };
            });
            self.refresh_tray();
        }

        self.logger.info(
            "core",
            &format!(
                "Подготовка подключения ({}) к «{}» ({}:{})",
                if mode == ConnectionMode::Tun {
                    "TUN"
                } else {
                    "Системный прокси"
                },
                profile.name,
                profile.address,
                profile.port
            ),
        );

        let xray_path = match self.find_xray_path() {
            Ok(p) => p,
            Err(err) => {
                return Err(self.handle_connect_failure(
                    &profile.id,
                    CoreConnectError::BinaryMissing { detail: err },
                    None,
                    reconnecting_mode,
                ));
            }
        };

        if let Err(err) = self.verify_binary_integrity(&xray_path, EMBEDDED_XRAY_SHA256, "xray.exe")
        {
            return Err(self.handle_connect_failure(&profile.id, err, None, reconnecting_mode));
        }

        let diag_now = self.diagnostics_cached();
        let selected_core = match validate_core_for_profile(
            &profile,
            settings.advanced.core_selection,
            mode,
            &diag_now,
        ) {
            Ok(c) => c,
            Err(detail) => {
                return Err(self.handle_connect_failure(
                    &profile.id,
                    CoreConnectError::InvalidConfig { detail },
                    None,
                    reconnecting_mode,
                ));
            }
        };
        self.emit_timeline_event(
            "core_verified",
            "info",
            &format!("Ядро проверено SHA-256 ({selected_core:?})"),
            None,
        );

        if mode == ConnectionMode::Tun {
            let wintun_path = xray_path
                .parent()
                .map(|dir| dir.join("wintun.dll"))
                .unwrap_or_else(|| PathBuf::from("wintun.dll"));
            if !wintun_path.exists() {
                return Err(self.handle_connect_failure(
                    &profile.id,
                    CoreConnectError::BinaryMissing {
                        detail: "Модуль wintun.dll не найден рядом с xray.exe. Переустановите приложение.".into(),
                    },
                    None,
                    reconnecting_mode,
                ));
            }
            if let Err(err) =
                self.verify_binary_integrity(&wintun_path, EMBEDDED_WINTUN_SHA256, "wintun.dll")
            {
                return Err(self.handle_connect_failure(&profile.id, err, None, reconnecting_mode));
            }
            if !is_elevated() {
                return Err(self.handle_connect_failure(
                    &profile.id,
                    CoreConnectError::AdminRequired {
                        detail: "Для работы TUN-режима требуются права администратора Windows. Перезапустите AURA VPN от имени администратора или переключитесь в «Системный прокси».".into(),
                    },
                    None,
                    reconnecting_mode,
                ));
            }
        }

        let is_udp_only = matches!(
            profile.protocol,
            ProtocolType::Hysteria2 | ProtocolType::Wireguard | ProtocolType::AmneziaWg
        ) || matches!(
            &profile.details,
            ProtocolDetails::RawXray(d) if matches!(
                d.outbound_json.get("protocol").and_then(|v| v.as_str()),
                Some("hysteria") | Some("wireguard")
            ) || matches!(
                d.outbound_json
                    .get("streamSettings")
                    .and_then(|s| s.get("network"))
                    .and_then(|v| v.as_str()),
                Some("kcp") | Some("quic")
            )
        );
        let core_start_timeout_secs = settings.advanced.core_start_timeout_secs.clamp(3, 20);
        let has_multi_outbounds = matches!(
            &profile.details,
            ProtocolDetails::RawXray(d) if !d.extra_outbounds.is_empty()
        );

        let ks_blocks_pre_ping = keep_ks_guard || { self.kill_switch.lock().await.is_engaged() };

        // Advisory TCP reachability check BEFORE creating TUN routes or spawning child cores
        // (unless UDP-only or Kill Switch is currently blocking aura-vpn.exe sockets).
        // Even if TCP pre-ping times out (e.g. CDN/ICMP filtering), continue and validate via tunnel probe.
        let latency = if is_udp_only || ks_blocks_pre_ping {
            None
        } else if has_multi_outbounds {
            let ms = Self::ping_profile(&profile).await;
            if ms.is_none() {
                self.logger.warn(
                    "core",
                    &format!(
                        "Предварительная TCP-проверка {}:{} не ответила — пробуем прямое подключение...",
                        profile.address, profile.port
                    ),
                );
            }
            ms
        } else {
            match Self::ping_server(&profile.address, profile.port).await {
                Some(ms) => Some(ms),
                None => {
                    self.logger.warn(
                        "core",
                        &format!(
                            "Предварительная TCP-проверка {}:{} не ответила — пробуем прямое подключение...",
                            profile.address, profile.port
                        ),
                    );
                    None
                }
            }
        };

        if mode == ConnectionMode::SystemProxy
            && settings.routing.split_tunnel_mode != SplitTunnelMode::AllVpn
            && !settings.routing.split_apps.is_empty()
        {
            self.logger.warn(
                "routing",
                "Split Tunneling по процессам применяется только в TUN-режиме — в «Системный прокси» трафик браузеров идёт через VPN.",
            );
        }

        let job = JobGuard::new_kill_on_close();
        let stderr_ring: Arc<Mutex<VecDeque<String>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(STDERR_RING_CAPACITY)));

        // Start AmneziaWG sidecar if profile is AmneziaWG
        let mut aux_child: Option<Arc<Mutex<Child>>> = None;
        let mut aux_config_path: Option<PathBuf> = None;
        let mut awg_socks_port: Option<u16> = None;

        let awg_bridge_details: Option<AmneziaWgDetails> = match &profile.details {
            ProtocolDetails::AmneziaWg(awg) => Some(awg.clone()),
            ProtocolDetails::Wireguard(wg) if selected_core == CoreSelectionMode::WireproxyAwg => {
                Some(AmneziaWgDetails {
                    secret_key: wg.secret_key.clone(),
                    address: wg.address.clone(),
                    public_key: wg.public_key.clone(),
                    preshared_key: wg.preshared_key.clone(),
                    endpoint: wg.endpoint.clone(),
                    mtu: wg.mtu,
                    dns: wg.dns.clone(),
                    keepalive: wg.keepalive,
                    jc: None,
                    jmin: None,
                    jmax: None,
                    s1: None,
                    s2: None,
                    h1: None,
                    h2: None,
                    h3: None,
                    h4: None,
                    extra_params: Default::default(),
                })
            }
            _ => None,
        };

        if let Some(ref awg_details) = awg_bridge_details {
            let awg_bin = match self.find_awg_path() {
                Ok(p) => p,
                Err(err) => {
                    return Err(self.handle_connect_failure(
                        &profile.id,
                        CoreConnectError::BinaryMissing { detail: err },
                        latency,
                        reconnecting_mode,
                    ));
                }
            };
            if let Err(err) =
                self.verify_binary_integrity(&awg_bin, EMBEDDED_AWG_SHA256, "wireproxy-awg.exe")
            {
                return Err(self.handle_connect_failure(
                    &profile.id,
                    err,
                    latency,
                    reconnecting_mode,
                ));
            }
            let (awg_port, _) = match pick_ephemeral_loopback_ports() {
                Ok(p) => p,
                Err(err) => {
                    return Err(self.handle_connect_failure(
                        &profile.id,
                        CoreConnectError::SystemError { detail: err },
                        latency,
                        reconnecting_mode,
                    ));
                }
            };
            let mut effective_awg = awg_details.clone();
            if let Some(ref ov) = profile.overrides {
                if let Some(m) = ov.mtu {
                    effective_awg.mtu = Some(m.clamp(1280, 1500));
                }
                if let Some(ref cdns) = ov.custom_dns {
                    if cdns.trim().parse::<IpAddr>().is_ok() {
                        effective_awg.dns = vec![cdns.trim().to_string()];
                    }
                }
            }
            effective_awg
                .dns
                .retain(|d| d.trim().parse::<IpAddr>().is_ok());
            let awg_dns_override = if !effective_awg.dns.is_empty()
                || settings.dns.mode.eq_ignore_ascii_case("direct")
            {
                None
            } else {
                Some(settings.dns.primary_dns.as_str())
            };
            let awg_conf = match generate_wireproxy_awg_config_with_dns(
                &effective_awg,
                awg_port,
                awg_dns_override,
            ) {
                Ok(c) => c,
                Err(err) => {
                    return Err(self.handle_connect_failure(
                        &profile.id,
                        CoreConnectError::InvalidConfig { detail: err },
                        latency,
                        reconnecting_mode,
                    ));
                }
            };
            let awg_path = self
                .storage
                .runtime_dir()
                .join(format!("awg-config-{}.conf", uuid::Uuid::new_v4()));
            if let Err(e) = crate::storage::atomic_write_bytes(&awg_path, awg_conf.as_bytes()) {
                return Err(self.handle_connect_failure(
                    &profile.id,
                    CoreConnectError::SystemError {
                        detail: format!("Не удалось записать конфиг AmneziaWG: {e}"),
                    },
                    latency,
                    reconnecting_mode,
                ));
            }
            if let Err(err) = validate_awg_config(&awg_bin, &awg_path).await {
                secure_delete_file(&awg_path);
                return Err(self.handle_connect_failure(
                    &profile.id,
                    CoreConnectError::InvalidConfig { detail: err },
                    latency,
                    reconnecting_mode,
                ));
            }

            let mut awg_cmd = Command::new(&awg_bin);
            awg_cmd
                .arg("-c")
                .arg(&awg_path)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .creation_flags(CREATE_NO_WINDOW);

            let mut spawned_awg = match awg_cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    secure_delete_file(&awg_path);
                    return Err(self.handle_connect_failure(
                        &profile.id,
                        CoreConnectError::CoreCrashed {
                            detail: format!(
                                "Не удалось запустить ядро AmneziaWG (wireproxy-awg): {e}"
                            ),
                        },
                        latency,
                        reconnecting_mode,
                    ));
                }
            };
            if let Some(ref j) = job {
                if let Err(win_err) = j.assign_child(&spawned_awg) {
                    self.logger.warn(
                        "awg",
                        &format!("AssignProcessToJobObject не привязал wireproxy-awg (код Windows {win_err})"),
                    );
                }
            }
            pipe_child_logs(
                &mut spawned_awg,
                self.logger.clone(),
                "awg",
                Some(stderr_ring.clone()),
            );
            let awg_arc = Arc::new(Mutex::new(spawned_awg));
            if let Err(err) =
                wait_for_local_port(awg_port, &awg_arc, &stderr_ring, core_start_timeout_secs).await
            {
                terminate_child(&awg_arc);
                secure_delete_file(&awg_path);
                return Err(self.handle_connect_failure(
                    &profile.id,
                    CoreConnectError::CoreCrashed { detail: err },
                    latency,
                    reconnecting_mode,
                ));
            }

            aux_child = Some(awg_arc);
            aux_config_path = Some(awg_path);
            awg_socks_port = Some(awg_port);
            self.logger.info(
                "awg",
                &format!(
                    "AmneziaWG туннель инициализирован на локальном узле 127.0.0.1:{awg_port}"
                ),
            );
        }

        let (internal_http_port, internal_socks_port) = match pick_ephemeral_loopback_ports() {
            Ok(ports) => ports,
            Err(err) => {
                cleanup_aux(&aux_child, &aux_config_path);
                return Err(self.handle_connect_failure(
                    &profile.id,
                    CoreConnectError::SystemError { detail: err },
                    latency,
                    reconnecting_mode,
                ));
            }
        };

        let stats_api_port = if mode == ConnectionMode::Tun {
            match settings
                .advanced
                .stats_api_mode
                .trim()
                .to_ascii_lowercase()
                .as_str()
            {
                "disabled" => None,
                "fixed" => settings
                    .advanced
                    .stats_api_port
                    .filter(|&p| p >= 1024 && p != settings.http_port && p != settings.socks_port)
                    .or_else(|| pick_ephemeral_loopback_ports().ok().map(|(p, _)| p)),
                _ => pick_ephemeral_loopback_ports().ok().map(|(p, _)| p),
            }
        } else {
            None
        };

        let pack = self.rulepack_snapshot();
        let config = generate_xray_config_with_options(
            &profile,
            mode,
            internal_http_port,
            internal_socks_port,
            stats_api_port,
            awg_socks_port,
            &settings.routing,
            route_private_direct,
            &settings.dns,
            settings.ipv6_enabled,
            &settings.log_level,
            &pack,
            XrayGenOptions::from_settings(&settings),
        );

        let config_path = self
            .storage
            .runtime_dir()
            .join(format!("active-config-{}.json", uuid::Uuid::new_v4()));
        let config_text = serde_json::to_string_pretty(&config)
            .map_err(|e| format!("Ошибка сериализации конфигурации ядра: {e}"))?;
        if let Err(e) = crate::storage::atomic_write_bytes(&config_path, config_text.as_bytes()) {
            cleanup_aux(&aux_child, &aux_config_path);
            return Err(self.handle_connect_failure(
                &profile.id,
                CoreConnectError::SystemError {
                    detail: format!("Не удалось записать конфигурацию ядра: {e}"),
                },
                latency,
                reconnecting_mode,
            ));
        }

        if let Err(err) = validate_xray_config(&xray_path, &config_path).await {
            secure_delete_file(&config_path);
            cleanup_aux(&aux_child, &aux_config_path);
            return Err(self.handle_connect_failure(
                &profile.id,
                CoreConnectError::InvalidConfig { detail: err },
                latency,
                reconnecting_mode,
            ));
        }

        if mode == ConnectionMode::SystemProxy {
            let mut ks = self.kill_switch.lock().await;
            let _ = ks.disengage_async().await;
        } else {
            let core_exes = self.resolve_core_exe_paths();
            let extra_exes = Self::resolve_routing_aware_exes(&settings.routing);
            let mut ks = self.kill_switch.lock().await;
            ks.sync_armed_tunnel_state(&ks_cfg, true, &core_exes, &extra_exes, None);
        }

        let meter = if mode == ConnectionMode::SystemProxy {
            match start_proxy_meter(
                settings.http_port,
                settings.socks_port,
                internal_http_port,
                internal_socks_port,
                self.counters.clone(),
            )
            .await
            {
                Ok(m) => Some(m),
                Err(err) => {
                    if ks_cfg.mode != KillSwitchMode::Off && keep_ks_guard {
                        let mut ks = self.kill_switch.lock().await;
                        let _ = ks
                            .engage_proxy_guards(
                                settings.http_port,
                                Some(settings.socks_port),
                                ks_cfg.mode,
                                err.clone(),
                            )
                            .await;
                    }
                    secure_delete_file(&config_path);
                    cleanup_aux(&aux_child, &aux_config_path);
                    return Err(self.handle_connect_failure(
                        &profile.id,
                        classify_error_string(&err),
                        latency,
                        reconnecting_mode,
                    ));
                }
            }
        } else {
            None
        };

        let mut cmd = Command::new(&xray_path);
        cmd.arg("run")
            .arg("-c")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW);

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                if let Some(m) = meter {
                    m.stop_async().await;
                }
                self.reengage_proxy_guard_on_abort(
                    keep_ks_guard,
                    mode,
                    &settings,
                    &ks_cfg,
                    "Не удалось запустить ядро Xray — Kill Switch удерживает блокировку.",
                )
                .await;
                secure_delete_file(&config_path);
                cleanup_aux(&aux_child, &aux_config_path);
                return Err(self.handle_connect_failure(
                    &profile.id,
                    CoreConnectError::CoreCrashed {
                        detail: format!("Не удалось запустить ядро Xray: {e}"),
                    },
                    latency,
                    reconnecting_mode,
                ));
            }
        };

        if let Some(ref j) = job {
            if let Err(win_err) = j.assign_child(&child) {
                self.logger.warn(
                    "core",
                    &format!(
                        "AssignProcessToJobObject не привязал xray.exe (код Windows {win_err})"
                    ),
                );
            }
        }
        pipe_child_logs(
            &mut child,
            self.logger.clone(),
            "xray",
            Some(stderr_ring.clone()),
        );

        let child_arc = Arc::new(Mutex::new(child));

        if mode == ConnectionMode::SystemProxy {
            if let Err(err) = wait_for_local_port(
                internal_http_port,
                &child_arc,
                &stderr_ring,
                core_start_timeout_secs,
            )
            .await
            {
                terminate_child(&child_arc);
                if let Some(m) = meter {
                    m.stop_async().await;
                }
                self.reengage_proxy_guard_on_abort(keep_ks_guard, mode, &settings, &ks_cfg, &err)
                    .await;
                secure_delete_file(&config_path);
                cleanup_aux(&aux_child, &aux_config_path);
                return Err(self.handle_connect_failure(
                    &profile.id,
                    CoreConnectError::CoreCrashed { detail: err },
                    latency,
                    reconnecting_mode,
                ));
            }
            self.emit_timeline_event(
                "port_open",
                "info",
                &format!("Локальный прокси 127.0.0.1:{} открыт", settings.http_port),
                latency,
            );
            self.update_snapshot(|s| {
                s.health.state = TunnelHealthState::PortOpen;
                s.health.last_checked_at = Some(Utc::now().to_rfc3339());
            });
        } else {
            if let Err(err) = wait_for_tun_startup(
                stats_api_port,
                &settings.tun.adapter_name,
                &child_arc,
                &stderr_ring,
                core_start_timeout_secs,
            )
            .await
            {
                terminate_child(&child_arc);
                self.reengage_proxy_guard_on_abort(keep_ks_guard, mode, &settings, &ks_cfg, &err)
                    .await;
                secure_delete_file(&config_path);
                cleanup_aux(&aux_child, &aux_config_path);
                return Err(self.handle_connect_failure(
                    &profile.id,
                    classify_error_string(&err),
                    latency,
                    reconnecting_mode,
                ));
            }
            // Refresh WFP permits now that the Wintun interface exists so user traffic & probes route through LUID
            let core_exes = self.resolve_core_exe_paths();
            let extra_exes = Self::resolve_routing_aware_exes(&settings.routing);
            {
                let mut ks = self.kill_switch.lock().await;
                ks.sync_armed_tunnel_state(
                    &ks_cfg,
                    true,
                    &core_exes,
                    &extra_exes,
                    Some(&settings.tun.adapter_name),
                );
            }
            self.emit_timeline_event("tun_up", "info", "TUN-интерфейс поднят", latency);
            self.update_snapshot(|s| {
                s.health.state = TunnelHealthState::TunnelEstablished;
                s.health.last_checked_at = Some(Utc::now().to_rfc3339());
            });
        }

        let mut probe_rtt: Option<u64> = None;
        if run_public_probe {
            if !reconnecting_mode {
                self.update_snapshot(|s| {
                    s.status = ConnectionStatus::Verifying;
                    s.health.state = TunnelHealthState::TunnelEstablished;
                });
                self.refresh_tray();
            }
            let probe_timeout = Duration::from_secs(
                settings
                    .advanced
                    .probe_timeout_secs
                    .max(connect_timeout_secs)
                    .clamp(4, 30),
            );
            let probe_res = if mode == ConnectionMode::SystemProxy {
                probe_proxy_tunnel(Some(settings.http_port), probe_timeout).await
            } else {
                probe_proxy_tunnel(None, probe_timeout).await
            };
            match probe_res {
                Ok((rtt, _endpoint)) => {
                    probe_rtt = Some(rtt);
                    self.emit_timeline_event(
                        "probe_ok",
                        "info",
                        &format!("Туннель подтверждён (HTTPS 204 за {rtt} мс)"),
                        Some(rtt),
                    );
                }
                Err(err) => {
                    self.emit_timeline_event("probe_fail", "warn", &err, None);
                    terminate_child(&child_arc);
                    if let Some(m) = meter {
                        m.stop_async().await;
                    }
                    self.reengage_proxy_guard_on_abort(
                        keep_ks_guard,
                        mode,
                        &settings,
                        &ks_cfg,
                        &err,
                    )
                    .await;
                    secure_delete_file(&config_path);
                    cleanup_aux(&aux_child, &aux_config_path);
                    return Err(self.handle_connect_failure(
                        &profile.id,
                        CoreConnectError::TunnelProbeFailed { detail: err },
                        latency,
                        reconnecting_mode,
                    ));
                }
            }
        }

        let apply_os_proxy = mode == ConnectionMode::SystemProxy && enable_os_proxy;
        if apply_os_proxy {
            let bypass = if ks_cfg.mode == KillSwitchMode::RoutingAware
                && (settings.routing.bypass_ru_domains
                    || settings.routing.profile == RoutingProfile::RuDirect)
            {
                vec!["*.ru".to_string(), "*.su".to_string(), "*.рф".to_string()]
            } else {
                Vec::new()
            };
            if let Err(err) = enable_system_proxy_with_override(
                &self.storage.proxy_backup_path(),
                settings.http_port,
                &bypass,
            ) {
                terminate_child(&child_arc);
                if let Some(m) = meter {
                    m.stop_async().await;
                }
                self.reengage_proxy_guard_on_abort(keep_ks_guard, mode, &settings, &ks_cfg, &err)
                    .await;
                secure_delete_file(&config_path);
                cleanup_aux(&aux_child, &aux_config_path);
                return Err(self.handle_connect_failure(
                    &profile.id,
                    CoreConnectError::SystemError { detail: err },
                    latency,
                    reconnecting_mode,
                ));
            }
            self.logger.info(
                "windows",
                &format!(
                    "Системный прокси Windows включён: 127.0.0.1:{}",
                    settings.http_port
                ),
            );
        }

        let core_exes = self.resolve_core_exe_paths();
        let extra_exes = Self::resolve_routing_aware_exes(&settings.routing);
        let ks_snap = {
            let mut ks = self.kill_switch.lock().await;
            ks.sync_armed_tunnel_state(
                &ks_cfg,
                mode == ConnectionMode::Tun,
                &core_exes,
                &extra_exes,
                (mode == ConnectionMode::Tun).then_some(settings.tun.adapter_name.as_str()),
            );
            ks.snapshot()
        };
        let claude_status = {
            let mut cg = self.claude_guard.lock().await;
            cg.resolve_claude_ips_if_needed(
                settings.routing.claude_guard.enabled,
                settings.routing.claude_guard.block_without_vpn,
            )
            .await;
            cg.sync(&settings.routing.claude_guard, true)
        };

        let intentional_stop = Arc::new(AtomicBool::new(false));
        let telemetry_task = match mode {
            ConnectionMode::SystemProxy => {
                self.spawn_proxy_telemetry_task(intentional_stop.clone())
            }
            ConnectionMode::Tun => match stats_api_port {
                Some(p) => self.spawn_tun_telemetry_task(xray_path, p, intentional_stop.clone()),
                None => tokio::spawn(async {}),
            },
        };
        let mut watchdog_settings = settings.clone();
        watchdog_settings.connection_mode = mode;
        let monitor_task = self.spawn_watchdog_task(
            my_gen,
            reconnect_count,
            child_arc.clone(),
            aux_child.clone(),
            stderr_ring.clone(),
            intentional_stop.clone(),
            apply_os_proxy,
            enable_os_proxy,
            run_public_probe,
            route_private_direct,
            profile.clone(),
            watchdog_settings,
        );

        let started_at = Utc::now();
        {
            let mut sess = self.session.lock().await;
            *sess = Some(ActiveSession {
                generation: my_gen,
                server_id: profile.id.clone(),
                server_name: profile.name.clone(),
                country_code: profile.country_code.clone(),
                protocol: format!("{:?}", profile.protocol).to_uppercase(),
                mode,
                started_at,
                reconnect_count,
                history_enabled: settings.history_enabled,
                child: child_arc,
                aux_child,
                proxy_meter: meter,
                _job: job,
                monitor_task,
                telemetry_task,
                intentional_stop,
                os_proxy_enabled: apply_os_proxy,
                config_path,
                aux_config_path,
            });
        }

        let health_state = if run_public_probe && probe_rtt.is_some() {
            TunnelHealthState::Verified
        } else {
            TunnelHealthState::TunnelEstablished
        };
        self.update_snapshot(|s| {
            s.status = ConnectionStatus::Connected;
            s.mode = mode;
            s.active_server_id = Some(profile.id.clone());
            s.connected_since = Some(started_at.timestamp());
            s.latency_ms = latency.or(probe_rtt);
            s.error_message = None;
            s.error_info = None;
            s.system_proxy_enabled = apply_os_proxy;
            s.kill_switch_engaged = ks_snap.blocking_active;
            s.kill_switch = ks_snap;
            s.claude_guard = claude_status;
            s.health = TunnelHealthSnapshot {
                state: health_state,
                consecutive_failures: 0,
                last_probe_rtt_ms: probe_rtt,
                last_checked_at: Some(Utc::now().to_rfc3339()),
                reason: None,
            };
            s.local_http_port = if mode == ConnectionMode::SystemProxy {
                Some(settings.http_port)
            } else {
                None
            };
            s.local_socks_port = if mode == ConnectionMode::SystemProxy {
                Some(settings.socks_port)
            } else {
                None
            };
        });

        self.record_server_connect_outcome(&profile.id, true, latency, probe_rtt, None);
        self.refresh_tray();

        let latency_note = latency
            .or(probe_rtt)
            .map(|ms| format!(" • задержка {ms} мс"))
            .unwrap_or_default();
        self.logger.info(
            "core",
            &format!("Подключено к «{}»{latency_note}", profile.name),
        );

        Ok(self.snapshot())
    }

    fn handle_connect_failure(
        &self,
        server_id: &str,
        err: CoreConnectError,
        tcp_ms: Option<u64>,
        suppress_snapshot_error: bool,
    ) -> String {
        let info = err.to_error_info();
        let msg = info.message.clone();
        let code = info.code.clone();
        self.logger.error(&info.category, &msg);
        if !suppress_snapshot_error {
            self.record_server_connect_outcome(server_id, false, tcp_ms, None, Some(&code));
            self.fail_with_structured_error(info);
        }
        msg
    }

    pub async fn disconnect(&self) -> Result<ConnectionSnapshot, String> {
        let _op_guard = self.op_lock.lock().await;
        let next_gen = self.session_gen.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.cancel_tx.send(next_gen);
        let ks_cfg = self
            .kill_switch_cfg
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let routing_live = self
            .routing_cfg
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut cached_settings = self
            .active_settings
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        cached_settings.kill_switch = ks_cfg.clone();
        cached_settings.routing = routing_live;
        cached_settings.connection_mode = self.snapshot().mode;
        let keep_always_on = ks_cfg.mode == KillSwitchMode::AlwaysOn;
        self.emit_timeline_event("disconnect", "info", "Сессия отключена пользователем", None);
        self.disconnect_locked_with_ks(true, "manual", keep_always_on, &cached_settings)
            .await?;
        Ok(self.snapshot())
    }

    pub async fn disengage_kill_switch(&self) -> Result<ConnectionSnapshot, String> {
        let _op_guard = self.op_lock.lock().await;
        let next_gen = self.session_gen.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.cancel_tx.send(next_gen);
        let disengage_res = {
            let mut ks = self.kill_switch.lock().await;
            ks.disengage_async().await
        };
        if let Err(msg) = disengage_res {
            let err = CoreConnectError::AdminRequired { detail: msg };
            self.fail_with_structured_error(err.to_error_info());
            self.refresh_tray();
            return Err(err.to_string());
        }
        let still_ks = {
            let ks = self.kill_switch.lock().await;
            ks.is_engaged()
        };
        if still_ks {
            let err = CoreConnectError::AdminRequired {
                detail: "Для снятия правила брандмауэра Kill Switch требуются права администратора (UAC).".into(),
            };
            self.fail_with_structured_error(err.to_error_info());
            self.refresh_tray();
            return Err(err.to_string());
        }
        let _ = restore_system_proxy(&self.storage.proxy_backup_path());
        self.logger.info(
            "security",
            "Блокировка Kill Switch снята, доступ в сеть восстановлен",
        );
        let ks_snap = self.kill_switch_snapshot_now().await;
        self.update_snapshot(|s| {
            s.status = ConnectionStatus::Disconnected;
            s.kill_switch_engaged = false;
            s.kill_switch = ks_snap;
            s.system_proxy_enabled = false;
            s.error_message = None;
            s.error_info = None;
            s.local_http_port = None;
            s.local_socks_port = None;
        });
        self.refresh_tray();
        Ok(self.snapshot())
    }

    async fn disconnect_locked_with_ks(
        &self,
        emit_disconnected: bool,
        end_reason: &str,
        keep_ks_guard: bool,
        settings: &AppSettings,
    ) -> Result<(), String> {
        let active = {
            let mut guard = self.session.lock().await;
            guard.take()
        };

        if let Some(mut session) = active {
            if emit_disconnected {
                self.update_snapshot(|s| {
                    s.status = ConnectionStatus::Disconnecting;
                });
            }
            session.intentional_stop.store(true, Ordering::SeqCst);
            session.telemetry_task.abort();
            session.monitor_task.abort();

            if let Some(m) = session.proxy_meter.take() {
                m.stop_async().await;
            }
            terminate_child(&session.child);
            cleanup_aux(&session.aux_child, &session.aux_config_path);
            secure_delete_file(&session.config_path);

            if keep_ks_guard {
                let ks_cfg = effective_kill_switch_config(settings);
                let mut ks = self.kill_switch.lock().await;
                if session.mode == ConnectionMode::SystemProxy {
                    let _ = ks
                        .engage_proxy_guards(
                            settings.http_port,
                            Some(settings.socks_port),
                            ks_cfg.mode,
                            "Kill Switch удерживает защиту во время переключения/отключения."
                                .into(),
                        )
                        .await;
                } else {
                    let extra_exes = Self::resolve_routing_aware_exes(&settings.routing);
                    let _ = ks
                        .engage_tun_firewall_guard(
                            &ks_cfg,
                            &extra_exes,
                            "Kill Switch удерживает блокировку WFP вне VPN.".into(),
                            false,
                        )
                        .await;
                }
            } else {
                {
                    let mut ks = self.kill_switch.lock().await;
                    let _ = ks.disengage_async().await;
                }
                if session.os_proxy_enabled {
                    if let Err(err) = restore_system_proxy(&self.storage.proxy_backup_path()) {
                        self.logger.error("windows", &err);
                    } else {
                        self.logger.info(
                            "windows",
                            "Системные настройки прокси Windows восстановлены",
                        );
                    }
                }
            }

            let _ = session.generation;
            self.persist_session_history(&session, end_reason);
        } else if !keep_ks_guard {
            {
                let mut ks = self.kill_switch.lock().await;
                let _ = ks.disengage_async().await;
            }
            let _ = restore_system_proxy(&self.storage.proxy_backup_path());
        }

        let cg_status = {
            let mut cg = self.claude_guard.lock().await;
            cg.resolve_claude_ips_if_needed(
                settings.routing.claude_guard.enabled,
                settings.routing.claude_guard.block_without_vpn,
            )
            .await;
            cg.sync(&settings.routing.claude_guard, false)
        };

        self.counters.reset();
        self.emit_traffic(TrafficStats::default());

        if emit_disconnected {
            let ks_snap = self.kill_switch_snapshot_now().await;
            let ks_blocking = ks_snap.blocking_active;
            self.update_snapshot(|s| {
                s.status = ConnectionStatus::Disconnected;
                s.connected_since = None;
                s.latency_ms = None;
                s.error_message = None;
                s.error_info = None;
                s.system_proxy_enabled = ks_blocking && s.mode == ConnectionMode::SystemProxy;
                s.kill_switch_engaged = ks_blocking;
                s.kill_switch = ks_snap;
                s.claude_guard = cg_status;
                s.health = TunnelHealthSnapshot::default();
                s.local_http_port = None;
                s.local_socks_port = None;
            });
            self.logger.info("core", "Отключено");
            self.refresh_tray();
        }

        Ok(())
    }

    pub fn blocking_cleanup_on_exit(&self) {
        if self.exit_cleaned.swap(true, Ordering::SeqCst) {
            return;
        }
        let next_gen = self.session_gen.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.cancel_tx.send(next_gen);

        let ks_cfg = self
            .kill_switch_cfg
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let persist = ks_cfg.mode == KillSwitchMode::AlwaysOn && ks_cfg.persist_on_exit;

        for _ in 0..25 {
            if let Ok(mut guard) = self.session.try_lock() {
                if let Some(mut session) = guard.take() {
                    session.intentional_stop.store(true, Ordering::SeqCst);
                    session.telemetry_task.abort();
                    session.monitor_task.abort();
                    if session.os_proxy_enabled && !persist {
                        let _ = restore_system_proxy(&self.storage.proxy_backup_path());
                    }
                    if let Some(m) = session.proxy_meter.take() {
                        m.stop();
                    }
                    terminate_child(&session.child);
                    cleanup_aux(&session.aux_child, &session.aux_config_path);
                    secure_delete_file(&session.config_path);
                    self.persist_session_history(&session, "app_exit");
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        for _ in 0..25 {
            if let Ok(mut ks) = self.kill_switch.try_lock() {
                ks.persist_exit_rule_if_requested(&ks_cfg);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        if !persist {
            let _ = restore_system_proxy(&self.storage.proxy_backup_path());
        }
        self.storage.sweep_stale_runtime_files();
    }

    fn fail_with_structured_error(&self, info: ConnectionErrorInfo) {
        let clean = redact_secrets(&info.message);
        let mut sanitized = info;
        sanitized.message = clean.clone();
        self.update_snapshot(|s| {
            s.status = ConnectionStatus::Error;
            s.connected_since = None;
            s.system_proxy_enabled = false;
            s.local_http_port = None;
            s.local_socks_port = None;
            s.error_message = Some(clean);
            s.error_info = Some(sanitized);
        });
        self.refresh_tray();
    }

    pub fn find_xray_path_pub(&self) -> Option<PathBuf> {
        self.find_xray_path().ok()
    }

    pub fn verify_xray_integrity(&self, path: &Path) -> Result<(), String> {
        self.verify_binary_integrity(path, EMBEDDED_XRAY_SHA256, "xray.exe")
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn find_awg_path_pub(&self) -> Option<PathBuf> {
        self.find_awg_path().ok()
    }

    pub async fn ping_profile_public(profile: &ServerProfile) -> Option<u64> {
        Self::ping_profile(profile).await
    }

    pub async fn probe_proxy_tunnel_public(
        http_port: Option<u16>,
        total_timeout: Duration,
    ) -> Result<(u64, String), String> {
        probe_proxy_tunnel(http_port, total_timeout).await
    }

    pub async fn run_speed_test_through_tunnel(
        &self,
        server_id: String,
        settings: &AppSettings,
    ) -> Result<SpeedTestResult, String> {
        let snap = self.snapshot();
        if snap.status != ConnectionStatus::Connected {
            return Err(
                "Подключитесь к серверу для выполнения ручного замера скорости через туннель."
                    .into(),
            );
        }
        if snap.kill_switch.blocking_active || snap.kill_switch_engaged {
            return Err("Kill Switch удерживает блокировку — замер скорости отменён.".into());
        }
        let proxy_port = if snap.mode == ConnectionMode::SystemProxy {
            snap.local_http_port.or(Some(settings.http_port))
        } else {
            None
        };
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(12))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(port) = proxy_port {
            let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))
                .map_err(|e| format!("Ошибка прокси: {e}"))?;
            builder = builder.proxy(proxy);
        } else {
            builder = builder.no_proxy();
        }
        let client = builder
            .build()
            .map_err(|e| format!("Ошибка HTTP-клиента: {e}"))?;

        const MAX_SPEEDTEST_BYTES: usize = 1_500_000;
        let started = Instant::now();
        let mut resp = client
            .get("https://speed.cloudflare.com/__down?bytes=1500000")
            .send()
            .await
            .map_err(|e| {
                format!(
                    "Сбой теста скорости через туннель: {}",
                    redact_secrets(&e.to_string())
                )
            })?;
        if !resp.status().is_success() {
            return Err(format!(
                "Тестовый ресурс вернул HTTP {}",
                resp.status().as_u16()
            ));
        }
        let mut downloaded = 0usize;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| format!("Ошибка чтения потока: {}", redact_secrets(&e.to_string())))?
        {
            downloaded = downloaded.saturating_add(chunk.len());
            if downloaded >= MAX_SPEEDTEST_BYTES {
                downloaded = MAX_SPEEDTEST_BYTES;
                break;
            }
        }
        let bounded = downloaded as u64;
        let elapsed_ms = started.elapsed().as_millis().max(1) as u64;
        let mbps = (bounded as f64 * 8.0) / ((elapsed_ms as f64) / 1000.0) / 1_000_000.0;

        Ok(SpeedTestResult {
            ok: bounded > 0,
            server_id,
            bytes_downloaded: bounded,
            duration_ms: elapsed_ms,
            mbps: (mbps * 100.0).round() / 100.0,
            via_vpn: true,
            note: "Ручной одноразовый замер ограничен лимитом 1.5 МБ для защиты квоты подписки."
                .into(),
        })
    }

    fn find_xray_path(&self) -> Result<PathBuf, String> {
        if let Some(cached) = self
            .cached_core_path
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
        {
            if cached.exists() {
                return Ok(cached);
            }
        }
        let app = self.app_handle.lock().ok().and_then(|g| g.clone());
        let resolved = resolve_xray_binary(app.as_ref())?;
        if let Ok(mut cached) = self.cached_core_path.lock() {
            *cached = Some(resolved.clone());
        }
        Ok(resolved)
    }

    fn find_awg_path(&self) -> Result<PathBuf, String> {
        if let Some(cached) = self
            .cached_awg_path
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
        {
            if cached.exists() {
                return Ok(cached);
            }
        }
        let app = self.app_handle.lock().ok().and_then(|g| g.clone());
        let resolved = resolve_awg_binary(app.as_ref())?;
        if let Ok(mut cached) = self.cached_awg_path.lock() {
            *cached = Some(resolved.clone());
        }
        Ok(resolved)
    }

    fn spawn_proxy_telemetry_task(self: &Arc<Self>, stop_flag: Arc<AtomicBool>) -> JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut prev_rx = 0u64;
            let mut prev_tx = 0u64;
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                let (rx, tx) = this.counters.totals();
                let rx_speed = rx.saturating_sub(prev_rx);
                let tx_speed = tx.saturating_sub(prev_tx);
                prev_rx = rx;
                prev_tx = tx;
                this.emit_traffic(TrafficStats {
                    rx_bytes_per_sec: rx_speed,
                    tx_bytes_per_sec: tx_speed,
                    total_rx_bytes: rx,
                    total_tx_bytes: tx,
                });
            }
        })
    }

    fn spawn_tun_telemetry_task(
        self: &Arc<Self>,
        xray_path: PathBuf,
        api_port: u16,
        stop_flag: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut prev_rx = 0u64;
            let mut prev_tx = 0u64;
            let mut interval = tokio::time::interval(Duration::from_millis(2500));
            loop {
                interval.tick().await;
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                let xray = xray_path.clone();
                let res =
                    tokio::task::spawn_blocking(move || query_xray_traffic_stats(&xray, api_port))
                        .await
                        .ok()
                        .flatten();
                if let Some((rx, tx)) = res {
                    let rx_speed = ((rx.saturating_sub(prev_rx)) as f64 / 2.5).round() as u64;
                    let tx_speed = ((tx.saturating_sub(prev_tx)) as f64 / 2.5).round() as u64;
                    prev_rx = rx;
                    prev_tx = tx;
                    this.emit_traffic(TrafficStats {
                        rx_bytes_per_sec: rx_speed,
                        tx_bytes_per_sec: tx_speed,
                        total_rx_bytes: rx,
                        total_tx_bytes: tx,
                    });
                }
            }
        })
    }

    pub async fn probe_active_connection(&self) -> Result<ProxyProbeResult, String> {
        let snap = self.snapshot();
        if snap.status != ConnectionStatus::Connected {
            return Err(
                "Подключитесь к серверу, чтобы проверить прохождение трафика через прокси."
                    .to_string(),
            );
        }
        let proxy_port = if snap.mode == ConnectionMode::SystemProxy {
            snap.local_http_port
        } else {
            None
        };
        match probe_proxy_tunnel(proxy_port, Duration::from_secs(9)).await {
            Ok((rtt_ms, endpoint)) => {
                self.logger.info(
                    "network",
                    &format!("Проверка прокси успешна: {endpoint} за {rtt_ms} мс"),
                );
                Ok(ProxyProbeResult {
                    ok: true,
                    rtt_ms: Some(rtt_ms),
                    endpoint,
                    message: format!("Туннель работает — HTTPS 204 получен за {rtt_ms} мс"),
                })
            }
            Err(err) => {
                self.logger.warn("network", &err);
                Ok(ProxyProbeResult {
                    ok: false,
                    rtt_ms: None,
                    endpoint: "cloudflare/gstatic HTTPS 204".to_string(),
                    message: err,
                })
            }
        }
    }

    pub async fn run_network_diagnostics(
        &self,
        settings: &AppSettings,
        active_profile: Option<&ServerProfile>,
        include_external_ip: bool,
    ) -> DiagnosticsReport {
        let diag = self.diagnostics();
        let snap = self.snapshot();
        let mut checks = Vec::new();

        // 1. Core integrity check
        let core_status = if !diag.core_available {
            (
                "fail",
                "Не найден",
                "Файл xray.exe отсутствует.".to_string(),
            )
        } else if !diag.core_integrity_ok {
            (
                "warn",
                "Ошибка хеша",
                diag.integrity_note
                    .clone()
                    .unwrap_or_else(|| "SHA-256 xray.exe не подтверждён.".into()),
            )
        } else if settings.connection_mode == ConnectionMode::Tun && !diag.wintun_integrity_ok {
            (
                "warn",
                "Проверьте Wintun",
                "Отсутствует или повреждён wintun.dll.".into(),
            )
        } else {
            (
                "ok",
                "Подтверждено",
                format!("{} • SHA-256 OK", diag.core_version),
            )
        };
        checks.push(NetworkCheckItem {
            id: "integrity".into(),
            label: "Целостность компонентов".into(),
            status: core_status.0.into(),
            value: core_status.1.into(),
            detail: core_status.2,
        });

        // 2. Ports & Windows Proxy consistency
        let port_check = if snap.kill_switch_engaged || snap.kill_switch.blocking_active {
            (
                "ok",
                format!("{}/{}", settings.http_port, settings.socks_port),
                "Порты удерживаются защитным фильтром Kill Switch 2.0 (штатное поведение).".into(),
            )
        } else if snap.status == ConnectionStatus::Connected {
            if snap.mode == ConnectionMode::SystemProxy {
                let matches = snap.system_proxy_enabled == diag.system_proxy_active;
                if matches {
                    (
                        "ok",
                        format!("127.0.0.1:{}", settings.http_port),
                        "Локальный прокси и системные параметры WinINET синхронизированы.".into(),
                    )
                } else {
                    (
                        "warn",
                        "Рассинхрон".to_string(),
                        "Состояние WinINET прокси отличается от активного туннеля.".into(),
                    )
                }
            } else {
                (
                    "ok",
                    "TUN Wintun".to_string(),
                    if diag.is_elevated {
                        "Интерфейс aura_tun активен с правами администратора.".into()
                    } else {
                        "TUN требует прав администратора.".into()
                    },
                )
            }
        } else {
            let bind_http = tokio::net::TcpListener::bind(("127.0.0.1", settings.http_port)).await;
            let bind_socks =
                tokio::net::TcpListener::bind(("127.0.0.1", settings.socks_port)).await;
            match (bind_http, bind_socks) {
                (Ok(_), Ok(_)) => (
                    "ok",
                    format!("{}/{}", settings.http_port, settings.socks_port),
                    "Оба локальных порта свободны и готовы к запуску.".into(),
                ),
                (Err(e), _) => (
                    "fail",
                    "Занят/блокирован".to_string(),
                    crate::proxy_meter::format_bind_error(settings.http_port, "HTTP-прокси", &e),
                ),
                (_, Err(e)) => (
                    "fail",
                    "Занят/блокирован".to_string(),
                    crate::proxy_meter::format_bind_error(settings.socks_port, "SOCKS5-прокси", &e),
                ),
            }
        };
        checks.push(NetworkCheckItem {
            id: "ports".into(),
            label: "Локальные порты и шлюз".into(),
            status: port_check.0.into(),
            value: port_check.1,
            detail: port_check.2,
        });

        // 3. DNS Resolution
        let dns_start = Instant::now();
        let dns_item = match tokio::time::timeout(
            Duration::from_secs(4),
            tokio::net::lookup_host(("one.one.one.one", 443)),
        )
        .await
        {
            Ok(Ok(addrs)) => {
                let count = addrs.count();
                let ms = dns_start.elapsed().as_millis().max(1);
                NetworkCheckItem {
                    id: "dns".into(),
                    label: "DNS-резолвинг".into(),
                    status: if count > 0 {
                        "ok".into()
                    } else {
                        "warn".into()
                    },
                    value: format!("{ms} мс"),
                    detail: format!("Системный DNS вернул {count} адрес(ов) для one.one.one.one."),
                }
            }
            Ok(Err(e)) => NetworkCheckItem {
                id: "dns".into(),
                label: "DNS-резолвинг".into(),
                status: "fail".into(),
                value: "Ошибка".into(),
                detail: format!("DNS не отвечает: {e}"),
            },
            Err(_) => NetworkCheckItem {
                id: "dns".into(),
                label: "DNS-резолвинг".into(),
                status: "fail".into(),
                value: "Таймаут".into(),
                detail: "DNS-запрос не уложился в 4 сек.".into(),
            },
        };
        checks.push(dns_item);

        // 4. End-to-end tunnel / active server reachability
        let tunnel_item = if snap.status == ConnectionStatus::Connected {
            let proxy_port = if snap.mode == ConnectionMode::SystemProxy {
                snap.local_http_port
            } else {
                None
            };
            match probe_proxy_tunnel(proxy_port, Duration::from_secs(7)).await {
                Ok((rtt, host)) => NetworkCheckItem {
                    id: "tunnel".into(),
                    label: "HTTPS 204 через туннель".into(),
                    status: "ok".into(),
                    value: format!("{rtt} мс"),
                    detail: format!("Подтверждён выход через {host} (HTTP 2xx)."),
                },
                Err(e) => NetworkCheckItem {
                    id: "tunnel".into(),
                    label: "HTTPS 204 через туннель".into(),
                    status: "fail".into(),
                    value: "Нет ответа".into(),
                    detail: e,
                },
            }
        } else if let Some(srv) = active_profile {
            match Self::ping_profile(srv).await {
                Some(ms) => NetworkCheckItem {
                    id: "tunnel".into(),
                    label: "Доступность выбранного узла".into(),
                    status: "ok".into(),
                    value: format!("{ms} мс"),
                    detail: format!(
                        "TCP-подключение к «{}» ({}:{}) успешно.",
                        srv.name, srv.address, srv.port
                    ),
                },
                None => NetworkCheckItem {
                    id: "tunnel".into(),
                    label: "Доступность выбранного узла".into(),
                    status: "warn".into(),
                    value: "Недоступен".into(),
                    detail: format!(
                        "Сервер «{}» ({}:{}) не ответил по TCP.",
                        srv.name, srv.address, srv.port
                    ),
                },
            }
        } else {
            NetworkCheckItem {
                id: "tunnel".into(),
                label: "Сквозной туннель".into(),
                status: "warn".into(),
                value: "Отключён".into(),
                detail: "Выберите сервер для проверки доступности.".into(),
            }
        };
        checks.push(tunnel_item);

        // 5. External IP (strictly opt-in, never bypasses Kill Switch!)
        let mut external_ip = None;
        if include_external_ip {
            if snap.kill_switch_engaged || snap.kill_switch.blocking_active {
                checks.push(NetworkCheckItem {
                    id: "external_ip".into(),
                    label: "Внешний IP (opt-in)".into(),
                    status: "warn".into(),
                    value: "Блок KS".into(),
                    detail: "Запрос отменён, так как Kill Switch активно блокирует внешний трафик."
                        .into(),
                });
            } else {
                let proxy_port = if snap.status == ConnectionStatus::Connected
                    && snap.mode == ConnectionMode::SystemProxy
                {
                    snap.local_http_port.or(Some(settings.http_port))
                } else {
                    None
                };
                let ip_res = fetch_external_ip(proxy_port).await;
                match ip_res {
                    Ok(ip) => {
                        external_ip = Some(ip.clone());
                        checks.push(NetworkCheckItem {
                            id: "external_ip".into(),
                            label: "Внешний IP (opt-in)".into(),
                            status: "ok".into(),
                            value: ip.clone(),
                            detail: "Определён по явному запросу через HTTPS api.ipify.org.".into(),
                        });
                    }
                    Err(e) => {
                        checks.push(NetworkCheckItem {
                            id: "external_ip".into(),
                            label: "Внешний IP (opt-in)".into(),
                            status: "warn".into(),
                            value: "Не определён".into(),
                            detail: e,
                        });
                    }
                }
            }
        } else {
            checks.push(NetworkCheckItem {
                id: "external_ip".into(),
                label: "Внешний IP (приватность)".into(),
                status: "ok".into(),
                value: "Отключено".into(),
                detail: "Запросы к внешним сервисам IP не выполняются без явного согласия.".into(),
            });
        }

        DiagnosticsReport {
            checked_at: Utc::now().to_rfc3339(),
            checks,
            external_ip,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_watchdog_task(
        self: &Arc<Self>,
        my_gen: u64,
        reconnect_count: u32,
        child: Arc<Mutex<Child>>,
        aux_child: Option<Arc<Mutex<Child>>>,
        stderr_ring: Arc<Mutex<VecDeque<String>>>,
        stop_flag: Arc<AtomicBool>,
        os_proxy_enabled: bool,
        enable_os_proxy: bool,
        run_public_probe: bool,
        route_private_direct: bool,
        profile: ServerProfile,
        settings: AppSettings,
    ) -> JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            let mut last_wall = Utc::now().timestamp();
            let mut last_mono = Instant::now();
            let mut health_tick_count: u32 = 0;
            let mut consecutive_health_failures: u32 = 0;

            loop {
                interval.tick().await;
                if stop_flag.load(Ordering::SeqCst)
                    || this.session_gen.load(Ordering::SeqCst) != my_gen
                {
                    break;
                }

                // Detect Windows sleep/hibernate wake via wall-clock vs monotonic jump
                let now_wall = Utc::now().timestamp();
                let wall_delta = now_wall - last_wall;
                let mono_delta = last_mono.elapsed().as_secs() as i64;
                last_wall = now_wall;
                last_mono = Instant::now();

                let woke_from_sleep =
                    settings.reconnect_on_wake && wall_delta > 20 && (wall_delta - mono_delta) > 12;

                if woke_from_sleep && !stop_flag.load(Ordering::SeqCst) {
                    this.logger.info(
                        "core",
                        "Обнаружено пробуждение Windows после сна — проверка состояния туннеля...",
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    if stop_flag.load(Ordering::SeqCst)
                        || this.session_gen.load(Ordering::SeqCst) != my_gen
                    {
                        break;
                    }
                    let probe_port = if settings.connection_mode == ConnectionMode::SystemProxy {
                        Some(settings.http_port)
                    } else {
                        None
                    };
                    if run_public_probe
                        && probe_proxy_tunnel(probe_port, Duration::from_secs(6))
                            .await
                            .is_err()
                    {
                        stop_flag.store(true, Ordering::SeqCst);
                        this.logger.warn(
                            "core",
                            "Туннель не отвечает после выхода из сна — запуск переподключения...",
                        );
                        let mgr = Arc::clone(&this);
                        let p_clone = profile.clone();
                        let s_clone = settings.clone();
                        tokio::spawn(async move {
                            let _op = mgr.op_lock.lock().await;
                            if mgr.session_gen.load(Ordering::SeqCst) != my_gen {
                                return;
                            }
                            let next_gen = mgr.session_gen.fetch_add(1, Ordering::SeqCst) + 1;
                            let _ = mgr.cancel_tx.send(next_gen);
                            mgr.update_snapshot(|s| {
                                s.status = ConnectionStatus::Reconnecting;
                                s.error_message = None;
                                s.error_info = None;
                            });
                            mgr.refresh_tray();
                            let _ = mgr
                                .connect_locked(
                                    p_clone,
                                    s_clone,
                                    enable_os_proxy,
                                    run_public_probe,
                                    route_private_direct,
                                    next_gen,
                                    reconnect_count.saturating_add(1),
                                    false,
                                )
                                .await;
                        });
                        break;
                    }
                }

                // Periodic tunnel health check honoring advanced health_check_interval_secs & failure_threshold
                health_tick_count = health_tick_count.saturating_add(1);
                let mut tunnel_stalled = false;
                let required_ticks =
                    (settings.advanced.health_check_interval_secs.clamp(10, 300) * 2) as u32;
                let fail_threshold = settings.advanced.health_failure_threshold.clamp(1, 5);
                if run_public_probe
                    && settings.advanced.health_check_enabled
                    && health_tick_count >= required_ticks
                {
                    health_tick_count = 0;
                    let probe_port = if settings.connection_mode == ConnectionMode::SystemProxy {
                        Some(settings.http_port)
                    } else {
                        None
                    };
                    let probe_to =
                        Duration::from_secs(settings.advanced.probe_timeout_secs.clamp(4, 30));
                    match probe_proxy_tunnel(probe_port, probe_to).await {
                        Ok((rtt, _)) => {
                            consecutive_health_failures = 0;
                            this.update_snapshot(|s| {
                                s.health = TunnelHealthSnapshot {
                                    state: TunnelHealthState::Verified,
                                    consecutive_failures: 0,
                                    last_probe_rtt_ms: Some(rtt),
                                    last_checked_at: Some(Utc::now().to_rfc3339()),
                                    reason: None,
                                };
                            });
                        }
                        Err(e) => {
                            consecutive_health_failures =
                                consecutive_health_failures.saturating_add(1);
                            if consecutive_health_failures >= fail_threshold {
                                tunnel_stalled = true;
                                this.emit_timeline_event(
                                    "health_lost",
                                    "error",
                                    &format!("Туннель потерян после {consecutive_health_failures} проверок: {e}"),
                                    None,
                                );
                                this.update_snapshot(|s| {
                                    s.health = TunnelHealthSnapshot {
                                        state: TunnelHealthState::Lost,
                                        consecutive_failures: consecutive_health_failures,
                                        last_probe_rtt_ms: None,
                                        last_checked_at: Some(Utc::now().to_rfc3339()),
                                        reason: Some(e),
                                    };
                                });
                            } else {
                                this.emit_timeline_event(
                                    "health_unstable",
                                    "warn",
                                    "Единичный сбой проверки туннеля — повторная проверка",
                                    None,
                                );
                                this.update_snapshot(|s| {
                                    s.health = TunnelHealthSnapshot {
                                        state: TunnelHealthState::Unstable,
                                        consecutive_failures: consecutive_health_failures,
                                        last_probe_rtt_ms: None,
                                        last_checked_at: Some(Utc::now().to_rfc3339()),
                                        reason: Some("Единичный сбой проверки туннеля — повтор при следующем интервале".into()),
                                    };
                                });
                            }
                        }
                    }
                }

                let primary_exited = {
                    let mut guard = child.lock().unwrap_or_else(|p| p.into_inner());
                    matches!(guard.try_wait(), Ok(Some(_)) | Err(_))
                };
                let aux_exited = aux_child.as_ref().is_some_and(|ac| {
                    let mut guard = ac.lock().unwrap_or_else(|p| p.into_inner());
                    matches!(guard.try_wait(), Ok(Some(_)) | Err(_))
                });
                if (primary_exited || aux_exited || tunnel_stalled)
                    && !stop_flag.load(Ordering::SeqCst)
                {
                    stop_flag.store(true, Ordering::SeqCst);
                    if this.session_gen.load(Ordering::SeqCst) != my_gen {
                        break;
                    }

                    let ks_cfg = this
                        .kill_switch_cfg
                        .read()
                        .unwrap_or_else(|p| p.into_inner())
                        .clone();
                    let routing_live = this
                        .routing_cfg
                        .read()
                        .unwrap_or_else(|p| p.into_inner())
                        .clone();
                    let ks_enabled = ks_cfg.mode != KillSwitchMode::Off;
                    let last_stderr = read_last_stderr_line(&stderr_ring);
                    let end_reason = if ks_enabled {
                        "kill_switch"
                    } else if tunnel_stalled {
                        "health_lost"
                    } else {
                        "crash"
                    };

                    // Tear down crashed process/proxy_meter and engage Kill Switch atomically under op_lock
                    // so concurrent user disconnect/connect cannot race with watchdog Kill Switch arming.
                    let mut ks_engaged_ok = false;
                    let mut ks_engage_err: Option<String> = None;
                    {
                        let _op = this.op_lock.lock().await;
                        if this.session_gen.load(Ordering::SeqCst) != my_gen {
                            break;
                        }
                        let crashed_sess = {
                            let mut sess = this.session.lock().await;
                            sess.take()
                        };

                        if let Some(mut s) = crashed_sess {
                            s.telemetry_task.abort();
                            if let Some(m) = s.proxy_meter.take() {
                                m.stop_async().await;
                            }
                            terminate_child(&s.child);
                            cleanup_aux(&s.aux_child, &s.aux_config_path);
                            secure_delete_file(&s.config_path);
                            this.persist_session_history(&s, end_reason);
                        }

                        // Step 1: Immediately engage Kill Switch blocking (fail-closed) BEFORE reconnect attempts!
                        if ks_enabled {
                            let extra_exes = Self::resolve_routing_aware_exes(&routing_live);
                            let drop_reason = if tunnel_stalled {
                                "Туннель перестал пропускать трафик — Kill Switch заблокировал утечку.".to_string()
                            } else {
                                "Сетевое ядро неожиданно завершилось — Kill Switch заблокировал трафик.".to_string()
                            };
                            let res = {
                                let mut ks = this.kill_switch.lock().await;
                                match settings.connection_mode {
                                    ConnectionMode::SystemProxy => {
                                        ks.engage_proxy_guards(
                                            settings.http_port,
                                            Some(settings.socks_port),
                                            ks_cfg.mode,
                                            drop_reason.clone(),
                                        )
                                        .await
                                    }
                                    ConnectionMode::Tun => {
                                        ks.engage_tun_firewall_guard(
                                            &ks_cfg,
                                            &extra_exes,
                                            drop_reason.clone(),
                                            false,
                                        )
                                        .await
                                    }
                                }
                            };
                            match res {
                                Ok(()) => ks_engaged_ok = true,
                                Err(e) => ks_engage_err = Some(e),
                            }
                        }
                    }

                    // Fail-closed Claude Guard BEFORE reconnect attempts
                    let cg_snap = {
                        let mut cg = this.claude_guard.lock().await;
                        cg.sync(&routing_live.claude_guard, false)
                    };
                    this.update_snapshot(|s| {
                        s.claude_guard = cg_snap.clone();
                    });

                    // Step 2: Run auto-reconnect (even when Kill Switch is armed, preserving blocking!)
                    let max_attempts = ks_cfg.reconnect_attempts.clamp(0, 10) as usize;
                    if settings.auto_reconnect && max_attempts > 0 {
                        this.logger.warn(
                            "core",
                            if ks_engaged_ok {
                                "Соединение прервано; Kill Switch блокирует трафик на время автопереподключения..."
                            } else {
                                "Соединение прервалось — попытка автоматического переподключения..."
                            },
                        );
                        let mut cancel_rx = this.cancel_tx.subscribe();
                        let mgr = Arc::clone(&this);
                        let p_clone = profile.clone();
                        let mut s_clone = settings.clone();
                        s_clone.kill_switch = ks_cfg.clone();
                        s_clone.routing = routing_live;
                        let crash_detail = last_stderr;

                        tokio::spawn(async move {
                            let ks_snap_now = mgr.kill_switch_snapshot_now().await;
                            mgr.update_snapshot(|s| {
                                s.status = ConnectionStatus::Reconnecting;
                                s.connected_since = None;
                                s.kill_switch_engaged = ks_engaged_ok;
                                s.kill_switch = ks_snap_now;
                                s.claude_guard = cg_snap.clone();
                                s.health.state = TunnelHealthState::Lost;
                                s.error_message = None;
                                s.error_info = None;
                            });
                            mgr.refresh_tray();

                            let mut reconnected = false;
                            let mut last_attempt_err: Option<String> = None;
                            let mut expected_gen = my_gen;

                            let base_delay =
                                s_clone.advanced.reconnect_base_delay_secs.clamp(1, 15);
                            let max_delay = s_clone
                                .advanced
                                .reconnect_max_delay_secs
                                .clamp(base_delay, 60);
                            for attempt_idx in 0..max_attempts {
                                let backoff_secs = (base_delay
                                    .saturating_mul(attempt_idx as u64 + 1))
                                .min(max_delay);
                                mgr.emit_timeline_event(
                                    "reconnect_attempt",
                                    "info",
                                    &format!(
                                        "Попытка переподключения #{} через {} с",
                                        attempt_idx + 1,
                                        backoff_secs
                                    ),
                                    None,
                                );
                                let sleep_fut =
                                    tokio::time::sleep(Duration::from_secs(backoff_secs));
                                tokio::select! {
                                    _ = sleep_fut => {}
                                    _ = cancel_rx.changed() => {
                                        return;
                                    }
                                }

                                if mgr.session_gen.load(Ordering::SeqCst) != expected_gen {
                                    return;
                                }

                                let res = {
                                    let _op = mgr.op_lock.lock().await;
                                    if mgr.session_gen.load(Ordering::SeqCst) != expected_gen {
                                        return;
                                    }
                                    let next_gen =
                                        mgr.session_gen.fetch_add(1, Ordering::SeqCst) + 1;
                                    expected_gen = next_gen;
                                    mgr.connect_locked(
                                        p_clone.clone(),
                                        s_clone.clone(),
                                        enable_os_proxy,
                                        run_public_probe,
                                        route_private_direct,
                                        next_gen,
                                        reconnect_count.saturating_add(attempt_idx as u32 + 1),
                                        true,
                                    )
                                    .await
                                };

                                match res {
                                    Ok(_) => {
                                        reconnected = true;
                                        mgr.refresh_tray();
                                        break;
                                    }
                                    Err(err) => {
                                        last_attempt_err = Some(err);
                                        if mgr.session_gen.load(Ordering::SeqCst) != expected_gen {
                                            return;
                                        }
                                    }
                                }
                            }

                            if !reconnected {
                                if ks_enabled && ks_engaged_ok {
                                    let ks_snap_final = mgr.kill_switch_snapshot_now().await;
                                    let msg = "Переподключение не удалось. Kill Switch продолжает блокировать трафик до восстановления или ручного отключения.".to_string();
                                    let info = CoreConnectError::KillSwitchEngaged {
                                        detail: msg.clone(),
                                    }
                                    .to_error_info();
                                    mgr.update_snapshot(|s| {
                                        s.status = ConnectionStatus::Error;
                                        s.connected_since = None;
                                        s.kill_switch_engaged = true;
                                        s.kill_switch = ks_snap_final;
                                        s.system_proxy_enabled = os_proxy_enabled;
                                        s.error_message = Some(msg);
                                        s.error_info = Some(info);
                                    });
                                    mgr.refresh_tray();
                                } else {
                                    if os_proxy_enabled && !ks_enabled {
                                        let _ =
                                            restore_system_proxy(&mgr.storage.proxy_backup_path());
                                    }
                                    let detail = ks_engage_err
                                        .or(last_attempt_err)
                                        .or(crash_detail)
                                        .unwrap_or_else(|| {
                                            "Не удалось переподключиться после обрыва ядра."
                                                .to_string()
                                        });
                                    mgr.record_server_connect_outcome(
                                        &p_clone.id,
                                        false,
                                        None,
                                        None,
                                        Some("CORE_CRASHED"),
                                    );
                                    mgr.fail_with_structured_error(
                                        CoreConnectError::CoreCrashed { detail }.to_error_info(),
                                    );
                                }
                            }
                        });
                        break;
                    }

                    if ks_engaged_ok {
                        let ks_snap_final = this.kill_switch_snapshot_now().await;
                        let msg =
                            "Ядро VPN остановлено. Kill Switch 2.0 заблокировал утечку трафика."
                                .to_string();
                        this.logger.error("security", &msg);
                        let info = CoreConnectError::KillSwitchEngaged {
                            detail: msg.clone(),
                        }
                        .to_error_info();
                        this.update_snapshot(|s| {
                            s.status = ConnectionStatus::Error;
                            s.connected_since = None;
                            s.kill_switch_engaged = true;
                            s.kill_switch = ks_snap_final;
                            s.system_proxy_enabled = os_proxy_enabled;
                            s.error_message = Some(msg);
                            s.error_info = Some(info);
                        });
                        this.refresh_tray();
                        break;
                    } else if let Some(err) = ks_engage_err {
                        if os_proxy_enabled {
                            let _ = restore_system_proxy(&this.storage.proxy_backup_path());
                        }
                        this.logger.error("security", &err);
                        let ks_snap_final = this.kill_switch_snapshot_now().await;
                        let info = ConnectionErrorInfo {
                            code: "KILL_SWITCH_ACTIVE".into(),
                            category: "security".into(),
                            title: "Сбой активации Kill Switch".into(),
                            message: err.clone(),
                            hint: "Проверьте права администратора (UAC) или используйте аварийное восстановление сети.".into(),
                            action: Some("relaunch_admin".into()),
                        };
                        this.update_snapshot(|s| {
                            s.status = ConnectionStatus::Error;
                            s.connected_since = None;
                            s.kill_switch_engaged = false;
                            s.kill_switch = ks_snap_final;
                            s.system_proxy_enabled = false;
                            s.error_message = Some(err);
                            s.error_info = Some(info);
                        });
                        this.refresh_tray();
                        break;
                    }

                    if os_proxy_enabled {
                        let _ = restore_system_proxy(&this.storage.proxy_backup_path());
                    }
                    let detail = match last_stderr {
                        Some(line) => format!(
                            "Процесс сетевого ядра неожиданно завершился ({line}). Сетевые настройки восстановлены."
                        ),
                        None => "Процесс сетевого ядра неожиданно завершился. Сетевые настройки восстановлены.".to_string(),
                    };
                    this.logger.error("core", &detail);
                    this.record_server_connect_outcome(
                        &profile.id,
                        false,
                        None,
                        None,
                        Some("CORE_CRASHED"),
                    );
                    this.fail_with_structured_error(
                        CoreConnectError::CoreCrashed { detail }.to_error_info(),
                    );
                    break;
                }
            }
        })
    }
}

fn recompute_quality_score(entry: &mut ServerQualityMetrics, active_ms: Option<u64>) {
    let base_rtt = active_ms.or(entry.last_http_rtt_ms).or(entry.last_tcp_ms);
    let rtt_score: i32 = match base_rtt {
        Some(ms) if ms <= 60 => 96,
        Some(ms) if ms <= 120 => 84,
        Some(ms) if ms <= 250 => 66,
        Some(ms) if ms <= 450 => 45,
        Some(_) => 25,
        None => 40,
    };
    let total = entry.success_count.saturating_add(entry.fail_count).max(1) as f64;
    let ratio = (entry.success_count as f64 + 0.5) / (total + 0.5);
    let penalty = (entry.consecutive_failures.min(4) * 18) as i32;
    let raw = ((rtt_score as f64) * ratio).round() as i32 - penalty;
    let clamped = raw.clamp(0, 100) as u8;
    entry.quality_score = clamped;
    entry.quality_label = match clamped {
        80..=100 => "Отлично".into(),
        55..=79 => "Хорошо".into(),
        30..=54 => "Нестабильно".into(),
        _ => "Недоступен".into(),
    };
}

pub(crate) fn compute_file_sha256(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn read_last_stderr_line(ring: &Arc<Mutex<VecDeque<String>>>) -> Option<String> {
    ring.lock()
        .ok()
        .and_then(|q| q.back().cloned())
        .filter(|s| !s.trim().is_empty())
}

fn pipe_child_logs(
    child: &mut Child,
    logger: Arc<AppLogger>,
    tag: &'static str,
    stderr_ring: Option<Arc<Mutex<VecDeque<String>>>>,
) {
    if let Some(stdout) = child.stdout.take() {
        let log_clone = logger.clone();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    log_clone.info(tag, trimmed);
                }
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            use std::io::BufRead;
            let reader = std::io::BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    let clean = redact_secrets(trimmed);
                    if let Some(ref ring) = stderr_ring {
                        if let Ok(mut q) = ring.lock() {
                            if q.len() >= STDERR_RING_CAPACITY {
                                q.pop_front();
                            }
                            q.push_back(clean.clone());
                        }
                    }
                    logger.warn(tag, &clean);
                }
            }
        });
    }
}

fn cleanup_aux(aux_child: &Option<Arc<Mutex<Child>>>, aux_config_path: &Option<PathBuf>) {
    if let Some(ref c) = aux_child {
        terminate_child(c);
    }
    if let Some(ref p) = aux_config_path {
        secure_delete_file(p);
    }
}

fn resolve_resource_bin(app: Option<&AppHandle>, file_name: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(handle) = app {
        if let Ok(res_dir) = handle.path().resource_dir() {
            candidates.push(res_dir.join("resources").join("core").join(file_name));
            candidates.push(res_dir.join("core").join(file_name));
            candidates.push(res_dir.join(file_name));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("resources").join("core").join(file_name));
            candidates.push(parent.join(file_name));
        }
    }
    #[cfg(debug_assertions)]
    {
        candidates.push(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources")
                .join("core")
                .join(file_name),
        );
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(
                cwd.join("src-tauri")
                    .join("resources")
                    .join("core")
                    .join(file_name),
            );
            candidates.push(cwd.join("resources").join("core").join(file_name));
        }
    }

    candidates.into_iter().find(|path| path.exists())
}

pub fn resolve_xray_binary(app: Option<&AppHandle>) -> Result<PathBuf, String> {
    resolve_resource_bin(app, "xray.exe")
        .ok_or_else(|| "Исполняемый файл ядра xray.exe не найден в ресурсах приложения".to_string())
}

pub fn resolve_awg_binary(app: Option<&AppHandle>) -> Result<PathBuf, String> {
    resolve_resource_bin(app, "wireproxy-awg.exe").ok_or_else(|| {
        "Компонент AmneziaWG (wireproxy-awg.exe) не найден в ресурсах приложения".to_string()
    })
}

fn run_helper_command_with_timeout(
    bin: &Path,
    args: &[String],
    timeout: Duration,
) -> Result<(bool, String, String), String> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("Не удалось запустить {}: {e}", bin.display()))?;

    let job = JobGuard::new_kill_on_close();
    if let Some(ref j) = job {
        let _ = j.assign_child(&child);
    }

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let out_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut s) = stdout_pipe {
            let _ = s.read_to_end(&mut buf);
        }
        String::from_utf8_lossy(&buf).to_string()
    });
    let err_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut s) = stderr_pipe {
            let _ = s.read_to_end(&mut buf);
        }
        String::from_utf8_lossy(&buf).to_string()
    });

    let deadline = Instant::now() + timeout;
    let mut status_ok = None;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                status_ok = Some(st.success());
                break;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }

    let stdout = out_handle.join().unwrap_or_default();
    let stderr = err_handle.join().unwrap_or_default();

    match status_ok {
        Some(ok) => Ok((ok, stdout, stderr)),
        None => Err(format!(
            "Превышен таймаут ({} сек) при выполнении {}",
            timeout.as_secs(),
            bin.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("subprocess")
        )),
    }
}

fn query_xray_version(path: &Path) -> Option<String> {
    let (ok, stdout, _) =
        run_helper_command_with_timeout(path, &["version".to_string()], Duration::from_secs(3))
            .ok()?;
    if !ok {
        return None;
    }
    stdout.lines().next().map(|l| l.trim().to_string())
}

fn query_xray_traffic_stats(xray_path: &Path, api_port: u16) -> Option<(u64, u64)> {
    let args = vec![
        "api".to_string(),
        "statsquery".to_string(),
        format!("--server=127.0.0.1:{api_port}"),
    ];
    let (ok, stdout, _) =
        run_helper_command_with_timeout(xray_path, &args, Duration::from_secs(3)).ok()?;
    if !ok {
        return None;
    }
    let json: serde_json::Value = serde_json::from_str(&stdout).ok()?;
    let stats = json.get("stat")?.as_array()?;
    let mut rx = 0u64;
    let mut tx = 0u64;
    for item in stats {
        let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if !name.starts_with("outbound>>>")
            || name.starts_with("outbound>>>direct>>>")
            || name.starts_with("outbound>>>block>>>")
            || name.starts_with("outbound>>>dns-out>>>")
        {
            continue;
        }
        let val = match item.get("value") {
            Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
            Some(serde_json::Value::String(s)) => s.parse::<u64>().unwrap_or(0),
            _ => 0,
        };
        if name.ends_with(">>>downlink") {
            rx = rx.saturating_add(val);
        } else if name.ends_with(">>>uplink") {
            tx = tx.saturating_add(val);
        }
    }
    Some((rx, tx))
}

pub async fn validate_awg_config(awg_path: &Path, config_path: &Path) -> Result<(), String> {
    let bin = awg_path.to_path_buf();
    let cfg = config_path.to_string_lossy().to_string();
    let (ok, stdout, stderr) = tokio::task::spawn_blocking(move || {
        run_helper_command_with_timeout(
            &bin,
            &["-n".to_string(), "-c".to_string(), cfg],
            Duration::from_secs(10),
        )
    })
    .await
    .map_err(|e| format!("Ошибка проверки AmneziaWG: {e}"))??;

    if ok {
        return Ok(());
    }

    let detail = redact_secrets(if !stderr.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    });
    Err(format!(
        "Ошибка конфигурации AmneziaWG: {}",
        detail.lines().next().unwrap_or("некорректные параметры")
    ))
}

pub async fn validate_xray_config(xray_path: &Path, config_path: &Path) -> Result<(), String> {
    let xray = xray_path.to_path_buf();
    let cfg = config_path.to_string_lossy().to_string();
    let (ok, stdout, stderr) = tokio::task::spawn_blocking(move || {
        run_helper_command_with_timeout(
            &xray,
            &[
                "run".to_string(),
                "-test".to_string(),
                "-c".to_string(),
                cfg,
            ],
            Duration::from_secs(10),
        )
    })
    .await
    .map_err(|e| format!("Ошибка проверки конфигурации: {e}"))??;

    if ok {
        return Ok(());
    }

    let detail = redact_secrets(if !stderr.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    });
    let short_line = detail
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("Недопустимые параметры конфигурации");
    if short_line.contains("vless without TLS or other encryption is prohibited") {
        return Err(
            "VLESS без шифрования (security=none) запрещён ядром Xray для публичных серверов — используйте TLS или Reality"
                .to_string(),
        );
    }
    Err(format!("Ошибка конфигурации Xray: {short_line}"))
}

async fn wait_for_local_port(
    port: u16,
    child: &Arc<Mutex<Child>>,
    stderr_ring: &Arc<Mutex<VecDeque<String>>>,
    timeout_secs: u64,
) -> Result<(), String> {
    let steps = (timeout_secs.clamp(3, 20) * 10) as usize;
    for _ in 0..steps {
        {
            let mut guard = child.lock().unwrap_or_else(|p| p.into_inner());
            if let Ok(Some(status)) = guard.try_wait() {
                let extra = read_last_stderr_line(stderr_ring)
                    .map(|l| format!(" Детали: {l}"))
                    .unwrap_or_default();
                return Err(format!(
                    "Процесс ядра завершился при запуске (код {}). Проверьте параметры ключа.{extra}",
                    status.code().unwrap_or(-1)
                ));
            }
        }
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "Ядро не открыло локальный прокси-порт за {} секунд",
        timeout_secs.clamp(3, 20)
    ))
}

async fn wait_for_tun_startup(
    api_port: Option<u16>,
    tun_alias: &str,
    child: &Arc<Mutex<Child>>,
    stderr_ring: &Arc<Mutex<VecDeque<String>>>,
    timeout_secs: u64,
) -> Result<(), String> {
    let clamped = timeout_secs.clamp(3, 20);
    let steps = (clamped * 10) as usize;
    let mut tcp_ready_since: Option<Instant> = if api_port.is_none() {
        Some(Instant::now())
    } else {
        None
    };

    for _ in 0..steps {
        {
            let mut guard = child.lock().unwrap_or_else(|p| p.into_inner());
            if let Ok(Some(status)) = guard.try_wait() {
                let extra = read_last_stderr_line(stderr_ring)
                    .map(|l| format!(" Детали: {l}"))
                    .unwrap_or_default();
                return Err(format!(
                    "Не удалось создать TUN-адаптер (код {}). Убедитесь, что приложение запущено от имени администратора и wintun.dll не заблокирован.{extra}",
                    status.code().unwrap_or(-1)
                ));
            }
        }
        if tcp_ready_since.is_none() {
            if let Some(port) = api_port {
                if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                    tcp_ready_since = Some(Instant::now());
                }
            }
        }
        if let Some(ready_at) = tcp_ready_since {
            let luid_ready =
                crate::kill_switch::resolve_interface_luid_by_alias(tun_alias).is_some();
            let fallback_elapsed = ready_at.elapsed() >= Duration::from_millis(2000);
            if luid_ready || fallback_elapsed {
                tokio::time::sleep(Duration::from_millis(700)).await;
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("TUN-интерфейс Xray не ответил за {clamped} секунд"))
}

async fn probe_proxy_tunnel_once(
    http_port: Option<u16>,
    total_timeout: Duration,
) -> Result<(u64, String), String> {
    let per_req_timeout =
        (total_timeout / 2).clamp(Duration::from_secs(3), Duration::from_secs(10));
    let mut builder = reqwest::Client::builder()
        .timeout(per_req_timeout)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(port) = http_port {
        let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))
            .map_err(|e| format!("Ошибка настройки локального HTTP-прокси: {e}"))?;
        builder = builder.proxy(proxy);
    } else {
        builder = builder.no_proxy();
    }
    let client = builder
        .build()
        .map_err(|e| format!("Ошибка создания тестового HTTP-клиента: {e}"))?;

    let probe_urls = [
        ("www.gstatic.com", "https://www.gstatic.com/generate_204"),
        (
            "cp.cloudflare.com",
            "https://cp.cloudflare.com/generate_204",
        ),
        ("1.1.1.1", "https://1.1.1.1/cdn-cgi/trace"),
    ];

    tokio::time::timeout(total_timeout, async move {
        let mut set = tokio::task::JoinSet::new();
        for (label, url) in probe_urls {
            let c = client.clone();
            set.spawn(async move {
                let started = Instant::now();
                match c.get(url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        let rtt = started.elapsed().as_millis().max(1) as u64;
                        Ok((rtt, label.to_string()))
                    }
                    Ok(resp) => Err(format!(
                        "{label}: HTTP {} (ожидался 204/2xx)",
                        resp.status().as_u16()
                    )),
                    Err(e) => Err(format!("{label}: {}", redact_secrets(&e.to_string()))),
                }
            });
        }

        let mut last_err = String::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(Ok(ok_res)) => {
                    set.abort_all();
                    return Ok(ok_res);
                }
                Ok(Err(e)) => {
                    last_err = e;
                }
                Err(e) => {
                    last_err = format!("Ошибка задачи проверки: {e}");
                }
            }
        }
        Err(format!(
            "Не удалось установить туннель через сервер — проверьте корректность ключа или доступность узла ({last_err})"
        ))
    })
    .await
    .map_err(|_| {
        format!(
            "Превышен общий таймаут проверки туннеля ({} сек)",
            total_timeout.as_secs()
        )
    })?
}

async fn probe_proxy_tunnel(
    http_port: Option<u16>,
    total_timeout: Duration,
) -> Result<(u64, String), String> {
    let first = probe_proxy_tunnel_once(http_port, total_timeout).await;
    if first.is_ok() || http_port.is_some() {
        return first;
    }
    // In TUN mode Wintun route/DNS convergence may lag slightly; allow one quick retry
    tokio::time::sleep(Duration::from_millis(700)).await;
    match probe_proxy_tunnel_once(None, total_timeout).await {
        Ok(res) => Ok(res),
        Err(mut err) => {
            if let Some(other) = crate::config_gen::detect_conflicting_vpn_adapter("aura_tun") {
                err.push_str(&format!(
                    " Обнаружен активный адаптер стороннего VPN «{other}» — отключите его и повторите попытку."
                ));
            }
            Err(err)
        }
    }
}

async fn fetch_external_ip(http_port: Option<u16>) -> Result<String, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(port) = http_port {
        let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))
            .map_err(|e| format!("Ошибка настройки прокси: {e}"))?;
        builder = builder.proxy(proxy);
    } else {
        builder = builder.no_proxy();
    }
    let client = builder
        .build()
        .map_err(|e| format!("Ошибка создания HTTP-клиента: {e}"))?;
    let mut resp = client
        .get("https://api.ipify.org")
        .send()
        .await
        .map_err(|e| {
            format!(
                "Не удалось запросить внешний IP: {}",
                redact_secrets(&e.to_string())
            )
        })?;
    if !resp.status().is_success() {
        return Err(format!(
            "Сервис определения IP вернул HTTP {}",
            resp.status().as_u16()
        ));
    }
    if let Some(len) = resp.content_length() {
        if len > 256 {
            return Err("Ответ сервиса определения IP слишком велик".into());
        }
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| redact_secrets(&e.to_string()))?
    {
        if bytes.len().saturating_add(chunk.len()) > 256 {
            return Err("Ответ сервиса определения IP слишком велик".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let body = String::from_utf8_lossy(&bytes);
    let parsed: IpAddr = body
        .trim()
        .parse()
        .map_err(|_| "Сервис вернул некорректный IP-адрес".to_string())?;
    Ok(parsed.to_string())
}

fn terminate_child(child: &Arc<Mutex<Child>>) {
    if let Ok(mut guard) = child.lock() {
        let _ = guard.kill();
        let _ = guard.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_gen::{
        generate_wireproxy_awg_config, generate_xray_config, generate_xray_config_full,
    };
    use crate::models::{
        DnsConfig, RoutingConfig, RoutingProfile, RoutingRule, RuleAction, RuleMatchType,
        SplitTunnelMode,
    };
    use crate::parser::{parse_import_text, parse_single_uri};
    use crate::routing_rules::default_rulepack;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn xray_and_awg_validate_all_supported_protocol_configs() {
        let xray = resolve_xray_binary(None).expect("xray.exe must be provisioned");
        let awg = resolve_awg_binary(None).expect("wireproxy-awg.exe must be provisioned");
        let temp_dir = std::env::temp_dir().join(format!("aura_cfg_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let sample_uris = [
            "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:443?encryption=none&security=none&type=tcp#VLESS-Loopback",
            "vless://custom-tg-user-id@1.1.1.1:443?encryption=none&security=tls&sni=example.com&allowInsecure=1&type=tcp#VLESS-TLS-InsecureStripped",
            "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=9A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1&sid=a1b2c3d4&type=tcp#VLESS-Reality",
            "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?encryption=none&security=tls&sni=example.com&type=xhttp&mode=packet-up&path=%2Fxhttp#VLESS-XHTTP",
            "vmess://eyJ2IjoiMiIsInBzIjoiVk1lc3MtVGVzdCIsImFkZCI6IjEuMS4xLjEiLCJwb3J0IjoiNDQzIiwiaWQiOiIxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTUiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiZXhhbXBsZS5jb20iLCJwYXRoIjoiL3dzIiwidGxzIjoidGxzIiwiYWxsb3dJbnNlY3VyZSI6dHJ1ZX0=",
            "trojan://secretpass@1.1.1.1:443?security=tls&sni=example.com&allowInsecure=1&type=tcp#Trojan-TLS",
            "ss://YWVzLTI1Ni1nY206c2VjcmV0cGFzcw==@1.1.1.1:8388#Shadowsocks",
            "hy2://secretPass@1.1.1.1:8443?sni=example.com&obfs=salamander&obfs-password=obfs&insecure=1&upmbps=100&downmbps=200#Hysteria2",
            "wg://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D@1.1.1.1:51820?publicKey=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB%3D&address=10.8.0.2/32&mtu=1420#WireGuard",
        ];

        for (idx, uri) in sample_uris.iter().enumerate() {
            let mut profiles = parse_single_uri(uri, None)
                .unwrap_or_else(|e| panic!("parse failed for {uri}: {e}"));
            let profile = profiles.remove(0);
            let cfg =
                generate_xray_config(&profile, 20000 + idx as u16 * 2, 20001 + idx as u16 * 2);
            let path = temp_dir.join(format!("cfg_{idx}.json"));
            fs::write(&path, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
            validate_xray_config(&xray, &path)
                .await
                .unwrap_or_else(|e| panic!("xray -test failed for {}: {e}", profile.name));
        }

        // Validate AmneziaWG INI with real wireproxy-awg.exe -n AND chained Xray config
        let awg_ini = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.8.1.2/32\nDNS = 1.1.1.1\nJc = 4\nJmin = 40\nJmax = 120\nS1 = 15\nS2 = 25\nH1 = 111111\nH2 = 222222\nH3 = 333333\nH4 = 444444\n\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\nEndpoint = 1.1.1.1:51820\n";
        let awg_profile = parse_import_text(awg_ini, None).imported_servers.remove(0);
        if let ProtocolDetails::AmneziaWg(ref d) = awg_profile.details {
            let awg_conf_path = temp_dir.join("awg_test.conf");
            fs::write(
                &awg_conf_path,
                generate_wireproxy_awg_config(d, 20900).unwrap(),
            )
            .unwrap();
            validate_awg_config(&awg, &awg_conf_path)
                .await
                .expect("wireproxy-awg -n failed for AmneziaWG config");
        }
        let awg_xray_cfg = generate_xray_config_full(
            &awg_profile,
            ConnectionMode::SystemProxy,
            20901,
            20902,
            None,
            Some(20900),
            &RoutingConfig::default(),
            true,
            &DnsConfig::default(),
            false,
            "warning",
            &default_rulepack(),
        );
        let awg_xray_path = temp_dir.join("cfg_awg_chain.json");
        fs::write(
            &awg_xray_path,
            serde_json::to_string_pretty(&awg_xray_cfg).unwrap(),
        )
        .unwrap();
        validate_xray_config(&xray, &awg_xray_path)
            .await
            .expect("xray -test failed for AmneziaWG SOCKS chain");

        // Validate Raw Xray JSON with deprecated allowInsecure stripped
        let raw_json = r#"{"remarks":"RawJSON","outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"1.1.1.1","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none"}]}]},"streamSettings":{"network":"raw","security":"tls","tlsSettings":{"serverName":"example.com","allowInsecure":true}}}]}"#;
        let raw_profile = parse_import_text(raw_json, None).imported_servers.remove(0);
        let raw_cfg = generate_xray_config(&raw_profile, 20903, 20904);
        let raw_path = temp_dir.join("cfg_raw_json.json");
        fs::write(&raw_path, serde_json::to_string_pretty(&raw_cfg).unwrap()).unwrap();
        validate_xray_config(&xray, &raw_path)
            .await
            .expect("xray -test failed for RawXray JSON");

        // Validate multi-outbound RawXray with balancer + dialerProxy fragment + burstObservatory
        let multi_raw_json = r#"{
            "remarks": "🇳🇱Основной ключ",
            "outbounds": [
                {
                    "tag": "proxy-1",
                    "protocol": "vless",
                    "settings": { "vnext": [{ "address": "1.1.1.1", "port": 443, "users": [{ "id": "11111111-2222-3333-4444-555555555555", "encryption": "none", "flow": "xtls-rprx-vision" }] }] },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": { "serverName": "www.microsoft.com", "fingerprint": "chrome", "publicKey": "9A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1", "shortId": "a1b2c3d4" },
                        "sockopt": { "dialerProxy": "fragment-out" }
                    }
                },
                {
                    "tag": "proxy-2",
                    "protocol": "vless",
                    "settings": { "vnext": [{ "address": "1.0.0.1", "port": 443, "users": [{ "id": "11111111-2222-3333-4444-555555555555", "encryption": "none" }] }] },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": { "serverName": "www.microsoft.com", "fingerprint": "chrome", "publicKey": "9A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1", "shortId": "a1b2c3d4" }
                    }
                },
                {
                    "tag": "fragment-out",
                    "protocol": "freedom",
                    "settings": { "fragment": { "packets": "tlshello", "length": "10-20", "interval": "10-20" } }
                },
                { "tag": "direct", "protocol": "freedom" }
            ],
            "routing": {
                "balancers": [{
                    "tag": "auto-bal",
                    "selector": ["proxy-"],
                    "strategy": { "type": "leastPing" }
                }]
            },
            "burstObservatory": {
                "subjectSelector": ["proxy-"],
                "pingConfig": { "destination": "https://www.gstatic.com/generate_204", "interval": "5m" }
            }
        }"#;
        let multi_profile = parse_import_text(multi_raw_json, None)
            .imported_servers
            .remove(0);
        let multi_cfg = generate_xray_config(&multi_profile, 20905, 20906);
        let multi_path = temp_dir.join("cfg_multi_balancer.json");
        fs::write(
            &multi_path,
            serde_json::to_string_pretty(&multi_cfg).unwrap(),
        )
        .unwrap();
        validate_xray_config(&xray, &multi_path)
            .await
            .expect("xray -test failed for multi-outbound balancer + fragment");

        // Validate TUN + Split Tunneling + RU bypass + Custom Rules + IPv6 block + DNS-53 hijack
        let vless_profile = parse_single_uri(sample_uris[2], None).unwrap().remove(0);
        let ru_pack = default_rulepack();
        let routing_bypass = RoutingConfig {
            profile: RoutingProfile::Custom,
            bypass_lan: true,
            bypass_ru_domains: true,
            split_tunnel_mode: SplitTunnelMode::BypassApps,
            split_apps: vec!["steam".into(), "qbittorrent".into()],
            custom_rules: vec![
                RoutingRule {
                    id: "r1".into(),
                    enabled: true,
                    match_type: RuleMatchType::Domain,
                    pattern: "domain:ads.example.com".into(),
                    action: RuleAction::Block,
                    note: None,
                },
                RoutingRule {
                    id: "r2".into(),
                    enabled: true,
                    match_type: RuleMatchType::Ip,
                    pattern: "8.8.4.4/32".into(),
                    action: RuleAction::Proxy,
                    note: None,
                },
            ],
            ..Default::default()
        };
        let tun_cfg = generate_xray_config_full(
            &vless_profile,
            ConnectionMode::Tun,
            0,
            0,
            Some(21090),
            None,
            &routing_bypass,
            true,
            &DnsConfig::default(),
            false,
            "warning",
            &ru_pack,
        );
        let tun_rules = tun_cfg["routing"]["rules"].as_array().unwrap();
        assert!(tun_rules
            .iter()
            .any(|r| r["outboundTag"] == "dns-out" && r["port"] == "53"));
        assert!(tun_rules.iter().any(|r| r["outboundTag"] == "block"
            && r["ip"]
                .as_array()
                .is_some_and(|a| a.iter().any(|x| x == "::/0"))));
        let tun_path = temp_dir.join("cfg_tun_bypass.json");
        fs::write(&tun_path, serde_json::to_string_pretty(&tun_cfg).unwrap()).unwrap();
        validate_xray_config(&xray, &tun_path)
            .await
            .expect("xray -test failed for TUN + RuDirect + SplitDNS + CustomRules");

        let routing_only = RoutingConfig {
            profile: RoutingProfile::OnlyApps,
            bypass_lan: true,
            bypass_ru_domains: false,
            split_tunnel_mode: SplitTunnelMode::OnlyApps,
            split_apps: vec!["chrome".into(), "telegram".into()],
            ..Default::default()
        };
        let tun_only_cfg = generate_xray_config_full(
            &vless_profile,
            ConnectionMode::Tun,
            0,
            0,
            Some(21091),
            None,
            &routing_only,
            true,
            &DnsConfig::default(),
            true,
            "info",
            &ru_pack,
        );
        let tun_only_rules = tun_only_cfg["routing"]["rules"].as_array().unwrap();
        assert!(!tun_only_rules.iter().any(|r| r["outboundTag"] == "block"
            && r["ip"]
                .as_array()
                .is_some_and(|a| a.iter().any(|x| x == "::/0"))));
        let tun_only_path = temp_dir.join("cfg_tun_only.json");
        fs::write(
            &tun_only_path,
            serde_json::to_string_pretty(&tun_only_cfg).unwrap(),
        )
        .unwrap();
        validate_xray_config(&xray, &tun_only_path)
            .await
            .expect("xray -test failed for TUN + OnlyApps");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn system_proxy_only_apps_does_not_bypass_vpn() {
        let xray = resolve_xray_binary(None).expect("xray.exe must be provisioned");
        let temp_dir =
            std::env::temp_dir().join(format!("aura_sp_onlyapps_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let uri = "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?encryption=none&security=tls&sni=example.com&type=tcp#SP-Test";
        let profile = parse_single_uri(uri, None).unwrap().remove(0);

        let routing = RoutingConfig {
            profile: RoutingProfile::OnlyApps,
            split_tunnel_mode: SplitTunnelMode::OnlyApps,
            split_apps: vec!["chrome.exe".into()],
            bypass_ru_domains: false,
            ..Default::default()
        };

        let cfg = generate_xray_config_full(
            &profile,
            ConnectionMode::SystemProxy,
            21092,
            21093,
            None,
            None,
            &routing,
            true,
            &DnsConfig::default(),
            false,
            "warning",
            &default_rulepack(),
        );
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert!(
            !rules
                .iter()
                .any(|r| r["port"] == "0-65535" && r["outboundTag"] == "direct"),
            "SystemProxy + OnlyApps must NOT emit catch-all direct bypass rule"
        );
        assert!(
            !rules.iter().any(|r| r.get("process").is_some()),
            "SystemProxy mode must NOT emit process split-tunneling rules"
        );

        let path = temp_dir.join("sp_onlyapps.json");
        fs::write(&path, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
        validate_xray_config(&xray, &path)
            .await
            .expect("xray -test failed for SystemProxy + OnlyApps");
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn binary_sha256_matches_embedded_manifests() {
        let dir = std::env::temp_dir().join(format!("aura_sha_{}", uuid::Uuid::new_v4()));
        let storage = AppStorage::new(dir.clone()).unwrap();
        let mgr = CoreManager::new(storage, Arc::new(AppLogger::new()));
        let xray = resolve_xray_binary(None).unwrap();
        let awg = resolve_awg_binary(None).unwrap();
        let wintun = xray.parent().unwrap().join("wintun.dll");

        assert!(mgr
            .verify_binary_integrity(&xray, EMBEDDED_XRAY_SHA256, "xray.exe")
            .unwrap());
        assert!(mgr
            .verify_binary_integrity(&awg, EMBEDDED_AWG_SHA256, "wireproxy-awg.exe")
            .unwrap());
        assert!(mgr
            .verify_binary_integrity(&wintun, EMBEDDED_WINTUN_SHA256, "wintun.dll")
            .unwrap());

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn concurrent_connect_disconnect_serializes_cleanly() {
        let dir = std::env::temp_dir().join(format!("aura_race_{}", uuid::Uuid::new_v4()));
        let storage = AppStorage::new(dir.clone()).unwrap();
        let core = Arc::new(CoreManager::new(storage, Arc::new(AppLogger::new())));

        // Closed loopback port so connect attempts fail quickly without hanging
        let (dead_port, _) = pick_ephemeral_loopback_ports().unwrap();
        let uri = format!(
            "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:{dead_port}?encryption=none&security=none&type=tcp#RaceTest"
        );
        let profile = parse_single_uri(&uri, None).unwrap().remove(0);

        let c1 = Arc::clone(&core);
        let p1 = profile.clone();
        let t1 = tokio::spawn(async move {
            let _ = c1
                .connect_internal(p1, AppSettings::default(), false, false, false)
                .await;
        });

        let c2 = Arc::clone(&core);
        let t2 = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(15)).await;
            let _ = c2.disconnect().await;
        });

        let _ = tokio::join!(t1, t2);
        let final_disc = core.disconnect().await.unwrap();
        assert_eq!(final_disc.status, ConnectionStatus::Disconnected);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn end_to_end_local_vless_tunnel_transfers_http_and_meters_traffic() {
        let xray = resolve_xray_binary(None).expect("xray.exe must be provisioned");
        let test_dir = std::env::temp_dir().join(format!("aura_e2e_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&test_dir).unwrap();

        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin_listener.local_addr().unwrap().port();
        let origin_task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = origin_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let body = "AURA_TUNNEL_OK";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let (vless_port, _) = pick_ephemeral_loopback_ports().unwrap();
        let test_uuid = "11111111-2222-3333-4444-555555555555";
        let server_cfg = serde_json::json!({
            "log": { "loglevel": "info" },
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": vless_port,
                "protocol": "vless",
                "settings": {
                    "clients": [{ "id": test_uuid }],
                    "decryption": "none"
                },
                "streamSettings": { "network": "raw", "security": "none" }
            }],
            "outbounds": [{
                "protocol": "freedom",
                "tag": "direct",
                "settings": {
                    "finalRules": [{
                        "action": "allow",
                        "network": "tcp,udp",
                        "ip": ["127.0.0.1/32"]
                    }]
                }
            }]
        });
        let server_cfg_path = test_dir.join("server.json");
        fs::write(
            &server_cfg_path,
            serde_json::to_string_pretty(&server_cfg).unwrap(),
        )
        .unwrap();

        let mut server_child = Command::new(&xray)
            .arg("run")
            .arg("-c")
            .arg(&server_cfg_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .expect("spawn xray server");
        let server_job = JobGuard::new_kill_on_close();
        if let Some(ref j) = server_job {
            let _ = j.assign_child(&server_child);
        }

        let mut server_ready = false;
        for _ in 0..30 {
            if let Ok(Some(st)) = server_child.try_wait() {
                panic!("xray server exited early ({st})");
            }
            if TcpStream::connect(("127.0.0.1", vless_port)).await.is_ok() {
                server_ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(server_ready, "xray server failed to open port {vless_port}");

        let storage = AppStorage::new(test_dir.join("appdata")).unwrap();
        let logger = Arc::new(AppLogger::new());
        let core = Arc::new(CoreManager::new(storage, logger.clone()));

        let uri = format!(
            "vless://{test_uuid}@127.0.0.1:{vless_port}?encryption=none&security=none&type=tcp#LocalTest"
        );
        let profile = parse_single_uri(&uri, None).unwrap().remove(0);
        let (http_port, socks_port) = pick_ephemeral_loopback_ports().unwrap();
        let settings = AppSettings {
            http_port,
            socks_port,
            ..Default::default()
        };

        let snap = core
            .connect_internal(profile, settings, false, false, false)
            .await
            .expect("core connect_internal must succeed");
        assert_eq!(snap.status, ConnectionStatus::Connected);

        let proxy = reqwest::Proxy::http(format!("http://127.0.0.1:{http_port}")).unwrap();
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let resp = client
            .get(format!("http://127.0.0.1:{origin_port}/health"))
            .send()
            .await
            .expect("proxied HTTP request must succeed");
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let body = resp.text().await.unwrap();
        assert_eq!(body, "AURA_TUNNEL_OK");

        let (rx, tx) = core.counters.totals();
        assert!(
            rx > 0 && tx > 0,
            "expected metered rx>0, tx>0, got rx={rx}, tx={tx}"
        );

        let disc = core.disconnect().await.unwrap();
        assert_eq!(disc.status, ConnectionStatus::Disconnected);

        let _ = server_child.kill();
        let _ = server_child.wait();
        origin_task.abort();
        let _ = fs::remove_dir_all(&test_dir);
    }
}
