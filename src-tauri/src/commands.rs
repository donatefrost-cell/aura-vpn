use crate::autostart::sync_autostart;
use crate::config_analyzer::analyze_server_profile as run_config_analysis;
use crate::config_studio::{build_config_studio_view, validate_custom_outbound_json};
use crate::core_manager::CoreManager;
use crate::core_registry::{build_core_inventory, check_core_updates_online};
use crate::dns_manager::{build_dns_inspector_report, run_dns_lookup_honest, test_dns_server_live};
use crate::elevation::{is_elevated, relaunch_as_admin as os_relaunch_as_admin};
use crate::hwid;
use crate::logger::{redact_secrets, AppLogger};
use crate::models::{
    AppSettings, AutoSelectResult, BackgroundStyle, BootstrapState, ConfigAdaptationMode,
    ConfigAdaptationProposal, ConfigStudioView, ConfigValidationResult, ConnectionHistoryResponse,
    ConnectionInspectorSnapshot, ConnectionMode, ConnectionSnapshot, ConnectionStatus,
    ConnectionTimelineEvent, CoreDiagnostics, CoreInventorySnapshot, CoreKind,
    CoreUpdateCheckResult, DiagnosticsReport, DnsInspectorReport, DnsLiveLookupResult,
    DnsRouteCheckResult, DnsServerTestResult, EmergencyRecoveryReport, ImportPreviewItem,
    ImportPreviewResult, ImportResult, IpMonitorState, IpProviderId, KillSwitchConfig,
    KillSwitchMode, KillSwitchSnapshot, LogEntry, NetworkDoctorReport, PrivacyInventory,
    PrivacyPurgeReport, PrivacyPurgeScope, ProfileAnalysisReport, ProfileOverrides,
    ProtectionCenterSnapshot, ProtocolDetails, ProtocolType, ProxyProbeResult, RawXrayDetails,
    RouteTestResult, RoutingProfile, RulepackStatus, ServerProfile, SpeedTestResult,
    SplitTunnelMode, Subscription, SubscriptionErrorEntry, SubscriptionRefreshDiff,
    SubscriptionRefreshOutcome, SubscriptionSyncEntry, ThemeMode, TunManagerSnapshot,
    UpdateCheckResult, VirtualAdapterConflict, WindowModeState,
};
use crate::net_fetch::validate_http_url;
use crate::network_doctor::run_network_doctor_suite;
use crate::parser::{
    compute_profile_fingerprint, extract_subscription_url_from_text, parse_import_text,
};
use crate::privacy::build_privacy_inventory;
use crate::routing_rules::{
    build_rulepack_status, evaluate_route, is_ru_bypass_active, rollback_rulepack as rb_rulepack,
    update_rulepack_from_url, validate_routing_rule,
};
use crate::storage::{AppStorage, StoredProfileRevision};
use crate::subscription::fetch_subscription;
use crate::tray::TrayController;
use crate::tun_manager::collect_tun_snapshot;
use crate::updater::check_for_updates as fetch_update_status;
use crate::window_state::{
    apply_mini_mode_transition, apply_window_background_style, save_window_state, WindowState,
};
use chrono::Utc;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportOutcome {
    pub result: ImportResult,
    pub state: BootstrapState,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionImportOutcome {
    pub subscription: Subscription,
    pub state: BootstrapState,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SmartImportOutcome {
    pub kind: String,
    pub imported_count: usize,
    pub skipped_lines: usize,
    pub title: Option<String>,
    pub state: BootstrapState,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyRecoveryOutcome {
    pub report: EmergencyRecoveryReport,
    pub state: BootstrapState,
}

pub struct AppState {
    pub storage: AppStorage,
    pub logger: Arc<AppLogger>,
    pub core: Arc<CoreManager>,
    pub tray: TrayController,
    pub profiles: Mutex<Vec<ServerProfile>>,
    pub subscriptions: Mutex<Vec<Subscription>>,
    pub settings: Mutex<AppSettings>,
    pub window_state: Mutex<WindowState>,
    pub needs_kill_switch_elevation: AtomicBool,
    pub sub_refresh_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    pub ping_lock: Arc<tokio::sync::Mutex<()>>,
}

pub fn is_active_status(status: ConnectionStatus) -> bool {
    matches!(
        status,
        ConnectionStatus::Connected
            | ConnectionStatus::Connecting
            | ConnectionStatus::Verifying
            | ConnectionStatus::Switching
            | ConnectionStatus::Reconnecting
    )
}

pub fn resolve_is_dark(settings: &AppSettings) -> bool {
    match settings.theme {
        ThemeMode::Dark => true,
        ThemeMode::Light => false,
        ThemeMode::System => {
            #[cfg(windows)]
            {
                use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
                use winreg::RegKey;
                let hkcu = RegKey::predef(HKEY_CURRENT_USER);
                if let Ok(key) = hkcu.open_subkey_with_flags(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                    KEY_READ,
                ) {
                    if let Ok(val) = key.get_value::<u32, _>("AppsUseLightTheme") {
                        return val == 0;
                    }
                }
            }
            true
        }
    }
}

fn apply_safe_proposals_to_profile(
    srv: &mut ServerProfile,
    settings: &AppSettings,
    diagnostics: &CoreDiagnostics,
    explicit_apply: Option<bool>,
) {
    let should_apply = match explicit_apply {
        Some(v) => v,
        None => settings.config_adaptation_mode == ConfigAdaptationMode::Auto,
    };
    if !should_apply {
        return;
    }
    let report = run_config_analysis(srv, settings, diagnostics);
    let mut ov = srv.overrides.clone().unwrap_or_default();
    let mut changed = false;
    for prop in report.proposals {
        if !prop.safe_to_auto_apply {
            continue;
        }
        if prop.field == "mtu" {
            if let Ok(m) = prop.proposed_value.trim().parse::<u16>() {
                ov.mtu = Some(m.clamp(1280, 1500));
                changed = true;
            }
        }
    }
    if changed {
        srv.overrides = Some(ov);
    }
}

impl AppState {
    pub fn build_bootstrap(&self) -> BootstrapState {
        let profiles = self
            .profiles
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let subscriptions = self
            .subscriptions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let settings = self
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let conn = self.core.snapshot();
        BootstrapState {
            profiles,
            subscriptions,
            settings,
            kill_switch: conn.kill_switch.clone(),
            connection: conn,
            traffic: self.core.traffic_snapshot(),
            diagnostics: self.core.diagnostics(),
            server_quality: self.core.server_quality_snapshot(),
            needs_kill_switch_elevation: self.needs_kill_switch_elevation.load(Ordering::Relaxed),
            ip_monitor: self.core.ip_monitor_snapshot(),
        }
    }

    fn subscription_lock(&self, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self
            .sub_refresh_locks
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        Arc::clone(
            map.entry(id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }
}

#[tauri::command]
pub fn get_bootstrap_state(state: State<'_, AppState>) -> BootstrapState {
    state.build_bootstrap()
}

#[tauri::command]
pub fn import_from_text(
    raw: String,
    apply_adaptations: Option<bool>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ImportOutcome, String> {
    let mut result = parse_import_text(&raw, None);
    if result.imported_servers.is_empty() {
        let first_err = result
            .errors
            .first()
            .cloned()
            .unwrap_or_else(|| "Не удалось распознать VPN-ключ".to_string());
        return Err(first_err);
    }

    let diag = state.core.diagnostics();
    let single_source = if result.imported_servers.len() == 1 && raw.len() <= 8192 {
        Some(raw.trim().to_string())
    } else {
        None
    };
    {
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let mut settings = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        let policy = settings.duplicate_policy.trim().to_ascii_lowercase();

        for srv in &mut result.imported_servers {
            if srv.fingerprint_key.is_none() {
                srv.fingerprint_key = Some(compute_profile_fingerprint(srv));
            }
            if srv.original_source.is_none() {
                srv.original_source = single_source.clone();
            }
            apply_safe_proposals_to_profile(srv, &settings, &diag, apply_adaptations);

            let dup_idx = profiles.iter().position(|e| {
                e.fingerprint_key.as_deref() == srv.fingerprint_key.as_deref()
                    || (e.protocol == srv.protocol
                        && e.port == srv.port
                        && e.address.eq_ignore_ascii_case(&srv.address)
                        && e.name == srv.name)
            });
            match (policy.as_str(), dup_idx) {
                ("skip", Some(_)) => continue,
                ("replace", Some(idx)) => {
                    srv.id = profiles[idx].id.clone();
                    srv.favorite = profiles[idx].favorite;
                    srv.custom_name = profiles[idx].custom_name.clone();
                    if let Some(ref cn) = srv.custom_name {
                        srv.name = cn.clone();
                    }
                    if settings.keep_local_sub_overrides {
                        srv.overrides = profiles[idx].overrides.clone();
                    }
                    profiles[idx] = srv.clone();
                }
                _ => profiles.push(srv.clone()),
            }
        }
        if settings.active_server_id.is_none() {
            settings.active_server_id = profiles.first().map(|s| s.id.clone());
            let _ = state.storage.save_settings(&settings);
        }
        state.storage.save_profiles(&profiles)?;
    }

    state.logger.info(
        "import",
        &format!("Импортировано серверов: {}", result.imported_servers.len()),
    );
    state.tray.update_from_state(&app);

    Ok(ImportOutcome {
        result,
        state: state.build_bootstrap(),
    })
}

#[tauri::command]
pub fn preview_import_text(raw: String, state: State<'_, AppState>) -> ImportPreviewResult {
    if extract_subscription_url_from_text(&raw).is_some() {
        return ImportPreviewResult {
            kind: "subscription".to_string(),
            valid_count: 1,
            duplicate_count: 0,
            skipped_lines: 0,
            errors: vec![],
            servers: vec![],
            warnings: vec![],
            capabilities_summary: vec!["HTTPS-подписка".to_string()],
            suggested_adaptations: vec![],
        };
    }

    let parsed = parse_import_text(&raw, None);
    let existing = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let diag = state.core.diagnostics();
    let mut duplicate_count = 0usize;
    let mut servers = Vec::with_capacity(parsed.imported_servers.len().min(200));
    let mut warnings: Vec<String> = Vec::new();
    let mut capabilities_summary: Vec<String> = Vec::new();
    let mut suggested_adaptations: Vec<ConfigAdaptationProposal> = Vec::new();

    for (idx, srv) in parsed.imported_servers.iter().enumerate() {
        let srv_fp = compute_profile_fingerprint(srv);
        let is_dup = existing.iter().any(|e| {
            e.fingerprint_key.as_deref().is_some_and(|fp| fp == srv_fp)
                || (e.protocol == srv.protocol
                    && e.port == srv.port
                    && e.address.eq_ignore_ascii_case(&srv.address))
        });
        if is_dup {
            duplicate_count += 1;
        }
        if idx < 25 {
            let analysis = run_config_analysis(srv, &settings, &diag);
            for w in analysis.warnings {
                if !warnings.contains(&w) && warnings.len() < 12 {
                    warnings.push(w);
                }
            }
            let cap_tag = format!(
                "{} / {}",
                analysis.capabilities.protocol, analysis.capabilities.security
            );
            if !capabilities_summary.contains(&cap_tag) && capabilities_summary.len() < 10 {
                capabilities_summary.push(cap_tag);
            }
            for f in analysis.capabilities.features {
                if !capabilities_summary.contains(&f) && capabilities_summary.len() < 12 {
                    capabilities_summary.push(f);
                }
            }
            for prop in analysis.proposals {
                if !suggested_adaptations
                    .iter()
                    .any(|p| p.field == prop.field && p.proposed_value == prop.proposed_value)
                    && suggested_adaptations.len() < 10
                {
                    suggested_adaptations.push(prop);
                }
            }
        }
        if servers.len() < 200 {
            servers.push(ImportPreviewItem {
                name: srv.name.clone(),
                protocol: format!("{:?}", srv.protocol).to_uppercase(),
                address: srv.address.clone(),
                port: srv.port,
                country_code: srv.country_code.clone(),
                is_duplicate: is_dup,
            });
        }
    }

    ImportPreviewResult {
        kind: "servers".to_string(),
        valid_count: parsed.imported_servers.len(),
        duplicate_count,
        skipped_lines: parsed.skipped_lines,
        errors: parsed.errors.into_iter().take(10).collect(),
        servers,
        warnings,
        capabilities_summary,
        suggested_adaptations,
    }
}

#[tauri::command]
pub async fn import_subscription(
    url: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<SubscriptionImportOutcome, String> {
    import_subscription_internal(url, &app, &state).await
}

fn resolve_subscription_identity(state: &AppState) -> Option<hwid::DeviceIdentity> {
    let settings = state.settings.lock().unwrap_or_else(|p| p.into_inner());
    if settings.send_hwid {
        Some(hwid::resolve_device_identity(
            settings.device_hwid.as_deref(),
        ))
    } else {
        None
    }
}

async fn import_subscription_internal(
    url: String,
    app: &AppHandle,
    state: &AppState,
) -> Result<SubscriptionImportOutcome, String> {
    let clean_url =
        extract_subscription_url_from_text(&url).unwrap_or_else(|| url.trim().to_string());
    let existing_id = {
        let subs = state
            .subscriptions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        subs.iter()
            .find(|s| s.url.eq_ignore_ascii_case(&clean_url))
            .map(|s| (s.id.clone(), s.title.clone()))
    };
    let identity = resolve_subscription_identity(state);

    let started = std::time::Instant::now();
    let mut fetched = match existing_id {
        Some((id, title)) => {
            fetch_subscription(&clean_url, Some(id), Some(title), identity.as_ref()).await?
        }
        None => fetch_subscription(&clean_url, None, None, identity.as_ref()).await?,
    };
    let duration_ms = started.elapsed().as_millis() as u64;

    let old_sub_profiles: Vec<ServerProfile> = {
        let profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        profiles
            .iter()
            .filter(|p| p.subscription_id.as_deref() == Some(&fetched.subscription.id))
            .cloned()
            .collect()
    };
    let backup_id = if !old_sub_profiles.is_empty()
        && state
            .storage
            .save_subscription_backup(&fetched.subscription.id, &old_sub_profiles)
            .is_ok()
    {
        Some(fetched.subscription.id.clone())
    } else {
        None
    };

    let diag = state.core.diagnostics();
    {
        let mut subs = state
            .subscriptions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let mut settings = state.settings.lock().unwrap_or_else(|p| p.into_inner());

        let mut old_by_fp: HashMap<String, ServerProfile> = HashMap::new();
        for prev in &old_sub_profiles {
            let fp = prev
                .fingerprint_key
                .clone()
                .unwrap_or_else(|| compute_profile_fingerprint(prev));
            old_by_fp.entry(fp).or_insert_with(|| prev.clone());
        }

        let sync_entry = SubscriptionSyncEntry {
            id: uuid::Uuid::new_v4().to_string(),
            subscription_id: fetched.subscription.id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            status: "success".to_string(),
            added: fetched.servers.len(),
            removed: old_sub_profiles.len(),
            updated: 0,
            unchanged: 0,
            server_count: fetched.servers.len(),
            duration_ms,
            error_message: None,
            backup_snapshot_id: backup_id,
        };

        if let Some(pos) = subs.iter().position(|s| s.id == fetched.subscription.id) {
            let prev_sub = subs[pos].clone();
            fetched.subscription.enabled = prev_sub.enabled;
            fetched.subscription.auto_update = prev_sub.auto_update;
            fetched.subscription.error_history = prev_sub.error_history;
            fetched.subscription.sync_history = prev_sub.sync_history;
            fetched.subscription.sync_history.insert(0, sync_entry);
            fetched.subscription.sync_history.truncate(20);
            subs[pos] = fetched.subscription.clone();
        } else {
            fetched.subscription.sync_history.insert(0, sync_entry);
            subs.push(fetched.subscription.clone());
        }

        profiles.retain(|p| p.subscription_id.as_deref() != Some(&fetched.subscription.id));
        for srv in &mut fetched.servers {
            let fp = compute_profile_fingerprint(srv);
            srv.fingerprint_key = Some(fp.clone());
            if let Some(prev) = old_by_fp.get(&fp) {
                srv.favorite = prev.favorite;
                srv.last_used_at = prev.last_used_at.clone();
                srv.latency_ms = prev.latency_ms;
                if settings.keep_local_sub_overrides {
                    srv.overrides = prev.overrides.clone();
                    if let Some(ref cn) = prev.custom_name {
                        srv.custom_name = Some(cn.clone());
                        srv.name = cn.clone();
                    }
                }
            } else {
                apply_safe_proposals_to_profile(srv, &settings, &diag, None);
            }
            profiles.push(srv.clone());
        }

        let active_still_exists = settings
            .active_server_id
            .as_ref()
            .is_some_and(|id| profiles.iter().any(|p| &p.id == id));
        if !active_still_exists {
            settings.active_server_id = fetched
                .servers
                .first()
                .or_else(|| profiles.first())
                .map(|s| s.id.clone());
            let _ = state.storage.save_settings(&settings);
        }

        state.storage.save_subscriptions(&subs)?;
        state.storage.save_profiles(&profiles)?;
    }

    state.logger.info(
        "subscription",
        &format!(
            "Подписка «{}» загружена: {} серверов",
            fetched.subscription.title, fetched.subscription.server_count
        ),
    );
    state.tray.update_from_state(app);

    Ok(SubscriptionImportOutcome {
        subscription: fetched.subscription,
        state: state.build_bootstrap(),
    })
}

#[tauri::command]
pub async fn smart_import(
    raw: String,
    apply_adaptations: Option<bool>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<SmartImportOutcome, String> {
    if let Some(sub_url) = extract_subscription_url_from_text(&raw) {
        let outcome = import_subscription_internal(sub_url, &app, &state).await?;
        return Ok(SmartImportOutcome {
            kind: "subscription".to_string(),
            imported_count: outcome.subscription.server_count,
            skipped_lines: 0,
            title: Some(outcome.subscription.title),
            state: outcome.state,
        });
    }

    let mut result = parse_import_text(&raw, None);
    if result.imported_servers.is_empty() {
        let first_err = result
            .errors
            .first()
            .cloned()
            .unwrap_or_else(|| "Не удалось распознать VPN-ключ или конфиг".to_string());
        return Err(first_err);
    }

    let first_name = result.imported_servers.first().map(|s| s.name.clone());
    let imported_count = result.imported_servers.len();
    let skipped_lines = result.skipped_lines;
    let diag = state.core.diagnostics();
    let single_source = if result.imported_servers.len() == 1 && raw.len() <= 8192 {
        Some(raw.trim().to_string())
    } else {
        None
    };

    {
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let mut settings = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        let policy = settings.duplicate_policy.trim().to_ascii_lowercase();

        for srv in &mut result.imported_servers {
            if srv.fingerprint_key.is_none() {
                srv.fingerprint_key = Some(compute_profile_fingerprint(srv));
            }
            if srv.original_source.is_none() {
                srv.original_source = single_source.clone();
            }
            apply_safe_proposals_to_profile(srv, &settings, &diag, apply_adaptations);

            let dup_idx = profiles.iter().position(|e| {
                e.fingerprint_key.as_deref() == srv.fingerprint_key.as_deref()
                    || (e.protocol == srv.protocol
                        && e.port == srv.port
                        && e.address.eq_ignore_ascii_case(&srv.address)
                        && e.name == srv.name)
            });
            match (policy.as_str(), dup_idx) {
                ("skip", Some(_)) => continue,
                ("replace", Some(idx)) => {
                    srv.id = profiles[idx].id.clone();
                    srv.favorite = profiles[idx].favorite;
                    srv.custom_name = profiles[idx].custom_name.clone();
                    if let Some(ref cn) = srv.custom_name {
                        srv.name = cn.clone();
                    }
                    if settings.keep_local_sub_overrides {
                        srv.overrides = profiles[idx].overrides.clone();
                    }
                    profiles[idx] = srv.clone();
                }
                _ => profiles.push(srv.clone()),
            }
        }
        if settings.active_server_id.is_none() {
            settings.active_server_id = profiles.first().map(|s| s.id.clone());
            let _ = state.storage.save_settings(&settings);
        }
        state.storage.save_profiles(&profiles)?;
    }

    state.logger.info(
        "import",
        &format!("Импортировано серверов: {imported_count}"),
    );
    state.tray.update_from_state(&app);

    Ok(SmartImportOutcome {
        kind: "servers".to_string(),
        imported_count,
        skipped_lines,
        title: first_name,
        state: state.build_bootstrap(),
    })
}

#[tauri::command]
pub async fn refresh_subscription(
    id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<SubscriptionRefreshOutcome, String> {
    refresh_subscription_inner(id, &app, &state).await
}

pub(crate) async fn refresh_subscription_inner(
    id: String,
    app: &AppHandle,
    state: &AppState,
) -> Result<SubscriptionRefreshOutcome, String> {
    let sub_lock = state.subscription_lock(&id);
    let _guard = sub_lock.lock().await;

    let (url, title) = {
        let subs = state
            .subscriptions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let sub = subs
            .iter()
            .find(|s| s.id == id)
            .ok_or_else(|| "Подписка не найдена".to_string())?;
        (sub.url.clone(), sub.title.clone())
    };

    let identity = resolve_subscription_identity(state);
    let started = std::time::Instant::now();

    let fetched =
        match fetch_subscription(&url, Some(id.clone()), Some(title), identity.as_ref()).await {
            Ok(f) => f,
            Err(err) => {
                let duration_ms = started.elapsed().as_millis() as u64;
                let clean_err = redact_secrets(&err);
                let mut subs = state
                    .subscriptions
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                if let Some(sub) = subs.iter_mut().find(|s| s.id == id) {
                    let server_count = sub.server_count;
                    sub.last_error = Some(clean_err.clone());
                    sub.error_history.insert(
                        0,
                        SubscriptionErrorEntry {
                            timestamp: Utc::now().to_rfc3339(),
                            message: clean_err.clone(),
                        },
                    );
                    sub.error_history.truncate(10);
                    sub.sync_history.insert(
                        0,
                        SubscriptionSyncEntry {
                            id: uuid::Uuid::new_v4().to_string(),
                            subscription_id: id.clone(),
                            timestamp: Utc::now().to_rfc3339(),
                            status: "error".to_string(),
                            added: 0,
                            removed: 0,
                            updated: 0,
                            unchanged: 0,
                            server_count,
                            duration_ms,
                            error_message: Some(clean_err.clone()),
                            backup_snapshot_id: None,
                        },
                    );
                    sub.sync_history.truncate(20);
                }
                let _ = state.storage.save_subscriptions(&subs);
                state.logger.error("subscription", &clean_err);
                return Err(clean_err);
            }
        };
    let duration_ms = started.elapsed().as_millis() as u64;

    let old_sub_profiles: Vec<ServerProfile> = {
        let profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        profiles
            .iter()
            .filter(|p| p.subscription_id.as_deref() == Some(&id))
            .cloned()
            .collect()
    };
    let can_rollback = state
        .storage
        .save_subscription_backup(&id, &old_sub_profiles)
        .is_ok()
        && state.storage.has_subscription_backup(&id);

    let diag = state.core.diagnostics();
    let mut remaps: Vec<(String, String)> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let (added, removed, updated, unchanged, active_server_changed) = {
        let mut subs = state
            .subscriptions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let mut settings = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        let keep_overrides = settings.keep_local_sub_overrides;

        let old_active_id = state
            .core
            .snapshot()
            .active_server_id
            .or_else(|| settings.active_server_id.clone());

        let mut old_by_fp: HashMap<String, Vec<ServerProfile>> = HashMap::new();
        let mut old_by_tuple: HashMap<(String, u16, String), ServerProfile> = HashMap::new();
        for mut prev in old_sub_profiles.clone() {
            let fp = prev
                .fingerprint_key
                .take()
                .unwrap_or_else(|| compute_profile_fingerprint(&prev));
            prev.fingerprint_key = Some(fp.clone());
            old_by_tuple.insert(
                (prev.address.clone(), prev.port, prev.name.clone()),
                prev.clone(),
            );
            old_by_fp.entry(fp).or_default().push(prev);
        }

        profiles.retain(|p| p.subscription_id.as_deref() != Some(&id));

        let mut matched_old_ids: HashSet<String> = HashSet::new();
        let mut added_count = 0usize;
        let mut updated_count = 0usize;
        let mut unchanged_count = 0usize;
        let mut replacement_active: Option<String> = None;
        let total_servers = fetched.servers.len();

        for mut srv in fetched.servers {
            let fp = compute_profile_fingerprint(&srv);
            srv.fingerprint_key = Some(fp.clone());

            let matched_prev = old_by_fp
                .get_mut(&fp)
                .and_then(|list| {
                    list.iter()
                        .position(|p| !matched_old_ids.contains(&p.id))
                        .map(|idx| list.remove(idx))
                })
                .or_else(|| {
                    old_by_tuple
                        .get(&(srv.address.clone(), srv.port, srv.name.clone()))
                        .filter(|p| !matched_old_ids.contains(&p.id))
                        .cloned()
                });

            if let Some(prev) = matched_prev {
                matched_old_ids.insert(prev.id.clone());
                let name_or_endpoint_changed = prev.address != srv.address
                    || prev.port != srv.port
                    || (prev.custom_name.is_none() && prev.name != srv.name);
                if name_or_endpoint_changed {
                    updated_count += 1;
                } else {
                    unchanged_count += 1;
                }

                // Preserve user metadata & stable ID across subscription refreshes
                srv.favorite = prev.favorite;
                srv.last_used_at = prev.last_used_at;
                srv.latency_ms = prev.latency_ms;
                if keep_overrides {
                    srv.overrides = prev.overrides;
                    if let Some(ref cn) = prev.custom_name {
                        srv.custom_name = Some(cn.clone());
                        srv.name = cn.clone();
                    }
                } else {
                    apply_safe_proposals_to_profile(&mut srv, &settings, &diag, None);
                }

                remaps.push((prev.id.clone(), srv.id.clone()));
                if old_active_id.as_deref() == Some(prev.id.as_str()) {
                    replacement_active = Some(srv.id.clone());
                }
            } else {
                added_count += 1;
                apply_safe_proposals_to_profile(&mut srv, &settings, &diag, None);
            }

            profiles.push(srv);
        }

        let removed_count = old_sub_profiles.len().saturating_sub(matched_old_ids.len());

        if let Some(pos) = subs.iter().position(|s| s.id == id) {
            let prev = subs[pos].clone();
            let mut updated_sub = fetched.subscription.clone();
            updated_sub.enabled = prev.enabled;
            updated_sub.auto_update = prev.auto_update;
            updated_sub.error_history = prev.error_history;
            updated_sub.sync_history = prev.sync_history;
            if prev.update_interval_hours.is_some() {
                updated_sub.update_interval_hours = prev.update_interval_hours;
            }
            updated_sub.sync_history.insert(
                0,
                SubscriptionSyncEntry {
                    id: uuid::Uuid::new_v4().to_string(),
                    subscription_id: id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    status: "success".to_string(),
                    added: added_count,
                    removed: removed_count,
                    updated: updated_count,
                    unchanged: unchanged_count,
                    server_count: total_servers,
                    duration_ms,
                    error_message: None,
                    backup_snapshot_id: if can_rollback { Some(id.clone()) } else { None },
                },
            );
            updated_sub.sync_history.truncate(20);
            subs[pos] = updated_sub;
        }

        let old_active_was_in_sub = old_active_id
            .as_deref()
            .is_some_and(|aid| old_sub_profiles.iter().any(|p| p.id == aid));
        let mut active_changed = false;
        if old_active_was_in_sub {
            let replaced_ok = replacement_active.is_some();
            let next_active = replacement_active
                .or_else(|| {
                    profiles
                        .iter()
                        .find(|p| p.subscription_id.as_deref() == Some(&id))
                        .map(|p| p.id.clone())
                })
                .or_else(|| profiles.first().map(|p| p.id.clone()));
            if !replaced_ok && old_active_id.is_some() {
                active_changed = true;
                warnings.push(
                    "Активный узел удалён провайдером и заменён другим сервером подписки.".into(),
                );
            }
            settings.active_server_id = next_active;
            let _ = state.storage.save_settings(&settings);
        }

        state.storage.save_subscriptions(&subs)?;
        state.storage.save_profiles(&profiles)?;
        (
            added_count,
            removed_count,
            updated_count,
            unchanged_count,
            active_changed,
        )
    };

    for (old_id, new_id) in remaps {
        state.core.remap_active_server_id(&old_id, &new_id).await;
    }

    state.logger.info(
        "subscription",
        &format!(
            "Подписка «{}» обновлена: +{} / -{} / ~{}",
            fetched.subscription.title, added, removed, updated
        ),
    );
    state.tray.update_from_state(app);

    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    Ok(SubscriptionRefreshOutcome {
        diff: SubscriptionRefreshDiff {
            subscription_id: id,
            added,
            removed,
            updated,
            unchanged,
            active_server_changed,
            can_rollback,
            warnings,
        },
        state: boot,
    })
}

#[tauri::command]
pub async fn rollback_subscription(
    id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    let sub_lock = state.subscription_lock(&id);
    let _guard = sub_lock.lock().await;

    let backup = state.storage.load_subscription_backup(&id)?;
    if backup.is_empty() {
        return Err("Резервная копия подписки пуста".to_string());
    }

    let restored_count = backup.len();
    let first_restored_id = backup.first().map(|p| p.id.clone());
    let old_active_in_sub = {
        let mut subs = state
            .subscriptions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let mut settings = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        let current_active = state
            .core
            .snapshot()
            .active_server_id
            .or_else(|| settings.active_server_id.clone());
        let in_sub = current_active.as_deref().is_some_and(|aid| {
            profiles
                .iter()
                .any(|p| p.id == aid && p.subscription_id.as_deref() == Some(&id))
        });

        profiles.retain(|p| p.subscription_id.as_deref() != Some(&id));
        profiles.extend(backup);
        state.storage.save_profiles(&profiles)?;

        if let Some(sub) = subs.iter_mut().find(|s| s.id == id) {
            sub.server_count = restored_count;
            sub.last_error = None;
            sub.sync_history.insert(
                0,
                SubscriptionSyncEntry {
                    id: uuid::Uuid::new_v4().to_string(),
                    subscription_id: id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    status: "rollback".to_string(),
                    added: 0,
                    removed: 0,
                    updated: restored_count,
                    unchanged: 0,
                    server_count: restored_count,
                    duration_ms: 0,
                    error_message: None,
                    backup_snapshot_id: None,
                },
            );
            sub.sync_history.truncate(20);
            state.storage.save_subscriptions(&subs)?;
        }

        if in_sub {
            if let Some(ref cur) = current_active {
                if !profiles.iter().any(|p| p.id == *cur) {
                    if let Some(ref next_id) = first_restored_id {
                        settings.active_server_id = Some(next_id.clone());
                        let _ = state.storage.save_settings(&settings);
                    }
                }
            }
        }
        if in_sub {
            current_active.zip(first_restored_id)
        } else {
            None
        }
    };

    if let Some((old_id, new_id)) = old_active_in_sub {
        state.core.remap_active_server_id(&old_id, &new_id).await;
    }
    state.storage.delete_subscription_backup(&id);
    state.logger.info(
        "subscription",
        "Выполнен откат узлов подписки к предыдущей версии",
    );
    state.tray.update_from_state(&app);
    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    Ok(boot)
}

#[tauri::command]
pub async fn delete_subscription(
    id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    let active_belongs_to_sub = {
        let profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let snap = state.core.snapshot();
        is_active_status(snap.status)
            && snap.active_server_id.as_ref().is_some_and(|aid| {
                profiles
                    .iter()
                    .any(|p| &p.id == aid && p.subscription_id.as_deref() == Some(&id))
            })
    };

    if active_belongs_to_sub {
        let _ = disconnect_internal(&app, &state).await;
    }

    {
        let mut subs = state
            .subscriptions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let mut settings = state.settings.lock().unwrap_or_else(|p| p.into_inner());

        subs.retain(|s| s.id != id);
        profiles.retain(|p| p.subscription_id.as_deref() != Some(&id));

        if let Some(ref aid) = settings.active_server_id {
            if !profiles.iter().any(|p| &p.id == aid) {
                settings.active_server_id = profiles.first().map(|p| p.id.clone());
                let _ = state.storage.save_settings(&settings);
            }
        }

        state.storage.save_subscriptions(&subs)?;
        state.storage.save_profiles(&profiles)?;
    }

    state.storage.delete_subscription_backup(&id);
    state.tray.update_from_state(&app);
    Ok(state.build_bootstrap())
}

pub async fn select_server_internal(
    id: String,
    app: &AppHandle,
    state: &AppState,
) -> Result<BootstrapState, String> {
    let profile = {
        let profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        profiles
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| "Выбранный сервер не найден".to_string())?
    };

    let settings = {
        let mut settings = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        settings.active_server_id = Some(id.clone());
        state.storage.save_settings(&settings)?;
        settings.clone()
    };

    let snap = state.core.snapshot();
    if is_active_status(snap.status) && snap.active_server_id.as_deref() != Some(&id) {
        let _ = state.core.connect(profile, settings).await?;
    }

    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    state.tray.update_from_state(app);
    Ok(boot)
}

#[tauri::command]
pub async fn select_server(
    id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    select_server_internal(id, &app, &state).await
}

#[tauri::command]
pub fn rename_server(
    id: String,
    name: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    let clean = name.trim();
    if clean.is_empty() {
        return Err("Название сервера не может быть пустым".to_string());
    }
    if clean.chars().count() > 120 {
        return Err("Название сервера не должно превышать 120 символов".to_string());
    }

    {
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let srv = profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| "Сервер не найден".to_string())?;
        srv.name = clean.to_string();
        srv.custom_name = Some(clean.to_string());
        state.storage.save_profiles(&profiles)?;
    }

    state.tray.update_from_state(&app);
    Ok(state.build_bootstrap())
}

#[tauri::command]
pub async fn delete_server(
    id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    let snap = state.core.snapshot();
    if is_active_status(snap.status) && snap.active_server_id.as_deref() == Some(&id) {
        let _ = disconnect_internal(&app, &state).await;
    }

    {
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let mut settings = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        profiles.retain(|p| p.id != id);
        if settings.active_server_id.as_deref() == Some(&id) {
            settings.active_server_id = profiles.first().map(|p| p.id.clone());
            state.storage.save_settings(&settings)?;
        }
        state.storage.save_profiles(&profiles)?;
    }

    state.tray.update_from_state(&app);
    Ok(state.build_bootstrap())
}

#[tauri::command]
pub async fn ping_server(
    id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<u64>, String> {
    let ks_snap = state.core.kill_switch_snapshot_now().await;
    let status_now = state.core.snapshot().status;
    if ks_snap.blocking_active
        || (status_now != ConnectionStatus::Connected && state.core.snapshot().kill_switch_engaged)
    {
        return Err("Прямой TCP-пинг заблокирован активным Kill Switch.".to_string());
    }
    let profile = {
        let profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        profiles
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| "Сервер не найден".to_string())?
    };

    let ms = CoreManager::ping_profile(&profile).await;
    state.core.record_server_tcp_ping(&id, ms);
    {
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(srv) = profiles.iter_mut().find(|p| p.id == id) {
            srv.latency_ms = ms;
        }
        let _ = state.storage.save_profiles(&profiles);
    }
    state.tray.update_from_state(&app);
    Ok(ms)
}

async fn run_ping_all(state: &AppState) -> Result<Vec<ServerProfile>, String> {
    let ks_snap = state.core.kill_switch_snapshot_now().await;
    let status_now = state.core.snapshot().status;
    if ks_snap.blocking_active
        || (status_now != ConnectionStatus::Connected && state.core.snapshot().kill_switch_engaged)
    {
        return Err("Массовый прямой TCP-пинг заблокирован активным Kill Switch.".to_string());
    }
    let _ping_guard = state.ping_lock.lock().await;
    let max_parallel = {
        let s = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        s.advanced.max_parallel_pings.clamp(1, 32)
    };
    let targets: Vec<ServerProfile> = {
        let profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        profiles.clone()
    };

    let sem = Arc::new(tokio::sync::Semaphore::new(max_parallel));
    let mut handles = Vec::with_capacity(targets.len());
    for srv in targets {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| e.to_string())?;
        handles.push(tokio::spawn(async move {
            let _p = permit;
            let ms = CoreManager::ping_profile(&srv).await;
            (srv.id, ms)
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(item) = handle.await {
            results.push(item);
        }
    }

    state.core.record_server_tcp_pings_batch(&results);

    let updated = {
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        for (id, ms) in results {
            if let Some(srv) = profiles.iter_mut().find(|p| p.id == id) {
                srv.latency_ms = ms;
            }
        }
        let _ = state.storage.save_profiles(&profiles);
        profiles.clone()
    };

    Ok(updated)
}

#[tauri::command]
pub async fn ping_all_servers(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Vec<ServerProfile>, String> {
    let updated = run_ping_all(&state).await?;
    state.tray.update_from_state(&app);
    Ok(updated)
}

#[tauri::command]
pub async fn auto_select_fastest_server(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AutoSelectResult, String> {
    let updated = run_ping_all(&state).await?;
    let quality_map = state.core.server_quality_snapshot();
    let fastest = updated
        .iter()
        .filter_map(|p| {
            p.latency_ms.map(|ms| {
                let q = quality_map.get(&p.id);
                let fail_penalty = q.map_or(0, |m| u64::from(m.consecutive_failures) * 300);
                let quality_score = q.map_or(70, |m| m.quality_score);
                (
                    p,
                    ms,
                    ms.saturating_add(fail_penalty),
                    std::cmp::Reverse(quality_score),
                )
            })
        })
        .min_by_key(|(_, _, weighted_ms, rev_q)| (*weighted_ms, *rev_q))
        .ok_or_else(|| "Ни один сервер не ответил на TCP-проверку задержки".to_string())?;

    let chosen_id = fastest.0.id.clone();
    let chosen_name = fastest.0.name.clone();
    let chosen_ms = fastest.1;

    let boot = select_server_internal(chosen_id.clone(), &app, &state).await?;
    state.logger.info(
        "network",
        &format!("Автовыбор: выбран самый быстрый узел «{chosen_name}» ({chosen_ms} мс)"),
    );

    Ok(AutoSelectResult {
        selected_server_id: chosen_id,
        server_name: chosen_name,
        latency_ms: chosen_ms,
        state: boot,
    })
}

pub async fn connect_internal(
    app: &AppHandle,
    state: &AppState,
    server_id: Option<String>,
) -> Result<ConnectionSnapshot, String> {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let target_id = server_id
        .or_else(|| settings.active_server_id.clone())
        .ok_or_else(|| "Сначала добавьте и выберите VPN-сервер".to_string())?;

    let profile = {
        let profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        profiles
            .iter()
            .find(|p| p.id == target_id)
            .cloned()
            .ok_or_else(|| "Выбранный сервер не найден".to_string())?
    };

    if settings.active_server_id.as_deref() != Some(&target_id) {
        let mut guard = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        guard.active_server_id = Some(target_id.clone());
        let _ = state.storage.save_settings(&guard);
    }

    state.tray.update_from_state(app);

    let res = state.core.connect(profile.clone(), settings).await;
    match res {
        Ok(snap) => {
            {
                let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(p) = profiles.iter_mut().find(|x| x.id == target_id) {
                    if let Some(ms) = snap.latency_ms {
                        p.latency_ms = Some(ms);
                    }
                    p.last_used_at = Some(Utc::now().to_rfc3339());
                }
                let _ = state.storage.save_profiles(&profiles);
            }
            let boot = state.build_bootstrap();
            let _ = app.emit("bootstrap-sync", &boot);
            state.tray.update_from_state(app);
            Ok(snap)
        }
        Err(err) => {
            state.tray.update_from_state(app);
            Err(err)
        }
    }
}

pub async fn disconnect_internal(
    app: &AppHandle,
    state: &AppState,
) -> Result<ConnectionSnapshot, String> {
    let snap = state.core.disconnect().await?;
    state.tray.update_from_state(app);
    Ok(snap)
}

#[tauri::command]
pub async fn connect(
    server_id: Option<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ConnectionSnapshot, String> {
    connect_internal(&app, &state, server_id).await
}

#[tauri::command]
pub async fn disconnect(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ConnectionSnapshot, String> {
    disconnect_internal(&app, &state).await
}

#[tauri::command]
pub async fn disengage_kill_switch(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ConnectionSnapshot, String> {
    let snap = state.core.disengage_kill_switch().await?;
    state
        .needs_kill_switch_elevation
        .store(false, Ordering::Relaxed);
    state.tray.update_from_state(&app);
    Ok(snap)
}

pub async fn switch_mode_from_tray(app: &AppHandle, state: &AppState, mode: ConnectionMode) {
    {
        let mut guard = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        if guard.connection_mode == mode {
            return;
        }
        guard.connection_mode = mode;
        let _ = state.storage.save_settings(&guard);
    }
    if is_active_status(state.core.snapshot().status) {
        let _ = connect_internal(app, state, None).await;
    }
    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    state.tray.update_from_state(app);
}

pub async fn toggle_ru_direct_from_tray(app: &AppHandle, state: &AppState) {
    {
        let mut guard = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        let currently_active = is_ru_bypass_active(&guard.routing);
        match guard.routing.profile {
            RoutingProfile::AllVpn | RoutingProfile::RuDirect => {
                if currently_active {
                    guard.routing.profile = RoutingProfile::AllVpn;
                    guard.routing.bypass_ru_domains = false;
                } else {
                    guard.routing.profile = RoutingProfile::RuDirect;
                    guard.routing.bypass_ru_domains = true;
                }
            }
            _ => {
                guard.routing.bypass_ru_domains = !currently_active;
            }
        }
        let _ = state.storage.save_settings(&guard);
    }
    if is_active_status(state.core.snapshot().status) {
        let _ = connect_internal(app, state, None).await;
    }
    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    state.tray.update_from_state(app);
}

fn validate_dns_field(raw: &str, label: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.len() > 253
        || !trimmed.is_ascii()
        || trimmed.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(format!(
            "Некорректный адрес {label}: недопустимые символы или длина"
        ));
    }
    if trimmed.parse::<std::net::IpAddr>().is_ok() {
        return Ok(trimmed.to_string());
    }
    if let Ok(url) = reqwest::Url::parse(trimmed) {
        let scheme = url.scheme().to_ascii_lowercase();
        if matches!(scheme.as_str(), "https" | "https+local") {
            let normalized = if scheme == "https+local" {
                trimmed.replacen("https+local://", "https://", 1)
            } else {
                trimmed.to_string()
            };
            crate::net_fetch::validate_http_url(&normalized, true, false)
                .map_err(|e| format!("Некорректный {label}: {e}"))?;
            return Ok(trimmed.to_string());
        }
        if matches!(scheme.as_str(), "tls" | "quic" | "tcp" | "udp")
            && url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
        {
            return Ok(trimmed.to_string());
        }
    }
    Err(format!(
        "Некорректный {label}: укажите IPv4/IPv6 или URL вида https://... / tls://..."
    ))
}

fn normalize_optional_https_url(
    raw: Option<String>,
    field_label: &str,
) -> Result<Option<String>, String> {
    let Some(val) = raw else {
        return Ok(None);
    };
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > 1024 {
        return Err(format!("{field_label}: ссылка слишком длинная"));
    }
    let parsed =
        validate_http_url(trimmed, true, false).map_err(|e| format!("{field_label}: {e}"))?;
    Ok(Some(parsed.to_string()))
}

fn validate_split_app_name(raw: &str) -> Result<String, String> {
    let clean = raw.trim();
    if clean.is_empty() || clean.len() > 128 {
        return Err(
            "Имя процесса для Split Tunneling должно быть от 1 до 128 символов".to_string(),
        );
    }
    if clean.contains("..")
        || clean.contains('/')
        || clean.contains('\\')
        || clean.chars().any(|c| c.is_control())
    {
        return Err(format!(
            "Недопустимое имя процесса в Split Tunneling: {clean}"
        ));
    }
    Ok(clean.to_string())
}

fn normalize_and_validate_settings(mut new_settings: AppSettings) -> Result<AppSettings, String> {
    if new_settings.http_port < 1024 || new_settings.socks_port < 1024 {
        return Err("Выберите локальные порты в диапазоне 1024–65535".to_string());
    }
    if new_settings.http_port == new_settings.socks_port {
        return Err("Порты HTTP и SOCKS5 не должны совпадать".to_string());
    }
    new_settings.ui_scale = new_settings.ui_scale.clamp(90, 120);
    new_settings.connect_timeout_secs = new_settings.connect_timeout_secs.clamp(5, 30);
    new_settings.kill_switch.reconnect_attempts =
        new_settings.kill_switch.reconnect_attempts.min(10);
    new_settings.kill_switch_enabled = new_settings.kill_switch.mode != KillSwitchMode::Off;

    if let Some(ref hex) = new_settings.custom_accent_hex {
        let trimmed = hex.trim();
        let valid_hex = trimmed.len() == 7
            && trimmed.starts_with('#')
            && trimmed[1..].chars().all(|c| c.is_ascii_hexdigit());
        new_settings.custom_accent_hex = if valid_hex {
            Some(trimmed.to_ascii_uppercase())
        } else {
            None
        };
    }

    let dns_mode = new_settings.dns.mode.trim().to_ascii_lowercase();
    new_settings.dns.mode = match dns_mode.as_str() {
        "auto" | "hybrid" => "hybrid".to_string(),
        "vpn" => "vpn".to_string(),
        "direct" => "direct".to_string(),
        "config" => "config".to_string(),
        "system" => "system".to_string(),
        "custom" => "custom".to_string(),
        _ => {
            return Err(format!(
                "Неподдерживаемый режим DNS: {}",
                new_settings.dns.mode
            ))
        }
    };
    new_settings.dns.primary_dns =
        validate_dns_field(&new_settings.dns.primary_dns, "Primary DNS")?;
    new_settings.dns.direct_dns = validate_dns_field(&new_settings.dns.direct_dns, "Direct DNS")?;
    new_settings.dns.fallback_dns = match new_settings.dns.fallback_dns.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(v) => Some(validate_dns_field(v, "Fallback DNS")?),
    };
    new_settings.dns.direct_fallback_dns = match new_settings
        .dns
        .direct_fallback_dns
        .as_deref()
        .map(str::trim)
    {
        None | Some("") => None,
        Some(v) => Some(validate_dns_field(v, "Direct Fallback DNS")?),
    };
    let proto_hint = new_settings.dns.protocol_hint.trim().to_ascii_lowercase();
    new_settings.dns.protocol_hint = match proto_hint.as_str() {
        "plain" | "doh" | "dot" | "doq" => proto_hint,
        _ => "plain".to_string(),
    };
    new_settings.dns.query_strategy = new_settings
        .dns
        .query_strategy
        .as_deref()
        .map(str::trim)
        .filter(|s| matches!(*s, "UseIP" | "UseIPv4" | "UseIPv6"))
        .map(|s| s.to_string());

    let adapter_clean = new_settings.tun.adapter_name.trim().to_string();
    if adapter_clean.is_empty() {
        new_settings.tun.adapter_name = "aura_tun".to_string();
    } else if adapter_clean.len() > 32
        || !adapter_clean
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Имя TUN-адаптера может содержать только латинские буквы, цифры, `_` и `-` (до 32 символов)".to_string());
    } else {
        new_settings.tun.adapter_name = adapter_clean;
    }
    new_settings.tun.mtu = new_settings.tun.mtu.clamp(1280, 1500);
    let valid_v4_cidr = new_settings
        .tun
        .ipv4_address
        .split_once('/')
        .and_then(|(ip, prefix)| {
            Some((
                ip.parse::<std::net::Ipv4Addr>().ok()?,
                prefix.parse::<u8>().ok()?,
            ))
        })
        .is_some_and(|(_, p)| p <= 32);
    if !valid_v4_cidr {
        new_settings.tun.ipv4_address = "10.24.0.1/24".to_string();
    }
    let valid_v6_cidr = new_settings
        .tun
        .ipv6_address
        .split_once('/')
        .and_then(|(ip, prefix)| {
            Some((
                ip.parse::<std::net::Ipv6Addr>().ok()?,
                prefix.parse::<u8>().ok()?,
            ))
        })
        .is_some_and(|(_, p)| p <= 128);
    if !valid_v6_cidr {
        new_settings.tun.ipv6_address = "fd00:10:24::1/126".to_string();
    }

    new_settings.advanced.core_start_timeout_secs =
        new_settings.advanced.core_start_timeout_secs.clamp(3, 20);
    new_settings.advanced.probe_timeout_secs =
        new_settings.advanced.probe_timeout_secs.clamp(4, 30);
    new_settings.advanced.health_check_interval_secs = new_settings
        .advanced
        .health_check_interval_secs
        .clamp(10, 300);
    new_settings.advanced.health_failure_threshold =
        new_settings.advanced.health_failure_threshold.clamp(1, 5);
    new_settings.advanced.reconnect_base_delay_secs =
        new_settings.advanced.reconnect_base_delay_secs.clamp(1, 15);
    new_settings.advanced.reconnect_max_delay_secs = new_settings
        .advanced
        .reconnect_max_delay_secs
        .clamp(new_settings.advanced.reconnect_base_delay_secs, 60);
    new_settings.advanced.max_parallel_pings =
        new_settings.advanced.max_parallel_pings.clamp(1, 32);
    new_settings.advanced.tcp_keepalive_interval_secs =
        new_settings.advanced.tcp_keepalive_interval_secs.min(120);
    new_settings.advanced.mux_concurrency = new_settings.advanced.mux_concurrency.clamp(1, 16);
    new_settings.advanced.mux_xudp_concurrency =
        new_settings.advanced.mux_xudp_concurrency.clamp(1, 16);
    new_settings.advanced.manual_mtu = new_settings
        .advanced
        .manual_mtu
        .map(|m| m.clamp(1280, 1500));
    new_settings.advanced.dialer_domain_strategy =
        match new_settings.advanced.dialer_domain_strategy.trim() {
            s @ ("AsIs" | "UseIP" | "UseIPv4" | "UseIPv6" | "UseIPv4v6" | "UseIPv6v4") => {
                s.to_string()
            }
            _ => "AsIs".to_string(),
        };
    new_settings.advanced.stats_api_mode = match new_settings
        .advanced
        .stats_api_mode
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "fixed" => "fixed".to_string(),
        "disabled" => "disabled".to_string(),
        _ => "ephemeral".to_string(),
    };
    if let Some(p) = new_settings.advanced.stats_api_port {
        if p < 1024 || p == new_settings.http_port || p == new_settings.socks_port {
            new_settings.advanced.stats_api_port = None;
        }
    }
    if new_settings.auto_check_ip_interval_secs > 0 {
        new_settings.auto_check_ip_interval_secs =
            new_settings.auto_check_ip_interval_secs.clamp(60, 3600);
    }
    new_settings.duplicate_policy = match new_settings
        .duplicate_policy
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "skip" => "skip".to_string(),
        "replace" => "replace".to_string(),
        "keep" => "keep".to_string(),
        _ => "merge".to_string(),
    };

    let log_lvl = new_settings.log_level.trim().to_ascii_lowercase();
    new_settings.log_level = match log_lvl.as_str() {
        "debug" | "info" | "warning" | "error" | "none" => log_lvl,
        _ => "warning".to_string(),
    };

    new_settings.update_feed_url =
        normalize_optional_https_url(new_settings.update_feed_url, "Лента обновлений")?;
    new_settings.routing.rulepack_update_url =
        normalize_optional_https_url(new_settings.routing.rulepack_update_url, "URL базы правил")?;

    if new_settings.routing.split_apps.len() > 200 {
        return Err(
            "Список приложений Split Tunneling не должен превышать 200 записей".to_string(),
        );
    }
    let mut sanitized_apps = Vec::with_capacity(new_settings.routing.split_apps.len());
    for app_name in &new_settings.routing.split_apps {
        sanitized_apps.push(validate_split_app_name(app_name)?);
    }
    new_settings.routing.split_apps = sanitized_apps;

    if new_settings.routing.custom_rules.len() > 300 {
        return Err("Количество пользовательских правил не должно превышать 300".to_string());
    }

    match new_settings.routing.profile {
        RoutingProfile::AllVpn => {
            new_settings.routing.bypass_ru_domains = false;
            new_settings.routing.split_tunnel_mode = SplitTunnelMode::AllVpn;
        }
        RoutingProfile::RuDirect => {
            new_settings.routing.bypass_ru_domains = true;
            new_settings.routing.split_tunnel_mode = SplitTunnelMode::AllVpn;
        }
        RoutingProfile::BypassApps => {
            new_settings.routing.split_tunnel_mode = SplitTunnelMode::BypassApps;
        }
        RoutingProfile::OnlyApps => {
            new_settings.routing.split_tunnel_mode = SplitTunnelMode::OnlyApps;
        }
        RoutingProfile::Custom => {}
    }

    for rule in &new_settings.routing.custom_rules {
        validate_routing_rule(rule)?;
    }

    match new_settings.device_hwid.as_deref().map(str::trim) {
        None | Some("") => {
            new_settings.device_hwid = Some(hwid::generate_default_hwid());
        }
        Some(val) => {
            new_settings.device_hwid = Some(hwid::validate_hwid(val)?);
        }
    }

    Ok(new_settings)
}

fn network_settings_changed(prev: &AppSettings, next: &AppSettings) -> bool {
    prev.connection_mode != next.connection_mode
        || prev.http_port != next.http_port
        || prev.socks_port != next.socks_port
        || prev.ipv6_enabled != next.ipv6_enabled
        || prev.log_level != next.log_level
        || prev.connect_timeout_secs != next.connect_timeout_secs
        || serde_json::to_value(&prev.routing).ok() != serde_json::to_value(&next.routing).ok()
        || serde_json::to_value(&prev.dns).ok() != serde_json::to_value(&next.dns).ok()
        || serde_json::to_value(&prev.tun).ok() != serde_json::to_value(&next.tun).ok()
        || serde_json::to_value(&prev.advanced).ok() != serde_json::to_value(&next.advanced).ok()
}

#[tauri::command]
pub async fn update_settings(
    new_settings: AppSettings,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AppSettings, String> {
    let validated = normalize_and_validate_settings(new_settings)?;

    if let Err(err) = sync_autostart(validated.autostart, validated.start_minimized) {
        state.logger.warn("windows", &err);
        return Err(err);
    }

    let need_reconnect = {
        let mut guard = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        let changed = network_settings_changed(&guard, &validated);
        *guard = validated.clone();
        state.storage.save_settings(&guard)?;
        changed && is_active_status(state.core.snapshot().status)
    };

    if let Some(win) = app.get_webview_window("main") {
        apply_window_background_style(
            &win,
            validated.background_style,
            resolve_is_dark(&validated),
        );
    }
    state.core.sync_kill_switch_live(&validated).await;

    state
        .logger
        .info("settings", "Настройки приложения сохранены");

    if need_reconnect {
        state.logger.info(
            "core",
            "Применение изменённых сетевых параметров — перезапуск активного туннеля...",
        );
        if let Err(err) = connect_internal(&app, &state, None).await {
            state.logger.warn(
                "core",
                &format!("Переподключение после изменения настроек: {err}"),
            );
        }
    }

    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    state.tray.update_from_state(&app);
    Ok(validated)
}

#[tauri::command]
pub fn set_window_background_style(
    style: BackgroundStyle,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AppSettings, String> {
    let saved = {
        let mut guard = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        guard.background_style = style;
        state.storage.save_settings(&guard)?;
        guard.clone()
    };
    if let Some(win) = app.get_webview_window("main") {
        apply_window_background_style(&win, style, resolve_is_dark(&saved));
    }
    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    Ok(saved)
}

#[tauri::command]
pub async fn get_kill_switch_status(
    state: State<'_, AppState>,
) -> Result<KillSwitchSnapshot, String> {
    Ok(state.core.kill_switch_snapshot_now().await)
}

#[tauri::command]
pub async fn set_kill_switch_config(
    mut config: KillSwitchConfig,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    config.reconnect_attempts = config.reconnect_attempts.min(10);
    let updated_settings = {
        let mut guard = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        guard.kill_switch = config;
        guard.kill_switch_enabled = guard.kill_switch.mode != KillSwitchMode::Off;
        state.storage.save_settings(&guard)?;
        guard.clone()
    };
    state.core.sync_kill_switch_live(&updated_settings).await;
    state
        .needs_kill_switch_elevation
        .store(false, Ordering::Relaxed);
    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    state.tray.update_from_state(&app);
    Ok(boot)
}

#[tauri::command]
pub async fn emergency_recover_network(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<EmergencyRecoveryOutcome, String> {
    let report = state.core.emergency_recover_network().await;
    state
        .needs_kill_switch_elevation
        .store(report.needs_elevation, Ordering::Relaxed);
    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    state.tray.update_from_state(&app);
    Ok(EmergencyRecoveryOutcome {
        report,
        state: boot,
    })
}

#[tauri::command]
pub async fn check_ip_monitor(
    include_ipv6: bool,
    provider: Option<IpProviderId>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<IpMonitorState, String> {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let next = state
        .core
        .check_ip_monitor(&settings, include_ipv6, provider)
        .await?;
    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    Ok(next)
}

#[tauri::command]
pub fn set_ip_mask(mask_ip: bool, app: AppHandle, state: State<'_, AppState>) -> IpMonitorState {
    let next = state.core.set_ip_mask(mask_ip);
    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    next
}

#[tauri::command]
pub async fn get_protection_center(
    state: State<'_, AppState>,
) -> Result<ProtectionCenterSnapshot, String> {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    Ok(state.core.build_protection_center(&settings).await)
}

#[tauri::command]
pub fn analyze_server_profile(
    id: String,
    state: State<'_, AppState>,
) -> Result<ProfileAnalysisReport, String> {
    let profile = {
        let profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        profiles
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| "Сервер не найден".to_string())?
    };
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let diag = state.core.diagnostics();
    Ok(run_config_analysis(&profile, &settings, &diag))
}

#[tauri::command]
pub async fn apply_profile_overrides(
    id: String,
    mut overrides: ProfileOverrides,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    if let Some(mtu) = overrides.mtu {
        overrides.mtu = Some(mtu.clamp(1280, 1500));
    }
    if let Some(ref dns) = overrides.custom_dns {
        let valid = validate_dns_field(dns, "DNS профиля")?;
        overrides.custom_dns = if valid.is_empty() { None } else { Some(valid) };
    }
    if let Some(timeout) = overrides.connect_timeout_secs {
        overrides.connect_timeout_secs = Some(timeout.clamp(5, 30));
    }

    let is_empty_overrides = overrides.mtu.is_none()
        && overrides.custom_dns.is_none()
        && overrides.preferred_mode.is_none()
        && overrides.preferred_core.is_none()
        && overrides.mtu_mode.is_none()
        && overrides.dns_mode_override.is_none()
        && overrides.connect_timeout_secs.is_none()
        && overrides.mux_override.is_none();

    {
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let srv = profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| "Сервер не найден".to_string())?;
        srv.overrides = if is_empty_overrides {
            None
        } else {
            Some(overrides)
        };
        state.storage.save_profiles(&profiles)?;
    }

    let snap = state.core.snapshot();
    if is_active_status(snap.status) && snap.active_server_id.as_deref() == Some(&id) {
        let _ = connect_internal(&app, &state, Some(id)).await;
    }

    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    state.tray.update_from_state(&app);
    Ok(boot)
}

#[tauri::command]
pub fn get_windows_accent_color() -> Option<String> {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(dwm) = hkcu.open_subkey_with_flags("Software\\Microsoft\\Windows\\DWM", KEY_READ)
        {
            if let Ok(abgr) = dwm.get_value::<u32, _>("AccentColor") {
                let r = abgr & 0xff;
                let g = (abgr >> 8) & 0xff;
                let b = (abgr >> 16) & 0xff;
                return Some(format!("#{r:02x}{g:02x}{b:02x}"));
            }
            if let Ok(argb) = dwm.get_value::<u32, _>("ColorizationColor") {
                let r = (argb >> 16) & 0xff;
                let g = (argb >> 8) & 0xff;
                let b = argb & 0xff;
                return Some(format!("#{r:02x}{g:02x}{b:02x}"));
            }
        }
    }
    None
}

#[tauri::command]
pub fn toggle_favorite_server(
    id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    {
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let srv = profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| "Сервер не найден".to_string())?;
        srv.favorite = !srv.favorite;
        state.storage.save_profiles(&profiles)?;
    }
    state.tray.update_from_state(&app);
    Ok(state.build_bootstrap())
}

#[tauri::command]
pub fn rename_subscription(
    id: String,
    title: String,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    let clean = title.trim();
    if clean.is_empty() {
        return Err("Название подписки не может быть пустым".to_string());
    }
    if clean.chars().count() > 120 {
        return Err("Название подписки не должно превышать 120 символов".to_string());
    }
    {
        let mut subs = state
            .subscriptions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let sub = subs
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or_else(|| "Подписка не найдена".to_string())?;
        sub.title = clean.to_string();
        state.storage.save_subscriptions(&subs)?;
    }
    Ok(state.build_bootstrap())
}

#[tauri::command]
pub fn toggle_subscription_enabled(
    id: String,
    enabled: bool,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    {
        let mut subs = state
            .subscriptions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let sub = subs
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or_else(|| "Подписка не найдена".to_string())?;
        sub.enabled = enabled;
        state.storage.save_subscriptions(&subs)?;
    }
    state.tray.update_from_state(&app);
    Ok(state.build_bootstrap())
}

#[tauri::command]
pub fn update_subscription_config(
    id: String,
    auto_update: bool,
    update_interval_hours: Option<u32>,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    {
        let mut subs = state
            .subscriptions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let sub = subs
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or_else(|| "Подписка не найдена".to_string())?;
        sub.auto_update = auto_update;
        sub.update_interval_hours = update_interval_hours.map(|h| h.clamp(1, 168));
        state.storage.save_subscriptions(&subs)?;
    }
    Ok(state.build_bootstrap())
}

#[tauri::command]
pub fn get_rulepack_status(state: State<'_, AppState>) -> RulepackStatus {
    let xray_dir = state.core.xray_resource_dir();
    build_rulepack_status(state.storage.base_dir(), xray_dir.as_deref())
}

#[tauri::command]
pub async fn update_rulepack(
    url: Option<String>,
    state: State<'_, AppState>,
) -> Result<RulepackStatus, String> {
    let ks_snap = state.core.kill_switch_snapshot_now().await;
    if ks_snap.blocking_active {
        return Err("Обновление базы правил заблокировано активным Kill Switch.".to_string());
    }
    let validated_candidate = match url {
        Some(ref u) => normalize_optional_https_url(Some(u.clone()), "URL базы правил")?,
        None => None,
    };
    let resolved_url =
        {
            let mut guard = state.settings.lock().unwrap_or_else(|p| p.into_inner());
            if url.is_some() {
                guard.routing.rulepack_update_url = validated_candidate;
                let _ = state.storage.save_settings(&guard);
            }
            guard.routing.rulepack_update_url.clone().ok_or_else(|| {
                "Укажите HTTPS URL для загрузки обновления базы правил".to_string()
            })?
        };

    let pack = update_rulepack_from_url(state.storage.base_dir(), &resolved_url).await?;
    state.core.reload_rulepack();
    state.logger.info(
        "routing",
        &format!(
            "База российских сервисов обновлена до версии {}",
            pack.version
        ),
    );
    let xray_dir = state.core.xray_resource_dir();
    Ok(build_rulepack_status(
        state.storage.base_dir(),
        xray_dir.as_deref(),
    ))
}

#[tauri::command]
pub fn rollback_rulepack(state: State<'_, AppState>) -> Result<RulepackStatus, String> {
    let pack = rb_rulepack(state.storage.base_dir())?;
    state.core.reload_rulepack();
    state.logger.info(
        "routing",
        &format!("Выполнен откат базы правил к версии {}", pack.version),
    );
    let xray_dir = state.core.xray_resource_dir();
    Ok(build_rulepack_status(
        state.storage.base_dir(),
        xray_dir.as_deref(),
    ))
}

#[tauri::command]
pub fn test_route(
    query: String,
    process: Option<String>,
    state: State<'_, AppState>,
) -> Result<RouteTestResult, String> {
    if query.trim().is_empty() {
        return Err("Введите домен, URL или IP-адрес для проверки маршрута".to_string());
    }
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let pack = state.core.rulepack_snapshot();
    Ok(evaluate_route(
        &query,
        process.as_deref(),
        &settings.routing,
        settings.connection_mode,
        &pack,
    ))
}

#[tauri::command]
pub async fn dns_lookup_route(
    domain: String,
    state: State<'_, AppState>,
) -> Result<DnsRouteCheckResult, String> {
    let ks_snap = state.core.kill_switch_snapshot_now().await;
    let snap = state.core.snapshot();
    if ks_snap.blocking_active
        || (snap.status != ConnectionStatus::Connected && snap.kill_switch_engaged)
    {
        return Err("Прямой DNS-запрос заблокирован активным Kill Switch.".to_string());
    }
    let trimmed = domain.trim();
    let without_scheme = if let Some((_, rest)) = trimmed.split_once("://") {
        rest
    } else {
        trimmed
    };
    let host_raw = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim();

    let clean = reqwest::Url::parse(&format!("https://{host_raw}"))
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_default();

    if clean.is_empty()
        || clean.len() > 253
        || !clean
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err("Укажите корректный домен для DNS-проверки".to_string());
    }
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host((clean.clone(), 443)),
    )
    .await;
    match res {
        Ok(Ok(addrs)) => {
            let mut ips: Vec<String> = Vec::new();
            for addr in addrs {
                let s = addr.ip().to_string();
                if !ips.contains(&s) {
                    ips.push(s);
                }
                if ips.len() >= 12 {
                    break;
                }
            }
            Ok(DnsRouteCheckResult {
                domain: clean,
                resolved_ips: ips,
                error: None,
            })
        }
        Ok(Err(e)) => Ok(DnsRouteCheckResult {
            domain: clean,
            resolved_ips: vec![],
            error: Some(format!("DNS не разрешил домен: {e}")),
        }),
        Err(_) => Ok(DnsRouteCheckResult {
            domain: clean,
            resolved_ips: vec![],
            error: Some("Таймаут DNS-запроса (5 сек)".to_string()),
        }),
    }
}

#[tauri::command]
pub async fn probe_active_connection(
    state: State<'_, AppState>,
) -> Result<ProxyProbeResult, String> {
    state.core.probe_active_connection().await
}

#[tauri::command]
pub async fn run_network_diagnostics(
    include_external_ip: bool,
    state: State<'_, AppState>,
) -> Result<DiagnosticsReport, String> {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let active_profile = {
        let profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        settings
            .active_server_id
            .as_ref()
            .and_then(|aid| profiles.iter().find(|p| &p.id == aid).cloned())
    };
    Ok(state
        .core
        .run_network_diagnostics(&settings, active_profile.as_ref(), include_external_ip)
        .await)
}

#[tauri::command]
pub fn get_connection_history(state: State<'_, AppState>) -> ConnectionHistoryResponse {
    state.core.connection_history_response()
}

#[tauri::command]
pub fn clear_connection_history(
    state: State<'_, AppState>,
) -> Result<ConnectionHistoryResponse, String> {
    state.core.clear_connection_history()?;
    Ok(state.core.connection_history_response())
}

#[tauri::command]
pub fn export_diagnostics_bundle(state: State<'_, AppState>) -> Result<String, String> {
    let mut diag = state.core.diagnostics();
    diag.core_path = redact_secrets(&diag.core_path);
    diag.config_dir = redact_secrets(&diag.config_dir);
    diag.active_proxy_endpoint = diag.active_proxy_endpoint.map(|s| redact_secrets(&s));
    diag.integrity_note = diag.integrity_note.map(|s| redact_secrets(&s));
    let mut snap = state.core.snapshot();
    snap.error_message = snap.error_message.map(|m| redact_secrets(&m));
    snap.kill_switch.last_reason = snap.kill_switch.last_reason.map(|r| redact_secrets(&r));
    snap.health.reason = snap.health.reason.map(|r| redact_secrets(&r));
    if let Some(ref mut info) = snap.error_info {
        info.message = redact_secrets(&info.message);
    }
    let logs: Vec<LogEntry> = state
        .logger
        .list()
        .into_iter()
        .map(|mut l| {
            l.message = redact_secrets(&l.message);
            l
        })
        .collect();
    let xray_dir = state.core.xray_resource_dir();
    let mut rulepack = build_rulepack_status(state.storage.base_dir(), xray_dir.as_deref());
    rulepack.source = redact_secrets(&rulepack.source);
    let bundle = serde_json::json!({
        "appVersion": env!("CARGO_PKG_VERSION"),
        "exportedAt": Utc::now().to_rfc3339(),
        "diagnostics": diag,
        "connection": snap,
        "rulepack": rulepack,
        "logs": logs,
    });
    serde_json::to_string_pretty(&bundle).map_err(|e| format!("Ошибка экспорта диагностики: {e}"))
}

#[tauri::command]
pub fn export_settings_backup(state: State<'_, AppState>) -> Result<String, String> {
    let mut settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    // Never export unique per-device HWID into shareable JSON backups
    settings.device_hwid = None;
    serde_json::to_string_pretty(&settings)
        .map_err(|e| format!("Ошибка резервного копирования настроек: {e}"))
}

#[tauri::command]
pub async fn import_settings_backup(
    raw_json: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<AppSettings, String> {
    if raw_json.len() > 256 * 1024 {
        return Err("Файл настроек превышает лимит 256 КБ".to_string());
    }
    let parsed: AppSettings = serde_json::from_str(&raw_json)
        .map_err(|_| "Файл настроек повреждён или имеет неверный формат JSON".to_string())?;
    let mut validated = normalize_and_validate_settings(parsed)?;

    let (need_reconnect, saved) = {
        let mut guard = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        // Preserve per-device HWID & autostart; strip external feed/rulepack URLs from untrusted backups
        validated.device_hwid = guard.device_hwid.clone();
        validated.autostart = guard.autostart;
        validated.update_feed_url = None;
        validated.routing.rulepack_update_url = None;

        let changed = network_settings_changed(&guard, &validated);
        *guard = validated.clone();
        state.storage.save_settings(&guard)?;
        (
            changed && is_active_status(state.core.snapshot().status),
            validated,
        )
    };

    if let Some(win) = app.get_webview_window("main") {
        apply_window_background_style(&win, saved.background_style, resolve_is_dark(&saved));
    }
    state.core.sync_kill_switch_live(&saved).await;

    if need_reconnect {
        let _ = connect_internal(&app, &state, None).await;
    }

    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    state.tray.update_from_state(&app);
    state.logger.info(
        "settings",
        "Настройки восстановлены из резервной копии (без перезаписи HWID, автозапуска и URL фидов)",
    );
    Ok(saved)
}

#[tauri::command]
pub async fn reset_settings_to_default(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    let reset_copy = {
        let mut guard = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        let preserved_server = guard.active_server_id.clone();
        let preserved_hwid = guard.device_hwid.clone();
        let reset = AppSettings {
            active_server_id: preserved_server,
            device_hwid: preserved_hwid.or_else(|| Some(hwid::generate_default_hwid())),
            onboarding_completed: true,
            ..AppSettings::default()
        };
        sync_autostart(reset.autostart, reset.start_minimized)?;
        *guard = reset.clone();
        state.storage.save_settings(&guard)?;
        reset
    };
    if let Some(win) = app.get_webview_window("main") {
        apply_window_background_style(
            &win,
            reset_copy.background_style,
            resolve_is_dark(&reset_copy),
        );
    }
    state.core.sync_kill_switch_live(&reset_copy).await;

    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    state.tray.update_from_state(&app);
    state
        .logger
        .info("settings", "Настройки сброшены на значения по умолчанию");
    Ok(boot)
}

#[tauri::command]
pub fn get_elevation_status() -> bool {
    is_elevated()
}

#[tauri::command]
pub fn relaunch_as_admin(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    os_relaunch_as_admin()?;
    state.core.blocking_cleanup_on_exit();
    app.exit(0);
    Ok(())
}

#[tauri::command]
pub async fn set_always_admin(
    enabled: bool,
    relaunch_now: bool,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreDiagnostics, String> {
    crate::elevation::set_always_admin(enabled)?;
    let (autostart, start_minimized) = {
        let guard = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        (guard.autostart, guard.start_minimized)
    };
    if let Err(err) = sync_autostart(autostart, start_minimized) {
        state.logger.warn("windows", &err);
    }
    state.core.invalidate_diagnostics_cache();
    let diag = state.core.diagnostics();
    state.logger.info(
        "windows",
        if enabled {
            "Постоянный запуск от имени администратора (RUNASADMIN) включён"
        } else {
            "Постоянный запуск от имени администратора (RUNASADMIN) отключён"
        },
    );
    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    state.tray.update_from_state(&app);
    if relaunch_now && enabled && !is_elevated() {
        os_relaunch_as_admin()?;
        state.core.blocking_cleanup_on_exit();
        app.exit(0);
    }
    Ok(diag)
}

#[tauri::command]
pub async fn check_for_updates(state: State<'_, AppState>) -> Result<UpdateCheckResult, String> {
    let ks_snap = state.core.kill_switch_snapshot_now().await;
    if ks_snap.blocking_active {
        return Err(
            "Проверка обновлений приложения заблокирована активным Kill Switch.".to_string(),
        );
    }
    let (feed, channel) = {
        let guard = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        (guard.update_feed_url.clone(), guard.update_channel)
    };
    let res = fetch_update_status(feed.as_deref(), channel).await;
    state.logger.info("updater", &res.message);
    Ok(res)
}

#[tauri::command]
pub fn get_logs(state: State<'_, AppState>) -> Vec<LogEntry> {
    state.logger.list()
}

#[tauri::command]
pub fn clear_logs(state: State<'_, AppState>) {
    state.logger.clear();
}

#[tauri::command]
pub fn get_diagnostics(state: State<'_, AppState>) -> CoreDiagnostics {
    state.core.diagnostics()
}

#[tauri::command]
pub fn window_minimize(app: AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.minimize();
    }
}

#[tauri::command]
pub fn window_close_action(app: AppHandle, state: State<'_, AppState>) {
    let minimize_to_tray = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .minimize_to_tray;
    if minimize_to_tray {
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.hide();
        }
    } else {
        state.core.blocking_cleanup_on_exit();
        app.exit(0);
    }
}

#[tauri::command]
pub fn get_window_mode_state(state: State<'_, AppState>) -> WindowModeState {
    let ws = state.window_state.lock().unwrap_or_else(|p| p.into_inner());
    WindowModeState {
        mini_mode: ws.mini_mode,
        always_on_top: ws.always_on_top,
    }
}

#[tauri::command]
pub fn set_mini_mode(
    enabled: bool,
    always_on_top: Option<bool>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<WindowModeState, String> {
    let mut ws = state.window_state.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(win) = app.get_webview_window("main") {
        apply_mini_mode_transition(&win, &mut ws, enabled, always_on_top);
    } else {
        ws.mini_mode = enabled;
        if let Some(aot) = always_on_top {
            ws.always_on_top = aot;
        }
    }
    save_window_state(state.storage.base_dir(), &ws);
    Ok(WindowModeState {
        mini_mode: ws.mini_mode,
        always_on_top: ws.always_on_top,
    })
}

#[tauri::command]
pub fn set_always_on_top(
    enabled: bool,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<WindowModeState, String> {
    let mut ws = state.window_state.lock().unwrap_or_else(|p| p.into_inner());
    ws.always_on_top = enabled;
    if ws.mini_mode {
        if let Some(win) = app.get_webview_window("main") {
            let _ = win.set_always_on_top(enabled);
        }
    }
    save_window_state(state.storage.base_dir(), &ws);
    Ok(WindowModeState {
        mini_mode: ws.mini_mode,
        always_on_top: ws.always_on_top,
    })
}

#[tauri::command]
pub async fn bulk_delete_servers(
    ids: Vec<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    if ids.is_empty() {
        return Ok(state.build_bootstrap());
    }
    let id_set: std::collections::HashSet<String> = ids.into_iter().collect();
    let active_deleted = {
        let settings = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        let snap_id = state.core.snapshot().active_server_id;
        settings
            .active_server_id
            .as_ref()
            .is_some_and(|aid| id_set.contains(aid))
            || snap_id.as_ref().is_some_and(|aid| id_set.contains(aid))
    };
    if active_deleted && is_active_status(state.core.snapshot().status) {
        let _ = disconnect_internal(&app, &state).await;
    }

    let removed_count = {
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let before = profiles.len();
        profiles.retain(|p| !id_set.contains(&p.id));
        let removed = before.saturating_sub(profiles.len());
        state.storage.save_profiles(&profiles)?;

        if active_deleted {
            let mut settings = state.settings.lock().unwrap_or_else(|p| p.into_inner());
            settings.active_server_id = profiles.first().map(|p| p.id.clone());
            let _ = state.storage.save_settings(&settings);
        }
        removed
    };

    state
        .logger
        .info("servers", &format!("Удалено серверов: {removed_count}"));
    state.tray.update_from_state(&app);
    Ok(state.build_bootstrap())
}

#[tauri::command]
pub fn bulk_set_favorite_servers(
    ids: Vec<String>,
    favorite: bool,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    if ids.is_empty() {
        return Ok(state.build_bootstrap());
    }
    let id_set: std::collections::HashSet<String> = ids.into_iter().collect();
    {
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        for p in profiles.iter_mut() {
            if id_set.contains(&p.id) {
                p.favorite = favorite;
            }
        }
        state.storage.save_profiles(&profiles)?;
    }
    state.tray.update_from_state(&app);
    Ok(state.build_bootstrap())
}

// ===== v0.8.0 Core Manager, DNS, TUN, Inspector, Config Studio, Doctor & Privacy Commands =====

fn extract_addr_port_from_outbound(ob: &serde_json::Value) -> Option<(String, u16)> {
    let s = ob.get("settings")?;
    if let Some(v) = s
        .get("vnext")
        .and_then(|x| x.as_array())
        .and_then(|a| a.first())
    {
        let addr = v.get("address")?.as_str()?.to_string();
        let port = u16::try_from(v.get("port")?.as_u64()?).ok()?;
        return Some((addr, port));
    }
    if let Some(srv) = s
        .get("servers")
        .and_then(|x| x.as_array())
        .and_then(|a| a.first())
    {
        let addr = srv.get("address")?.as_str()?.to_string();
        let port = u16::try_from(srv.get("port")?.as_u64()?).ok()?;
        return Some((addr, port));
    }
    if let (Some(addr), Some(port_u64)) = (
        s.get("address").and_then(|x| x.as_str()),
        s.get("port").and_then(|x| x.as_u64()),
    ) {
        let port = u16::try_from(port_u64).ok()?;
        return Some((addr.to_string(), port));
    }
    None
}

#[tauri::command]
pub fn get_core_inventory(state: State<'_, AppState>) -> CoreInventorySnapshot {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let diag = state.core.diagnostics_cached();
    let xray = state.core.find_xray_path_pub();
    let awg = state.core.find_awg_path_pub();
    build_core_inventory(&settings, &diag, xray.as_deref(), awg.as_deref())
}

#[tauri::command]
pub fn verify_core_integrity(state: State<'_, AppState>) -> CoreDiagnostics {
    state.core.invalidate_diagnostics_cache();
    let diag = state.core.diagnostics_cached();
    state.logger.info(
        "core",
        &format!(
            "Проверка SHA-256 ядер: xray={}, awg={}, wintun={}",
            diag.core_integrity_ok, diag.awg_integrity_ok, diag.wintun_integrity_ok
        ),
    );
    diag
}

#[tauri::command]
pub async fn check_core_updates(
    kind: CoreKind,
    state: State<'_, AppState>,
) -> Result<CoreUpdateCheckResult, String> {
    let ks_snap = state.core.kill_switch_snapshot_now().await;
    if ks_snap.blocking_active {
        return Err("Проверка обновлений ядра заблокирована активным Kill Switch.".to_string());
    }
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let diag = state.core.diagnostics_cached();
    let xray = state.core.find_xray_path_pub();
    let awg = state.core.find_awg_path_pub();
    let inv = build_core_inventory(&settings, &diag, xray.as_deref(), awg.as_deref());
    let current_version = inv
        .cores
        .iter()
        .find(|c| c.kind == kind)
        .map(|c| c.version.clone())
        .unwrap_or_default();
    let is_active = is_active_status(state.core.snapshot().status);
    Ok(check_core_updates_online(kind, current_version, is_active).await)
}

#[tauri::command]
pub fn get_dns_inspector_report(state: State<'_, AppState>) -> DnsInspectorReport {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let snap = state.core.snapshot();
    let active_profile = {
        let profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        snap.active_server_id
            .as_ref()
            .or(settings.active_server_id.as_ref())
            .and_then(|aid| profiles.iter().find(|p| &p.id == aid).cloned())
    };
    let pack = state.core.rulepack_snapshot();
    build_dns_inspector_report(&settings, active_profile.as_ref(), &snap, &pack, None)
}

#[tauri::command]
pub async fn test_dns_server(
    server: String,
    domain: Option<String>,
    state: State<'_, AppState>,
) -> Result<DnsServerTestResult, String> {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let snap = state.core.snapshot();
    Ok(test_dns_server_live(&server, domain.as_deref(), &snap, &settings).await)
}

#[tauri::command]
pub async fn run_dns_inspector_lookup(
    domain: String,
    state: State<'_, AppState>,
) -> Result<DnsLiveLookupResult, String> {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let snap = state.core.snapshot();
    Ok(run_dns_lookup_honest(&domain, &settings, &snap).await)
}

#[tauri::command]
pub fn get_tun_status(state: State<'_, AppState>) -> TunManagerSnapshot {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let diag = state.core.diagnostics_cached();
    collect_tun_snapshot(&settings.tun, &diag)
}

#[tauri::command]
pub fn detect_tun_conflicts(state: State<'_, AppState>) -> Vec<VirtualAdapterConflict> {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let diag = state.core.diagnostics_cached();
    collect_tun_snapshot(&settings.tun, &diag).conflicts
}

#[tauri::command]
pub async fn get_connection_inspector(
    state: State<'_, AppState>,
) -> Result<ConnectionInspectorSnapshot, String> {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let snap = state.core.snapshot();
    let active_profile = {
        let profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        snap.active_server_id
            .as_ref()
            .or(settings.active_server_id.as_ref())
            .and_then(|aid| profiles.iter().find(|p| &p.id == aid).cloned())
    };
    Ok(state
        .core
        .inspector_snapshot(active_profile.as_ref(), &settings)
        .await)
}

#[tauri::command]
pub fn get_connection_timeline(state: State<'_, AppState>) -> Vec<ConnectionTimelineEvent> {
    state.core.inspector.timeline_snapshot()
}

#[tauri::command]
pub fn clear_connection_timeline(state: State<'_, AppState>) -> Vec<ConnectionTimelineEvent> {
    state.core.inspector.clear_timeline();
    Vec::new()
}

#[tauri::command]
pub fn get_config_studio_view(
    id: String,
    reveal_secrets: bool,
    state: State<'_, AppState>,
) -> Result<ConfigStudioView, String> {
    let profile = {
        let profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        profiles
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| "Сервер не найден".to_string())?
    };
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let pack = state.core.rulepack_snapshot();
    Ok(build_config_studio_view(
        &profile,
        &settings,
        &pack,
        &state.storage,
        !reveal_secrets,
    ))
}

#[tauri::command]
pub async fn validate_custom_profile_config(
    id: String,
    raw_json: String,
    state: State<'_, AppState>,
) -> Result<ConfigValidationResult, String> {
    {
        let profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        if !profiles.iter().any(|p| p.id == id) {
            return Err("Сервер не найден".to_string());
        }
    }
    let xray = state.core.find_xray_path_pub();
    if let Some(ref xp) = xray {
        state.core.verify_xray_integrity(xp)?;
    }
    let (_, res) =
        validate_custom_outbound_json(&raw_json, xray.as_deref(), &state.storage.runtime_dir())
            .await?;
    Ok(res)
}

#[tauri::command]
pub async fn save_profile_config_edit(
    id: String,
    raw_json: String,
    note: Option<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    let xray = state.core.find_xray_path_pub();
    if let Some(ref xp) = xray {
        state.core.verify_xray_integrity(xp)?;
    }
    let (ob, validation) =
        validate_custom_outbound_json(&raw_json, xray.as_deref(), &state.storage.runtime_dir())
            .await?;
    if !validation.ok {
        return Err(validation
            .errors
            .first()
            .cloned()
            .unwrap_or_else(|| "Конфигурация не прошла проверку безопасности или Xray".into()));
    }

    let summary_note = note
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("Ручное редактирование outbound в Config Studio")
        .to_string();

    {
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let srv = profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| "Сервер не найден".to_string())?;

        let pre_snapshot = srv.clone();
        let rev = StoredProfileRevision {
            revision_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            note: summary_note.clone(),
            summary: format!("Ревизия до правки (rev #{})", pre_snapshot.config_revision),
            snapshot: pre_snapshot,
        };
        state.storage.append_profile_revision(&id, rev)?;

        if let Some((addr, port)) = extract_addr_port_from_outbound(&ob) {
            srv.address = addr;
            srv.port = port;
        }
        let proto_str = ob
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("raw_xray")
            .to_ascii_uppercase();
        srv.protocol = ProtocolType::RawXray;
        srv.details = ProtocolDetails::RawXray(RawXrayDetails {
            outbound_json: ob,
            label: format!("Custom {proto_str}"),
            extra_outbounds: vec![],
            balancers: vec![],
            observatory: None,
            burst_observatory: None,
            transport_summary: Some("Config Studio JSON".to_string()),
            node_count: Some(1),
        });
        srv.config_revision = srv.config_revision.saturating_add(1);
        srv.fingerprint_key = Some(compute_profile_fingerprint(srv));
        state.storage.save_profiles(&profiles)?;
    }

    let snap = state.core.snapshot();
    if is_active_status(snap.status) && snap.active_server_id.as_deref() == Some(&id) {
        let _ = connect_internal(&app, &state, Some(id.clone())).await;
    }

    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    state.tray.update_from_state(&app);
    state.logger.info("config_studio", &summary_note);
    Ok(boot)
}

#[tauri::command]
pub async fn rollback_profile_config(
    id: String,
    revision_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    let revisions = state.storage.load_profile_revisions(&id);
    let target_rev = revisions
        .into_iter()
        .find(|r| r.revision_id == revision_id)
        .ok_or_else(|| "Указанная ревизия профиля не найдена".to_string())?;

    {
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let srv = profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| "Сервер не найден".to_string())?;

        let pre_snapshot = srv.clone();
        let backup_rev = StoredProfileRevision {
            revision_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            note: "Перед откатом ревизии".to_string(),
            summary: format!("Снимок до отката (rev #{})", pre_snapshot.config_revision),
            snapshot: pre_snapshot,
        };
        let _ = state.storage.append_profile_revision(&id, backup_rev);

        let mut restored = target_rev.snapshot;
        restored.config_revision = srv.config_revision.saturating_add(1);
        *srv = restored;
        state.storage.save_profiles(&profiles)?;
    }

    let snap = state.core.snapshot();
    if is_active_status(snap.status) && snap.active_server_id.as_deref() == Some(&id) {
        let _ = connect_internal(&app, &state, Some(id.clone())).await;
    }

    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    state.tray.update_from_state(&app);
    state.logger.info(
        "config_studio",
        "Выполнен откат профиля к выбранной ревизии",
    );
    Ok(boot)
}

#[tauri::command]
pub fn duplicate_server_profile(
    id: String,
    custom_name: Option<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    {
        let mut profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        let src = profiles
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| "Сервер не найден".to_string())?;
        let mut copy = src;
        copy.id = uuid::Uuid::new_v4().to_string();
        let next_name = custom_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.chars().take(120).collect::<String>())
            .unwrap_or_else(|| format!("{} (копия)", copy.name).chars().take(120).collect());
        copy.name = next_name.clone();
        copy.custom_name = Some(next_name);
        copy.subscription_id = None;
        copy.favorite = false;
        copy.last_used_at = None;
        copy.created_at = Utc::now().to_rfc3339();
        copy.config_revision = 0;
        profiles.push(copy);
        state.storage.save_profiles(&profiles)?;
    }
    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    state.tray.update_from_state(&app);
    Ok(boot)
}

#[tauri::command]
pub async fn run_network_doctor(
    include_external_probes: bool,
    state: State<'_, AppState>,
) -> Result<NetworkDoctorReport, String> {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let snap = state.core.snapshot();
    let diag = state.core.diagnostics_cached();
    let active_profile = {
        let profiles = state.profiles.lock().unwrap_or_else(|p| p.into_inner());
        snap.active_server_id
            .as_ref()
            .or(settings.active_server_id.as_ref())
            .and_then(|aid| profiles.iter().find(|p| &p.id == aid).cloned())
    };
    let proxy_backup = state.storage.proxy_backup_path().exists();
    let ks_marker = state.storage.kill_switch_state_path().exists();
    Ok(run_network_doctor_suite(
        &settings,
        &snap,
        &diag,
        active_profile.as_ref(),
        proxy_backup,
        ks_marker,
        include_external_probes,
    )
    .await)
}

#[tauri::command]
pub fn get_privacy_inventory(state: State<'_, AppState>) -> PrivacyInventory {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let subs = state
        .subscriptions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let ip_mon = state.core.stored_ip_monitor_snapshot();
    let logs_count = state.logger.list().len();
    build_privacy_inventory(&state.storage, &settings, &subs, &ip_mon, logs_count)
}

#[tauri::command]
pub fn rotate_device_hwid(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BootstrapState, String> {
    let next_hwid = uuid::Uuid::new_v4().to_string();
    {
        let mut guard = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        guard.device_hwid = Some(next_hwid);
        state.storage.save_settings(&guard)?;
    }
    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    state
        .logger
        .info("privacy", "Идентификатор устройства (HWID) перевыпущен");
    Ok(boot)
}

#[tauri::command]
pub fn purge_privacy_data(
    scope: PrivacyPurgeScope,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<PrivacyPurgeReport, String> {
    let mut items_removed = 0usize;
    let mut parts = Vec::new();

    if scope.clear_history && state.core.clear_connection_history().is_ok() {
        items_removed += 1;
        parts.push("история сессий");
    }
    if scope.clear_original_ip {
        state.core.clear_original_ip();
        items_removed += 1;
        parts.push("сохранённый реальный IP");
    }
    if scope.clear_vpn_ip {
        state.core.clear_ip_monitor_cache();
        items_removed += 1;
        parts.push("кэш Мой IP");
    }
    if scope.clear_logs {
        state.logger.clear();
        items_removed += 1;
        parts.push("журнал событий");
    }
    if scope.clear_server_quality && state.core.clear_server_quality().is_ok() {
        items_removed += 1;
        parts.push("метрики качества узлов");
    }
    if scope.clear_sub_backups {
        let n = state.storage.clear_all_subscription_backups();
        items_removed += n;
        if n > 0 {
            parts.push("бэкапы подписок");
        }
    }
    if scope.clear_sync_history {
        let mut subs = state
            .subscriptions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        for s in subs.iter_mut() {
            items_removed += s.sync_history.len();
            s.sync_history.clear();
            s.error_history.clear();
        }
        let _ = state.storage.save_subscriptions(&subs);
        parts.push("журнал синхронизаций");
    }
    if scope.clear_profile_edit_history {
        let n = state.storage.clear_all_profile_revisions();
        items_removed += n;
        if n > 0 {
            parts.push("ревизии Config Studio");
        }
    }

    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    let summary = if parts.is_empty() {
        "Категории для очистки не выбраны.".to_string()
    } else {
        format!("Очищено: {}", parts.join(", "))
    };
    Ok(PrivacyPurgeReport {
        items_removed,
        summary,
    })
}

#[tauri::command]
pub fn set_ip_provider(
    provider: IpProviderId,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<IpMonitorState, String> {
    {
        let mut guard = state.settings.lock().unwrap_or_else(|p| p.into_inner());
        guard.preferred_ip_provider = provider;
        state.storage.save_settings(&guard)?;
    }
    let next = state.core.set_ip_provider(provider);
    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    Ok(next)
}

#[tauri::command]
pub fn clear_original_ip(app: AppHandle, state: State<'_, AppState>) -> IpMonitorState {
    let next = state.core.clear_original_ip();
    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    next
}

#[tauri::command]
pub fn clear_ip_monitor_cache(app: AppHandle, state: State<'_, AppState>) -> IpMonitorState {
    let next = state.core.clear_ip_monitor_cache();
    let boot = state.build_bootstrap();
    let _ = app.emit("bootstrap-sync", &boot);
    next
}

#[tauri::command]
pub fn get_subscription_sync_history(
    id: String,
    state: State<'_, AppState>,
) -> Result<Vec<SubscriptionSyncEntry>, String> {
    let subs = state
        .subscriptions
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let sub = subs
        .iter()
        .find(|s| s.id == id)
        .ok_or_else(|| "Подписка не найдена".to_string())?;
    Ok(sub.sync_history.clone())
}

#[tauri::command]
pub async fn run_server_speed_test(
    id: String,
    state: State<'_, AppState>,
) -> Result<SpeedTestResult, String> {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let snap = state.core.snapshot();
    if snap.active_server_id.as_deref() != Some(&id) {
        return Err("Подключитесь к выбранному серверу, чтобы выполнить ручной замер скорости через его туннель.".into());
    }
    state
        .core
        .run_speed_test_through_tunnel(id, &settings)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{RoutingRule, RuleAction, RuleMatchType};

    #[test]
    fn settings_validation_rejects_bad_urls_split_apps_and_disabled_rules() {
        let s = AppSettings {
            update_feed_url: Some("http://127.0.0.1/feed.json".to_string()),
            ..Default::default()
        };
        assert!(normalize_and_validate_settings(s).is_err());

        let mut s2 = AppSettings::default();
        s2.routing.split_apps.push("..\\evil.exe".to_string());
        assert!(normalize_and_validate_settings(s2).is_err());

        let mut s3 = AppSettings::default();
        s3.routing.custom_rules.push(RoutingRule {
            id: "r1".to_string(),
            enabled: false,
            match_type: RuleMatchType::Process,
            pattern: "C:\\bad\\app.exe".to_string(),
            action: RuleAction::Direct,
            note: None,
        });
        assert!(normalize_and_validate_settings(s3).is_err());

        let s4 = AppSettings {
            dns: crate::models::DnsConfig {
                mode: "auto".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let ok = normalize_and_validate_settings(s4).unwrap();
        assert_eq!(ok.dns.mode, "hybrid");
    }
}
