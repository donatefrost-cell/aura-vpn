pub mod autostart;
pub mod commands;
pub mod config_analyzer;
pub mod config_gen;
pub mod config_studio;
pub mod connection_inspector;
pub mod core_manager;
pub mod core_registry;
pub mod dns_manager;
pub mod elevation;
pub mod hwid;
pub mod ip_monitor;
pub mod kill_switch;
pub mod logger;
pub mod models;
pub mod net_fetch;
pub mod network_doctor;
pub mod parser;
pub mod privacy;
pub mod proxy_meter;
pub mod routing_rules;
pub mod storage;
pub mod subscription;
pub mod tray;
pub mod tun_manager;
pub mod updater;
pub mod window_state;
pub mod windows_proxy;

use commands::AppState;
use core_manager::CoreManager;
use logger::AppLogger;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use storage::AppStorage;
use tauri::{Manager, RunEvent, WindowEvent};
use tray::{setup_tray, show_main_window, TrayController};
use window_state::{
    apply_initial_window_state, apply_window_background_style, capture_live_window_geometry,
    flush_window_state_on_exit, load_window_state, save_window_state,
};

fn signal_wake_marker_if_present() {
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let dir = std::path::PathBuf::from(appdata).join("app.auravpn.desktop");
        if dir.is_dir() {
            let _ = std::fs::write(dir.join(".wake"), b"1");
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    signal_wake_marker_if_present();
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main_window(app);
        }))
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            let storage = AppStorage::new(app_data_dir.clone()).map_err(std::io::Error::other)?;
            storage.sweep_stale_runtime_files();

            let logger = Arc::new(AppLogger::new());
            logger.attach_app(app.handle().clone());

            let mut needs_kill_switch_elevation = false;
            match kill_switch::recover_kill_switch_if_dirty(&storage.kill_switch_state_path()) {
                Ok(true) => logger.warn(
                    "security",
                    "Обнаружена активная блокировка Kill Switch от прошлой сессии — доступ в сеть восстановлен",
                ),
                Ok(false) => {}
                Err(err) => {
                    logger.error("security", &err);
                    needs_kill_switch_elevation = true;
                }
            }

            match windows_proxy::recover_if_dirty(&storage.proxy_backup_path()) {
                Ok(true) => logger.warn(
                    "windows",
                    "Обнаружены незавершённые настройки прокси от прошлой сессии — параметры Windows восстановлены",
                ),
                Ok(false) => {}
                Err(err) => logger.error("windows", &err),
            }

            let profiles_legacy = storage.is_plaintext_legacy("profiles.json");
            let profiles = storage.load_profiles();
            if profiles_legacy && !profiles.is_empty() {
                let _ = storage.save_profiles(&profiles);
            }
            let subs_legacy = storage.is_plaintext_legacy("subscriptions.json");
            let subscriptions = storage.load_subscriptions();
            if subs_legacy && !subscriptions.is_empty() {
                let _ = storage.save_subscriptions(&subscriptions);
            }
            let mut settings = storage.load_settings();
            let mut settings_dirty = false;

            if settings.kill_switch_enabled
                && settings.kill_switch.mode == models::KillSwitchMode::Off
            {
                settings.kill_switch.mode = models::KillSwitchMode::OnDrop;
                settings_dirty = true;
            } else if settings.kill_switch.mode != models::KillSwitchMode::Off
                && !settings.kill_switch_enabled
            {
                settings.kill_switch_enabled = true;
                settings_dirty = true;
            }

            if settings.dns.mode.eq_ignore_ascii_case("auto") {
                settings.dns.mode = "hybrid".to_string();
                settings_dirty = true;
            }

            if settings.routing.bypass_ru_domains
                && settings.routing.profile == models::RoutingProfile::AllVpn
            {
                settings.routing.profile = models::RoutingProfile::RuDirect;
                settings_dirty = true;
            } else if settings.routing.split_tunnel_mode == models::SplitTunnelMode::BypassApps
                && settings.routing.profile == models::RoutingProfile::AllVpn
            {
                settings.routing.profile = models::RoutingProfile::BypassApps;
                settings_dirty = true;
            } else if settings.routing.split_tunnel_mode == models::SplitTunnelMode::OnlyApps
                && settings.routing.profile == models::RoutingProfile::AllVpn
            {
                settings.routing.profile = models::RoutingProfile::OnlyApps;
                settings_dirty = true;
            }

            // Existing-user migration: skip first-run onboarding if profiles/subscriptions already exist
            if (!profiles.is_empty() || !subscriptions.is_empty()) && !settings.onboarding_completed {
                settings.onboarding_completed = true;
                settings_dirty = true;
            }

            let needs_hwid = settings
                .device_hwid
                .as_deref()
                .and_then(|raw| hwid::validate_hwid(raw).ok())
                .is_none();
            if needs_hwid {
                settings.device_hwid = Some(hwid::generate_default_hwid());
                settings_dirty = true;
            } else if let Some(valid) = settings
                .device_hwid
                .as_deref()
                .and_then(|raw| hwid::validate_hwid(raw).ok())
            {
                if settings.device_hwid.as_deref() != Some(valid.as_str()) {
                    settings.device_hwid = Some(valid);
                    settings_dirty = true;
                }
            }

            if settings_dirty {
                let _ = storage.save_settings(&settings);
            }

            let core = Arc::new(CoreManager::new(storage.clone(), logger.clone()));
            core.attach_app(app.handle().clone());
            let initial_ws = load_window_state(storage.base_dir());

            let state = AppState {
                storage,
                logger: logger.clone(),
                core,
                tray: TrayController::new(),
                profiles: Mutex::new(profiles),
                subscriptions: Mutex::new(subscriptions),
                settings: Mutex::new(settings.clone()),
                window_state: Mutex::new(initial_ws.clone()),
                needs_kill_switch_elevation: AtomicBool::new(needs_kill_switch_elevation),
                sub_refresh_locks: Mutex::new(HashMap::new()),
                ping_lock: Arc::new(tokio::sync::Mutex::new(())),
            };

            app.manage(state);
            setup_tray(app.handle())?;

            let launched_minimized = std::env::args().any(|arg| arg == "--minimized");
            if let Some(win) = app.get_webview_window("main") {
                apply_initial_window_state(&win, &initial_ws);
                apply_window_background_style(
                    &win,
                    settings.background_style,
                    commands::resolve_is_dark(&settings),
                );
                if (launched_minimized || settings.start_minimized) && settings.minimize_to_tray {
                    let _ = win.hide();
                } else {
                    let _ = win.show();
                    let _ = win.set_focus();
                }
            }

            {
                let wake_path = app_data_dir.join(".wake");
                let _ = std::fs::remove_file(&wake_path);
                let handle = app.handle().clone();
                let settings_boot = settings.clone();
                let should_autoconnect = settings.auto_connect_on_launch
                    && settings.active_server_id.is_some()
                    && !needs_kill_switch_elevation;
                tauri::async_runtime::spawn(async move {
                    if let Some(st) = handle.try_state::<AppState>() {
                        st.core.sync_kill_switch_live(&settings_boot).await;
                        if should_autoconnect {
                            let _ = commands::connect_internal(&handle, &st, None).await;
                        }
                    }
                });
                let wake_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                        if wake_path.exists() {
                            let _ = std::fs::remove_file(&wake_path);
                            show_main_window(&wake_handle);
                        }
                    }
                });
                let sub_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                        let Some(st) = sub_handle.try_state::<AppState>() else {
                            continue;
                        };
                        if st.core.snapshot().kill_switch.blocking_active {
                            continue;
                        }
                        let due_ids: Vec<String> = {
                            let subs = st.subscriptions.lock().unwrap_or_else(|p| p.into_inner());
                            let now = chrono::Utc::now();
                            subs.iter()
                                .filter(|s| s.enabled && s.auto_update && !s.url.trim().is_empty())
                                .filter(|s| {
                                    let interval_h = s.update_interval_hours.unwrap_or(24).clamp(1, 168) as i64;
                                    chrono::DateTime::parse_from_rfc3339(&s.updated_at)
                                        .map(|dt| {
                                            dt.with_timezone(&chrono::Utc)
                                                + chrono::Duration::hours(interval_h)
                                                <= now
                                        })
                                        .unwrap_or(false)
                                })
                                .map(|s| s.id.clone())
                                .collect()
                        };
                        for sid in due_ids {
                            if st.core.snapshot().kill_switch.blocking_active {
                                break;
                            }
                            let _ = commands::refresh_subscription_inner(sid, &sub_handle, &st).await;
                        }
                    }
                });
            }

            logger.info("app", "AURA VPN готов к работе");
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() == "main" {
                match event {
                    WindowEvent::Moved(_) | WindowEvent::Resized(_) => {
                        let app = window.app_handle();
                        if let Some(state) = app.try_state::<AppState>() {
                            if let Some(win) = app.get_webview_window("main") {
                                let mut ws = state.window_state.lock().unwrap_or_else(|p| p.into_inner());
                                capture_live_window_geometry(&win, &mut ws);
                            }
                        }
                    }
                    WindowEvent::CloseRequested { api, .. } => {
                        let app = window.app_handle();
                        if let Some(state) = app.try_state::<AppState>() {
                            {
                                let mut ws = state.window_state.lock().unwrap_or_else(|p| p.into_inner());
                                if let Some(win) = app.get_webview_window("main") {
                                    capture_live_window_geometry(&win, &mut ws);
                                }
                                save_window_state(state.storage.base_dir(), &ws);
                            }
                            let minimize_to_tray = state
                                .settings
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .minimize_to_tray;
                            if minimize_to_tray {
                                api.prevent_close();
                                let _ = window.hide();
                                return;
                            }
                            state.core.blocking_cleanup_on_exit();
                        }
                    }
                    _ => {}
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_bootstrap_state,
            commands::import_from_text,
            commands::preview_import_text,
            commands::import_subscription,
            commands::smart_import,
            commands::refresh_subscription,
            commands::rollback_subscription,
            commands::delete_subscription,
            commands::select_server,
            commands::rename_server,
            commands::delete_server,
            commands::ping_server,
            commands::ping_all_servers,
            commands::auto_select_fastest_server,
            commands::connect,
            commands::disconnect,
            commands::disengage_kill_switch,
            commands::get_kill_switch_status,
            commands::set_kill_switch_config,
            commands::emergency_recover_network,
            commands::check_ip_monitor,
            commands::set_ip_mask,
            commands::get_protection_center,
            commands::analyze_server_profile,
            commands::apply_profile_overrides,
            commands::set_window_background_style,
            commands::update_settings,
            commands::get_elevation_status,
            commands::relaunch_as_admin,
            commands::check_for_updates,
            commands::get_logs,
            commands::clear_logs,
            commands::get_diagnostics,
            commands::run_network_diagnostics,
            commands::get_connection_history,
            commands::clear_connection_history,
            commands::window_minimize,
            commands::window_close_action,
            commands::get_windows_accent_color,
            commands::toggle_favorite_server,
            commands::rename_subscription,
            commands::toggle_subscription_enabled,
            commands::update_subscription_config,
            commands::get_rulepack_status,
            commands::update_rulepack,
            commands::rollback_rulepack,
            commands::test_route,
            commands::dns_lookup_route,
            commands::probe_active_connection,
            commands::export_diagnostics_bundle,
            commands::export_settings_backup,
            commands::import_settings_backup,
            commands::reset_settings_to_default,
            commands::get_window_mode_state,
            commands::set_mini_mode,
            commands::set_always_on_top,
            commands::bulk_delete_servers,
            commands::bulk_set_favorite_servers,
            commands::get_core_inventory,
            commands::verify_core_integrity,
            commands::check_core_updates,
            commands::get_dns_inspector_report,
            commands::test_dns_server,
            commands::run_dns_inspector_lookup,
            commands::get_tun_status,
            commands::detect_tun_conflicts,
            commands::get_connection_inspector,
            commands::get_connection_timeline,
            commands::clear_connection_timeline,
            commands::get_config_studio_view,
            commands::validate_custom_profile_config,
            commands::save_profile_config_edit,
            commands::rollback_profile_config,
            commands::duplicate_server_profile,
            commands::run_network_doctor,
            commands::get_privacy_inventory,
            commands::rotate_device_hwid,
            commands::purge_privacy_data,
            commands::set_ip_provider,
            commands::clear_original_ip,
            commands::clear_ip_monitor_cache,
            commands::get_subscription_sync_history,
            commands::run_server_speed_test,
        ]);

    let app = builder
        .build(tauri::generate_context!())
        .expect("error while building AURA VPN");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            if let Some(state) = app_handle.try_state::<AppState>() {
                {
                    let mut ws = state.window_state.lock().unwrap_or_else(|p| p.into_inner());
                    flush_window_state_on_exit(app_handle, state.storage.base_dir(), &mut ws);
                }
                state.core.blocking_cleanup_on_exit();
            }
        }
    });
}
