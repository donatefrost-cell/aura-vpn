use crate::commands::AppState;
use crate::models::{ConnectionMode, ConnectionStatus, ServerProfile};
use crate::routing_rules::is_ru_bypass_active;
use std::collections::HashMap;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager};

const TRAY_ID: &str = "aura-tray";
const MENU_SHOW: &str = "tray-show";
const MENU_TOGGLE: &str = "tray-toggle";
const MENU_DISENGAGE_KS: &str = "tray-disengage-ks";
const MENU_MODE_PROXY: &str = "tray-mode-proxy";
const MENU_MODE_TUN: &str = "tray-mode-tun";
const MENU_TOGGLE_RU_DIRECT: &str = "tray-toggle-ru-direct";
const MENU_SERVER_PREFIX: &str = "tray-srv:";
const MENU_QUIT: &str = "tray-quit";

static ICON_DISCONNECTED: &[u8] = include_bytes!("../icons/tray-disconnected.png");
static ICON_CONNECTING: &[u8] = include_bytes!("../icons/tray-connecting.png");
static ICON_CONNECTED: &[u8] = include_bytes!("../icons/tray-connected.png");
static ICON_RECONNECTING: &[u8] = include_bytes!("../icons/tray-reconnecting.png");
static ICON_ERROR: &[u8] = include_bytes!("../icons/tray-error.png");
static ICON_KILLSWITCH: &[u8] = include_bytes!("../icons/tray-killswitch.png");

fn select_tray_icon_bytes(status: ConnectionStatus, kill_switch_engaged: bool) -> &'static [u8] {
    if kill_switch_engaged {
        return ICON_KILLSWITCH;
    }
    match status {
        ConnectionStatus::Connected => ICON_CONNECTED,
        ConnectionStatus::Connecting
        | ConnectionStatus::Verifying
        | ConnectionStatus::Switching => ICON_CONNECTING,
        ConnectionStatus::Reconnecting => ICON_RECONNECTING,
        ConnectionStatus::Error => ICON_ERROR,
        ConnectionStatus::Disconnected | ConnectionStatus::Disconnecting => ICON_DISCONNECTED,
    }
}

pub struct TrayController;

impl Default for TrayController {
    fn default() -> Self {
        Self::new()
    }
}

impl TrayController {
    pub fn new() -> Self {
        Self
    }

    pub fn update_from_state(&self, app: &AppHandle) {
        let Some(state) = app.try_state::<AppState>() else {
            return;
        };
        let snap = state.core.snapshot();
        let profiles = state
            .profiles
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let subs = state
            .subscriptions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let settings = state
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();

        let sub_enabled_map: HashMap<String, bool> =
            subs.into_iter().map(|s| (s.id, s.enabled)).collect();
        let visible_profiles: Vec<ServerProfile> = profiles
            .into_iter()
            .filter(|p| {
                p.subscription_id
                    .as_ref()
                    .and_then(|sid| sub_enabled_map.get(sid).copied())
                    .unwrap_or(true)
            })
            .collect();

        let active_id = snap
            .active_server_id
            .clone()
            .or_else(|| settings.active_server_id.clone());
        let active_name = active_id
            .as_ref()
            .and_then(|id| visible_profiles.iter().find(|p| &p.id == id))
            .map(|p| p.name.clone());

        if let Some(tray) = app.tray_by_id(TRAY_ID) {
            let bytes = select_tray_icon_bytes(snap.status, snap.kill_switch_engaged);
            if let Ok(img) = Image::from_bytes(bytes) {
                let _ = tray.set_icon(Some(img));
            }
            let tooltip = match snap.status {
                ConnectionStatus::Connected => {
                    let mode_tag = if snap.mode == ConnectionMode::Tun {
                        "TUN"
                    } else {
                        "Прокси"
                    };
                    match active_name.as_deref() {
                        Some(name) => format!("AURA VPN — Подключено [{mode_tag}] ({name})"),
                        None => format!("AURA VPN — Подключено [{mode_tag}]"),
                    }
                }
                ConnectionStatus::Connecting => "AURA VPN — Подключение...".to_string(),
                ConnectionStatus::Verifying => "AURA VPN — Проверка туннеля...".to_string(),
                ConnectionStatus::Switching => "AURA VPN — Переключение сервера...".to_string(),
                ConnectionStatus::Reconnecting => "AURA VPN — Переподключение...".to_string(),
                ConnectionStatus::Disconnecting => "AURA VPN — Отключение...".to_string(),
                ConnectionStatus::Error if snap.kill_switch_engaged => {
                    "AURA VPN — Kill Switch активен".to_string()
                }
                ConnectionStatus::Error => "AURA VPN — Ошибка соединения".to_string(),
                ConnectionStatus::Disconnected => "AURA VPN — Отключено".to_string(),
            };
            let _ = tray.set_tooltip(Some(&tooltip));

            let ru_direct = is_ru_bypass_active(&settings.routing);
            if let Ok(menu) = build_tray_menu(
                app,
                snap.status,
                snap.kill_switch_engaged,
                settings.connection_mode,
                ru_direct,
                &visible_profiles,
                active_id.as_deref(),
            ) {
                let _ = tray.set_menu(Some(menu));
            }
        }
    }
}

fn build_tray_menu(
    app: &AppHandle,
    status: ConnectionStatus,
    kill_switch_engaged: bool,
    mode: ConnectionMode,
    ru_direct: bool,
    profiles: &[ServerProfile],
    active_id: Option<&str>,
) -> Result<Menu<tauri::Wry>, tauri::Error> {
    let show_item = MenuItem::with_id(app, MENU_SHOW, "Открыть AURA VPN", true, None::<&str>)?;
    let toggle_label = match status {
        ConnectionStatus::Connected => "Отключить VPN",
        ConnectionStatus::Connecting => "Подключение...",
        ConnectionStatus::Verifying => "Проверка туннеля...",
        ConnectionStatus::Switching => "Переключение...",
        ConnectionStatus::Reconnecting => "Переподключение...",
        ConnectionStatus::Disconnecting => "Отключение...",
        _ => "Подключить VPN",
    };
    let toggle_enabled = !matches!(
        status,
        ConnectionStatus::Connecting
            | ConnectionStatus::Verifying
            | ConnectionStatus::Switching
            | ConnectionStatus::Reconnecting
            | ConnectionStatus::Disconnecting
    ) && !profiles.is_empty();
    let toggle_item =
        MenuItem::with_id(app, MENU_TOGGLE, toggle_label, toggle_enabled, None::<&str>)?;

    let menu = Menu::new(app)?;
    menu.append(&show_item)?;
    menu.append(&toggle_item)?;

    if kill_switch_engaged {
        let ks_item = MenuItem::with_id(
            app,
            MENU_DISENGAGE_KS,
            "Снять блокировку Kill Switch",
            true,
            None::<&str>,
        )?;
        menu.append(&ks_item)?;
    }

    if !profiles.is_empty() {
        let mut prioritized: Vec<&ServerProfile> = profiles.iter().collect();
        prioritized.sort_by_key(|p| {
            let is_active = active_id == Some(p.id.as_str());
            (!is_active, !p.favorite)
        });

        let server_sub = Submenu::new(app, "Серверы", true)?;
        for srv in prioritized.into_iter().take(8) {
            let mark = if active_id == Some(srv.id.as_str()) {
                "✓ "
            } else if srv.favorite {
                "★ "
            } else {
                ""
            };
            let ping = srv
                .latency_ms
                .map(|ms| format!(" ({ms} мс)"))
                .unwrap_or_default();
            let item = MenuItem::with_id(
                app,
                format!("{MENU_SERVER_PREFIX}{}", srv.id),
                format!("{mark}{}{ping}", srv.name),
                true,
                None::<&str>,
            )?;
            server_sub.append(&item)?;
        }
        menu.append(&server_sub)?;
    }

    let mode_sub = Submenu::new(app, "Режим подключения", true)?;
    let proxy_label = if mode == ConnectionMode::SystemProxy {
        "✓ Системный прокси"
    } else {
        "Системный прокси"
    };
    let tun_label = if mode == ConnectionMode::Tun {
        "✓ TUN (Весь трафик)"
    } else {
        "TUN (Весь трафик)"
    };
    mode_sub.append(&MenuItem::with_id(
        app,
        MENU_MODE_PROXY,
        proxy_label,
        true,
        None::<&str>,
    )?)?;
    mode_sub.append(&MenuItem::with_id(
        app,
        MENU_MODE_TUN,
        tun_label,
        true,
        None::<&str>,
    )?)?;
    menu.append(&mode_sub)?;

    let ru_label = if ru_direct {
        "✓ Российские сервисы напрямую"
    } else {
        "Российские сервисы напрямую"
    };
    menu.append(&MenuItem::with_id(
        app,
        MENU_TOGGLE_RU_DIRECT,
        ru_label,
        true,
        None::<&str>,
    )?)?;

    menu.append(&PredefinedMenuItem::separator(app)?)?;
    menu.append(&MenuItem::with_id(
        app,
        MENU_QUIT,
        "Выйти",
        true,
        None::<&str>,
    )?)?;

    Ok(menu)
}

pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let keep_on_top = app
            .try_state::<AppState>()
            .map(|st| {
                st.window_state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .always_on_top
            })
            .unwrap_or(false);
        let _ = window.unminimize();
        let _ = window.show();
        if !keep_on_top {
            // Brief z-order nudge guarantees foreground activation after cross-integrity single-instance wake-up.
            let _ = window.set_always_on_top(true);
            let _ = window.set_always_on_top(false);
        }
        let _ = window.set_focus();
    }
}

pub fn setup_tray(app: &AppHandle) -> Result<(), tauri::Error> {
    let (profiles, mode, ru_direct, active_id) = if let Some(state) = app.try_state::<AppState>() {
        let profiles = state
            .profiles
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let settings = state
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        (
            profiles,
            settings.connection_mode,
            is_ru_bypass_active(&settings.routing),
            settings.active_server_id,
        )
    } else {
        (vec![], ConnectionMode::SystemProxy, false, None)
    };

    let menu = build_tray_menu(
        app,
        ConnectionStatus::Disconnected,
        false,
        mode,
        ru_direct,
        &profiles,
        active_id.as_deref(),
    )?;
    let icon = Image::from_bytes(ICON_DISCONNECTED)?;

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .tooltip("AURA VPN — Отключено")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .on_menu_event(|app, event| {
            let id_str = event.id().as_ref().to_string();
            match id_str.as_str() {
                MENU_SHOW => show_main_window(app),
                MENU_TOGGLE => {
                    let handle = app.clone();
                    tauri::async_runtime::spawn(async move {
                        if let Some(state) = handle.try_state::<AppState>() {
                            let status = state.core.snapshot().status;
                            if matches!(
                                status,
                                ConnectionStatus::Connected
                                    | ConnectionStatus::Connecting
                                    | ConnectionStatus::Verifying
                                    | ConnectionStatus::Switching
                                    | ConnectionStatus::Reconnecting
                            ) {
                                let _ = crate::commands::disconnect_internal(&handle, &state).await;
                            } else {
                                let _ =
                                    crate::commands::connect_internal(&handle, &state, None).await;
                            }
                        }
                    });
                }
                MENU_DISENGAGE_KS => {
                    let handle = app.clone();
                    tauri::async_runtime::spawn(async move {
                        if let Some(state) = handle.try_state::<AppState>() {
                            let _ = state.core.disengage_kill_switch().await;
                            state
                                .needs_kill_switch_elevation
                                .store(false, std::sync::atomic::Ordering::Relaxed);
                            state.tray.update_from_state(&handle);
                        }
                    });
                }
                MENU_MODE_PROXY => {
                    let handle = app.clone();
                    tauri::async_runtime::spawn(async move {
                        if let Some(state) = handle.try_state::<AppState>() {
                            crate::commands::switch_mode_from_tray(
                                &handle,
                                &state,
                                ConnectionMode::SystemProxy,
                            )
                            .await;
                        }
                    });
                }
                MENU_MODE_TUN => {
                    let handle = app.clone();
                    tauri::async_runtime::spawn(async move {
                        if let Some(state) = handle.try_state::<AppState>() {
                            crate::commands::switch_mode_from_tray(
                                &handle,
                                &state,
                                ConnectionMode::Tun,
                            )
                            .await;
                        }
                    });
                }
                MENU_TOGGLE_RU_DIRECT => {
                    let handle = app.clone();
                    tauri::async_runtime::spawn(async move {
                        if let Some(state) = handle.try_state::<AppState>() {
                            crate::commands::toggle_ru_direct_from_tray(&handle, &state).await;
                        }
                    });
                }
                MENU_QUIT => {
                    if let Some(state) = app.try_state::<AppState>() {
                        state.core.blocking_cleanup_on_exit();
                    }
                    app.exit(0);
                }
                _ if id_str.starts_with(MENU_SERVER_PREFIX) => {
                    let server_id = id_str.trim_start_matches(MENU_SERVER_PREFIX).to_string();
                    let handle = app.clone();
                    tauri::async_runtime::spawn(async move {
                        if let Some(state) = handle.try_state::<AppState>() {
                            let _ =
                                crate::commands::select_server_internal(server_id, &handle, &state)
                                    .await;
                        }
                    });
                }
                _ => {}
            }
        })
        .build(app)?;

    Ok(())
}
