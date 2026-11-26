use crate::storage::atomic_write_bytes;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tauri::{AppHandle, LogicalSize, Manager, PhysicalPosition, PhysicalSize, Size, WebviewWindow};

pub const NORMAL_MIN_WIDTH: f64 = 840.0;
pub const NORMAL_MIN_HEIGHT: f64 = 580.0;
pub const DEFAULT_WIDTH: f64 = 960.0;
pub const DEFAULT_HEIGHT: f64 = 640.0;
pub const MINI_WIDTH: f64 = 380.0;
pub const MINI_HEIGHT: f64 = 540.0;
pub const MINI_MIN_WIDTH: f64 = 340.0;
pub const MINI_MIN_HEIGHT: f64 = 480.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WindowState {
    pub x: Option<i32>,
    pub y: Option<i32>,
    pub logical_width: f64,
    pub logical_height: f64,
    pub maximized: bool,
    pub mini_mode: bool,
    pub mini_x: Option<i32>,
    pub mini_y: Option<i32>,
    pub always_on_top: bool,
}

impl Default for WindowState {
    fn default() -> Self {
        Self {
            x: None,
            y: None,
            logical_width: DEFAULT_WIDTH,
            logical_height: DEFAULT_HEIGHT,
            maximized: false,
            mini_mode: false,
            mini_x: None,
            mini_y: None,
            always_on_top: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MonitorBounds {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub scale_factor: f64,
}

pub fn is_ignored_windows_geometry(x: i32, y: i32, width: u32, height: u32) -> bool {
    x <= -31_000 || y <= -31_000 || width < 100 || height < 100
}

pub fn clamp_bounds_to_monitors(
    saved_x: Option<i32>,
    saved_y: Option<i32>,
    logical_w: f64,
    logical_h: f64,
    min_logical_w: f64,
    min_logical_h: f64,
    monitors: &[MonitorBounds],
) -> (Option<(i32, i32)>, f64, f64) {
    let base_w = if logical_w.is_finite() {
        logical_w.max(min_logical_w)
    } else {
        min_logical_w
    };
    let base_h = if logical_h.is_finite() {
        logical_h.max(min_logical_h)
    } else {
        min_logical_h
    };

    if monitors.is_empty() {
        return (None, base_w, base_h);
    }

    let chosen = saved_x.zip(saved_y).and_then(|(sx, sy)| {
        monitors.iter().copied().find(|m| {
            let scale = if m.scale_factor > 0.1 {
                m.scale_factor
            } else {
                1.0
            };
            let est_w = (base_w * scale).round() as i32;
            let right = sx.saturating_add(est_w);
            let title_bottom = sy.saturating_add(44);
            let m_right = m.x.saturating_add(m.width as i32);
            let m_bottom = m.y.saturating_add(m.height as i32);
            let overlap_w = right.min(m_right).saturating_sub(sx.max(m.x));
            let overlap_h = title_bottom.min(m_bottom).saturating_sub(sy.max(m.y));
            overlap_w >= 120 && overlap_h >= 28
        })
    });

    let Some(mon) = chosen else {
        let primary = monitors[0];
        let scale = if primary.scale_factor > 0.1 {
            primary.scale_factor
        } else {
            1.0
        };
        let max_lw = ((primary.width as f64 / scale) - 24.0).max(min_logical_w);
        let max_lh = ((primary.height as f64 / scale) - 24.0).max(min_logical_h);
        return (None, base_w.min(max_lw), base_h.min(max_lh));
    };

    let scale = if mon.scale_factor > 0.1 {
        mon.scale_factor
    } else {
        1.0
    };
    let max_lw = ((mon.width as f64 / scale) - 16.0).max(min_logical_w);
    let max_lh = ((mon.height as f64 / scale) - 16.0).max(min_logical_h);
    let clamped_w = base_w.min(max_lw);
    let clamped_h = base_h.min(max_lh);

    let phys_w = (clamped_w * scale).round() as i32;
    let phys_h = (clamped_h * scale).round() as i32;
    let max_x = mon.x.saturating_add((mon.width as i32 - phys_w).max(0));
    let max_y = mon.y.saturating_add((mon.height as i32 - phys_h).max(0));
    let (sx, sy) = saved_x.zip(saved_y).unwrap_or((mon.x, mon.y));
    let cx = sx.clamp(mon.x, max_x);
    let cy = sy.clamp(mon.y, max_y);

    (Some((cx, cy)), clamped_w, clamped_h)
}

pub fn load_window_state(base_dir: &Path) -> WindowState {
    let path = base_dir.join("window-state.json");
    let Ok(raw) = fs::read_to_string(path) else {
        return WindowState::default();
    };
    serde_json::from_str::<WindowState>(&raw).unwrap_or_default()
}

pub fn save_window_state(base_dir: &Path, ws: &WindowState) {
    let path = base_dir.join("window-state.json");
    if let Ok(bytes) = serde_json::to_vec_pretty(ws) {
        let _ = atomic_write_bytes(&path, &bytes);
    }
}

fn collect_monitor_bounds(win: &WebviewWindow) -> Vec<MonitorBounds> {
    let Ok(list) = win.available_monitors() else {
        return Vec::new();
    };
    list.into_iter()
        .map(|m| {
            let area = m.work_area();
            MonitorBounds {
                x: area.position.x,
                y: area.position.y,
                width: area.size.width,
                height: area.size.height,
                scale_factor: m.scale_factor(),
            }
        })
        .collect()
}

pub fn apply_initial_window_state(win: &WebviewWindow, ws: &WindowState) {
    let monitors = collect_monitor_bounds(win);
    if ws.mini_mode {
        let _ = win.set_min_size(Some(Size::Logical(LogicalSize::new(
            MINI_MIN_WIDTH,
            MINI_MIN_HEIGHT,
        ))));
        let (pos, w, h) = clamp_bounds_to_monitors(
            ws.mini_x,
            ws.mini_y,
            MINI_WIDTH,
            MINI_HEIGHT,
            MINI_MIN_WIDTH,
            MINI_MIN_HEIGHT,
            &monitors,
        );
        let _ = win.set_size(Size::Logical(LogicalSize::new(w, h)));
        if let Some((x, y)) = pos {
            let _ = win.set_position(PhysicalPosition::new(x, y));
        } else {
            let _ = win.center();
        }
        let _ = win.set_always_on_top(ws.always_on_top);
    } else {
        let _ = win.set_min_size(Some(Size::Logical(LogicalSize::new(
            NORMAL_MIN_WIDTH,
            NORMAL_MIN_HEIGHT,
        ))));
        let (pos, w, h) = clamp_bounds_to_monitors(
            ws.x,
            ws.y,
            ws.logical_width,
            ws.logical_height,
            NORMAL_MIN_WIDTH,
            NORMAL_MIN_HEIGHT,
            &monitors,
        );
        let _ = win.set_size(Size::Logical(LogicalSize::new(w, h)));
        if let Some((x, y)) = pos {
            let _ = win.set_position(PhysicalPosition::new(x, y));
        } else {
            let _ = win.center();
        }
        if ws.maximized {
            let _ = win.maximize();
        }
        let _ = win.set_always_on_top(false);
    }
}

pub fn capture_live_window_geometry(win: &WebviewWindow, ws: &mut WindowState) {
    if win.is_minimized().unwrap_or(false) {
        return;
    }
    let is_max = win.is_maximized().unwrap_or(false);
    if !ws.mini_mode {
        ws.maximized = is_max;
    }
    if is_max {
        return;
    }
    let Ok(pos) = win.outer_position() else {
        return;
    };
    let Ok(size) = win.inner_size() else {
        return;
    };
    if is_ignored_windows_geometry(pos.x, pos.y, size.width, size.height) {
        return;
    }
    if ws.mini_mode {
        ws.mini_x = Some(pos.x);
        ws.mini_y = Some(pos.y);
    } else {
        let scale = win.scale_factor().unwrap_or(1.0);
        let safe_scale = if scale > 0.1 { scale } else { 1.0 };
        ws.x = Some(pos.x);
        ws.y = Some(pos.y);
        ws.logical_width = (size.width as f64 / safe_scale).max(NORMAL_MIN_WIDTH);
        ws.logical_height = (size.height as f64 / safe_scale).max(NORMAL_MIN_HEIGHT);
    }
}

pub fn apply_mini_mode_transition(
    win: &WebviewWindow,
    ws: &mut WindowState,
    enable_mini: bool,
    always_on_top_override: Option<bool>,
) {
    capture_live_window_geometry(win, ws);
    let monitors = collect_monitor_bounds(win);

    if let Some(aot) = always_on_top_override {
        ws.always_on_top = aot;
    }

    if enable_mini {
        if win.is_maximized().unwrap_or(false) {
            let _ = win.unmaximize();
        }
        ws.mini_mode = true;
        let _ = win.set_min_size(Some(Size::Logical(LogicalSize::new(
            MINI_MIN_WIDTH,
            MINI_MIN_HEIGHT,
        ))));
        let (pos, w, h) = clamp_bounds_to_monitors(
            ws.mini_x,
            ws.mini_y,
            MINI_WIDTH,
            MINI_HEIGHT,
            MINI_MIN_WIDTH,
            MINI_MIN_HEIGHT,
            &monitors,
        );
        let _ = win.set_size(Size::Logical(LogicalSize::new(w, h)));
        if let Some((x, y)) = pos {
            let _ = win.set_position(PhysicalPosition::new(x, y));
        } else {
            let _ = win.center();
        }
        let _ = win.set_always_on_top(ws.always_on_top);
    } else {
        ws.mini_mode = false;
        let _ = win.set_always_on_top(false);
        let _ = win.set_min_size(Some(Size::Logical(LogicalSize::new(
            NORMAL_MIN_WIDTH,
            NORMAL_MIN_HEIGHT,
        ))));
        let (pos, w, h) = clamp_bounds_to_monitors(
            ws.x,
            ws.y,
            ws.logical_width,
            ws.logical_height,
            NORMAL_MIN_WIDTH,
            NORMAL_MIN_HEIGHT,
            &monitors,
        );
        let _ = win.set_size(Size::Logical(LogicalSize::new(w, h)));
        if let Some((x, y)) = pos {
            let _ = win.set_position(PhysicalPosition::new(x, y));
        } else {
            let _ = win.center();
        }
        if ws.maximized {
            let _ = win.maximize();
        }
    }
}

pub fn flush_window_state_on_exit(app: &AppHandle, base_dir: &Path, ws: &mut WindowState) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = PhysicalSize::<u32>::new(0, 0);
        capture_live_window_geometry(&win, ws);
    }
    save_window_state(base_dir, ws);
}

#[cfg(target_os = "windows")]
pub fn apply_window_background_style(
    win: &WebviewWindow,
    style: crate::models::BackgroundStyle,
    is_dark: bool,
) {
    use crate::models::BackgroundStyle;
    use windows_sys::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMSBT_MAINWINDOW, DWMSBT_NONE, DWMWA_SYSTEMBACKDROP_TYPE,
        DWMWA_USE_IMMERSIVE_DARK_MODE,
    };

    let Ok(hwnd) = win.hwnd() else {
        return;
    };
    let dark_val: i32 = if is_dark { 1 } else { 0 };
    let backdrop: i32 = match style {
        BackgroundStyle::Mica => DWMSBT_MAINWINDOW,
        _ => DWMSBT_NONE,
    };
    unsafe {
        let _ = DwmSetWindowAttribute(
            hwnd.0,
            DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
            &dark_val as *const _ as *const _,
            std::mem::size_of::<i32>() as u32,
        );
        let _ = DwmSetWindowAttribute(
            hwnd.0,
            DWMWA_SYSTEMBACKDROP_TYPE as u32,
            &backdrop as *const _ as *const _,
            std::mem::size_of::<i32>() as u32,
        );
    }
}

#[cfg(not(target_os = "windows"))]
pub fn apply_window_background_style(
    _win: &WebviewWindow,
    _style: crate::models::BackgroundStyle,
    _is_dark: bool,
) {
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dual_monitors() -> Vec<MonitorBounds> {
        vec![
            MonitorBounds {
                x: 0,
                y: 0,
                width: 1920,
                height: 1040,
                scale_factor: 1.0,
            },
            MonitorBounds {
                x: 1920,
                y: 0,
                width: 2560,
                height: 1400,
                scale_factor: 1.25,
            },
        ]
    }

    #[test]
    fn preserves_valid_secondary_monitor_geometry() {
        let monitors = dual_monitors();
        let (pos, w, h) = clamp_bounds_to_monitors(
            Some(2100),
            Some(100),
            1020.0,
            700.0,
            NORMAL_MIN_WIDTH,
            NORMAL_MIN_HEIGHT,
            &monitors,
        );
        assert_eq!(pos, Some((2100, 100)));
        assert_eq!((w, h), (1020.0, 700.0));
    }

    #[test]
    fn falls_back_cleanly_when_saved_monitor_unplugged() {
        let primary_only = vec![dual_monitors()[0]];
        let (pos, w, h) = clamp_bounds_to_monitors(
            Some(2500),
            Some(120),
            1020.0,
            700.0,
            NORMAL_MIN_WIDTH,
            NORMAL_MIN_HEIGHT,
            &primary_only,
        );
        assert_eq!(pos, None);
        assert_eq!((w, h), (1020.0, 700.0));
    }

    #[test]
    fn ignores_windows_minimized_sentinel_coordinates() {
        assert!(is_ignored_windows_geometry(-32000, -32000, 160, 28));
        assert!(is_ignored_windows_geometry(100, 100, 0, 0));
        assert!(!is_ignored_windows_geometry(100, 100, 960, 640));
    }

    #[test]
    fn clamps_oversized_logical_window_under_high_dpi() {
        let small_hidpi = vec![MonitorBounds {
            x: 0,
            y: 0,
            width: 1920,
            height: 1040,
            scale_factor: 1.5, // logical 1280x693
        }];
        let (_pos, w, h) = clamp_bounds_to_monitors(
            Some(20),
            Some(20),
            1600.0,
            1000.0,
            NORMAL_MIN_WIDTH,
            NORMAL_MIN_HEIGHT,
            &small_hidpi,
        );
        assert!(w <= 1280.0);
        assert!(h <= 700.0);
        assert!(w >= NORMAL_MIN_WIDTH);
        assert!(h >= NORMAL_MIN_HEIGHT);
    }
}
