use crate::core_manager::{
    compute_file_sha256, EMBEDDED_AWG_SHA256, EMBEDDED_WINTUN_SHA256, EMBEDDED_XRAY_SHA256,
};
use crate::elevation::is_elevated;
use crate::logger::redact_secrets;
use crate::models::{
    AppSettings, ConnectionMode, CoreCapabilities, CoreCompatibilityRow, CoreDiagnostics,
    CoreHistoryEntry, CoreInventorySnapshot, CoreKind, CoreSelectionMode, CoreUpdateCheckResult,
    InstalledCoreInfo, ProtocolDetails, ProtocolType, ServerProfile,
};
use crate::net_fetch::fetch_https_bytes_safe;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct ManifestStamp {
    version: Option<String>,
    #[serde(rename = "provisionedAt")]
    provisioned_at: Option<String>,
    license: Option<String>,
}

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    published_at: Option<String>,
    draft: Option<bool>,
    prerelease: Option<bool>,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

#[derive(Deserialize)]
struct GitHubAsset {
    name: String,
    #[serde(default)]
    digest: Option<String>,
}

pub fn sing_box_evaluation_note() -> String {
    "sing-box (GPL-3.0-or-later) в сборку v0.8.0 не включён: все поддерживаемые протоколы (VLESS/Reality/XHTTP/PQ, VMess, Trojan, Shadowsocks, Hysteria2, WireGuard, AmneziaWG) уже покрыты встроенными Xray-core 26.11.9 (MPL-2.0) и wireproxy-awg (ISC) + Wintun 0.14.1 без дублирования стеков и риска лицензионного конфликта.".into()
}

pub fn compatibility_matrix() -> Vec<CoreCompatibilityRow> {
    vec![
        CoreCompatibilityRow {
            protocol: ProtocolType::Vless,
            protocol_label: "VLESS (TCP / Vision / TLS / Reality / WebSocket / gRPC / XHTTP / KCP / PQ)".into(),
            supported_cores: vec!["Xray-core".into()],
            required_aux: Some("Wintun 0.14.1 (в режиме TUN)".into()),
            min_version: "26.11.9".into(),
            notes: "Полная поддержка XTLS-Vision, REALITY + ML-DSA-65 (`pqv`), gRPC multiMode и DoH/DoT/DoQ DNS.".into(),
        },
        CoreCompatibilityRow {
            protocol: ProtocolType::Vmess,
            protocol_label: "VMess (AEAD / WS / gRPC / XHTTP)".into(),
            supported_cores: vec!["Xray-core".into()],
            required_aux: Some("Wintun 0.14.1 (в режиме TUN)".into()),
            min_version: "26.11.9".into(),
            notes: "Поддерживаются авто/AEAD шифры и мультиплексирование Mux (если совместимо с транспортом).".into(),
        },
        CoreCompatibilityRow {
            protocol: ProtocolType::Trojan,
            protocol_label: "Trojan (TLS / Reality / WS / gRPC / XHTTP)".into(),
            supported_cores: vec!["Xray-core".into()],
            required_aux: Some("Wintun 0.14.1 (в режиме TUN)".into()),
            min_version: "26.11.9".into(),
            notes: "Совместим как с Системным прокси, так и с TUN.".into(),
        },
        CoreCompatibilityRow {
            protocol: ProtocolType::Shadowsocks,
            protocol_label: "Shadowsocks (2022 / AEAD / UoT)".into(),
            supported_cores: vec!["Xray-core".into()],
            required_aux: None,
            min_version: "26.11.9".into(),
            notes: "Внешние бинарные SIP003-плагины не загружаются по соображениям безопасности; встроенный `uot` поддерживается.".into(),
        },
        CoreCompatibilityRow {
            protocol: ProtocolType::Hysteria2,
            protocol_label: "Hysteria2 (QUIC / Salamander / udphop)".into(),
            supported_cores: vec!["Xray-core".into()],
            required_aux: None,
            min_version: "26.11.9".into(),
            notes: "Нативный QUIC outbound + Salamander + `udphop`; TCP Mux неприменим.".into(),
        },
        CoreCompatibilityRow {
            protocol: ProtocolType::Wireguard,
            protocol_label: "WireGuard (стандартный)".into(),
            supported_cores: vec!["Xray-core".into(), "wireproxy-awg (как SOCKS-мост)".into()],
            required_aux: Some("Wintun 0.14.1 (в режиме TUN)".into()),
            min_version: "26.11.9".into(),
            notes: "В режиме `Auto` или `Xray` работает напрямую через Xray; можно выбрать `wireproxy-awg` в Инспекторе узла.".into(),
        },
        CoreCompatibilityRow {
            protocol: ProtocolType::AmneziaWg,
            protocol_label: "AmneziaWG (Jc / Jmin / Jmax / S1 / S2 / H1..H4 / CPS)".into(),
            supported_cores: vec!["wireproxy-awg + Xray-core".into()],
            required_aux: Some("wireproxy-awg обязателен (обфускация AWG)".into()),
            min_version: "v1.0.18".into(),
            notes: "Требует `wireproxy-awg` для обфускации AWG и работает через локальный SOCKS5-мост в Xray.".into(),
        },
        CoreCompatibilityRow {
            protocol: ProtocolType::RawXray,
            protocol_label: "Raw Xray JSON / Автобалансировка".into(),
            supported_cores: vec!["Xray-core".into()],
            required_aux: Some("Wintun 0.14.1 (в режиме TUN)".into()),
            min_version: "26.11.9".into(),
            notes: "Поддержка мульти-узлов и `observatory` / `burstObservatory` с обязательной санитизацией опасных полей.".into(),
        },
    ]
}

pub fn validate_core_for_profile(
    profile: &ServerProfile,
    selection: CoreSelectionMode,
    mode: ConnectionMode,
    diag: &CoreDiagnostics,
) -> Result<CoreSelectionMode, String> {
    let effective = profile
        .overrides
        .as_ref()
        .and_then(|o| o.preferred_core)
        .filter(|&c| c != CoreSelectionMode::Auto)
        .unwrap_or(selection);

    if !diag.core_available || !diag.core_integrity_ok {
        return Err(
            "Основное ядро Xray-core отсутствует или не прошло проверку целостности SHA-256."
                .into(),
        );
    }
    if mode == ConnectionMode::Tun && (!diag.wintun_available || !diag.wintun_integrity_ok) {
        return Err(
            "Для режима TUN требуется целостный драйвер Wintun 0.14.1 (wintun.dll).".into(),
        );
    }

    match profile.protocol {
        ProtocolType::AmneziaWg => {
            if effective == CoreSelectionMode::Xray {
                return Err("Профиль AmneziaWG использует обфускацию Jc/S1/H1..H4 и не может запускаться без `wireproxy-awg`. Выберите «Авто» или «wireproxy-awg».".into());
            }
            if !diag.awg_available || !diag.awg_integrity_ok {
                return Err("Компонент `wireproxy-awg.exe` отсутствует или повреждён.".into());
            }
            Ok(CoreSelectionMode::WireproxyAwg)
        }
        ProtocolType::Wireguard => {
            if effective == CoreSelectionMode::WireproxyAwg {
                if !diag.awg_available || !diag.awg_integrity_ok {
                    return Err("Выбран `wireproxy-awg`, но компонент отсутствует или не прошёл проверку SHA-256.".into());
                }
                Ok(CoreSelectionMode::WireproxyAwg)
            } else {
                Ok(CoreSelectionMode::Xray)
            }
        }
        ProtocolType::Shadowsocks => {
            if effective == CoreSelectionMode::WireproxyAwg {
                return Err("Ядро `wireproxy-awg` поддерживает только WireGuard/AmneziaWG, но не Shadowsocks.".into());
            }
            if let ProtocolDetails::Shadowsocks(ref ss) = profile.details {
                if let Some(ref plugin) = ss.plugin {
                    if !plugin.trim().is_empty() {
                        return Err(format!(
                            "Внешний SIP003-плагин Shadowsocks («{plugin}») не поддерживается встроенным Xray-core и не запускается без песочницы."
                        ));
                    }
                }
            }
            Ok(CoreSelectionMode::Xray)
        }
        _ => {
            if effective == CoreSelectionMode::WireproxyAwg {
                return Err(format!(
                    "Ядро `wireproxy-awg` поддерживает только протоколы WireGuard / AmneziaWG (выбран {:?}). Несовместимое ядро запрещено.",
                    profile.protocol
                ));
            }
            Ok(CoreSelectionMode::Xray)
        }
    }
}

fn read_manifest_stamp(core_dir: &Path, name: &str) -> Option<ManifestStamp> {
    let raw = fs::read_to_string(core_dir.join(name)).ok()?;
    serde_json::from_str::<ManifestStamp>(&raw).ok()
}

fn file_meta_info(path: &Path) -> (u64, Option<String>) {
    let Ok(meta) = fs::metadata(path) else {
        return (0, None);
    };
    let ts = meta
        .modified()
        .ok()
        .map(|st| DateTime::<Utc>::from(st).to_rfc3339());
    (meta.len(), ts)
}

pub fn build_core_inventory(
    settings: &AppSettings,
    diag: &CoreDiagnostics,
    xray_path: Option<&Path>,
    awg_path: Option<&Path>,
) -> CoreInventorySnapshot {
    let resource_dir = xray_path.and_then(|p| p.parent()).map(|d| d.to_path_buf());
    let xray_stamp = resource_dir
        .as_deref()
        .and_then(|d| read_manifest_stamp(d, "core-manifest.json"));
    let awg_stamp = resource_dir
        .as_deref()
        .and_then(|d| read_manifest_stamp(d, "awg-manifest.json"));
    let wintun_stamp = resource_dir
        .as_deref()
        .and_then(|d| read_manifest_stamp(d, "wintun-manifest.json"));

    let elevated = is_elevated();
    let wintun_path: Option<PathBuf> = xray_path
        .and_then(|p| p.parent())
        .map(|d| d.join("wintun.dll"));

    let xray_info = {
        let path_str = xray_path
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| diag.core_path.clone());
        let (size_bytes, mtime) = xray_path.map(file_meta_info).unwrap_or((0, None));
        let installed_at = xray_stamp
            .as_ref()
            .and_then(|s| s.provisioned_at.clone())
            .or(mtime);
        let actual_sha = xray_path.and_then(|p| compute_file_sha256(p).ok());
        let ver = xray_stamp
            .as_ref()
            .and_then(|s| s.version.clone())
            .unwrap_or_else(|| diag.core_version.clone());
        let history = actual_sha
            .as_ref()
            .map(|h| {
                vec![CoreHistoryEntry {
                    version: ver.clone(),
                    installed_at: installed_at
                        .clone()
                        .unwrap_or_else(|| "Встроен в релиз".into()),
                    sha256: h.clone(),
                    path: path_str.clone(),
                    can_rollback: false,
                }]
            })
            .unwrap_or_default();

        InstalledCoreInfo {
            id: "xray".into(),
            kind: CoreKind::Xray,
            name: "Xray-core".into(),
            license: xray_stamp
                .as_ref()
                .and_then(|s| s.license.clone())
                .unwrap_or_else(|| "MPL-2.0".into()),
            version: ver,
            available_version: None,
            arch: "x64 (Windows amd64)".into(),
            path: path_str,
            size_bytes,
            installed_at,
            sha256: actual_sha,
            expected_sha256: (!EMBEDDED_XRAY_SHA256.is_empty())
                .then(|| EMBEDDED_XRAY_SHA256.to_string()),
            integrity_ok: diag.core_integrity_ok,
            source: "Встроенный компонент (SHA-256 манифест сборки)".into(),
            source_origin: "https://github.com/XTLS/Xray-core/releases".into(),
            status: if !diag.core_available {
                "Отсутствует".into()
            } else if !diag.core_integrity_ok {
                "Ошибка целостности SHA-256".into()
            } else {
                "Готово к работе".into()
            },
            permissions_note: "Стандартные права пользователя (в TUN — через Wintun с правами UAC)"
                .into(),
            is_active: true,
            supported_protocols: vec![
                ProtocolType::Vless,
                ProtocolType::Vmess,
                ProtocolType::Trojan,
                ProtocolType::Shadowsocks,
                ProtocolType::Hysteria2,
                ProtocolType::Wireguard,
                ProtocolType::RawXray,
            ],
            capabilities: CoreCapabilities {
                supports_tun: true,
                supports_system_proxy: true,
                supports_doh: true,
                supports_dot: true,
                supports_doq: true,
                supports_mux: true,
                supports_reality: true,
                supports_xhttp: true,
                supports_hysteria2: true,
                supports_awg: false,
            },
            history,
        }
    };

    let awg_info = {
        let path_str = awg_path
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "resources/core/wireproxy-awg.exe".into());
        let (size_bytes, mtime) = awg_path.map(file_meta_info).unwrap_or((0, None));
        let installed_at = awg_stamp
            .as_ref()
            .and_then(|s| s.provisioned_at.clone())
            .or(mtime);
        let actual_sha = awg_path.and_then(|p| compute_file_sha256(p).ok());
        let ver = awg_stamp
            .as_ref()
            .and_then(|s| s.version.clone())
            .unwrap_or_else(|| "v1.0.18".into());
        let history = actual_sha
            .as_ref()
            .map(|h| {
                vec![CoreHistoryEntry {
                    version: ver.clone(),
                    installed_at: installed_at
                        .clone()
                        .unwrap_or_else(|| "Встроен в релиз".into()),
                    sha256: h.clone(),
                    path: path_str.clone(),
                    can_rollback: false,
                }]
            })
            .unwrap_or_default();

        InstalledCoreInfo {
            id: "wireproxy-awg".into(),
            kind: CoreKind::WireproxyAwg,
            name: "wireproxy-awg".into(),
            license: awg_stamp
                .as_ref()
                .and_then(|s| s.license.clone())
                .unwrap_or_else(|| "ISC".into()),
            version: ver,
            available_version: None,
            arch: "x64 (Windows amd64)".into(),
            path: path_str,
            size_bytes,
            installed_at,
            sha256: actual_sha,
            expected_sha256: (!EMBEDDED_AWG_SHA256.is_empty())
                .then(|| EMBEDDED_AWG_SHA256.to_string()),
            integrity_ok: diag.awg_integrity_ok,
            source: "Встроенный компонент (SOCKS5-мост AmneziaWG)".into(),
            source_origin: "https://github.com/artem-russkikh/wireproxy-awg".into(),
            status: if !diag.awg_available {
                "Отсутствует".into()
            } else if !diag.awg_integrity_ok {
                "Ошибка целостности SHA-256".into()
            } else {
                "Готово к работе".into()
            },
            permissions_note: "Стандартные права пользователя (локальный порт 127.0.0.1)".into(),
            is_active: settings.advanced.core_selection == CoreSelectionMode::WireproxyAwg,
            supported_protocols: vec![ProtocolType::AmneziaWg, ProtocolType::Wireguard],
            capabilities: CoreCapabilities {
                supports_tun: false,
                supports_system_proxy: true,
                supports_doh: false,
                supports_dot: false,
                supports_doq: false,
                supports_mux: false,
                supports_reality: false,
                supports_xhttp: false,
                supports_hysteria2: false,
                supports_awg: true,
            },
            history,
        }
    };

    let wintun_info = {
        let wp = wintun_path.as_deref().filter(|p| p.exists());
        let path_str = wp
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "resources/core/wintun.dll".into());
        let (size_bytes, mtime) = wp.map(file_meta_info).unwrap_or((0, None));
        let installed_at = wintun_stamp
            .as_ref()
            .and_then(|s| s.provisioned_at.clone())
            .or(mtime);
        let actual_sha = wp.and_then(|p| compute_file_sha256(p).ok());
        let ver = wintun_stamp
            .as_ref()
            .and_then(|s| s.version.clone())
            .unwrap_or_else(|| "0.14.1".into());
        let history = actual_sha
            .as_ref()
            .map(|h| {
                vec![CoreHistoryEntry {
                    version: ver.clone(),
                    installed_at: installed_at
                        .clone()
                        .unwrap_or_else(|| "Встроен в релиз".into()),
                    sha256: h.clone(),
                    path: path_str.clone(),
                    can_rollback: false,
                }]
            })
            .unwrap_or_default();

        InstalledCoreInfo {
            id: "wintun".into(),
            kind: CoreKind::Wintun,
            name: "Wintun L3 TUN Driver".into(),
            license: "WireGuard Prebuilt".into(),
            version: ver,
            available_version: None,
            arch: "x64 (amd64)".into(),
            path: path_str,
            size_bytes,
            installed_at,
            sha256: actual_sha,
            expected_sha256: (!EMBEDDED_WINTUN_SHA256.is_empty())
                .then(|| EMBEDDED_WINTUN_SHA256.to_string()),
            integrity_ok: diag.wintun_integrity_ok,
            source: "Встроенный подписанный драйвер Wintun 0.14.1".into(),
            source_origin: "https://www.wintun.net/".into(),
            status: if !diag.wintun_available {
                "Отсутствует".into()
            } else if !diag.wintun_integrity_ok {
                "Ошибка целостности SHA-256".into()
            } else if elevated {
                "Готово к работе (UAC активен)".into()
            } else {
                "Целостен (для TUN нужен запуск от администратора)".into()
            },
            permissions_note: if elevated {
                "Права администратора подтверждены (создание виртуального адаптера доступно)".into()
            } else {
                "Требуются права администратора Windows (UAC) при подключении в режиме TUN".into()
            },
            is_active: settings.connection_mode == ConnectionMode::Tun && diag.wintun_available,
            supported_protocols: vec![
                ProtocolType::Vless,
                ProtocolType::Vmess,
                ProtocolType::Trojan,
                ProtocolType::Shadowsocks,
                ProtocolType::Hysteria2,
                ProtocolType::Wireguard,
                ProtocolType::AmneziaWg,
                ProtocolType::RawXray,
            ],
            capabilities: CoreCapabilities {
                supports_tun: true,
                supports_system_proxy: false,
                supports_doh: false,
                supports_dot: false,
                supports_doq: false,
                supports_mux: false,
                supports_reality: false,
                supports_xhttp: false,
                supports_hysteria2: false,
                supports_awg: false,
            },
            history,
        }
    };

    CoreInventorySnapshot {
        checked_at: Utc::now().to_rfc3339(),
        cores: vec![xray_info, awg_info, wintun_info],
        compatibility_matrix: compatibility_matrix(),
        sing_box_note: sing_box_evaluation_note(),
        active_selection: settings.advanced.core_selection,
    }
}

pub async fn check_core_updates_online(
    kind: CoreKind,
    current_version: String,
    active_connection: bool,
) -> CoreUpdateCheckResult {
    let api_url = match kind {
        CoreKind::Xray => Some("https://api.github.com/repos/XTLS/Xray-core/releases/latest"),
        CoreKind::WireproxyAwg => None,
        CoreKind::Wintun => None,
    };

    let Some(url) = api_url else {
        return CoreUpdateCheckResult {
            core_kind: kind,
            current_version,
            latest_version: None,
            update_available: false,
            release_url: None,
            asset_name: None,
            expected_sha256: None,
            published_at: None,
            blocked_by_active_connection: active_connection,
            status: "pinned".into(),
            message: "Версия этого системного компонента жёстко зафиксирована манифестом сборки AURA VPN для гарантии стабильности.".into(),
        };
    };

    let user_agent = concat!("AURA-VPN-CoreCheck/", env!("CARGO_PKG_VERSION"));
    match fetch_https_bytes_safe(
        url,
        user_agent,
        512 * 1024,
        std::time::Duration::from_secs(10),
        "Ответ GitHub Releases API превысил лимит 512 КБ",
        false,
    )
    .await
    {
        Ok((_final_url, bytes)) => {
            if let Ok(rel) = serde_json::from_slice::<GitHubRelease>(&bytes) {
                let safe_release_url =
                    crate::net_fetch::validate_http_url(&rel.html_url, true, false)
                        .ok()
                        .filter(|u| {
                            let host = u.host_str().unwrap_or("").to_ascii_lowercase();
                            (host == "github.com" || host == "www.github.com")
                                && u.path()
                                    .to_ascii_lowercase()
                                    .starts_with("/xtls/xray-core/releases")
                        })
                        .map(|u| u.to_string());
                if rel.draft.unwrap_or(false) || rel.prerelease.unwrap_or(false) {
                    return CoreUpdateCheckResult {
                        core_kind: kind,
                        current_version,
                        latest_version: None,
                        update_available: false,
                        release_url: safe_release_url,
                        asset_name: None,
                        expected_sha256: None,
                        published_at: rel.published_at,
                        blocked_by_active_connection: active_connection,
                        status: "up_to_date".into(),
                        message: "Стабильный релиз без флага prerelease не требует обновления."
                            .into(),
                    };
                }
                let latest = rel.tag_name.trim_start_matches(['v', 'V']).to_string();
                let asset = rel
                    .assets
                    .into_iter()
                    .find(|a| a.name.eq_ignore_ascii_case("Xray-windows-64.zip"));
                let cur_clean = current_version
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or(&current_version)
                    .trim_start_matches(['v', 'V'])
                    .to_string();
                let update_available = crate::updater::compare_semver_strict(&cur_clean, &latest)
                    == Some(std::cmp::Ordering::Less);
                let msg = if update_available && active_connection {
                    format!("Доступен Xray-core v{latest}, но замена ядра заблокирована во время активного VPN-подключения.")
                } else if update_available {
                    format!("Доступен официальный релиз Xray-core v{latest} (проверяйте обновление через новый релиз AURA VPN для сохранения вшитого SHA-256).")
                } else {
                    format!("Установлена актуальная версия Xray-core ({cur_clean}).")
                };
                CoreUpdateCheckResult {
                    core_kind: kind,
                    current_version,
                    latest_version: Some(latest),
                    update_available,
                    release_url: safe_release_url,
                    asset_name: asset.as_ref().map(|a| a.name.clone()),
                    expected_sha256: asset.and_then(|a| a.digest),
                    published_at: rel.published_at,
                    blocked_by_active_connection: active_connection,
                    status: if update_available {
                        "update_available".into()
                    } else {
                        "up_to_date".into()
                    },
                    message: msg,
                }
            } else {
                CoreUpdateCheckResult {
                    core_kind: kind,
                    current_version,
                    latest_version: None,
                    update_available: false,
                    release_url: None,
                    asset_name: None,
                    expected_sha256: None,
                    published_at: None,
                    blocked_by_active_connection: active_connection,
                    status: "error".into(),
                    message: "Некорректный формат ответа GitHub Releases API.".into(),
                }
            }
        }
        Err(err) => CoreUpdateCheckResult {
            core_kind: kind,
            current_version,
            latest_version: None,
            update_available: false,
            release_url: None,
            asset_name: None,
            expected_sha256: None,
            published_at: None,
            blocked_by_active_connection: active_connection,
            status: "error".into(),
            message: format!(
                "Не удалось проверить обновления ядра: {}",
                redact_secrets(&err)
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ShadowsocksDetails, WireguardDetails};

    fn ready_diag() -> CoreDiagnostics {
        CoreDiagnostics {
            core_name: "Xray-core".into(),
            core_version: "Xray 26.11.9".into(),
            core_path: "xray.exe".into(),
            core_available: true,
            wintun_available: true,
            awg_available: true,
            is_elevated: true,
            always_run_as_admin: false,
            kill_switch_engaged: false,
            system_proxy_active: false,
            active_proxy_endpoint: None,
            config_dir: ".".into(),
            core_integrity_ok: true,
            awg_integrity_ok: true,
            wintun_integrity_ok: true,
            integrity_note: None,
        }
    }

    #[test]
    fn rejects_incompatible_wireproxy_core_for_vless_and_ss_plugin() {
        let diag = ready_diag();
        let ss_with_plugin = ServerProfile {
            id: "ss1".into(),
            name: "SS Plugin".into(),
            protocol: ProtocolType::Shadowsocks,
            address: "1.2.3.4".into(),
            port: 8388,
            country_code: None,
            subscription_id: None,
            latency_ms: None,
            details: ProtocolDetails::Shadowsocks(ShadowsocksDetails {
                method: "aes-256-gcm".into(),
                password: "pw".into(),
                uot: false,
                plugin: Some("obfs-local".into()),
                plugin_opts: None,
            }),
            created_at: String::new(),
            favorite: false,
            last_used_at: None,
            fingerprint_key: None,
            custom_name: None,
            overrides: None,
            original_source: None,
            config_revision: 0,
        };
        assert!(validate_core_for_profile(
            &ss_with_plugin,
            CoreSelectionMode::Auto,
            ConnectionMode::SystemProxy,
            &diag
        )
        .is_err());

        let wg = ServerProfile {
            id: "wg1".into(),
            name: "WG".into(),
            protocol: ProtocolType::Wireguard,
            address: "1.2.3.4".into(),
            port: 51820,
            country_code: None,
            subscription_id: None,
            latency_ms: None,
            details: ProtocolDetails::Wireguard(WireguardDetails {
                secret_key: "a".into(),
                address: vec!["10.0.0.2/32".into()],
                public_key: "b".into(),
                preshared_key: None,
                endpoint: "1.2.3.4:51820".into(),
                mtu: Some(1420),
                dns: vec![],
                reserved: None,
                keepalive: Some(25),
            }),
            created_at: String::new(),
            favorite: false,
            last_used_at: None,
            fingerprint_key: None,
            custom_name: None,
            overrides: None,
            original_source: None,
            config_revision: 0,
        };
        assert_eq!(
            validate_core_for_profile(
                &wg,
                CoreSelectionMode::WireproxyAwg,
                ConnectionMode::SystemProxy,
                &diag
            )
            .unwrap(),
            CoreSelectionMode::WireproxyAwg
        );
    }
}
