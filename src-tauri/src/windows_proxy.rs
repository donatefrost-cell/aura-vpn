use crate::storage::atomic_write_bytes;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use windows_sys::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
use winreg::RegKey;

const INTERNET_SETTINGS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const DEFAULT_BYPASS: &str =
    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyBackup {
    pub proxy_enable: Option<u32>,
    pub proxy_server: Option<String>,
    pub proxy_override: Option<String>,
    pub auto_config_url: Option<String>,
    pub aura_endpoint: String,
}

fn notify_windows_internet_settings() {
    unsafe {
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        );
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        );
    }
}

fn read_opt_dword(key: &RegKey, name: &str) -> Option<u32> {
    key.get_value::<u32, _>(name).ok()
}

fn read_opt_string(key: &RegKey, name: &str) -> Option<String> {
    key.get_value::<String, _>(name).ok()
}

fn restore_opt_dword(key: &RegKey, name: &str, val: Option<u32>) -> Result<(), String> {
    match val {
        Some(v) => key
            .set_value(name, &v)
            .map_err(|e| format!("Не удалось восстановить {name}: {e}")),
        None => {
            let _ = key.delete_value(name);
            Ok(())
        }
    }
}

fn restore_opt_string(key: &RegKey, name: &str, val: Option<&str>) -> Result<(), String> {
    match val {
        Some(v) => key
            .set_value(name, &v)
            .map_err(|e| format!("Не удалось восстановить {name}: {e}")),
        None => {
            let _ = key.delete_value(name);
            Ok(())
        }
    }
}

pub fn enable_proxy_at_subkey(
    subkey_path: &str,
    backup_path: &Path,
    proxy_endpoint: &str,
    notify_os: bool,
) -> Result<(), String> {
    enable_proxy_at_subkey_with_override(subkey_path, backup_path, proxy_endpoint, &[], notify_os)
}

pub fn enable_proxy_at_subkey_with_override(
    subkey_path: &str,
    backup_path: &Path,
    proxy_endpoint: &str,
    extra_bypass: &[String],
    notify_os: bool,
) -> Result<(), String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey_with_flags(subkey_path, KEY_READ | KEY_WRITE)
        .map_err(|e| format!("Нет доступа к настройкам системного прокси Windows: {e}"))?;

    // Only capture backup if one is not already stored (or refresh aura_endpoint if ports changed while active)
    if !backup_path.exists() {
        let backup = ProxyBackup {
            proxy_enable: read_opt_dword(&key, "ProxyEnable"),
            proxy_server: read_opt_string(&key, "ProxyServer"),
            proxy_override: read_opt_string(&key, "ProxyOverride"),
            auto_config_url: read_opt_string(&key, "AutoConfigURL"),
            aura_endpoint: proxy_endpoint.to_string(),
        };
        let json = serde_json::to_string_pretty(&backup)
            .map_err(|e| format!("Ошибка сериализации резервной копии прокси: {e}"))?;
        atomic_write_bytes(backup_path, json.as_bytes())
            .map_err(|e| format!("Не удалось сохранить резервную копию прокси: {e}"))?;
    } else if let Ok(raw) = fs::read_to_string(backup_path) {
        if let Ok(mut backup) = serde_json::from_str::<ProxyBackup>(&raw) {
            if backup.aura_endpoint != proxy_endpoint {
                backup.aura_endpoint = proxy_endpoint.to_string();
                if let Ok(json) = serde_json::to_string_pretty(&backup) {
                    let _ = atomic_write_bytes(backup_path, json.as_bytes());
                }
            }
        }
    }

    let bypass_value = if extra_bypass.is_empty() {
        DEFAULT_BYPASS.to_string()
    } else {
        let mut items: Vec<String> = DEFAULT_BYPASS.split(';').map(|s| s.to_string()).collect();
        for entry in extra_bypass {
            let clean = entry.trim();
            if !clean.is_empty()
                && !clean.contains([';', '\r', '\n'])
                && !items.iter().any(|x| x.eq_ignore_ascii_case(clean))
            {
                items.push(clean.to_string());
            }
        }
        items.join(";")
    };

    let _ = key.delete_value("AutoConfigURL");
    key.set_value("ProxyServer", &proxy_endpoint)
        .map_err(|e| format!("Не удалось записать ProxyServer: {e}"))?;
    key.set_value("ProxyOverride", &bypass_value)
        .map_err(|e| format!("Не удалось записать ProxyOverride: {e}"))?;
    key.set_value("ProxyEnable", &1u32)
        .map_err(|e| format!("Не удалось включить ProxyEnable: {e}"))?;

    if notify_os {
        notify_windows_internet_settings();
    }
    Ok(())
}

pub fn restore_proxy_at_subkey(
    subkey_path: &str,
    backup_path: &Path,
    notify_os: bool,
) -> Result<bool, String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(key) = hkcu.open_subkey_with_flags(subkey_path, KEY_READ | KEY_WRITE) else {
        let _ = fs::remove_file(backup_path);
        return Ok(false);
    };

    if backup_path.exists() {
        let raw = fs::read_to_string(backup_path);
        let parsed: Option<ProxyBackup> = raw
            .ok()
            .and_then(|s| serde_json::from_str::<ProxyBackup>(&s).ok());

        if let Some(backup) = parsed {
            let current_server = read_opt_string(&key, "ProxyServer").unwrap_or_default();
            let current_enabled = read_opt_dword(&key, "ProxyEnable").unwrap_or(0) == 1;
            // Only overwrite registry if it still matches AURA's saved endpoint or was cleared
            let owned_by_aura = current_server.is_empty() || current_server == backup.aura_endpoint;

            if !current_enabled || owned_by_aura {
                restore_opt_dword(&key, "ProxyEnable", backup.proxy_enable)?;
                restore_opt_string(&key, "ProxyServer", backup.proxy_server.as_deref())?;
                restore_opt_string(&key, "ProxyOverride", backup.proxy_override.as_deref())?;
                restore_opt_string(&key, "AutoConfigURL", backup.auto_config_url.as_deref())?;
                let _ = fs::remove_file(backup_path);
                if notify_os {
                    notify_windows_internet_settings();
                }
                return Ok(true);
            }

            // User intentionally switched to another external proxy after crash; drop stale backup without clobbering
            let _ = fs::remove_file(backup_path);
            return Ok(false);
        }

        // Corrupt proxy-backup.json fallback: never trap Windows pointing at dead 127.0.0.1
        let current_server = read_opt_string(&key, "ProxyServer").unwrap_or_default();
        let current_enabled = read_opt_dword(&key, "ProxyEnable").unwrap_or(0) == 1;
        let _ = fs::remove_file(backup_path);
        if current_enabled && current_server.starts_with("127.0.0.1:") {
            let _ = key.set_value("ProxyEnable", &0u32);
            let _ = key.delete_value("ProxyServer");
            if notify_os {
                notify_windows_internet_settings();
            }
            return Ok(true);
        }
        return Ok(false);
    }

    Ok(false)
}

pub fn enable_system_proxy(backup_path: &Path, http_port: u16) -> Result<String, String> {
    let endpoint = format!("127.0.0.1:{http_port}");
    enable_proxy_at_subkey(INTERNET_SETTINGS_KEY, backup_path, &endpoint, true)?;
    Ok(endpoint)
}

pub fn enable_system_proxy_with_override(
    backup_path: &Path,
    http_port: u16,
    extra_bypass: &[String],
) -> Result<String, String> {
    let endpoint = format!("127.0.0.1:{http_port}");
    enable_proxy_at_subkey_with_override(
        INTERNET_SETTINGS_KEY,
        backup_path,
        &endpoint,
        extra_bypass,
        true,
    )?;
    Ok(endpoint)
}

pub fn restore_system_proxy(backup_path: &Path) -> Result<bool, String> {
    restore_proxy_at_subkey(INTERNET_SETTINGS_KEY, backup_path, true)
}

pub fn recover_if_dirty(backup_path: &Path) -> Result<bool, String> {
    if backup_path.exists() {
        restore_system_proxy(backup_path)
    } else {
        Ok(false)
    }
}

pub fn inspect_system_proxy() -> (bool, Option<String>) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(key) = hkcu.open_subkey_with_flags(INTERNET_SETTINGS_KEY, KEY_READ) else {
        return (false, None);
    };
    let enabled = read_opt_dword(&key, "ProxyEnable").unwrap_or(0) == 1;
    let server = read_opt_string(&key, "ProxyServer");
    (enabled, server)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backs_up_applies_and_restores_registry_proxy_cleanly() {
        let test_id = uuid::Uuid::new_v4().to_string();
        let subkey = format!(r"Software\AuraVPN_UnitTest_{test_id}");
        let temp_dir = std::env::temp_dir().join(format!("aura_proxy_test_{test_id}"));
        fs::create_dir_all(&temp_dir).unwrap();
        let backup_path = temp_dir.join("proxy-backup.json");

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        {
            let (key, _) = hkcu.create_subkey(&subkey).unwrap();
            key.set_value("ProxyEnable", &1u32).unwrap();
            key.set_value("ProxyServer", &"10.20.30.40:8080").unwrap();
            key.set_value("AutoConfigURL", &"http://pac.example.local/proxy.pac")
                .unwrap();
        }

        enable_proxy_at_subkey(&subkey, &backup_path, "127.0.0.1:10809", false).unwrap();
        {
            let key = hkcu.open_subkey(&subkey).unwrap();
            assert_eq!(key.get_value::<u32, _>("ProxyEnable").unwrap(), 1);
            assert_eq!(
                key.get_value::<String, _>("ProxyServer").unwrap(),
                "127.0.0.1:10809"
            );
            assert!(key.get_value::<String, _>("AutoConfigURL").is_err());
        }

        let restored = restore_proxy_at_subkey(&subkey, &backup_path, false).unwrap();
        assert!(restored);
        assert!(!backup_path.exists());
        {
            let key = hkcu.open_subkey(&subkey).unwrap();
            assert_eq!(key.get_value::<u32, _>("ProxyEnable").unwrap(), 1);
            assert_eq!(
                key.get_value::<String, _>("ProxyServer").unwrap(),
                "10.20.30.40:8080"
            );
            assert_eq!(
                key.get_value::<String, _>("AutoConfigURL").unwrap(),
                "http://pac.example.local/proxy.pac"
            );
        }

        let _ = hkcu.delete_subkey_all(&subkey);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn recovers_gracefully_from_corrupt_proxy_backup() {
        let test_id = uuid::Uuid::new_v4().to_string();
        let subkey = format!(r"Software\AuraVPN_CorruptProxy_{test_id}");
        let temp_dir = std::env::temp_dir().join(format!("aura_corrupt_proxy_{test_id}"));
        fs::create_dir_all(&temp_dir).unwrap();
        let backup_path = temp_dir.join("proxy-backup.json");
        fs::write(&backup_path, b"{truncated_corrupt_json").unwrap();

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        {
            let (key, _) = hkcu.create_subkey(&subkey).unwrap();
            key.set_value("ProxyEnable", &1u32).unwrap();
            key.set_value("ProxyServer", &"127.0.0.1:10809").unwrap();
        }

        let restored = restore_proxy_at_subkey(&subkey, &backup_path, false).unwrap();
        assert!(restored);
        assert!(!backup_path.exists());
        let key = hkcu.open_subkey(&subkey).unwrap();
        assert_eq!(key.get_value::<u32, _>("ProxyEnable").unwrap(), 0);
        assert!(key.get_value::<String, _>("ProxyServer").is_err());

        let _ = hkcu.delete_subkey_all(&subkey);
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
