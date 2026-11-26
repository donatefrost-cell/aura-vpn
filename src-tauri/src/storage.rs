use crate::models::{
    AppSettings, ConnectionHistoryEntry, ServerProfile, ServerQualityMetrics, Subscription,
};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

const MAX_HISTORY_ENTRIES: usize = 200;

#[derive(Serialize, Deserialize)]
struct DpapiEnvelope {
    format: String,
    data: String,
}

fn to_wide_null(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn atomic_write_bytes(target: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Не удалось создать папку {}: {e}", parent.display()))?;
    }

    let tmp_name = format!(
        "{}.{}.tmp",
        target
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("aura"),
        uuid::Uuid::new_v4()
    );
    let tmp = target.with_file_name(tmp_name);

    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| format!("Ошибка создания временного файла: {e}"))?;
        file.write_all(bytes)
            .map_err(|e| format!("Ошибка записи во временный файл: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("Ошибка сброса буфера на диск: {e}"))?;
    }

    let w_tmp = to_wide_null(&tmp);
    let w_target = to_wide_null(target);
    let ok = unsafe {
        MoveFileExW(
            w_tmp.as_ptr(),
            w_target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        let _ = fs::remove_file(&tmp);
        return Err(format!(
            "Ошибка атомарной замены файла {}: {err}",
            target.display()
        ));
    }
    Ok(())
}

pub fn atomic_copy_file(src: &Path, dst: &Path) -> Result<(), String> {
    let bytes = fs::read(src).map_err(|e| format!("Ошибка чтения файла {}: {e}", src.display()))?;
    atomic_write_bytes(dst, &bytes)
}

pub fn secure_delete_file(path: &Path) {
    if !path.exists() {
        return;
    }
    if let Ok(meta) = fs::metadata(path) {
        let total = meta.len();
        if total > 0 {
            if let Ok(mut f) = OpenOptions::new().write(true).open(path) {
                let chunk = [0u8; 64 * 1024];
                let mut remaining = total;
                while remaining > 0 {
                    let n = (remaining.min(chunk.len() as u64)) as usize;
                    if f.write_all(&chunk[..n]).is_err() {
                        break;
                    }
                    remaining -= n as u64;
                }
                let _ = f.sync_all();
            }
        }
    }
    let _ = fs::remove_file(path);
}

fn dpapi_protect(plain: &[u8]) -> Result<Vec<u8>, String> {
    if plain.is_empty() {
        return Ok(Vec::new());
    }
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(plain.len())
            .map_err(|_| "Данные слишком велики для DPAPI".to_string())?,
        pbData: plain.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &in_blob,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return Err(format!(
            "Ошибка шифрования Windows DPAPI: {}",
            std::io::Error::last_os_error()
        ));
    }
    let slice = unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
    let out = slice.to_vec();
    unsafe {
        LocalFree(out_blob.pbData as _);
    }
    Ok(out)
}

fn dpapi_unprotect(cipher: &[u8]) -> Result<Vec<u8>, String> {
    if cipher.is_empty() {
        return Ok(Vec::new());
    }
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(cipher.len())
            .map_err(|_| "Некорректный размер DPAPI-блока".to_string())?,
        pbData: cipher.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &in_blob,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return Err(format!(
            "Ошибка расшифровки Windows DPAPI: {}",
            std::io::Error::last_os_error()
        ));
    }
    let slice = unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
    let out = slice.to_vec();
    unsafe {
        LocalFree(out_blob.pbData as _);
    }
    Ok(out)
}

#[derive(Clone)]
pub struct AppStorage {
    base_dir: PathBuf,
    history_lock: std::sync::Arc<std::sync::Mutex<()>>,
}

impl AppStorage {
    pub fn new(base_dir: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(&base_dir).map_err(|e| {
            format!(
                "Не удалось создать папку данных {}: {e}",
                base_dir.display()
            )
        })?;
        fs::create_dir_all(base_dir.join("runtime"))
            .map_err(|e| format!("Не удалось создать папку runtime: {e}"))?;
        Ok(Self {
            base_dir,
            history_lock: std::sync::Arc::new(std::sync::Mutex::new(())),
        })
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn runtime_dir(&self) -> PathBuf {
        self.base_dir.join("runtime")
    }

    pub fn proxy_backup_path(&self) -> PathBuf {
        self.base_dir.join("proxy-backup.json")
    }

    pub fn kill_switch_state_path(&self) -> PathBuf {
        self.base_dir.join("killswitch-state.json")
    }

    pub fn has_saved_settings(&self) -> bool {
        self.base_dir.join("settings.json").exists()
    }

    /// Removes orphaned temporary runtime configs (active-config-*.json, awg-config-*.conf)
    /// and stale .tmp files in base_dir/rulepacks/ left behind by crashes or forced terminations.
    pub fn sweep_stale_runtime_files(&self) -> usize {
        let mut cleaned = 0usize;
        let dir = self.runtime_dir();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                        if name.starts_with("active-config-")
                            || name.starts_with("awg-config-")
                            || name.ends_with(".tmp")
                        {
                            secure_delete_file(&path);
                            cleaned += 1;
                        }
                    }
                }
            }
        }
        for parent in [&self.base_dir, &self.base_dir.join("rulepacks")] {
            if let Ok(entries) = fs::read_dir(parent) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                            if name.ends_with(".tmp") {
                                secure_delete_file(&path);
                                cleaned += 1;
                            }
                        }
                    }
                }
            }
        }
        cleaned
    }

    fn quarantine_corrupt_file(&self, file_name: &str) {
        let path = self.base_dir.join(file_name);
        if path.exists() {
            let ts = Utc::now().timestamp();
            let corrupt = self.base_dir.join(format!("{file_name}.corrupt.{ts}"));
            let _ = fs::rename(&path, corrupt);
        }
    }

    fn read_json_or_default<T: DeserializeOwned + Default>(&self, file_name: &str) -> T {
        let path = self.base_dir.join(file_name);
        let Ok(raw) = fs::read_to_string(&path) else {
            return T::default();
        };
        if raw.trim().is_empty() {
            return T::default();
        }
        match serde_json::from_str(&raw) {
            Ok(val) => val,
            Err(_) => {
                self.quarantine_corrupt_file(file_name);
                T::default()
            }
        }
    }

    pub fn read_dpapi_or_legacy_json<T: DeserializeOwned + Default>(&self, file_name: &str) -> T {
        let path = self.base_dir.join(file_name);
        let Ok(raw) = fs::read_to_string(&path) else {
            return T::default();
        };
        if raw.trim().is_empty() {
            return T::default();
        }

        if let Ok(env) = serde_json::from_str::<DpapiEnvelope>(&raw) {
            if env.format == "aura-dpapi-v1" {
                if let Ok(cipher) = B64.decode(env.data.trim()) {
                    if let Ok(plain) = dpapi_unprotect(&cipher) {
                        if let Ok(val) = serde_json::from_slice::<T>(&plain) {
                            return val;
                        }
                    }
                }
                self.quarantine_corrupt_file(file_name);
                return T::default();
            }
        }

        // Legacy plaintext JSON (v0.4.0 and earlier) -> decode transparently
        match serde_json::from_str::<T>(&raw) {
            Ok(val) => val,
            Err(_) => {
                self.quarantine_corrupt_file(file_name);
                T::default()
            }
        }
    }

    fn write_json_atomic<T: Serialize>(&self, file_name: &str, value: &T) -> Result<(), String> {
        let target = self.base_dir.join(file_name);
        let serialized = serde_json::to_vec_pretty(value)
            .map_err(|e| format!("Ошибка сериализации {file_name}: {e}"))?;
        atomic_write_bytes(&target, &serialized)
    }

    pub fn write_dpapi_json_atomic<T: Serialize + ?Sized>(
        &self,
        file_name: &str,
        value: &T,
    ) -> Result<(), String> {
        let plain = serde_json::to_vec(value)
            .map_err(|e| format!("Ошибка сериализации {file_name}: {e}"))?;
        let cipher = dpapi_protect(&plain)?;
        let env = DpapiEnvelope {
            format: "aura-dpapi-v1".to_string(),
            data: B64.encode(cipher),
        };
        let encoded = serde_json::to_vec_pretty(&env)
            .map_err(|e| format!("Ошибка упаковки DPAPI {file_name}: {e}"))?;
        atomic_write_bytes(&self.base_dir.join(file_name), &encoded)
    }

    pub fn is_plaintext_legacy(&self, file_name: &str) -> bool {
        let path = self.base_dir.join(file_name);
        let Ok(raw) = fs::read_to_string(&path) else {
            return false;
        };
        if raw.trim().is_empty() {
            return false;
        }
        serde_json::from_str::<DpapiEnvelope>(&raw)
            .map(|env| env.format != "aura-dpapi-v1")
            .unwrap_or(true)
    }

    pub fn load_profiles(&self) -> Vec<ServerProfile> {
        self.read_dpapi_or_legacy_json("profiles.json")
    }

    pub fn save_profiles(&self, profiles: &[ServerProfile]) -> Result<(), String> {
        self.write_dpapi_json_atomic("profiles.json", &profiles)
    }

    pub fn load_subscriptions(&self) -> Vec<Subscription> {
        self.read_dpapi_or_legacy_json("subscriptions.json")
    }

    pub fn save_subscriptions(&self, subscriptions: &[Subscription]) -> Result<(), String> {
        self.write_dpapi_json_atomic("subscriptions.json", &subscriptions)
    }

    pub fn load_settings(&self) -> AppSettings {
        self.read_json_or_default("settings.json")
    }

    pub fn save_settings(&self, settings: &AppSettings) -> Result<(), String> {
        self.write_json_atomic("settings.json", settings)
    }

    pub fn load_history(&self) -> Vec<ConnectionHistoryEntry> {
        self.read_dpapi_or_legacy_json("history.json")
    }

    pub fn append_history_entry(&self, entry: ConnectionHistoryEntry) -> Result<(), String> {
        let _guard = self.history_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut items = self.load_history();
        items.insert(0, entry);
        items.truncate(MAX_HISTORY_ENTRIES);
        self.write_dpapi_json_atomic("history.json", &items)
    }

    pub fn clear_history(&self) -> Result<(), String> {
        let _guard = self.history_lock.lock().unwrap_or_else(|p| p.into_inner());
        let empty: Vec<ConnectionHistoryEntry> = Vec::new();
        self.write_dpapi_json_atomic("history.json", &empty)
    }

    fn safe_sub_backup_rel(sub_id: &str) -> Result<String, String> {
        if sub_id.is_empty()
            || sub_id.len() > 80
            || !sub_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("Некорректный идентификатор подписки".into());
        }
        Ok(format!("sub-backups/{sub_id}.json"))
    }

    pub fn save_subscription_backup(
        &self,
        sub_id: &str,
        profiles: &[ServerProfile],
    ) -> Result<(), String> {
        let rel = Self::safe_sub_backup_rel(sub_id)?;
        let dir = self.base_dir.join("sub-backups");
        fs::create_dir_all(&dir)
            .map_err(|e| format!("Не удалось создать папку резервных копий подписок: {e}"))?;
        self.write_dpapi_json_atomic(&rel, profiles)
    }

    pub fn has_subscription_backup(&self, sub_id: &str) -> bool {
        Self::safe_sub_backup_rel(sub_id)
            .map(|rel| self.base_dir.join(rel).exists())
            .unwrap_or(false)
    }

    pub fn load_subscription_backup(&self, sub_id: &str) -> Result<Vec<ServerProfile>, String> {
        let rel = Self::safe_sub_backup_rel(sub_id)?;
        if !self.base_dir.join(&rel).exists() {
            return Err("Резервная копия предыдущего состояния подписки отсутствует.".into());
        }
        Ok(self.read_dpapi_or_legacy_json(&rel))
    }

    pub fn delete_subscription_backup(&self, sub_id: &str) {
        if let Ok(rel) = Self::safe_sub_backup_rel(sub_id) {
            secure_delete_file(&self.base_dir.join(rel));
        }
    }

    fn safe_profile_history_rel(profile_id: &str) -> Result<String, String> {
        if profile_id.is_empty()
            || profile_id.len() > 80
            || !profile_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("Некорректный идентификатор профиля".into());
        }
        Ok(format!("profile-history/{profile_id}.json"))
    }

    pub fn load_profile_revisions(&self, profile_id: &str) -> Vec<StoredProfileRevision> {
        let Ok(rel) = Self::safe_profile_history_rel(profile_id) else {
            return Vec::new();
        };
        self.read_dpapi_or_legacy_json(&rel)
    }

    pub fn append_profile_revision(
        &self,
        profile_id: &str,
        revision: StoredProfileRevision,
    ) -> Result<(), String> {
        let rel = Self::safe_profile_history_rel(profile_id)?;
        let dir = self.base_dir.join("profile-history");
        fs::create_dir_all(&dir)
            .map_err(|e| format!("Не удалось создать папку истории профилей: {e}"))?;
        let mut items: Vec<StoredProfileRevision> = self.read_dpapi_or_legacy_json(&rel);
        items.insert(0, revision);
        items.truncate(15);
        self.write_dpapi_json_atomic(&rel, &items)
    }

    pub fn count_subscription_backups(&self) -> usize {
        fs::read_dir(self.base_dir.join("sub-backups"))
            .map(|rd| rd.flatten().filter(|e| e.path().is_file()).count())
            .unwrap_or(0)
    }

    pub fn clear_all_subscription_backups(&self) -> usize {
        let mut count = 0usize;
        if let Ok(rd) = fs::read_dir(self.base_dir.join("sub-backups")) {
            for entry in rd.flatten() {
                if entry.path().is_file() {
                    secure_delete_file(&entry.path());
                    count += 1;
                }
            }
        }
        count
    }

    pub fn clear_all_profile_revisions(&self) -> usize {
        let mut count = 0usize;
        if let Ok(rd) = fs::read_dir(self.base_dir.join("profile-history")) {
            for entry in rd.flatten() {
                if entry.path().is_file() {
                    secure_delete_file(&entry.path());
                    count += 1;
                }
            }
        }
        count
    }

    pub fn load_server_quality(&self) -> HashMap<String, ServerQualityMetrics> {
        self.read_json_or_default("server-quality.json")
    }

    pub fn save_server_quality(
        &self,
        map: &HashMap<String, ServerQualityMetrics>,
    ) -> Result<(), String> {
        self.write_json_atomic("server-quality.json", map)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredProfileRevision {
    pub revision_id: String,
    pub timestamp: String,
    pub note: String,
    pub summary: String,
    pub snapshot: ServerProfile,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ProtocolDetails, ProtocolType, ShadowsocksDetails};

    #[test]
    fn dpapi_encrypts_secrets_and_reads_legacy_plaintext() {
        let dir = std::env::temp_dir().join(format!("aura_dpapi_test_{}", uuid::Uuid::new_v4()));
        let storage = AppStorage::new(dir.clone()).unwrap();

        let sample = ServerProfile {
            id: "s1".to_string(),
            name: "Demo".to_string(),
            protocol: ProtocolType::Shadowsocks,
            address: "example.com".to_string(),
            port: 8388,
            country_code: Some("DE".to_string()),
            subscription_id: None,
            latency_ms: Some(42),
            details: ProtocolDetails::Shadowsocks(ShadowsocksDetails {
                method: "chacha20-ietf-poly1305".to_string(),
                password: "super-secret-password-xyz".to_string(),
                uot: false,
                plugin: None,
                plugin_opts: None,
            }),
            created_at: "2026-11-24T10:00:00Z".to_string(),
            favorite: false,
            last_used_at: None,
            fingerprint_key: None,
            custom_name: None,
            overrides: None,
            original_source: None,
            config_revision: 0,
        };

        // Write legacy plaintext v0.4.0 file
        let legacy_json = serde_json::to_string_pretty(&vec![sample.clone()]).unwrap();
        fs::write(dir.join("profiles.json"), legacy_json).unwrap();

        let loaded = storage.load_profiles();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "Demo");

        // Re-save -> encrypted with DPAPI (plaintext secret must not appear on disk)
        storage.save_profiles(&loaded).unwrap();
        let on_disk = fs::read_to_string(dir.join("profiles.json")).unwrap();
        assert!(on_disk.contains("aura-dpapi-v1"));
        assert!(!on_disk.contains("super-secret-password-xyz"));

        let decrypted = storage.load_profiles();
        assert_eq!(decrypted.len(), 1);
        assert_eq!(decrypted[0].address, "example.com");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_json_is_quarantined_to_backup() {
        let dir = std::env::temp_dir().join(format!("aura_corrupt_test_{}", uuid::Uuid::new_v4()));
        let storage = AppStorage::new(dir.clone()).unwrap();
        fs::write(dir.join("settings.json"), "{broken json").unwrap();

        let _ = storage.load_settings();
        assert!(!dir.join("settings.json").exists());
        let has_corrupt_bak = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains(".corrupt."));
        assert!(has_corrupt_bak);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweeps_stale_tmp_files_and_encrypts_history_dpapi() {
        let dir = std::env::temp_dir().join(format!("aura_hist_test_{}", uuid::Uuid::new_v4()));
        let storage = AppStorage::new(dir.clone()).unwrap();
        fs::write(dir.join("settings.json.123.tmp"), b"stale").unwrap();
        let swept = storage.sweep_stale_runtime_files();
        assert!(swept >= 1);
        assert!(!dir.join("settings.json.123.tmp").exists());

        storage
            .append_history_entry(ConnectionHistoryEntry {
                id: "h1".to_string(),
                server_id: Some("s1".to_string()),
                server_name: "Private-Server-Secret".to_string(),
                country_code: Some("NL".to_string()),
                protocol: "vless".to_string(),
                mode: crate::models::ConnectionMode::SystemProxy,
                started_at: "2026-11-24T12:00:00Z".to_string(),
                ended_at: "2026-11-24T12:05:00Z".to_string(),
                duration_secs: 300,
                rx_bytes: 1024,
                tx_bytes: 512,
                end_reason: "disconnected".to_string(),
                reconnect_count: 0,
            })
            .unwrap();
        let disk = fs::read_to_string(dir.join("history.json")).unwrap();
        assert!(disk.contains("aura-dpapi-v1"));
        assert!(!disk.contains("Private-Server-Secret"));
        assert_eq!(storage.load_history().len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }
}
