use crate::models::{LogEntry, LogLevel};
use chrono::Local;
use regex::Regex;
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use tauri::{AppHandle, Emitter};

const MAX_LOG_ENTRIES: usize = 300;

static UUID_RE: OnceLock<Regex> = OnceLock::new();
static VPN_URI_RE: OnceLock<Regex> = OnceLock::new();
static HTTP_SUB_URI_RE: OnceLock<Regex> = OnceLock::new();
static QUERY_SECRET_RE: OnceLock<Regex> = OnceLock::new();
static JSON_SECRET_RE: OnceLock<Regex> = OnceLock::new();
static INI_SECRET_RE: OnceLock<Regex> = OnceLock::new();
static HEADER_SECRET_RE: OnceLock<Regex> = OnceLock::new();
static WIN_USER_PATH_RE: OnceLock<Regex> = OnceLock::new();
static WG_B64_KEY_RE: OnceLock<Regex> = OnceLock::new();

pub fn redact_secrets(input: &str) -> String {
    let uuid_re = UUID_RE.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
            .expect("valid uuid regex")
    });
    let vpn_uri_re = VPN_URI_RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(vless|vmess|trojan|ss|hysteria2|hy2|hysteria|vpn|wireguard|wg|happ|v2raytun|hiddify|streisand|v2box|sing-box|sub)://([^\s#]+)",
        )
        .expect("valid vpn uri regex")
    });
    let http_sub_uri_re = HTTP_SUB_URI_RE.get_or_init(|| {
        Regex::new(r"(?i)\b(https?://)([^/\s]+)([^\s]*)").expect("valid http uri regex")
    });
    let query_re = QUERY_SECRET_RE.get_or_init(|| {
        Regex::new(r"(?i)\b(pbk|publickey|sid|shortid|password|obfs-password|obfspassword|privatekey|secretkey|presharedkey|token|secret|auth|key|uuid)=([^&\s]+)")
            .expect("valid query regex")
    });
    let json_re = JSON_SECRET_RE.get_or_init(|| {
        Regex::new(r#"(?i)("(?:id|password|publicKey|shortId|privateKey|secretKey|presharedKey|obfsPassword|pbk|sid|token|auth|secret)"\s*:\s*")([^"]+)(")"#)
            .expect("valid json regex")
    });
    let ini_re = INI_SECRET_RE.get_or_init(|| {
        Regex::new(r"(?im)^(\s*(?:PrivateKey|PresharedKey|PublicKey|Password)\s*=\s*)(\S+)")
            .expect("valid ini regex")
    });
    let header_re = HEADER_SECRET_RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(x-hwid\s*[:=]\s*|Authorization\s*:\s*(?:Bearer|Basic)\s+)([a-zA-Z0-9._+/=-]+)",
        )
        .expect("valid header regex")
    });
    let win_user_re = WIN_USER_PATH_RE.get_or_init(|| {
        Regex::new(r"(?i)([A-Z]:\\Users\\)([^\\\s/]+)").expect("valid win user path regex")
    });
    let wg_b64_re = WG_B64_KEY_RE.get_or_init(|| {
        Regex::new(r"(?m)(^|[^A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{43}=?)")
            .expect("valid wg/x25519 key regex")
    });

    let s1 = vpn_uri_re.replace_all(input, "$1://[REDACTED]");
    let s2 = http_sub_uri_re.replace_all(&s1, |caps: &regex::Captures| {
        let scheme = &caps[1];
        let auth_host = &caps[2];
        let path_q = &caps[3];
        let clean_host = auth_host.rsplit('@').next().unwrap_or(auth_host);
        if path_q.is_empty() || path_q == "/" {
            format!("{scheme}{clean_host}{path_q}")
        } else {
            format!("{scheme}{clean_host}/[REDACTED]")
        }
    });
    let s3 = uuid_re.replace_all(&s2, "[REDACTED-UUID]");
    let s4 = query_re.replace_all(&s3, "$1=[REDACTED]");
    let s5 = json_re.replace_all(&s4, "${1}[REDACTED]${3}");
    let s6 = ini_re.replace_all(&s5, "${1}[REDACTED]");
    let s7 = header_re.replace_all(&s6, "${1}[REDACTED]");
    let s8 = win_user_re.replace_all(&s7, "${1}[USER]");
    wg_b64_re
        .replace_all(&s8, "${1}[REDACTED-KEY]")
        .into_owned()
}

pub struct AppLogger {
    entries: Mutex<VecDeque<LogEntry>>,
    next_id: Mutex<u64>,
    app_handle: Mutex<Option<AppHandle>>,
}

impl AppLogger {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(MAX_LOG_ENTRIES)),
            next_id: Mutex::new(1),
            app_handle: Mutex::new(None),
        }
    }

    pub fn attach_app(&self, handle: AppHandle) {
        if let Ok(mut guard) = self.app_handle.lock() {
            *guard = Some(handle);
        }
    }

    pub fn log(&self, level: LogLevel, source: &str, message: &str) {
        let clean = redact_secrets(message);
        let id = {
            let mut n = self.next_id.lock().unwrap_or_else(|p| p.into_inner());
            let current = *n;
            *n += 1;
            current
        };
        let entry = LogEntry {
            id,
            timestamp: Local::now().format("%H:%M:%S").to_string(),
            level,
            source: source.to_string(),
            message: clean,
        };
        {
            let mut guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
            if guard.len() >= MAX_LOG_ENTRIES {
                guard.pop_front();
            }
            guard.push_back(entry.clone());
        }
        let app_opt = self
            .app_handle
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(app) = app_opt {
            let _ = app.emit("log-entry", &entry);
        }
    }

    pub fn info(&self, source: &str, message: &str) {
        self.log(LogLevel::Info, source, message);
    }

    pub fn warn(&self, source: &str, message: &str) {
        self.log(LogLevel::Warn, source, message);
    }

    pub fn error(&self, source: &str, message: &str) {
        self.log(LogLevel::Error, source, message);
    }

    pub fn list(&self) -> Vec<LogEntry> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    pub fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }
}

impl Default for AppLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_uuids_keys_and_uris() {
        let raw = "vless://550e8400-e29b-41d4-a716-446655440000@example.com:443?pbk=SECRET_PBK&sid=12ab#Demo";
        let red = redact_secrets(raw);
        assert!(!red.contains("550e8400"));
        assert!(!red.contains("SECRET_PBK"));
        assert!(red.contains("[REDACTED]"));
    }

    #[test]
    fn redacts_json_secrets() {
        let raw = r#"{"id":"my-secret-id","privateKey":"abc123","obfsPassword":"pw"}"#;
        let red = redact_secrets(raw);
        assert!(!red.contains("my-secret-id"));
        assert!(!red.contains("abc123"));
        assert!(!red.contains("pw"));
    }

    #[test]
    fn redacts_http_tokens_bearer_wg_keys_and_windows_username() {
        let raw = r#"https://sub.example.com/api/v1/secret-token-xyz Authorization: Bearer tok123 PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= C:\Users\alice\AppData\Local\AURA VPN"#;
        let red = redact_secrets(raw);
        assert!(!red.contains("secret-token-xyz"));
        assert!(!red.contains("tok123"));
        assert!(!red.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(!red.contains("alice"));
        assert!(red.contains("https://sub.example.com/[REDACTED]"));
        assert!(red.contains("C:\\Users\\[USER]"));
    }
}
