use super::{clean_host, extract_country_code, percent_decode};
use crate::models::{Hysteria2Details, ProtocolDetails, ProtocolType, ServerProfile};
use chrono::Utc;
use std::collections::HashMap;
use url::Url;

pub fn parse_bandwidth_mbps(raw: &str) -> Option<u32> {
    let low = raw.trim().to_ascii_lowercase();
    if low.is_empty() {
        return None;
    }
    let digits_end = low
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(low.len());
    let num: f64 = low[..digits_end].parse().ok()?;
    if !num.is_finite() || num <= 0.0 {
        return None;
    }
    let unit = low[digits_end..].trim();
    let mbps = if unit.starts_with('g') {
        num * 1000.0
    } else if unit.starts_with('k') {
        (num / 1000.0).max(1.0)
    } else if unit.starts_with('b') && !unit.starts_with("bps") {
        num / 125_000.0
    } else {
        num
    };
    Some(mbps.round().clamp(1.0, u32::MAX as f64) as u32)
}

pub fn normalize_pin_sha256(raw: &str) -> Option<String> {
    let cleaned = raw.trim().trim_start_matches("sha256/").trim();
    if cleaned.is_empty() {
        return None;
    }
    let no_colons: String = cleaned.chars().filter(|c| *c != ':' && *c != '-').collect();
    if no_colons.len() == 64 && no_colons.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(no_colons.to_ascii_lowercase());
    }
    if let Ok(bytes) = super::decode_base64_flexible(cleaned) {
        if bytes.len() == 32 {
            return Some(bytes.iter().map(|b| format!("{b:02x}")).collect());
        }
    }
    Some(no_colons)
}

pub fn parse_hysteria2(
    uri: &str,
    subscription_id: Option<String>,
) -> Result<ServerProfile, String> {
    let trimmed = uri.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("hysteria://") {
        return Err("Протокол Hysteria v1 (hysteria://) устарел и не поддерживается Xray-core — используйте Hysteria2 (hy2:// или hysteria2://)".to_string());
    }
    let normalized_for_url = if lower.starts_with("hy2://") {
        format!("hysteria2://{}", &trimmed[6..])
    } else {
        trimmed.to_string()
    };

    let parsed = Url::parse(&normalized_for_url)
        .map_err(|_| "Некорректный формат Hysteria2 URL".to_string())?;
    if !parsed.scheme().eq_ignore_ascii_case("hysteria2") {
        return Err("Ожидалась схема hysteria2:// или hy2://".to_string());
    }

    let params: HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.into_owned()))
        .collect();

    let password = {
        let user = percent_decode(parsed.username());
        let user_pw = match parsed.password() {
            Some(pw) if !pw.is_empty() => format!("{user}:{}", percent_decode(pw)),
            _ => user,
        };
        if !user_pw.is_empty() {
            user_pw
        } else {
            params
                .get("auth")
                .or_else(|| params.get("password"))
                .cloned()
                .unwrap_or_default()
        }
    };
    if password.is_empty() {
        return Err("В ключе Hysteria2 отсутствует пароль аутентификации".to_string());
    }

    let host = parsed
        .host_str()
        .map(clean_host)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "В ключе Hysteria2 не указан адрес сервера".to_string())?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("Некорректный порт Hysteria2-сервера".to_string());
    }

    let sni = params.get("sni").cloned().filter(|s| !s.is_empty());
    let obfs = params
        .get("obfs")
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| !s.is_empty() && s != "none");
    let obfs_password = params
        .get("obfs-password")
        .or_else(|| params.get("obfspassword"))
        .cloned()
        .filter(|s| !s.is_empty());

    let up_mbps = params
        .get("upmbps")
        .or_else(|| params.get("up"))
        .and_then(|v| parse_bandwidth_mbps(v));
    let down_mbps = params
        .get("downmbps")
        .or_else(|| params.get("down"))
        .and_then(|v| parse_bandwidth_mbps(v));
    let mport = params.get("mport").cloned().filter(|s| !s.is_empty());
    let hop_interval_secs = params
        .get("hop-interval")
        .or_else(|| params.get("hopinterval"))
        .and_then(|s| s.trim_end_matches('s').parse::<u32>().ok())
        .filter(|&v| v > 0);

    let alpn = params
        .get("alpn")
        .map(|v| {
            v.split(',')
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|list| !list.is_empty());

    let allow_insecure = params
        .get("insecure")
        .or_else(|| params.get("allowinsecure"))
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let pinned_cert_sha256 = params
        .get("pinsha256")
        .or_else(|| params.get("pcs"))
        .or_else(|| params.get("pinnedpeercertsha256"))
        .and_then(|s| normalize_pin_sha256(s));
    let verify_peer_cert_by_name = params
        .get("vcn")
        .or_else(|| params.get("verifypeercertbyname"))
        .cloned()
        .filter(|s| !s.is_empty());

    let name = parsed
        .fragment()
        .map(percent_decode)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{host}:{port}"));
    let country_code = extract_country_code(&name);

    Ok(ServerProfile {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        protocol: ProtocolType::Hysteria2,
        address: host,
        port,
        country_code,
        subscription_id,
        latency_ms: None,
        details: ProtocolDetails::Hysteria2(Hysteria2Details {
            password,
            sni,
            obfs,
            obfs_password,
            up_mbps,
            down_mbps,
            alpn,
            allow_insecure,
            pinned_cert_sha256,
            verify_peer_cert_by_name,
            mport,
            hop_interval_secs,
        }),
        created_at: Utc::now().to_rfc3339(),
        favorite: false,
        last_used_at: None,
        fingerprint_key: None,
        custom_name: None,
        overrides: None,
        original_source: None,
        config_revision: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_hysteria2;
    use crate::models::{ProtocolDetails, ProtocolType};

    #[test]
    fn parses_hy2_and_hysteria2_uris() {
        let uri = "hy2://mySecretPass@fi.example.com:8443/?sni=fi.example.com&obfs=salamander&obfs-password=obfsPass&upmbps=100&downmbps=300&insecure=1#FI%20Turbo";
        let profile = parse_hysteria2(uri, None).expect("valid hy2 uri");
        assert_eq!(profile.protocol, ProtocolType::Hysteria2);
        assert_eq!(profile.name, "FI Turbo");
        assert_eq!(profile.port, 8443);
        assert_eq!(profile.country_code.as_deref(), Some("FI"));
        match profile.details {
            ProtocolDetails::Hysteria2(d) => {
                assert_eq!(d.password, "mySecretPass");
                assert_eq!(d.obfs.as_deref(), Some("salamander"));
                assert_eq!(d.obfs_password.as_deref(), Some("obfsPass"));
                assert_eq!(d.up_mbps, Some(100));
                assert_eq!(d.down_mbps, Some(300));
                assert!(d.allow_insecure);
            }
            _ => panic!("expected Hysteria2 details"),
        }
    }
}
