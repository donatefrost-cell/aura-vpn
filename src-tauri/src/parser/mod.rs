pub mod amnezia;
pub mod clash;
pub mod hysteria2;
pub mod raw_json;
pub mod shadowsocks;
pub mod trojan;
pub mod vless;
pub mod vmess;
pub mod wireguard;

use crate::models::{ImportResult, ServerProfile};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use regex::Regex;
use std::sync::OnceLock;
use url::Url;

static EMBEDDED_URI_RE: OnceLock<Regex> = OnceLock::new();
static EMBEDDED_HTTP_RE: OnceLock<Regex> = OnceLock::new();

pub const MAX_IMPORT_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_IMPORT_LINES: usize = 2_000;
pub const MAX_IMPORT_SERVERS: usize = 500;
pub const MAX_DEEPLINK_DEPTH: usize = 3;

pub fn decode_base64_flexible(input: &str) -> Result<Vec<u8>, String> {
    if input.len() > MAX_IMPORT_BYTES * 2 {
        return Err("Входные Base64-данные превышают допустимый размер".to_string());
    }
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return Err("Пустая Base64-строка".to_string());
    }
    if compact.len() > MAX_IMPORT_BYTES * 2 {
        return Err("Входные Base64-данные превышают допустимый размер".to_string());
    }
    STANDARD
        .decode(&compact)
        .or_else(|_| STANDARD_NO_PAD.decode(&compact))
        .or_else(|_| URL_SAFE.decode(&compact))
        .or_else(|_| URL_SAFE_NO_PAD.decode(&compact))
        .map_err(|_| "Некорректная кодировка Base64".to_string())
}

pub fn decode_base64_text(input: &str) -> Result<String, String> {
    let bytes = decode_base64_flexible(input)?;
    String::from_utf8(bytes).map_err(|_| "Base64 не содержит корректный текст UTF-8".to_string())
}

use sha2::{Digest, Sha256};

pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn has_clash_proxies_key(text: &str) -> bool {
    text.lines().any(|l| {
        let t = l.trim_start();
        t == "proxies:" || t.starts_with("proxies:")
    })
}

pub fn compute_profile_fingerprint(p: &ServerProfile) -> String {
    use crate::models::ProtocolDetails;
    let mut h = Sha256::new();
    h.update(
        format!(
            "{:?}|{}|{}|",
            p.protocol,
            p.address.trim().to_ascii_lowercase(),
            p.port
        )
        .as_bytes(),
    );
    match &p.details {
        ProtocolDetails::Vless(d) => {
            h.update(
                format!(
                    "{}|{}|{}|{}",
                    d.uuid,
                    d.network,
                    d.sni.as_deref().unwrap_or(""),
                    d.path.as_deref().unwrap_or("")
                )
                .as_bytes(),
            );
        }
        ProtocolDetails::Vmess(d) => {
            h.update(
                format!(
                    "{}|{}|{}|{}",
                    d.uuid,
                    d.network,
                    d.sni.as_deref().unwrap_or(""),
                    d.path.as_deref().unwrap_or("")
                )
                .as_bytes(),
            );
        }
        ProtocolDetails::Trojan(d) => {
            h.update(
                format!(
                    "{}|{}|{}|{}",
                    d.password,
                    d.network,
                    d.sni.as_deref().unwrap_or(""),
                    d.path.as_deref().unwrap_or("")
                )
                .as_bytes(),
            );
        }
        ProtocolDetails::Shadowsocks(d) => {
            h.update(format!("{}|{}", d.method, d.password).as_bytes());
        }
        ProtocolDetails::Hysteria2(d) => {
            h.update(
                format!(
                    "{}|{}|{}",
                    d.password,
                    d.sni.as_deref().unwrap_or(""),
                    d.mport.as_deref().unwrap_or("")
                )
                .as_bytes(),
            );
        }
        ProtocolDetails::Wireguard(d) => {
            h.update(format!("{}|{}", d.public_key, d.endpoint).as_bytes());
        }
        ProtocolDetails::AmneziaWg(d) => {
            h.update(
                format!(
                    "{}|{}|{}",
                    d.public_key,
                    d.endpoint,
                    d.jc.as_deref().unwrap_or("")
                )
                .as_bytes(),
            );
        }
        ProtocolDetails::RawXray(d) => {
            h.update(format!("{}|{}", d.label, d.outbound_json).as_bytes());
        }
    }
    let digest = h.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn clean_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

pub fn extract_country_code(name: &str) -> Option<String> {
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        let code = c as u32;
        if (0x1F1E6..=0x1F1FF).contains(&code) {
            if let Some(&next) = chars.peek() {
                let next_code = next as u32;
                if (0x1F1E6..=0x1F1FF).contains(&next_code) {
                    let a = char::from_u32((code - 0x1F1E6) + b'A' as u32)?;
                    let b = char::from_u32((next_code - 0x1F1E6) + b'A' as u32)?;
                    return Some(format!("{a}{b}"));
                }
            }
        }
    }

    let upper = name.to_uppercase();
    let known = [
        ("EUROPE", "EU"),
        ("ЕВРОП", "EU"),
        ("АВТОВЫБОР", "EU"),
        ("NETHERLANDS", "NL"),
        ("AMSTERDAM", "NL"),
        ("НИДЕРЛАНД", "NL"),
        ("ГОЛЛАНД", "NL"),
        ("GERMANY", "DE"),
        ("FRANKFURT", "DE"),
        ("ГЕРМАНИ", "DE"),
        ("FINLAND", "FI"),
        ("HELSINKI", "FI"),
        ("ФИНЛЯНД", "FI"),
        ("UNITED STATES", "US"),
        ("USA", "US"),
        ("США", "US"),
        ("АМЕРИК", "US"),
        ("UNITED KINGDOM", "GB"),
        ("LONDON", "GB"),
        ("ВЕЛИКОБРИТ", "GB"),
        ("АНГЛИ", "GB"),
        ("SWEDEN", "SE"),
        ("STOCKHOLM", "SE"),
        ("ШВЕЦИ", "SE"),
        ("POLAND", "PL"),
        ("WARSAW", "PL"),
        ("ПОЛЬШ", "PL"),
        ("FRANCE", "FR"),
        ("PARIS", "FR"),
        ("ФРАНЦИ", "FR"),
        ("TURKEY", "TR"),
        ("ISTANBUL", "TR"),
        ("ТУРЦИ", "TR"),
        ("SINGAPORE", "SG"),
        ("СИНГАПУР", "SG"),
        ("JAPAN", "JP"),
        ("TOKYO", "JP"),
        ("ЯПОНИ", "JP"),
        ("LATVIA", "LV"),
        ("RIGA", "LV"),
        ("ЛАТВИ", "LV"),
        ("ESTONIA", "EE"),
        ("TALLINN", "EE"),
        ("ЭСТОНИ", "EE"),
        ("LITHUANIA", "LT"),
        ("VILNIUS", "LT"),
        ("ЛИТВ", "LT"),
        ("AUSTRIA", "AT"),
        ("VIENNA", "AT"),
        ("АВСТРИ", "AT"),
        ("SWITZERLAND", "CH"),
        ("ZURICH", "CH"),
        ("ШВЕЙЦАР", "CH"),
        ("CANADA", "CA"),
        ("КАНАД", "CA"),
        ("KAZAKHSTAN", "KZ"),
        ("КАЗАХСТАН", "KZ"),
        ("RUSSIA", "RU"),
        ("MOSCOW", "RU"),
        ("РОССИ", "RU"),
        ("UKRAINE", "UA"),
        ("УКРАИН", "UA"),
        ("ITALY", "IT"),
        ("MILAN", "IT"),
        ("ИТАЛИ", "IT"),
        ("SPAIN", "ES"),
        ("MADRID", "ES"),
        ("ИСПАНИ", "ES"),
        ("CZECH", "CZ"),
        ("PRAGUE", "CZ"),
        ("ЧЕХИ", "CZ"),
        ("NORWAY", "NO"),
        ("OSLO", "NO"),
        ("НОРВЕГ", "NO"),
        ("HONG KONG", "HK"),
        ("ГОНКОНГ", "HK"),
        ("KOREA", "KR"),
        ("SEOUL", "KR"),
        ("КОРЕ", "KR"),
        ("EMIRATES", "AE"),
        ("DUBAI", "AE"),
        ("UAE", "AE"),
        ("ЭМИРАТ", "AE"),
        ("ОАЭ", "AE"),
        ("ДУБА", "AE"),
        ("INDIA", "IN"),
        ("MUMBAI", "IN"),
        ("ИНДИ", "IN"),
        ("BRAZIL", "BR"),
        ("SAO PAULO", "BR"),
        ("БРАЗИЛ", "BR"),
        ("AUSTRALIA", "AU"),
        ("SYDNEY", "AU"),
        ("АВСТРАЛ", "AU"),
        ("BELGIUM", "BE"),
        ("БЕЛЬГ", "BE"),
        ("DENMARK", "DK"),
        ("ДАНИ", "DK"),
        ("IRELAND", "IE"),
        ("ИРЛАНД", "IE"),
        ("PORTUGAL", "PT"),
        ("ПОРТУГАЛ", "PT"),
        ("GREECE", "GR"),
        ("ГРЕЦ", "GR"),
        ("ROMANIA", "RO"),
        ("РУМЫН", "RO"),
        ("BULGARIA", "BG"),
        ("БОЛГАР", "BG"),
        ("HUNGARY", "HU"),
        ("ВЕНГР", "HU"),
        ("SLOVAKIA", "SK"),
        ("СЛОВАК", "SK"),
        ("MOLDOVA", "MD"),
        ("МОЛДОВ", "MD"),
        ("ARMENIA", "AM"),
        ("АРМЕН", "AM"),
        ("GEORGIA", "GE"),
        ("ГРУЗ", "GE"),
        ("ISRAEL", "IL"),
        ("ИЗРАИЛ", "IL"),
        ("CYPRUS", "CY"),
        ("КИПР", "CY"),
        ("SERBIA", "RS"),
        ("СЕРБ", "RS"),
        ("ICELAND", "IS"),
        ("ИСЛАНД", "IS"),
        ("LUXEMBOURG", "LU"),
        ("ЛЮКСЕМБУРГ", "LU"),
        ("TAIWAN", "TW"),
        ("ТАЙВАН", "TW"),
        ("MEXICO", "MX"),
        ("МЕКСИК", "MX"),
        ("ARGENTINA", "AR"),
        ("АРГЕНТИН", "AR"),
        ("BELARUS", "BY"),
        ("БЕЛАРУС", "BY"),
        ("THAILAND", "TH"),
        ("ТАИЛАНД", "TH"),
        ("VIETNAM", "VN"),
        ("ВЬЕТНАМ", "VN"),
        ("INDONESIA", "ID"),
        ("ИНДОНЕЗ", "ID"),
    ];
    for (kw, code) in known {
        if upper.contains(kw) {
            return Some(code.to_string());
        }
    }

    for token in upper.split(|c: char| !c.is_ascii_alphanumeric()) {
        if token.len() == 2
            && matches!(
                token,
                "EU" | "NL"
                    | "DE"
                    | "FI"
                    | "US"
                    | "GB"
                    | "UK"
                    | "SE"
                    | "PL"
                    | "FR"
                    | "TR"
                    | "SG"
                    | "JP"
                    | "LV"
                    | "EE"
                    | "LT"
                    | "AT"
                    | "CH"
                    | "CA"
                    | "KZ"
                    | "RU"
                    | "UA"
                    | "IT"
                    | "ES"
                    | "CZ"
                    | "NO"
                    | "HK"
                    | "KR"
                    | "AE"
                    | "IN"
                    | "BR"
                    | "AU"
                    | "BE"
                    | "DK"
                    | "IE"
                    | "PT"
                    | "GR"
                    | "RO"
                    | "BG"
                    | "HU"
                    | "SK"
                    | "MD"
                    | "AM"
                    | "GE"
                    | "IL"
                    | "CY"
                    | "RS"
                    | "IS"
                    | "LU"
                    | "TW"
                    | "MX"
                    | "AR"
                    | "BY"
                    | "TH"
                    | "VN"
                    | "ID"
            )
        {
            return Some(if token == "UK" {
                "GB".to_string()
            } else {
                token.to_string()
            });
        }
    }

    None
}

fn strip_enclosing_noise(s: &str) -> &str {
    s.trim().trim_matches(|c: char| {
        matches!(
            c,
            '`' | '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';'
        )
    })
}

pub fn unwrap_deeplink_target(raw: &str) -> Option<String> {
    let trimmed = strip_enclosing_noise(raw);
    let lower = trimmed.to_ascii_lowercase();

    for prefix in [
        "happ://add/",
        "happ://import/",
        "v2raytun://import/",
        "hiddify://import/",
        "streisand://import/",
        "v2box://install-sub?url=",
        "v2box://import/",
        "shadowrocket://add/sub://",
    ] {
        if lower.starts_with(prefix) {
            let rest = trimmed[prefix.len()..].trim();
            if rest.is_empty() {
                return None;
            }
            if prefix.ends_with("sub://") {
                if let Ok(decoded) = decode_base64_text(rest) {
                    return Some(decoded.trim().to_string());
                }
            }
            if rest.contains("%3A%2F%2F") || rest.contains("%3a%2f%2f") {
                return Some(percent_decode(rest));
            }
            return Some(rest.to_string());
        }
    }

    if lower.starts_with("sub://") {
        let rest = &trimmed[6..];
        if let Ok(decoded) = decode_base64_text(rest) {
            let clean = decoded.trim().to_string();
            if !clean.is_empty() {
                return Some(clean);
            }
        }
    }

    if lower.starts_with("sing-box://import-remote-profile")
        || lower.starts_with("hiddify://install-config")
        || lower.starts_with("clash://install-config")
    {
        if let Ok(url) = Url::parse(trimmed) {
            for (k, v) in url.query_pairs() {
                if k.eq_ignore_ascii_case("url") && !v.trim().is_empty() {
                    return Some(v.trim().to_string());
                }
            }
        }
    }

    None
}

pub fn extract_subscription_url_from_text(raw: &str) -> Option<String> {
    let trimmed = strip_enclosing_noise(raw);
    if let Some(unwrapped) = unwrap_deeplink_target(trimmed) {
        let low = unwrapped.to_ascii_lowercase();
        if low.starts_with("https://") || low.starts_with("http://") {
            return Some(unwrapped);
        }
    }

    // Search for deep-link or standalone HTTP(S) link in Telegram message prose
    let re_uri = EMBEDDED_URI_RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:happ|v2raytun|hiddify|streisand|v2box|shadowrocket|sing-box|clash|sub)://[^\s`"'<>]+"#)
            .expect("valid deeplink regex")
    });
    for m in re_uri.find_iter(raw) {
        if let Some(target) = unwrap_deeplink_target(m.as_str()) {
            let low = target.to_ascii_lowercase();
            if low.starts_with("https://") || low.starts_with("http://") {
                return Some(target);
            }
        }
    }

    let re_http = EMBEDDED_HTTP_RE
        .get_or_init(|| Regex::new(r#"(?i)https?://[^\s`"'<>]+"#).expect("valid http url regex"));
    // Only treat as subscription URL if there are no direct VPN protocol URIs in text
    let low_raw = raw.to_ascii_lowercase();
    let has_direct_vpn = low_raw.contains("vless://")
        || low_raw.contains("vmess://")
        || low_raw.contains("trojan://")
        || low_raw.contains("ss://")
        || low_raw.contains("hy2://")
        || low_raw.contains("hysteria2://")
        || low_raw.contains("vpn://")
        || low_raw.contains("wg://")
        || low_raw.contains("wireguard://");
    if !has_direct_vpn {
        if let Some(m) = re_http.find(raw) {
            return Some(strip_enclosing_noise(m.as_str()).to_string());
        }
    }

    None
}

pub fn parse_single_uri(
    raw: &str,
    subscription_id: Option<String>,
) -> Result<Vec<ServerProfile>, String> {
    parse_single_uri_inner(raw, subscription_id, 0)
}

fn parse_single_uri_inner(
    raw: &str,
    subscription_id: Option<String>,
    depth: usize,
) -> Result<Vec<ServerProfile>, String> {
    if depth > MAX_DEEPLINK_DEPTH {
        return Err("Превышена допустимая глубина вложенности ссылки".to_string());
    }
    let trimmed = strip_enclosing_noise(raw);
    if trimmed.is_empty() {
        return Err("Пустая строка ключа".to_string());
    }

    if let Some(unwrapped) = unwrap_deeplink_target(trimmed) {
        if !unwrapped.eq_ignore_ascii_case(trimmed) {
            return parse_single_uri_inner(&unwrapped, subscription_id, depth + 1);
        }
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("vless://") {
        Ok(vec![vless::parse_vless(trimmed, subscription_id)?])
    } else if lower.starts_with("vmess://") {
        Ok(vec![vmess::parse_vmess(trimmed, subscription_id)?])
    } else if lower.starts_with("trojan://") {
        Ok(vec![trojan::parse_trojan(trimmed, subscription_id)?])
    } else if lower.starts_with("ss://") {
        Ok(vec![shadowsocks::parse_shadowsocks(
            trimmed,
            subscription_id,
        )?])
    } else if lower.starts_with("hysteria2://")
        || lower.starts_with("hy2://")
        || lower.starts_with("hysteria://")
    {
        Ok(vec![hysteria2::parse_hysteria2(trimmed, subscription_id)?])
    } else if lower.starts_with("wireguard://") || lower.starts_with("wg://") {
        Ok(vec![wireguard::parse_wireguard_uri(
            trimmed,
            subscription_id,
        )?])
    } else if lower.starts_with("vpn://") {
        amnezia::parse_amnezia_vpn_link(trimmed, subscription_id)
    } else {
        Err("Неподдерживаемый или неизвестный формат ключа. Поддерживаются vless://, vmess://, trojan://, ss://, hy2://, vpn://, wg://, JSON, YAML и .conf".to_string())
    }
}

pub fn parse_import_text(raw: &str, subscription_id: Option<String>) -> ImportResult {
    parse_import_text_inner(raw, subscription_id, 0)
}

fn parse_import_text_inner(
    raw: &str,
    subscription_id: Option<String>,
    depth: usize,
) -> ImportResult {
    if raw.len() > MAX_IMPORT_BYTES {
        return ImportResult {
            imported_servers: vec![],
            skipped_lines: 0,
            errors: vec!["Размер импортируемых данных превышает допустимый лимит 5 МБ".to_string()],
        };
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return ImportResult {
            imported_servers: vec![],
            skipped_lines: 0,
            errors: vec!["Вставьте ключ, конфиг или список ключей для импорта".to_string()],
        };
    }

    // 1. JSON (Xray config or Amnezia backup JSON)
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let parsed = if json_val.get("containers").is_some() {
                amnezia::parse_amnezia_json_value(&json_val, subscription_id.clone())
            } else {
                raw_json::parse_xray_json_value(&json_val, None, subscription_id.clone())
            };
            match parsed {
                Ok(list) => {
                    return ImportResult {
                        imported_servers: list,
                        skipped_lines: 0,
                        errors: vec![],
                    };
                }
                Err(e) => {
                    return ImportResult {
                        imported_servers: vec![],
                        skipped_lines: 1,
                        errors: vec![e],
                    };
                }
            }
        }
    }

    // 2. WireGuard / AmneziaWG INI config (.conf)
    if trimmed.contains("[Interface]") && trimmed.contains("[Peer]") {
        match wireguard::parse_wg_ini(trimmed, None, subscription_id.clone()) {
            Ok(srv) => {
                return ImportResult {
                    imported_servers: vec![srv],
                    skipped_lines: 0,
                    errors: vec![],
                };
            }
            Err(e) => {
                return ImportResult {
                    imported_servers: vec![],
                    skipped_lines: 1,
                    errors: vec![e],
                };
            }
        }
    }

    // 3. Clash / Mihomo YAML (`proxies:`)
    if has_clash_proxies_key(trimmed) {
        match clash::parse_clash_yaml(trimmed, subscription_id.clone()) {
            Ok(list) => {
                return ImportResult {
                    imported_servers: list,
                    skipped_lines: 0,
                    errors: vec![],
                };
            }
            Err(e) => {
                return ImportResult {
                    imported_servers: vec![],
                    skipped_lines: 1,
                    errors: vec![e],
                };
            }
        }
    }

    // 4. Base64-encoded block (common for subscriptions or raw Telegram base64 pastes)
    let normalized = if !trimmed.contains("://") {
        decode_base64_text(trimmed).unwrap_or_else(|_| trimmed.to_string())
    } else {
        trimmed.to_string()
    };

    // Re-check decoded Base64 for JSON / Clash YAML / INI
    let norm_trim = normalized.trim();
    if depth == 0
        && norm_trim != trimmed
        && (norm_trim.starts_with('{')
            || norm_trim.starts_with('[')
            || has_clash_proxies_key(norm_trim)
            || (norm_trim.contains("[Interface]") && norm_trim.contains("[Peer]")))
    {
        return parse_import_text_inner(norm_trim, subscription_id, depth + 1);
    }

    let mut imported_servers = Vec::new();
    let mut skipped_lines = 0usize;
    let mut errors = Vec::new();

    for line in normalized.lines().take(MAX_IMPORT_LINES) {
        if imported_servers.len() >= MAX_IMPORT_SERVERS {
            break;
        }
        let line = strip_enclosing_noise(line);
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        let line_low = line.to_ascii_lowercase();
        let starts_with_known_vpn_uri = [
            "vless://",
            "vmess://",
            "trojan://",
            "ss://",
            "hy2://",
            "hysteria2://",
            "hysteria://",
            "wg://",
            "wireguard://",
            "vpn://",
        ]
        .iter()
        .any(|p| line_low.starts_with(p));

        // If the entire line IS a single VPN URI (preserving unencoded spaces inside #Fragment), keep it intact!
        let extracted_uris: Vec<String> = if starts_with_known_vpn_uri
            && line.matches("://").count() == 1
        {
            vec![line.to_string()]
        } else if line.contains("://") {
            let mut found = Vec::new();
            let mut rest = line;
            while let Some(idx) = rest.find("://") {
                // Walk backwards to scheme start (alphanumeric, +, -, .)
                let prefix = &rest[..idx];
                let scheme_start = prefix
                    .char_indices()
                    .rev()
                    .find(|(_, c)| {
                        !(c.is_ascii_alphanumeric() || *c == '+' || *c == '-' || *c == '.')
                    })
                    .map(|(p, c)| p + c.len_utf8())
                    .unwrap_or(0);
                let after_scheme = &rest[scheme_start..];
                // Read until whitespace, backtick, or closing quote/angle bracket
                let uri_end = after_scheme
                    .find(|c: char| c.is_whitespace() || matches!(c, '`' | '"' | '\'' | '<' | '>'))
                    .unwrap_or(after_scheme.len());
                let candidate = strip_enclosing_noise(&after_scheme[..uri_end]).to_string();
                let low = candidate.to_ascii_lowercase();
                if !low.starts_with("http://") && !low.starts_with("https://") {
                    found.push(candidate);
                }
                rest = &after_scheme[uri_end..];
            }
            if found.is_empty() {
                vec![line.to_string()]
            } else {
                found
            }
        } else {
            vec![line.to_string()]
        };

        for seg in extracted_uris {
            match parse_single_uri(&seg, subscription_id.clone()) {
                Ok(mut profiles) => imported_servers.append(&mut profiles),
                Err(err) => {
                    // Ignore pure prose lines in noisy Telegram pastes when other valid keys exist
                    if seg.contains("://") || imported_servers.is_empty() {
                        skipped_lines += 1;
                        if errors.len() < 5 {
                            errors.push(err);
                        }
                    }
                }
            }
        }
    }

    if imported_servers.is_empty() && errors.is_empty() {
        errors.push("Не найдено ни одного поддерживаемого VPN-ключа".to_string());
    }

    ImportResult {
        imported_servers,
        skipped_lines,
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_recursive_deeplinks_and_oversized_inputs() {
        let nested = "happ://add/happ://add/happ://add/happ://add/https://sub.example.com/1";
        assert!(parse_single_uri(nested, None).is_err());

        let big = "a".repeat(MAX_IMPORT_BYTES + 16);
        let res = parse_import_text(&big, None);
        assert!(res.imported_servers.is_empty());
        assert!(!res.errors.is_empty());
    }

    #[test]
    fn parses_multiline_and_base64_subscriptions() {
        let vless = "vless://11111111-2222-3333-4444-555555555555@nl.example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG&sid=a1b2c3d4&type=tcp&flow=xtls-rprx-vision#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam%2001";
        let trojan = "trojan://pass123@de.example.com:443?security=tls&sni=de.example.com&type=ws&path=%2Fws#DE%20Frankfurt";
        let payload = format!("#profile-title: Demo\n{vless}\n{trojan}");
        let encoded = STANDARD.encode(payload.as_bytes());

        let result = parse_import_text(&encoded, Some("sub-1".into()));
        assert_eq!(result.imported_servers.len(), 2);
        assert_eq!(
            result.imported_servers[0].country_code.as_deref(),
            Some("NL")
        );
        assert_eq!(
            result.imported_servers[1].country_code.as_deref(),
            Some("DE")
        );
        assert_eq!(
            result.imported_servers[0].subscription_id.as_deref(),
            Some("sub-1")
        );
    }

    #[test]
    fn extracts_keys_from_noisy_telegram_message() {
        let tg_msg = r#"
Вот ваш доступ на месяц 🚀:
Ключ VLESS: `vless://11111111-2222-3333-4444-555555555555@nl.example.com:443?security=reality&pbk=PubKey123&sni=www.microsoft.com#TG_NL`
И резерв Hysteria: <hy2://pass123@fi.example.com:8443?sni=fi.example.com#TG_FI>
"#;
        let result = parse_import_text(tg_msg, None);
        assert_eq!(result.imported_servers.len(), 2);
        assert_eq!(result.imported_servers[0].name, "TG_NL");
        assert_eq!(result.imported_servers[1].name, "TG_FI");
    }

    #[test]
    fn unwraps_happ_and_v2raytun_subscription_links_from_telegram() {
        let tg = "Откройте в приложении: `happ://add/https://sub.example.com/u/abc123`";
        let url = extract_subscription_url_from_text(tg).unwrap();
        assert_eq!(url, "https://sub.example.com/u/abc123");

        let encoded_tg = "v2raytun://import/https%3A%2F%2Fpanel.example.com%2Fsub%2Ftok";
        assert_eq!(
            extract_subscription_url_from_text(encoded_tg).as_deref(),
            Some("https://panel.example.com/sub/tok")
        );
    }

    #[test]
    fn extracts_extended_country_codes_and_eu() {
        assert_eq!(
            extract_country_code("🇪🇺Автовыбор WIFI+LTE").as_deref(),
            Some("EU")
        );
        assert_eq!(extract_country_code("🇦🇪 Эмираты").as_deref(), Some("AE"));
        assert_eq!(extract_country_code("🇮🇳Индия").as_deref(), Some("IN"));
        assert_eq!(extract_country_code("🇧🇷 Бразилия").as_deref(), Some("BR"));
        assert_eq!(
            extract_country_code("🇳🇱Основной ключ").as_deref(),
            Some("NL")
        );
        assert_eq!(extract_country_code("Дубай ОАЭ VIP").as_deref(), Some("AE"));
    }

    #[test]
    fn rejects_invalid_key_clearly() {
        let result = parse_import_text("not-a-valid-vpn-key", None);
        assert!(result.imported_servers.is_empty());
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn extracts_uri_adjacent_to_multibyte_utf8_without_panicking() {
        let noisy = "Ключ🚀vless://11111111-2222-3333-4444-555555555555@nl.example.com:443?security=reality&pbk=PubKey123#Cyrillic";
        let res = parse_import_text(noisy, None);
        assert_eq!(res.imported_servers.len(), 1);
        assert_eq!(res.imported_servers[0].name, "Cyrillic");

        let cyr = "Доступ:vless://11111111-2222-3333-4444-555555555555@de.example.com:443?security=tls#OK";
        let res2 = parse_import_text(cyr, None);
        assert_eq!(res2.imported_servers.len(), 1);
    }
}
