use super::{clean_host, extract_country_code, percent_decode};
use crate::models::{
    AmneziaWgDetails, ProtocolDetails, ProtocolType, ServerProfile, WireguardDetails,
};
use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use chrono::Utc;
use std::collections::HashMap;
use std::net::IpAddr;
use url::Url;

const WG_KEY_B64: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

pub fn is_safe_ini_token(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty()
        && t.len() <= 256
        && !t.chars().any(|c| c.is_control() || matches!(c, '#' | ';'))
        && !t.starts_with('[')
}

pub fn is_safe_cps_token(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty()
        && t.len() <= 4096
        && !t
            .chars()
            .any(|c| c.is_control() || matches!(c, '[' | ']' | '#' | ';'))
}

fn is_valid_awg_h_value(tv: &str) -> bool {
    if tv.is_empty() {
        return true;
    }
    if tv.parse::<u32>().is_ok() {
        return true;
    }
    if let Some((a, b)) = tv.split_once('-') {
        if let (Ok(min_v), Ok(max_v)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
            return min_v <= max_v;
        }
    }
    false
}

pub fn is_valid_wg_base64_key(s: &str) -> bool {
    let t = s.trim();
    if t.len() != 44 || !t.ends_with('=') || t.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return false;
    }
    WG_KEY_B64
        .decode(t)
        .map(|bytes| bytes.len() == 32)
        .unwrap_or(false)
}

pub fn is_valid_ip_or_cidr_token(s: &str) -> bool {
    let t = s.trim();
    if let Some((ip_part, prefix_part)) = t.split_once('/') {
        let Ok(ip) = ip_part.trim().parse::<IpAddr>() else {
            return false;
        };
        let Ok(prefix) = prefix_part.trim().parse::<u8>() else {
            return false;
        };
        match ip {
            IpAddr::V4(_) => prefix <= 32,
            IpAddr::V6(_) => prefix <= 128,
        }
    } else {
        t.parse::<IpAddr>().is_ok()
    }
}

pub fn validate_awg_details(d: &AmneziaWgDetails) -> Result<(), String> {
    if !is_valid_wg_base64_key(&d.secret_key) {
        return Err(
            "Некорректный PrivateKey AmneziaWG/WireGuard (ожидается 32-байтный Base64-ключ)"
                .to_string(),
        );
    }
    if !is_valid_wg_base64_key(&d.public_key) {
        return Err("Некорректный PublicKey пира AmneziaWG/WireGuard".to_string());
    }
    if let Some(psk) = &d.preshared_key {
        if !psk.trim().is_empty() && !is_valid_wg_base64_key(psk) {
            return Err("Некорректный PresharedKey в конфиге WireGuard/AmneziaWG".to_string());
        }
    }
    if d.address.is_empty() || !d.address.iter().all(|a| is_valid_ip_or_cidr_token(a)) {
        return Err(
            "Некорректный локальный IP/CIDR в поле Address WireGuard/AmneziaWG".to_string(),
        );
    }
    if !d.dns.iter().all(|x| x.trim().parse::<IpAddr>().is_ok()) {
        return Err("Некорректный DNS IP-адрес в конфиге WireGuard/AmneziaWG".to_string());
    }
    if !is_safe_ini_token(&d.endpoint) || split_endpoint(&d.endpoint).is_err() {
        return Err("Некорректный Endpoint в конфиге WireGuard/AmneziaWG".to_string());
    }
    for (name, opt) in [
        ("Jc", &d.jc),
        ("Jmin", &d.jmin),
        ("Jmax", &d.jmax),
        ("S1", &d.s1),
        ("S2", &d.s2),
    ] {
        if let Some(v) = opt {
            let tv = v.trim();
            if !tv.is_empty() && tv.parse::<u32>().is_err() {
                return Err(format!(
                    "Параметр AmneziaWG {name} должен быть целым числом"
                ));
            }
        }
    }
    for (name, opt) in [("H1", &d.h1), ("H2", &d.h2), ("H3", &d.h3), ("H4", &d.h4)] {
        if let Some(v) = opt {
            let tv = v.trim();
            if !is_valid_awg_h_value(tv) {
                return Err(format!(
                    "Параметр AmneziaWG {name} должен быть целым числом или диапазоном min-max"
                ));
            }
        }
    }
    for (k, v) in &d.extra_params {
        let ku = k.trim().to_ascii_uppercase();
        if !matches!(ku.as_str(), "S3" | "S4" | "I1" | "I2" | "I3" | "I4" | "I5") {
            return Err(format!("Недопустимый параметр AmneziaWG: {k}"));
        }
        if matches!(ku.as_str(), "S3" | "S4") {
            if v.trim().parse::<u32>().is_err() {
                return Err(format!("Параметр AmneziaWG {ku} должен быть целым числом"));
            }
        } else if !is_safe_cps_token(v) {
            return Err(format!("Недопустимые символы в параметре AmneziaWG {ku}"));
        }
    }
    Ok(())
}

pub fn validate_wg_details(d: &WireguardDetails) -> Result<(), String> {
    if !is_valid_wg_base64_key(&d.secret_key) {
        return Err(
            "Некорректный PrivateKey WireGuard (ожидается 32-байтный Base64-ключ)".to_string(),
        );
    }
    if !is_valid_wg_base64_key(&d.public_key) {
        return Err("Некорректный PublicKey пира WireGuard".to_string());
    }
    if let Some(psk) = &d.preshared_key {
        if !psk.trim().is_empty() && !is_valid_wg_base64_key(psk) {
            return Err("Некорректный PresharedKey в конфиге WireGuard".to_string());
        }
    }
    if d.address.is_empty() || !d.address.iter().all(|a| is_valid_ip_or_cidr_token(a)) {
        return Err("Некорректный IP/CIDR в поле Address WireGuard".to_string());
    }
    if !d.dns.iter().all(|x| x.trim().parse::<IpAddr>().is_ok()) {
        return Err("Некорректный DNS IP-адрес в конфиге WireGuard".to_string());
    }
    if !is_safe_ini_token(&d.endpoint) || split_endpoint(&d.endpoint).is_err() {
        return Err("Некорректный Endpoint в конфиге WireGuard".to_string());
    }
    Ok(())
}

pub fn split_endpoint(endpoint: &str) -> Result<(String, u16), String> {
    let trimmed = endpoint.trim();
    if !is_safe_ini_token(trimmed) {
        return Err("Endpoint содержит недопустимые символы".to_string());
    }
    if let Ok(fake) = Url::parse(&format!("http://{trimmed}")) {
        if let (Some(h), Some(p)) = (fake.host_str(), fake.port()) {
            return Ok((clean_host(h), p));
        }
    }
    let (h, p_str) = trimmed
        .rsplit_once(':')
        .ok_or_else(|| "В конфиге WireGuard/AmneziaWG не указан порт Endpoint".to_string())?;
    let port = p_str
        .trim()
        .parse::<u16>()
        .map_err(|_| "Некорректный порт Endpoint".to_string())?;
    Ok((clean_host(h), port))
}

pub fn parse_wg_ini(
    raw_ini: &str,
    fallback_name: Option<String>,
    subscription_id: Option<String>,
) -> Result<ServerProfile, String> {
    let mut section = String::new();
    let mut iface: HashMap<String, String> = HashMap::new();
    let mut peer: HashMap<String, String> = HashMap::new();

    for line in raw_ini.lines() {
        let no_comment = line.split(['#', ';']).next().unwrap_or("").trim();
        if no_comment.is_empty() {
            continue;
        }
        if no_comment.starts_with('[') && no_comment.ends_with(']') {
            section = no_comment[1..no_comment.len() - 1]
                .trim()
                .to_ascii_lowercase();
            continue;
        }
        if let Some((k, v)) = no_comment.split_once('=') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            match section.as_str() {
                "interface" => {
                    if matches!(key.as_str(), "address" | "dns") {
                        iface
                            .entry(key)
                            .and_modify(|existing| {
                                if !val.is_empty() {
                                    if !existing.is_empty() {
                                        existing.push(',');
                                    }
                                    existing.push_str(&val);
                                }
                            })
                            .or_insert(val);
                    } else {
                        iface.insert(key, val);
                    }
                }
                "peer" => {
                    peer.insert(key, val);
                }
                _ => {}
            }
        }
    }

    let secret_key = iface
        .get("privatekey")
        .cloned()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "В конфиге WireGuard отсутствует PrivateKey".to_string())?;
    let public_key = peer
        .get("publickey")
        .cloned()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "В конфиге WireGuard отсутствует PublicKey пира".to_string())?;
    let endpoint = peer
        .get("endpoint")
        .cloned()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "В конфиге WireGuard отсутствует Endpoint".to_string())?;

    let (address, port) = split_endpoint(&endpoint)?;

    let addresses: Vec<String> = iface
        .get("address")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| vec!["10.8.0.2/32".to_string()]);

    let dns: Vec<String> = iface
        .get("dns")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let mtu = iface.get("mtu").and_then(|s| s.parse::<u16>().ok());
    let preshared_key = peer.get("presharedkey").cloned().filter(|s| !s.is_empty());
    let keepalive = peer
        .get("persistentkeepalive")
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|k| *k > 0);

    let awg_keys = [
        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3",
        "i4", "i5",
    ];
    let has_awg = awg_keys.iter().any(|k| iface.contains_key(*k));

    let name = fallback_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if has_awg {
                format!("AmneziaWG {address}")
            } else {
                format!("WireGuard {address}")
            }
        });
    let country_code = extract_country_code(&name);

    if has_awg {
        let mut extra_params = HashMap::new();
        for key in ["s3", "s4", "i1", "i2", "i3", "i4", "i5"] {
            if let Some(val) = iface.get(key) {
                extra_params.insert(key.to_ascii_uppercase(), val.clone());
            }
        }
        let details = AmneziaWgDetails {
            secret_key,
            address: addresses,
            public_key,
            preshared_key,
            endpoint,
            mtu,
            dns,
            jc: iface.get("jc").cloned(),
            jmin: iface.get("jmin").cloned(),
            jmax: iface.get("jmax").cloned(),
            s1: iface.get("s1").cloned(),
            s2: iface.get("s2").cloned(),
            h1: iface.get("h1").cloned(),
            h2: iface.get("h2").cloned(),
            h3: iface.get("h3").cloned(),
            h4: iface.get("h4").cloned(),
            extra_params,
            keepalive,
        };
        validate_awg_details(&details)?;
        Ok(ServerProfile {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            protocol: ProtocolType::AmneziaWg,
            address,
            port,
            country_code,
            subscription_id,
            latency_ms: None,
            details: ProtocolDetails::AmneziaWg(details),
            created_at: Utc::now().to_rfc3339(),
            favorite: false,
            last_used_at: None,
            fingerprint_key: None,
            custom_name: None,
            overrides: None,
            original_source: None,
            config_revision: 0,
        })
    } else {
        let details = WireguardDetails {
            secret_key,
            address: addresses,
            public_key,
            preshared_key,
            endpoint,
            mtu,
            dns,
            reserved: None,
            keepalive,
        };
        validate_wg_details(&details)?;
        Ok(ServerProfile {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            protocol: ProtocolType::Wireguard,
            address,
            port,
            country_code,
            subscription_id,
            latency_ms: None,
            details: ProtocolDetails::Wireguard(details),
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
}

pub fn parse_wireguard_uri(
    uri: &str,
    subscription_id: Option<String>,
) -> Result<ServerProfile, String> {
    let trimmed = uri.trim();
    let lower = trimmed.to_ascii_lowercase();
    let normalized = if lower.starts_with("wg://") {
        format!("wireguard://{}", &trimmed[5..])
    } else {
        trimmed.to_string()
    };

    let parsed =
        Url::parse(&normalized).map_err(|_| "Некорректный формат WireGuard URI".to_string())?;
    let params: HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.into_owned()))
        .collect();

    let secret_key = {
        let u = percent_decode(parsed.username());
        if !u.is_empty() {
            u
        } else {
            params
                .get("privatekey")
                .or_else(|| params.get("secretkey"))
                .cloned()
                .unwrap_or_default()
        }
    };
    if secret_key.is_empty() {
        return Err("В WireGuard-ключе отсутствует PrivateKey".to_string());
    }

    let host = parsed
        .host_str()
        .map(clean_host)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "В WireGuard-ключе отсутствует адрес сервера".to_string())?;
    let port = parsed.port().unwrap_or(51820);
    let endpoint = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let public_key = params
        .get("publickey")
        .or_else(|| params.get("peerpublickey"))
        .cloned()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "В WireGuard-ключе отсутствует publicKey".to_string())?;

    let address: Vec<String> = params
        .get("address")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| vec!["10.8.0.2/32".to_string()]);

    let dns: Vec<String> = params
        .get("dns")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let mtu = params.get("mtu").and_then(|s| s.parse::<u16>().ok());
    let keepalive = params
        .get("keepalive")
        .or_else(|| params.get("persistentkeepalive"))
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|k| *k > 0);
    let preshared_key = params
        .get("presharedkey")
        .cloned()
        .filter(|s| !s.is_empty());
    let reserved = params.get("reserved").and_then(|s| {
        let trimmed = s.trim();
        let bytes: Vec<u8> = trimmed
            .split(',')
            .filter_map(|p| p.trim().parse::<u8>().ok())
            .collect();
        if bytes.len() == 3 {
            Some(bytes)
        } else {
            super::decode_base64_flexible(trimmed)
                .ok()
                .filter(|b| b.len() == 3)
        }
    });

    let has_awg = [
        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3",
        "i4", "i5",
    ]
    .iter()
    .any(|k| params.contains_key(*k));

    let name = parsed
        .fragment()
        .map(percent_decode)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{host}:{port}"));
    let country_code = extract_country_code(&name);

    if has_awg {
        let mut extra_params = HashMap::new();
        for key in ["s3", "s4", "i1", "i2", "i3", "i4", "i5"] {
            if let Some(val) = params.get(key) {
                extra_params.insert(key.to_ascii_uppercase(), val.clone());
            }
        }
        let details = AmneziaWgDetails {
            secret_key,
            address,
            public_key,
            preshared_key,
            endpoint,
            mtu,
            dns,
            jc: params.get("jc").cloned(),
            jmin: params.get("jmin").cloned(),
            jmax: params.get("jmax").cloned(),
            s1: params.get("s1").cloned(),
            s2: params.get("s2").cloned(),
            h1: params.get("h1").cloned(),
            h2: params.get("h2").cloned(),
            h3: params.get("h3").cloned(),
            h4: params.get("h4").cloned(),
            extra_params,
            keepalive,
        };
        validate_awg_details(&details)?;
        Ok(ServerProfile {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            protocol: ProtocolType::AmneziaWg,
            address: host,
            port,
            country_code,
            subscription_id,
            latency_ms: None,
            details: ProtocolDetails::AmneziaWg(details),
            created_at: Utc::now().to_rfc3339(),
            favorite: false,
            last_used_at: None,
            fingerprint_key: None,
            custom_name: None,
            overrides: None,
            original_source: None,
            config_revision: 0,
        })
    } else {
        let details = WireguardDetails {
            secret_key,
            address,
            public_key,
            preshared_key,
            endpoint,
            mtu,
            dns,
            reserved,
            keepalive,
        };
        validate_wg_details(&details)?;
        Ok(ServerProfile {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            protocol: ProtocolType::Wireguard,
            address: host,
            port,
            country_code,
            subscription_id,
            latency_ms: None,
            details: ProtocolDetails::Wireguard(details),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wg_and_awg_conf_files() {
        let awg_ini = r#"
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.8.1.2/32
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 120
S1 = 15
S2 = 25
H1 = 111111
H2 = 222222
H3 = 333333
H4 = 444444

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 185.20.30.40:51820
AllowedIPs = 0.0.0.0/0
"#;
        let profile = parse_wg_ini(awg_ini, Some("DE Amnezia".into()), None).unwrap();
        assert_eq!(profile.protocol, ProtocolType::AmneziaWg);
        assert_eq!(profile.address, "185.20.30.40");
        assert_eq!(profile.port, 51820);
        assert_eq!(profile.country_code.as_deref(), Some("DE"));

        let wg_ini = r#"
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.8.0.2/32

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 1.2.3.4:51820
"#;
        let wg_profile = parse_wg_ini(wg_ini, None, None).unwrap();
        assert_eq!(wg_profile.protocol, ProtocolType::Wireguard);
    }

    #[test]
    fn rejects_ini_section_injection_in_uri_or_ini() {
        let evil_uri = "wireguard://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=@1.2.3.4:51820?publickey=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=&address=10.8.0.2/32%0A%5BTCPServerTunnel%5D%0ABindAddress=0.0.0.0:3389#Evil";
        assert!(parse_wireguard_uri(evil_uri, None).is_err());

        let evil_ini = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.8.0.2/32\nJc = 4\nI1 = 123\n[TCPServerTunnel]\n";
        assert!(parse_wg_ini(evil_ini, None, None).is_err());
    }
}
