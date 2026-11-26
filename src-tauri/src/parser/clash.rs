use super::extract_country_code;
use crate::models::{
    Hysteria2Details, ProtocolDetails, ProtocolType, ServerProfile, ShadowsocksDetails,
    TrojanDetails, VlessDetails, VmessDetails, WireguardDetails,
};
use chrono::Utc;
use yaml_rust2::{Yaml, YamlLoader};

const MAX_CLASH_YAML_BYTES: usize = 2 * 1024 * 1024;
const MAX_CLASH_PROXIES: usize = 500;
const MAX_YAML_DEPTH: usize = 32;

fn validate_yaml_safety(node: &Yaml, depth: usize) -> Result<(), String> {
    if depth > MAX_YAML_DEPTH {
        return Err("YAML-конфиг превышает допустимую глубину вложенности".to_string());
    }
    match node {
        Yaml::Alias(_) => {
            Err("YAML-псевдонимы (& / *) запрещены из соображений безопасности".to_string())
        }
        Yaml::Array(arr) => {
            for item in arr {
                validate_yaml_safety(item, depth + 1)?;
            }
            Ok(())
        }
        Yaml::Hash(map) => {
            for (k, v) in map {
                validate_yaml_safety(k, depth + 1)?;
                validate_yaml_safety(v, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn contains_unquoted_yaml_anchor_or_alias(raw: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let bytes = raw.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let ch = bytes[i];
        if !in_single && !in_double && ch == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if !in_double && ch == b'\'' {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if !in_single && ch == b'"' {
            let mut bs = 0usize;
            let mut j = i;
            while j > 0 && bytes[j - 1] == b'\\' {
                bs += 1;
                j -= 1;
            }
            if bs.is_multiple_of(2) {
                in_double = !in_double;
            }
            i += 1;
            continue;
        }
        if !in_single && !in_double && (ch == b'&' || ch == b'*') {
            let prev = if i == 0 { b'\n' } else { bytes[i - 1] };
            let next = if i + 1 < bytes.len() {
                bytes[i + 1]
            } else {
                b' '
            };
            let prev_sep = matches!(
                prev,
                b' ' | b'\t' | b'\n' | b'\r' | b'[' | b'{' | b',' | b':'
            );
            let next_ident = next.is_ascii_alphanumeric() || next == b'_';
            if prev_sep && next_ident {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn y_get<'a>(v: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    v.as_hash()?.get(&Yaml::String(key.to_string()))
}

fn y_str(v: &Yaml, key: &str) -> Option<String> {
    match y_get(v, key) {
        Some(Yaml::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        Some(Yaml::Integer(n)) => Some(n.to_string()),
        Some(Yaml::Real(s)) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        _ => None,
    }
}

fn y_u16(v: &Yaml, key: &str) -> Option<u16> {
    match y_get(v, key) {
        Some(Yaml::Integer(n)) => u16::try_from(*n).ok(),
        Some(Yaml::String(s)) => s.trim().parse::<u16>().ok(),
        _ => None,
    }
}

fn y_bool(v: &Yaml, key: &str) -> bool {
    match y_get(v, key) {
        Some(Yaml::Boolean(b)) => *b,
        Some(Yaml::Integer(n)) => *n == 1,
        Some(Yaml::String(s)) => s == "1" || s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

pub fn parse_clash_yaml(
    raw_yaml: &str,
    subscription_id: Option<String>,
) -> Result<Vec<ServerProfile>, String> {
    if raw_yaml.len() > MAX_CLASH_YAML_BYTES {
        return Err("YAML-конфиг Clash превышает допустимый лимит 2 МБ".to_string());
    }
    if contains_unquoted_yaml_anchor_or_alias(raw_yaml) {
        return Err("YAML-псевдонимы (& / *) запрещены из соображений безопасности".to_string());
    }
    {
        let mut depth = 0usize;
        let mut in_s = false;
        let mut in_d = false;
        let b = raw_yaml.as_bytes();
        let mut idx = 0usize;
        while idx < b.len() {
            let ch = b[idx];
            if !in_s && !in_d && ch == b'#' {
                while idx < b.len() && b[idx] != b'\n' {
                    idx += 1;
                }
                continue;
            }
            if !in_d && ch == b'\'' {
                in_s = !in_s;
            } else if !in_s && ch == b'"' {
                let mut bs = 0usize;
                let mut j = idx;
                while j > 0 && b[j - 1] == b'\\' {
                    bs += 1;
                    j -= 1;
                }
                if bs.is_multiple_of(2) {
                    in_d = !in_d;
                }
            } else if !in_s && !in_d {
                if ch == b'[' || ch == b'{' {
                    depth += 1;
                    if depth > MAX_YAML_DEPTH {
                        return Err(format!(
                            "Глубина вложенности YAML-структуры превышает безопасный лимит {MAX_YAML_DEPTH}"
                        ));
                    }
                } else if ch == b']' || ch == b'}' {
                    depth = depth.saturating_sub(1);
                }
            }
            idx += 1;
        }
    }

    let docs = YamlLoader::load_from_str(raw_yaml)
        .map_err(|_| "Некорректный YAML-конфиг Clash / Mihomo".to_string())?;
    let Some(doc) = docs.first() else {
        return Err("YAML-конфиг пуст".to_string());
    };
    validate_yaml_safety(doc, 0)?;

    let Some(proxies) = y_get(doc, "proxies").and_then(|p| p.as_vec()) else {
        return Err("В YAML-конфиге отсутствует секция proxies".to_string());
    };

    let mut profiles = Vec::new();
    for item in proxies.iter().take(MAX_CLASH_PROXIES) {
        let ptype = y_str(item, "type").unwrap_or_default().to_ascii_lowercase();
        let name = y_str(item, "name").unwrap_or_else(|| "Clash Node".to_string());
        let server = match y_str(item, "server") {
            Some(s) => s,
            None => continue,
        };
        let port = y_u16(item, "port").unwrap_or(443);
        let country_code = extract_country_code(&name);

        let network_raw = y_str(item, "network")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| "tcp".to_string());
        let network = match network_raw.as_str() {
            "splithttp" => "xhttp".to_string(),
            "h2" => "http".to_string(),
            "mkcp" => "kcp".to_string(),
            _ => network_raw,
        };
        let ws_opts = y_get(item, "ws-opts");
        let grpc_opts = y_get(item, "grpc-opts");
        let reality_opts = y_get(item, "reality-opts");

        let path = ws_opts.and_then(|w| y_str(w, "path"));
        let ws_early_data =
            ws_opts
                .and_then(|w| y_get(w, "max-early-data"))
                .and_then(|v| match v {
                    Yaml::Integer(n) if *n > 0 => Some((*n).min(u32::MAX as i64) as u32),
                    Yaml::String(s) => s.trim().parse::<u32>().ok().filter(|n| *n > 0),
                    _ => None,
                });
        let ws_early_data_header = ws_opts.and_then(|w| y_str(w, "early-data-header-name"));
        let host_header = ws_opts
            .and_then(|w| y_get(w, "headers"))
            .and_then(|h| y_str(h, "Host"));
        let service_name = grpc_opts.and_then(|g| y_str(g, "grpc-service-name"));

        let sni = y_str(item, "servername").or_else(|| y_str(item, "sni"));
        let fingerprint = y_str(item, "client-fingerprint");
        let allow_insecure = y_bool(item, "skip-cert-verify");

        let details = match ptype.as_str() {
            "vless" => {
                let Some(uuid) = y_str(item, "uuid") else {
                    continue;
                };
                let pbk = reality_opts.and_then(|r| y_str(r, "public-key"));
                let sid = reality_opts.and_then(|r| y_str(r, "short-id"));
                let security = if pbk.is_some() {
                    "reality".to_string()
                } else if y_bool(item, "tls") {
                    "tls".to_string()
                } else {
                    "none".to_string()
                };
                (
                    ProtocolType::Vless,
                    ProtocolDetails::Vless(VlessDetails {
                        uuid,
                        encryption: y_str(item, "encryption").unwrap_or_else(|| "none".to_string()),
                        flow: y_str(item, "flow"),
                        network,
                        security,
                        sni,
                        fingerprint,
                        public_key: pbk,
                        short_id: sid,
                        spider_x: None,
                        path,
                        host_header,
                        service_name,
                        alpn: None,
                        allow_insecure,
                        pinned_cert_sha256: None,
                        verify_peer_cert_by_name: None,
                        header_type: None,
                        xhttp_mode: None,
                        xhttp_extra: None,
                        pqv: None,
                        grpc_authority: None,
                        grpc_multi_mode: false,
                        kcp_seed: None,
                        ws_early_data,
                        ws_early_data_header,
                    }),
                )
            }
            "vmess" => {
                let Some(uuid) = y_str(item, "uuid") else {
                    continue;
                };
                (
                    ProtocolType::Vmess,
                    ProtocolDetails::Vmess(VmessDetails {
                        uuid,
                        alter_id: y_u16(item, "alterId").unwrap_or(0),
                        cipher: y_str(item, "cipher").unwrap_or_else(|| "auto".to_string()),
                        network,
                        security: if y_bool(item, "tls") {
                            "tls".to_string()
                        } else {
                            "none".to_string()
                        },
                        sni,
                        fingerprint,
                        path,
                        host_header,
                        alpn: None,
                        allow_insecure,
                        pinned_cert_sha256: None,
                        verify_peer_cert_by_name: None,
                        header_type: None,
                        service_name,
                        grpc_authority: None,
                        grpc_multi_mode: false,
                        kcp_seed: None,
                        xhttp_mode: None,
                        xhttp_extra: None,
                    }),
                )
            }
            "trojan" => {
                let Some(password) = y_str(item, "password") else {
                    continue;
                };
                let pbk = reality_opts.and_then(|r| y_str(r, "public-key"));
                let sid = reality_opts.and_then(|r| y_str(r, "short-id"));
                let security = if pbk.is_some() {
                    "reality".to_string()
                } else {
                    "tls".to_string()
                };
                (
                    ProtocolType::Trojan,
                    ProtocolDetails::Trojan(TrojanDetails {
                        password,
                        network,
                        security,
                        sni,
                        fingerprint,
                        public_key: pbk,
                        short_id: sid,
                        spider_x: None,
                        path,
                        host_header,
                        service_name,
                        alpn: None,
                        allow_insecure,
                        pinned_cert_sha256: None,
                        verify_peer_cert_by_name: None,
                        header_type: None,
                        grpc_authority: None,
                        grpc_multi_mode: false,
                        xhttp_mode: None,
                        xhttp_extra: None,
                    }),
                )
            }
            "ss" | "shadowsocks" => {
                let (Some(method), Some(password)) =
                    (y_str(item, "cipher"), y_str(item, "password"))
                else {
                    continue;
                };
                (
                    ProtocolType::Shadowsocks,
                    ProtocolDetails::Shadowsocks(ShadowsocksDetails {
                        method,
                        password,
                        uot: y_bool(item, "udp"),
                        plugin: y_str(item, "plugin"),
                        plugin_opts: None,
                    }),
                )
            }
            "hysteria2" => {
                let Some(password) = y_str(item, "password") else {
                    continue;
                };
                let mport = y_str(item, "ports");
                let hop_interval_secs = y_str(item, "hop-interval")
                    .and_then(|s| s.trim().trim_end_matches('s').parse::<u32>().ok())
                    .filter(|n| *n > 0);
                let pinned_cert_sha256 = y_str(item, "fingerprint")
                    .and_then(|s| super::hysteria2::normalize_pin_sha256(&s));
                (
                    ProtocolType::Hysteria2,
                    ProtocolDetails::Hysteria2(Hysteria2Details {
                        password,
                        sni,
                        obfs: y_str(item, "obfs"),
                        obfs_password: y_str(item, "obfs-password"),
                        up_mbps: y_str(item, "up")
                            .and_then(|s| super::hysteria2::parse_bandwidth_mbps(&s)),
                        down_mbps: y_str(item, "down")
                            .and_then(|s| super::hysteria2::parse_bandwidth_mbps(&s)),
                        alpn: None,
                        allow_insecure,
                        pinned_cert_sha256,
                        verify_peer_cert_by_name: None,
                        mport,
                        hop_interval_secs,
                    }),
                )
            }
            "wireguard" => {
                let (Some(secret_key), Some(public_key)) =
                    (y_str(item, "private-key"), y_str(item, "public-key"))
                else {
                    continue;
                };
                let ip = y_str(item, "ip")
                    .map(|s| {
                        if s.contains('/') {
                            s
                        } else {
                            format!("{s}/32")
                        }
                    })
                    .unwrap_or_else(|| "10.8.0.2/32".to_string());
                let endpoint = if server.contains(':') {
                    format!("[{server}]:{port}")
                } else {
                    format!("{server}:{port}")
                };
                (
                    ProtocolType::Wireguard,
                    ProtocolDetails::Wireguard(WireguardDetails {
                        secret_key,
                        address: vec![ip],
                        public_key,
                        preshared_key: y_str(item, "preshared-key"),
                        endpoint,
                        mtu: y_u16(item, "mtu"),
                        dns: vec![],
                        reserved: None,
                        keepalive: None,
                    }),
                )
            }
            _ => continue,
        };

        profiles.push(ServerProfile {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            protocol: details.0,
            address: server,
            port,
            country_code,
            subscription_id: subscription_id.clone(),
            latency_ms: None,
            details: details.1,
            created_at: Utc::now().to_rfc3339(),
            favorite: false,
            last_used_at: None,
            fingerprint_key: None,
            custom_name: None,
            overrides: None,
            original_source: None,
            config_revision: 0,
        });
    }

    if profiles.is_empty() {
        return Err("В Clash YAML-конфиге не найдено поддерживаемых узлов".to_string());
    }
    Ok(profiles)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clash_yaml_proxies() {
        let yaml = r#"
proxies:
  - name: "🇩🇪 DE Reality"
    type: vless
    server: de.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    tls: true
    flow: xtls-rprx-vision
    servername: www.microsoft.com
    reality-opts:
      public-key: pub123
      short-id: aabb
  - name: "🇫🇮 Hy2"
    type: hysteria2
    server: fi.example.com
    port: 8443
    password: pass
    sni: fi.example.com
"#;
        let list = parse_clash_yaml(yaml, None).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].protocol, ProtocolType::Vless);
        assert_eq!(list[1].protocol, ProtocolType::Hysteria2);
    }

    #[test]
    fn rejects_flow_and_block_yaml_aliases() {
        let flow_bomb = "proxies: [&a { name: x }, *a]";
        assert!(parse_clash_yaml(flow_bomb, None).is_err());

        let tab_alias = "proxies:\n  - name: n1\n\tsni:\t&a test\n\thost: *a";
        assert!(parse_clash_yaml(tab_alias, None).is_err());

        // Quoted asterisk/ampersand inside passwords or names must remain allowed
        let quoted_secret = r#"
proxies:
  - name: "Safe & *Node"
    type: hysteria2
    server: fi.example.com
    port: 8443
    password: "pass*1&2"
"#;
        assert_eq!(parse_clash_yaml(quoted_secret, None).unwrap().len(), 1);
    }

    #[test]
    fn handles_escaped_backslash_before_quote_and_rejects_deep_flow_nesting() {
        let escaped_quote_alias = "proxies:\n  - name: \"foo\\\\\"\n    host: &a test\n    sni: *a";
        assert!(parse_clash_yaml(escaped_quote_alias, None).is_err());

        let deep_open = "[".repeat(40);
        let deep_close = "]".repeat(40);
        let deep_yaml = format!("proxies: {deep_open}{deep_close}");
        assert!(parse_clash_yaml(&deep_yaml, None).is_err());
    }
}
