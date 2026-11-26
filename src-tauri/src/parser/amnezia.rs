use super::raw_json::parse_xray_json_value;
use super::wireguard::{parse_wg_ini, split_endpoint};
use super::{decode_base64_flexible, extract_country_code};
use crate::models::{
    AmneziaWgDetails, ProtocolDetails, ProtocolType, ServerProfile, ShadowsocksDetails,
    WireguardDetails,
};
use chrono::Utc;
use flate2::read::ZlibDecoder;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Read;

const MAX_AMNEZIA_UNCOMPRESSED_BYTES: u64 = 2 * 1024 * 1024;

pub fn decode_amnezia_vpn_uri(uri: &str) -> Result<Value, String> {
    let encoded = uri
        .trim()
        .strip_prefix("vpn://")
        .or_else(|| uri.trim().strip_prefix("VPN://"))
        .ok_or_else(|| "Ожидалась схема vpn://".to_string())?;

    let raw_bytes = decode_base64_flexible(encoded)
        .map_err(|_| "Не удалось декодировать Base64 в ссылке vpn://".to_string())?;

    if raw_bytes.len() < 6 {
        return Err("Повреждённый контейнер Amnezia vpn:// (слишком короткий)".to_string());
    }

    // Amnezia uses Qt qCompress: 4-byte big-endian uncompressed length + zlib stream
    let compressed = &raw_bytes[4..];
    let mut limited = ZlibDecoder::new(compressed).take(MAX_AMNEZIA_UNCOMPRESSED_BYTES + 1);
    let mut buf = Vec::new();
    let json_str = match limited.read_to_end(&mut buf) {
        Ok(_) => {
            if (buf.len() as u64) > MAX_AMNEZIA_UNCOMPRESSED_BYTES {
                return Err("Распакованный контейнер Amnezia превышает лимит 2 МБ".to_string());
            }
            String::from_utf8(buf)
                .map_err(|_| "Контейнер Amnezia не содержит корректный UTF-8".to_string())?
        }
        Err(_) => {
            if (raw_bytes.len() as u64) > MAX_AMNEZIA_UNCOMPRESSED_BYTES {
                return Err("Размер контейнера Amnezia превышает лимит 2 МБ".to_string());
            }
            // Fallback: try raw JSON in case payload wasn't zlib-compressed
            String::from_utf8(raw_bytes)
                .map_err(|_| "Не удалось распаковать zlib-поток контейнера Amnezia".to_string())?
        }
    };

    serde_json::from_str::<Value>(&json_str)
        .map_err(|_| "Контейнер Amnezia vpn:// не содержит корректный JSON".to_string())
}

pub fn parse_amnezia_vpn_link(
    uri: &str,
    subscription_id: Option<String>,
) -> Result<Vec<ServerProfile>, String> {
    let root = decode_amnezia_vpn_uri(uri)?;
    parse_amnezia_json_value(&root, subscription_id)
}

fn str_field(obj: &Value, key: &str) -> Option<String> {
    match obj.get(key) {
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

fn str_field_ci(obj: &Value, key: &str) -> Option<String> {
    str_field(obj, key).or_else(|| str_field(obj, &key.to_ascii_lowercase()))
}

pub fn parse_amnezia_json_value(
    root: &Value,
    subscription_id: Option<String>,
) -> Result<Vec<ServerProfile>, String> {
    let host_name = str_field(root, "hostName");
    let description = str_field(root, "description");
    let dns1 = str_field(root, "dns1");
    let dns2 = str_field(root, "dns2");
    let default_dns: Vec<String> = [dns1, dns2].into_iter().flatten().collect();

    let Some(containers) = root.get("containers").and_then(|c| c.as_array()) else {
        // Might be direct Xray JSON rather than Amnezia container wrapper
        return parse_xray_json_value(root, description.or(host_name), subscription_id);
    };

    let mut profiles = Vec::new();
    for container in containers.iter().take(32) {
        let cname = str_field(container, "container")
            .unwrap_or_default()
            .to_ascii_lowercase();

        // Find nested config object (`awg`, `awg2`, `wireguard`, `xray`, `shadowsocks`, or `last_config`)
        let container_inner = container
            .get("awg")
            .or_else(|| container.get("awg2"))
            .or_else(|| container.get("wireguard"))
            .or_else(|| container.get("xray"))
            .or_else(|| container.get("shadowsocks"))
            .unwrap_or(container);

        let last_config_val = container_inner
            .get("last_config")
            .or_else(|| container.get("last_config"));

        let parsed_last: Option<Value> = match last_config_val {
            Some(Value::String(s)) => {
                // Might be raw INI or JSON string
                let t = s.trim();
                if t.starts_with('[') && t.contains("[Peer]") {
                    let base_name = description
                        .clone()
                        .or_else(|| host_name.clone())
                        .unwrap_or_else(|| "AmneziaWG".to_string());
                    if let Ok(p) = parse_wg_ini(t, Some(base_name), subscription_id.clone()) {
                        profiles.push(p);
                    }
                    continue;
                }
                serde_json::from_str::<Value>(t).ok()
            }
            Some(v @ Value::Object(_)) => Some(v.clone()),
            _ => None,
        };

        if cname.contains("xray") || cname.contains("vless") {
            if let Some(ref xray_json) = parsed_last {
                let label = description.clone().or_else(|| host_name.clone());
                if let Ok(mut list) =
                    parse_xray_json_value(xray_json, label, subscription_id.clone())
                {
                    profiles.append(&mut list);
                }
            }
            continue;
        }

        if cname.contains("awg") || cname.contains("wireguard") {
            if let Some(ref cfg) = parsed_last {
                if let Some(ini_text) = str_field(cfg, "config") {
                    if ini_text.contains("[Interface]") && ini_text.contains("[Peer]") {
                        let base_name = description
                            .clone()
                            .or_else(|| host_name.clone())
                            .unwrap_or_else(|| "AmneziaWG".to_string());
                        if let Ok(p) =
                            parse_wg_ini(&ini_text, Some(base_name), subscription_id.clone())
                        {
                            profiles.push(p);
                            continue;
                        }
                    }
                }

                if let (Some(secret), Some(pub_k)) = (
                    str_field(cfg, "client_priv_key").or_else(|| str_field(cfg, "privateKey")),
                    str_field(cfg, "server_pub_key").or_else(|| str_field(cfg, "publicKey")),
                ) {
                    let ep = str_field(cfg, "hostName")
                        .or_else(|| host_name.clone())
                        .unwrap_or_else(|| "127.0.0.1".to_string());
                    let port_str = str_field(container_inner, "port")
                        .or_else(|| str_field(cfg, "port"))
                        .unwrap_or_else(|| "51820".to_string());
                    let endpoint = if ep.contains(':') {
                        ep
                    } else {
                        format!("{ep}:{port_str}")
                    };
                    if let Ok((addr, port)) = split_endpoint(&endpoint) {
                        let client_ip = str_field(cfg, "client_ip")
                            .map(|ip| {
                                if ip.contains('/') {
                                    ip
                                } else {
                                    format!("{ip}/32")
                                }
                            })
                            .unwrap_or_else(|| "10.8.1.2/32".to_string());
                        let psk =
                            str_field(cfg, "psk_key").or_else(|| str_field(cfg, "presharedKey"));
                        let mtu = str_field(cfg, "mtu").and_then(|m| m.parse::<u16>().ok());
                        let name = description
                            .clone()
                            .unwrap_or_else(|| format!("AmneziaWG {addr}"));
                        let country_code = extract_country_code(&name);

                        let jc =
                            str_field_ci(container_inner, "Jc").or_else(|| str_field_ci(cfg, "Jc"));
                        let jmin = str_field_ci(container_inner, "Jmin")
                            .or_else(|| str_field_ci(cfg, "Jmin"));
                        let jmax = str_field_ci(container_inner, "Jmax")
                            .or_else(|| str_field_ci(cfg, "Jmax"));
                        let s1 =
                            str_field_ci(container_inner, "S1").or_else(|| str_field_ci(cfg, "S1"));
                        let s2 =
                            str_field_ci(container_inner, "S2").or_else(|| str_field_ci(cfg, "S2"));
                        let h1 =
                            str_field_ci(container_inner, "H1").or_else(|| str_field_ci(cfg, "H1"));
                        let h2 =
                            str_field_ci(container_inner, "H2").or_else(|| str_field_ci(cfg, "H2"));
                        let h3 =
                            str_field_ci(container_inner, "H3").or_else(|| str_field_ci(cfg, "H3"));
                        let h4 =
                            str_field_ci(container_inner, "H4").or_else(|| str_field_ci(cfg, "H4"));

                        let mut extra_params = HashMap::new();
                        for key in ["S3", "S4", "I1", "I2", "I3", "I4", "I5"] {
                            if let Some(val) = str_field_ci(container_inner, key)
                                .or_else(|| str_field_ci(cfg, key))
                            {
                                extra_params.insert(key.to_string(), val);
                            }
                        }

                        let keepalive = str_field_ci(container_inner, "persistentKeepalive")
                            .or_else(|| str_field_ci(cfg, "persistentKeepalive"))
                            .and_then(|s| s.parse::<u16>().ok())
                            .filter(|k| *k > 0);

                        let is_awg = cname.contains("awg")
                            || jc.is_some()
                            || s1.is_some()
                            || h1.is_some()
                            || !extra_params.is_empty();

                        if is_awg {
                            let details = AmneziaWgDetails {
                                secret_key: secret,
                                address: vec![client_ip],
                                public_key: pub_k,
                                preshared_key: psk,
                                endpoint,
                                mtu,
                                dns: default_dns.clone(),
                                jc,
                                jmin,
                                jmax,
                                s1,
                                s2,
                                h1,
                                h2,
                                h3,
                                h4,
                                extra_params,
                                keepalive,
                            };
                            if super::wireguard::validate_awg_details(&details).is_ok() {
                                profiles.push(ServerProfile {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    name,
                                    protocol: ProtocolType::AmneziaWg,
                                    address: addr,
                                    port,
                                    country_code,
                                    subscription_id: subscription_id.clone(),
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
                                });
                            }
                        } else {
                            let details = WireguardDetails {
                                secret_key: secret,
                                address: vec![client_ip],
                                public_key: pub_k,
                                preshared_key: psk,
                                endpoint,
                                mtu,
                                dns: default_dns.clone(),
                                reserved: None,
                                keepalive,
                            };
                            if super::wireguard::validate_wg_details(&details).is_ok() {
                                profiles.push(ServerProfile {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    name,
                                    protocol: ProtocolType::Wireguard,
                                    address: addr,
                                    port,
                                    country_code,
                                    subscription_id: subscription_id.clone(),
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
                                });
                            }
                        }
                    }
                }
            }
            continue;
        }

        if cname.contains("shadowsocks") {
            if let Some(ref cfg) = parsed_last {
                if let (Some(method), Some(password)) =
                    (str_field(cfg, "cipher"), str_field(cfg, "password"))
                {
                    let addr = str_field(cfg, "server")
                        .or_else(|| host_name.clone())
                        .unwrap_or_else(|| "127.0.0.1".to_string());
                    let port = str_field(cfg, "server_port")
                        .and_then(|p| p.parse::<u16>().ok())
                        .unwrap_or(8388);
                    let name = description
                        .clone()
                        .unwrap_or_else(|| format!("Amnezia SS {addr}"));
                    let country_code = extract_country_code(&name);
                    profiles.push(ServerProfile {
                        id: uuid::Uuid::new_v4().to_string(),
                        name,
                        protocol: ProtocolType::Shadowsocks,
                        address: addr,
                        port,
                        country_code,
                        subscription_id: subscription_id.clone(),
                        latency_ms: None,
                        details: ProtocolDetails::Shadowsocks(ShadowsocksDetails {
                            method,
                            password,
                            uot: false,
                            plugin: None,
                            plugin_opts: None,
                        }),
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
            }
        }
    }

    if profiles.is_empty() {
        return Err(
            "Контейнер Amnezia не содержит поддерживаемых конфигов (Xray / AmneziaWG / WireGuard / Shadowsocks)"
                .to_string(),
        );
    }
    Ok(profiles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn encode_vpn_link(json: &Value) -> String {
        let raw = serde_json::to_vec(json).unwrap();
        let len_header = (raw.len() as u32).to_be_bytes();
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&raw).unwrap();
        let compressed = enc.finish().unwrap();
        let mut blob = Vec::with_capacity(4 + compressed.len());
        blob.extend_from_slice(&len_header);
        blob.extend_from_slice(&compressed);
        format!("vpn://{}", URL_SAFE_NO_PAD.encode(blob))
    }

    #[test]
    fn decodes_amnezia_xray_and_awg_vpn_links() {
        let xray_cfg = serde_json::json!({
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "1.2.3.4",
                        "port": 443,
                        "users": [{ "id": "11111111-2222-3333-4444-555555555555", "encryption": "none" }]
                    }]
                },
                "streamSettings": { "network": "raw", "security": "tls", "tlsSettings": { "serverName": "example.com" } }
            }]
        });
        let container_json = serde_json::json!({
            "description": "NL Amnezia Xray",
            "hostName": "1.2.3.4",
            "containers": [{
                "container": "amnezia-xray",
                "xray": { "last_config": serde_json::to_string(&xray_cfg).unwrap() }
            }]
        });
        let vpn_link = encode_vpn_link(&container_json);
        let parsed = parse_amnezia_vpn_link(&vpn_link, None).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].protocol, ProtocolType::RawXray);
        assert_eq!(parsed[0].country_code.as_deref(), Some("NL"));

        let awg_ini = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.8.1.2/32\nJc = 5\nJmin = 50\nJmax = 100\nS1 = 12\nS2 = 24\nH1 = 100\nH2 = 200\nH3 = 300\nH4 = 400\n\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\nEndpoint = 5.6.7.8:51820\n";
        let awg_container = serde_json::json!({
            "description": "FI AmneziaWG",
            "hostName": "5.6.7.8",
            "containers": [{
                "container": "amnezia-awg",
                "awg": { "last_config": awg_ini }
            }]
        });
        let awg_link = encode_vpn_link(&awg_container);
        let parsed_awg = parse_amnezia_vpn_link(&awg_link, None).unwrap();
        assert_eq!(parsed_awg.len(), 1);
        assert_eq!(parsed_awg[0].protocol, ProtocolType::AmneziaWg);
        assert_eq!(parsed_awg[0].address, "5.6.7.8");
    }
}
