use super::extract_country_code;
use crate::models::{ProtocolDetails, ProtocolType, RawXrayDetails, ServerProfile};
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::HashSet;

fn is_forbidden_xray_key_lc(k_lc: &str) -> bool {
    matches!(
        k_lc,
        "allowinsecure"
            | "masterkeylog"
            | "certificatefile"
            | "keyfile"
            | "certificates"
            | "sendthrough"
            | "uds"
            | "interface"
            | "mark"
            | "tproxy"
            | "proxysettings"
    )
}

fn is_forbidden_prefix_for_proxy_selector(prefix: &str) -> bool {
    let p = prefix.trim().to_ascii_lowercase();
    p.is_empty()
        || "direct".starts_with(&p)
        || "block".starts_with(&p)
        || "dns-out".starts_with(&p)
        || "api".starts_with(&p)
}

pub fn sanitize_xray_outbound_v26(val: &mut Value) {
    match val {
        Value::Object(map) => {
            let keys_to_remove: Vec<String> = map
                .keys()
                .filter(|k| is_forbidden_xray_key_lc(&k.to_ascii_lowercase()))
                .cloned()
                .collect();
            for k in keys_to_remove {
                map.remove(&k);
            }

            let is_freedom = map.iter().any(|(k, v)| {
                k.eq_ignore_ascii_case("protocol")
                    && v.as_str()
                        .is_some_and(|s| s.eq_ignore_ascii_case("freedom"))
            });
            if is_freedom {
                let settings_key = map
                    .keys()
                    .find(|k| k.eq_ignore_ascii_case("settings"))
                    .cloned();
                if let Some(sk) = settings_key {
                    if let Some(settings) = map.get_mut(&sk).and_then(|s| s.as_object_mut()) {
                        let bad_freedom: Vec<String> = settings
                            .keys()
                            .filter(|k| {
                                let kl = k.to_ascii_lowercase();
                                kl == "redirect" || kl == "userlevel" || kl == "domainstrategy"
                            })
                            .cloned()
                            .collect();
                        for k in bad_freedom {
                            settings.remove(&k);
                        }
                    }
                }
            }

            let sockopt_path_key = map
                .keys()
                .find(|k| k.eq_ignore_ascii_case("streamSettings"))
                .cloned();
            if let Some(smk) = sockopt_path_key {
                if let Some(sm) = map.get_mut(&smk).and_then(|s| s.as_object_mut()) {
                    let skey = sm
                        .keys()
                        .find(|k| k.eq_ignore_ascii_case("sockopt"))
                        .cloned();
                    if let Some(sk) = skey {
                        if let Some(sockopt) = sm.get_mut(&sk).and_then(|s| s.as_object_mut()) {
                            let bad_dp: Vec<String> = sockopt
                                .iter()
                                .filter_map(|(k, v)| {
                                    if !k.eq_ignore_ascii_case("dialerProxy") {
                                        return None;
                                    }
                                    let clean =
                                        v.as_str().unwrap_or("").trim().to_ascii_lowercase();
                                    if clean.is_empty()
                                        || clean == "direct"
                                        || clean == "block"
                                        || clean == "dns-out"
                                        || clean == "api"
                                    {
                                        Some(k.clone())
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            for k in bad_dp {
                                sockopt.remove(&k);
                            }
                        }
                    }
                }
            }

            for (_, v) in map.iter_mut() {
                sanitize_xray_outbound_v26(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                sanitize_xray_outbound_v26(v);
            }
        }
        _ => {}
    }
}

pub fn is_allowed_proxy_protocol(ob: &Value) -> bool {
    let proto = ob
        .as_object()
        .and_then(|m| m.iter().find(|(k, _)| k.eq_ignore_ascii_case("protocol")))
        .and_then(|(_, v)| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        proto.as_str(),
        "vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria" | "wireguard"
    )
}

pub fn is_utility_outbound(ob: &Value) -> bool {
    !is_allowed_proxy_protocol(ob)
}

pub fn is_freedom_with_dpi_settings(ob: &Value) -> bool {
    let Some(map) = ob.as_object() else {
        return false;
    };
    let proto = map
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("protocol"))
        .and_then(|(_, v)| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if proto != "freedom" {
        return false;
    }
    let Some(settings) = map
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("settings"))
        .and_then(|(_, s)| s.as_object())
    else {
        return false;
    };
    let has_dpi = settings
        .keys()
        .any(|k| k.eq_ignore_ascii_case("fragment") || k.eq_ignore_ascii_case("noises"));
    let has_redirect = settings.keys().any(|k| k.eq_ignore_ascii_case("redirect"));
    has_dpi && !has_redirect
}

pub fn sanitize_burst_observatory(
    raw: Option<&Value>,
    allowed_proxy_tags: &[String],
    disallowed_tags: &[String],
) -> Option<Value> {
    if allowed_proxy_tags.is_empty() {
        return None;
    }
    let obj = raw?.as_object()?;
    let selectors = obj
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("subjectSelector"))
        .and_then(|(_, v)| v.as_array())?;
    let mut safe_selectors: Vec<String> = Vec::new();
    for sel in selectors {
        if let Some(prefix) = sel.as_str().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let p_lc = prefix.to_ascii_lowercase();
            let hits_disallowed = disallowed_tags
                .iter()
                .any(|dt| dt.to_ascii_lowercase().starts_with(&p_lc));
            if !is_forbidden_prefix_for_proxy_selector(prefix)
                && !hits_disallowed
                && allowed_proxy_tags.iter().any(|t| t.starts_with(prefix))
                && !safe_selectors.iter().any(|x| x == prefix)
            {
                safe_selectors.push(prefix.to_string());
            }
        }
    }
    if safe_selectors.is_empty() {
        return None;
    }
    Some(json!({
        "subjectSelector": safe_selectors,
        "pingConfig": {
            "destination": "https://www.gstatic.com/generate_204",
            "interval": "5m"
        }
    }))
}

pub fn extract_endpoint(ob: &Value) -> (String, u16) {
    if let Some(vnext) = ob
        .get("settings")
        .and_then(|s| s.get("vnext"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        let addr = vnext
            .get("address")
            .and_then(|v| v.as_str())
            .unwrap_or("127.0.0.1")
            .to_string();
        let port = vnext
            .get("port")
            .and_then(|v| v.as_u64())
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(443);
        return (addr, port);
    }

    if let Some(srv) = ob
        .get("settings")
        .and_then(|s| s.get("servers"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        let addr = srv
            .get("address")
            .and_then(|v| v.as_str())
            .unwrap_or("127.0.0.1")
            .to_string();
        let port = srv
            .get("port")
            .and_then(|v| v.as_u64())
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(443);
        return (addr, port);
    }

    if let Some(addr) = ob
        .get("settings")
        .and_then(|s| s.get("address"))
        .and_then(|v| v.as_str())
    {
        let port = ob
            .get("settings")
            .and_then(|s| s.get("port"))
            .and_then(|v| v.as_u64())
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(443);
        return (addr.to_string(), port);
    }

    if let Some(ep) = ob
        .get("settings")
        .and_then(|s| s.get("peers"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|p| p.get("endpoint"))
        .and_then(|v| v.as_str())
    {
        if let Some((a, p_str)) = ep.rsplit_once(':') {
            return (
                a.trim_matches(|c| c == '[' || c == ']').to_string(),
                p_str.parse::<u16>().unwrap_or(51820),
            );
        }
    }

    ("127.0.0.1".to_string(), 443)
}

fn describe_outbound(ob: &Value) -> (String, String) {
    let proto = ob
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("xray")
        .to_ascii_lowercase();

    let stream = ob.get("streamSettings");
    let raw_net = stream
        .and_then(|s| s.get("network"))
        .and_then(|v| v.as_str())
        .unwrap_or(if proto == "hysteria" {
            "hysteria"
        } else {
            "tcp"
        })
        .to_ascii_lowercase();
    let sec = stream
        .and_then(|s| s.get("security"))
        .and_then(|v| v.as_str())
        .unwrap_or(if proto == "hysteria" || proto == "hysteria2" {
            "tls"
        } else {
            "none"
        })
        .to_ascii_lowercase();

    let has_vision = ob
        .get("settings")
        .and_then(|s| s.get("vnext"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.get("users"))
        .and_then(|u| u.as_array())
        .and_then(|a| a.first())
        .and_then(|u| u.get("flow"))
        .and_then(|f| f.as_str())
        .map(|f| f.to_ascii_lowercase().contains("vision"))
        .unwrap_or(false);

    let has_salamander = stream
        .and_then(|s| s.get("udpmasks"))
        .and_then(|u| u.as_array())
        .map(|arr| {
            arr.iter().any(|item| {
                item.get("type")
                    .and_then(|t| t.as_str())
                    .map(|t| t.eq_ignore_ascii_case("salamander"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    let net_label = match raw_net.as_str() {
        "raw" | "tcp" | "" => "TCP".to_string(),
        "ws" => "WS".to_string(),
        "grpc" => "gRPC".to_string(),
        "xhttp" | "splithttp" => "XHTTP".to_string(),
        "httpupgrade" => "HTTPUpgrade".to_string(),
        "hysteria" => "QUIC".to_string(),
        "kcp" | "mkcp" => "mKCP".to_string(),
        "http" | "h2" => "H2".to_string(),
        other => other.to_ascii_uppercase(),
    };

    let badge = match proto.as_str() {
        "vless" => match sec.as_str() {
            "reality" => "VLESS Reality".to_string(),
            "tls" => "VLESS TLS".to_string(),
            _ => "VLESS".to_string(),
        },
        "vmess" => {
            if sec == "tls" {
                "VMess TLS".to_string()
            } else {
                "VMess".to_string()
            }
        }
        "trojan" => "Trojan".to_string(),
        "shadowsocks" => "Shadowsocks".to_string(),
        "hysteria" | "hysteria2" => "Hysteria2".to_string(),
        "wireguard" => "WireGuard".to_string(),
        other => other.to_ascii_uppercase(),
    };

    let transport = match proto.as_str() {
        "wireguard" => "UDP • Noise".to_string(),
        "shadowsocks" => ob
            .get("settings")
            .and_then(|s| s.get("servers"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|srv| srv.get("method"))
            .and_then(|m| m.as_str())
            .map(|m| m.to_string())
            .unwrap_or_else(|| "AEAD".to_string()),
        "hysteria" | "hysteria2" => {
            if has_salamander {
                "QUIC • Salamander".to_string()
            } else {
                "QUIC • TLS".to_string()
            }
        }
        _ => {
            let mut parts = vec![net_label];
            if sec == "reality" {
                if has_vision {
                    parts.push("Vision".to_string());
                } else {
                    parts.push("Reality".to_string());
                }
            } else if sec == "tls" {
                if has_vision {
                    parts.push("Vision".to_string());
                } else if !badge.ends_with("TLS") {
                    parts.push("TLS".to_string());
                }
            }
            parts.join(" • ")
        }
    };

    (badge, transport)
}

fn ensure_valid_outbound_tag(ob: &mut Value, fallback_tag: &str) {
    let existing = ob
        .get("tag")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .unwrap_or("");
    let reserved = existing.is_empty()
        || existing.eq_ignore_ascii_case("direct")
        || existing.eq_ignore_ascii_case("block");
    if reserved {
        if let Some(map) = ob.as_object_mut() {
            map.insert("tag".to_string(), json!(fallback_tag));
        }
    }
}

pub fn parse_xray_json_value(
    root: &Value,
    fallback_name: Option<String>,
    subscription_id: Option<String>,
) -> Result<Vec<ServerProfile>, String> {
    let configs: Vec<&Value> = match root {
        Value::Array(arr) => arr.iter().collect(),
        Value::Object(_) => vec![root],
        _ => return Err("Некорректная структура JSON-конфига".to_string()),
    };

    let mut out = Vec::new();
    for cfg in &configs {
        let remarks = ["remarks", "name", "ps", "description"]
            .iter()
            .find_map(|key| {
                cfg.get(*key)
                    .and_then(|r| r.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            });

        let mut proxy_obs: Vec<&Value> = Vec::new();
        let mut utility_obs: Vec<&Value> = Vec::new();

        if let Some(obs) = cfg.get("outbounds").and_then(|v| v.as_array()) {
            for ob in obs.iter().take(256) {
                if is_allowed_proxy_protocol(ob) {
                    proxy_obs.push(ob);
                } else {
                    utility_obs.push(ob);
                }
            }
        } else if cfg.get("protocol").is_some() && is_allowed_proxy_protocol(cfg) {
            proxy_obs.push(cfg);
        }

        if proxy_obs.is_empty() {
            continue;
        }

        let mut dialer_tags: HashSet<String> = HashSet::new();
        for ob in &proxy_obs {
            if let Some(dp) = ob
                .get("streamSettings")
                .and_then(|s| s.get("sockopt"))
                .and_then(|s| s.get("dialerProxy"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| {
                    !s.is_empty()
                        && !s.eq_ignore_ascii_case("direct")
                        && !s.eq_ignore_ascii_case("block")
                })
            {
                dialer_tags.insert(dp.to_string());
            }
        }

        let helper_obs: Vec<&Value> = utility_obs
            .into_iter()
            .filter(|ob| {
                if is_freedom_with_dpi_settings(ob) {
                    return true;
                }
                let is_dialer_target = ob
                    .get("tag")
                    .and_then(|v| v.as_str())
                    .map(|t| dialer_tags.contains(t.trim()))
                    .unwrap_or(false);
                if is_dialer_target {
                    let proto = ob
                        .get("protocol")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    return proto == "freedom";
                }
                false
            })
            .collect();

        let balancers: Vec<Value> = cfg
            .get("routing")
            .and_then(|r| r.get("balancers"))
            .and_then(|b| b.as_array())
            .cloned()
            .unwrap_or_default();
        // Never preserve untrusted arbitrary observatory URLs or selectors verbatim
        let observatory: Option<Value> = None;
        let proxy_tags_for_obs: Vec<String> = proxy_obs
            .iter()
            .filter_map(|ob| {
                ob.get("tag")
                    .and_then(|t| t.as_str())
                    .map(|s| s.trim().to_string())
            })
            .collect();
        let disallowed_tags_for_obs: Vec<String> = helper_obs
            .iter()
            .filter_map(|ob| {
                ob.get("tag")
                    .and_then(|t| t.as_str())
                    .map(|s| s.trim().to_string())
            })
            .collect();
        let burst_observatory = sanitize_burst_observatory(
            cfg.get("burstObservatory"),
            &proxy_tags_for_obs,
            &disallowed_tags_for_obs,
        );

        let group_as_one = proxy_obs.len() == 1
            || remarks.is_some()
            || configs.len() > 1
            || !balancers.is_empty()
            || !helper_obs.is_empty()
            || !dialer_tags.is_empty();

        if group_as_one {
            let mut primary_ob = proxy_obs[0].clone();
            sanitize_xray_outbound_v26(&mut primary_ob);

            let mut extra_outbounds: Vec<Value> = Vec::new();
            for (idx, ob) in proxy_obs.iter().skip(1).enumerate() {
                let mut clean = (*ob).clone();
                sanitize_xray_outbound_v26(&mut clean);
                ensure_valid_outbound_tag(&mut clean, &format!("proxy-node-{}", idx + 2));
                extra_outbounds.push(clean);
            }
            for (idx, ob) in helper_obs.iter().enumerate() {
                let mut clean = (*ob).clone();
                sanitize_xray_outbound_v26(&mut clean);
                ensure_valid_outbound_tag(&mut clean, &format!("helper-{}", idx + 1));
                extra_outbounds.push(clean);
            }

            if extra_outbounds.is_empty() && balancers.is_empty() {
                if let Some(map) = primary_ob.as_object_mut() {
                    map.insert("tag".to_string(), json!("proxy"));
                }
            } else {
                ensure_valid_outbound_tag(&mut primary_ob, "proxy");
                let mut used_tags: HashSet<String> = ["direct", "block", "dns-out"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                if let Some(primary_tag) = primary_ob.get("tag").and_then(|v| v.as_str()) {
                    used_tags.insert(primary_tag.to_string());
                }
                for (idx, extra) in extra_outbounds.iter_mut().enumerate() {
                    let cur = extra
                        .get("tag")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if cur.is_empty() || !used_tags.insert(cur) {
                        let mut suffix = idx + 2;
                        let mut candidate = format!("extra-node-{suffix}");
                        while !used_tags.insert(candidate.clone()) {
                            suffix += 1;
                            candidate = format!("extra-node-{suffix}");
                        }
                        if let Some(map) = extra.as_object_mut() {
                            map.insert("tag".to_string(), json!(candidate));
                        }
                    }
                }
            }

            let (label, transport_summary) = describe_outbound(&primary_ob);
            let (address, port) = extract_endpoint(&primary_ob);
            let name = remarks
                .clone()
                .or_else(|| fallback_name.clone())
                .or_else(|| {
                    proxy_obs[0]
                        .get("tag")
                        .and_then(|v| v.as_str())
                        .filter(|t| !t.eq_ignore_ascii_case("proxy"))
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| format!("{label} {address}:{port}"));
            let country_code = extract_country_code(&name);

            out.push(ServerProfile {
                id: uuid::Uuid::new_v4().to_string(),
                name,
                protocol: ProtocolType::RawXray,
                address,
                port,
                country_code,
                subscription_id: subscription_id.clone(),
                latency_ms: None,
                details: ProtocolDetails::RawXray(RawXrayDetails {
                    outbound_json: primary_ob,
                    label,
                    extra_outbounds,
                    balancers,
                    observatory,
                    burst_observatory,
                    transport_summary: Some(transport_summary),
                    node_count: Some(proxy_obs.len()),
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
        } else {
            for ob in proxy_obs {
                let mut clean_ob = ob.clone();
                sanitize_xray_outbound_v26(&mut clean_ob);
                if let Some(map) = clean_ob.as_object_mut() {
                    map.insert("tag".to_string(), json!("proxy"));
                }

                let (label, transport_summary) = describe_outbound(&clean_ob);
                let (address, port) = extract_endpoint(&clean_ob);
                let name = ob
                    .get("tag")
                    .and_then(|v| v.as_str())
                    .filter(|t| !t.eq_ignore_ascii_case("proxy"))
                    .map(|s| s.to_string())
                    .or_else(|| fallback_name.clone())
                    .unwrap_or_else(|| format!("{label} {address}:{port}"));
                let country_code = extract_country_code(&name);

                out.push(ServerProfile {
                    id: uuid::Uuid::new_v4().to_string(),
                    name,
                    protocol: ProtocolType::RawXray,
                    address,
                    port,
                    country_code,
                    subscription_id: subscription_id.clone(),
                    latency_ms: None,
                    details: ProtocolDetails::RawXray(RawXrayDetails {
                        outbound_json: clean_ob,
                        label,
                        extra_outbounds: vec![],
                        balancers: vec![],
                        observatory: None,
                        burst_observatory: None,
                        transport_summary: Some(transport_summary),
                        node_count: Some(1),
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

    if out.is_empty() {
        return Err(
            "В JSON-конфиге не найдено ни одного прокси-исходящего узла (outbound)".to_string(),
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_allow_insecure_and_parses_xray_json() {
        let raw = serde_json::json!({
            "remarks": "NL Custom JSON",
            "outbounds": [
                {
                    "tag": "vless-out",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "1.1.1.1",
                            "port": 443,
                            "users": [{ "id": "11111111-2222-3333-4444-555555555555", "encryption": "none" }]
                        }]
                    },
                    "streamSettings": {
                        "network": "raw",
                        "security": "tls",
                        "tlsSettings": { "serverName": "example.com", "allowInsecure": true }
                    }
                },
                { "tag": "direct", "protocol": "freedom" }
            ]
        });

        let profiles = parse_xray_json_value(&raw, None, None).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "NL Custom JSON");
        match &profiles[0].details {
            ProtocolDetails::RawXray(d) => {
                assert_eq!(d.label, "VLESS TLS");
                assert_eq!(d.transport_summary.as_deref(), Some("TCP"));
                assert_eq!(d.node_count, Some(1));
                assert!(d.outbound_json["streamSettings"]["tlsSettings"]
                    .get("allowInsecure")
                    .is_none());
            }
            _ => panic!("expected RawXray"),
        }
    }

    #[test]
    fn groups_multi_outbound_balancer_json_into_single_profile() {
        let raw = serde_json::json!([
            {
                "remarks": "🇳🇱Основной ключ",
                "outbounds": [
                    {
                        "tag": "proxy-1",
                        "protocol": "vless",
                        "settings": {
                            "vnext": [{
                                "address": "nl1.example.com",
                                "port": 443,
                                "users": [{ "id": "11111111-2222-3333-4444-555555555555", "encryption": "none", "flow": "xtls-rprx-vision" }]
                            }]
                        },
                        "streamSettings": {
                            "network": "tcp",
                            "security": "reality",
                            "sockopt": { "dialerProxy": "fragment-out" }
                        }
                    },
                    {
                        "tag": "proxy-2",
                        "protocol": "vless",
                        "settings": {
                            "vnext": [{
                                "address": "nl2.example.com",
                                "port": 443,
                                "users": [{ "id": "11111111-2222-3333-4444-555555555555", "encryption": "none" }]
                            }]
                        },
                        "streamSettings": { "network": "tcp", "security": "reality" }
                    },
                    {
                        "tag": "proxy-3",
                        "protocol": "vless",
                        "settings": {
                            "vnext": [{
                                "address": "nl3.example.com",
                                "port": 443,
                                "users": [{ "id": "11111111-2222-3333-4444-555555555555", "encryption": "none" }]
                            }]
                        },
                        "streamSettings": { "network": "tcp", "security": "reality" }
                    },
                    {
                        "tag": "fragment-out",
                        "protocol": "freedom",
                        "settings": { "fragment": { "packets": "tlshello", "length": "10-20", "interval": "10-20" } }
                    },
                    { "tag": "direct", "protocol": "freedom" },
                    { "tag": "block", "protocol": "blackhole" }
                ],
                "routing": {
                    "balancers": [{
                        "tag": "auto-bal",
                        "selector": ["proxy-"],
                        "strategy": { "type": "leastPing" }
                    }]
                },
                "burstObservatory": {
                    "subjectSelector": ["proxy-"],
                    "pingConfig": { "destination": "https://www.gstatic.com/generate_204", "interval": "5m" }
                }
            },
            {
                "remarks": "🇸🇪Швеция [HY2]",
                "outbounds": [
                    {
                        "tag": "proxy",
                        "protocol": "hysteria",
                        "settings": { "version": 2, "address": "se.example.com", "port": 8443 },
                        "streamSettings": {
                            "network": "hysteria",
                            "security": "tls"
                        }
                    },
                    { "tag": "direct", "protocol": "freedom" }
                ]
            }
        ]);

        let profiles = parse_xray_json_value(&raw, None, None).unwrap();
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].country_code.as_deref(), Some("NL"));
        assert_eq!(profiles[1].country_code.as_deref(), Some("SE"));

        match &profiles[0].details {
            ProtocolDetails::RawXray(d) => {
                assert_eq!(d.label, "VLESS Reality");
                assert_eq!(d.transport_summary.as_deref(), Some("TCP • Vision"));
                assert_eq!(d.node_count, Some(3));
                assert_eq!(d.extra_outbounds.len(), 3); // proxy-2, proxy-3, fragment-out
                assert_eq!(d.balancers.len(), 1);
                assert!(d.burst_observatory.is_some());
            }
            _ => panic!("expected RawXray"),
        }

        match &profiles[1].details {
            ProtocolDetails::RawXray(d) => {
                assert_eq!(d.label, "Hysteria2");
                assert_eq!(d.transport_summary.as_deref(), Some("QUIC • TLS"));
                assert_eq!(d.node_count, Some(1));
                assert!(d.extra_outbounds.is_empty());
            }
            _ => panic!("expected RawXray"),
        }
    }

    #[test]
    fn sanitizes_dangerous_xray_fields_and_blocks_evil_observatory() {
        let evil = json!({
            "outbounds": [
                {
                    "tag": "p1",
                    "protocol": "vless",
                    "settings": { "vnext": [{ "address": "1.1.1.1", "port": 443, "users": [{ "id": "11111111-2222-3333-4444-555555555555" }] }] },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": {
                            "allowInsecure": true,
                            "masterKeyLog": "C:\\Windows\\Temp\\pwn.log",
                            "certificates": [{ "certificateFile": "\\\\attacker\\share\\c.crt" }]
                        },
                        "sockopt": { "dialerProxy": "direct" }
                    }
                },
                { "tag": "socks-local", "protocol": "socks", "settings": {} }
            ],
            "burstObservatory": {
                "subjectSelector": ["direct"],
                "pingConfig": { "destination": "http://127.0.0.1:9999/ssrf" }
            }
        });

        let profiles = parse_xray_json_value(&evil, None, None).unwrap();
        assert_eq!(profiles.len(), 1);
        match &profiles[0].details {
            ProtocolDetails::RawXray(d) => {
                let s = serde_json::to_string(&d.outbound_json).unwrap();
                assert!(!s.contains("masterKeyLog"));
                assert!(!s.contains("certificateFile"));
                assert!(!s.contains("allowInsecure"));
                assert!(!s.contains("dialerProxy"));
                assert!(d.burst_observatory.is_none());
            }
            _ => panic!("expected RawXray"),
        }
    }

    #[test]
    fn sanitizes_uppercase_xray_keys_and_short_direct_prefix_balancer() {
        let evil_caps = json!({
            "outbounds": [
                {
                    "tag": "d",
                    "protocol": "VLESS",
                    "SENDTHROUGH": "0.0.0.0",
                    "PROXYSETTINGS": { "tag": "direct" },
                    "settings": { "vnext": [{ "address": "1.1.1.1", "port": 443, "users": [{ "id": "11111111-2222-3333-4444-555555555555" }] }] },
                    "StreamSettings": {
                        "tlsSettings": {
                            "ALLOWINSECURE": true,
                            "MASTERKEYLOG": "C:\\temp\\keys.log",
                            "CERTIFICATES": [{ "CERTIFICATEFILE": "\\\\attacker\\smb\\a.crt" }]
                        },
                        "SockOpt": { "DIALERPROXY": "direct" }
                    }
                }
            ],
            "routing": {
                "balancers": [{
                    "tag": "bal-direct",
                    "selector": ["d"],
                    "strategy": { "type": "leastPing" }
                }]
            },
            "burstObservatory": {
                "subjectSelector": ["d", "di"]
            }
        });

        let profiles = parse_xray_json_value(&evil_caps, None, None).unwrap();
        assert_eq!(profiles.len(), 1);
        match &profiles[0].details {
            ProtocolDetails::RawXray(d) => {
                let s = serde_json::to_string(&d.outbound_json)
                    .unwrap()
                    .to_ascii_lowercase();
                assert!(!s.contains("masterkeylog"));
                assert!(!s.contains("certificatefile"));
                assert!(!s.contains("allowinsecure"));
                assert!(!s.contains("dialerproxy"));
                assert!(!s.contains("sendthrough"));
                assert!(!s.contains("proxysettings"));
                assert!(d.burst_observatory.is_none());
            }
            _ => panic!("expected RawXray"),
        }
    }
}
