use super::{clean_host, extract_country_code, percent_decode};
use crate::models::{ProtocolDetails, ProtocolType, ServerProfile, VlessDetails};
use chrono::Utc;
use std::collections::HashMap;
use url::Url;

pub fn parse_vless(uri: &str, subscription_id: Option<String>) -> Result<ServerProfile, String> {
    let parsed = Url::parse(uri).map_err(|_| "Некорректный формат VLESS URL".to_string())?;
    if !parsed.scheme().eq_ignore_ascii_case("vless") {
        return Err("Ожидалась схема vless://".to_string());
    }

    let uuid_raw = percent_decode(parsed.username());
    let uuid = uuid_raw.trim().to_string();
    if uuid.is_empty()
        || uuid.len() > 128
        || uuid.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err("Неверный или отсутствующий идентификатор (UUID) в VLESS-ключе".to_string());
    }

    let host = parsed
        .host_str()
        .map(clean_host)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "В VLESS-ключе не указан адрес сервера".to_string())?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("Некорректный порт сервера (0)".to_string());
    }

    let params: HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.into_owned()))
        .collect();

    let encryption = params
        .get("encryption")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "none".to_string());

    let mut security = params
        .get("security")
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "none".to_string());
    if security == "xtls" {
        security = "tls".to_string();
    }

    if !matches!(security.as_str(), "none" | "tls" | "reality") {
        return Err(format!(
            "Неподдерживаемый тип безопасности VLESS: {security}"
        ));
    }

    let mut network = params
        .get("type")
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "tcp".to_string());
    if network == "splithttp" {
        network = "xhttp".to_string();
    } else if network == "h2" {
        network = "http".to_string();
    } else if network == "mkcp" {
        network = "kcp".to_string();
    }
    if !matches!(
        network.as_str(),
        "tcp" | "raw" | "ws" | "grpc" | "httpupgrade" | "xhttp" | "http" | "kcp"
    ) {
        return Err(format!("Неподдерживаемый транспорт VLESS: {network}"));
    }

    let flow = params.get("flow").cloned().filter(|s| !s.is_empty());
    let sni = params.get("sni").cloned().filter(|s| !s.is_empty());
    let fingerprint = params.get("fp").cloned().filter(|s| !s.is_empty());
    let public_key = params.get("pbk").cloned().filter(|s| !s.is_empty());
    let short_id = params.get("sid").cloned().filter(|s| !s.is_empty());
    let spider_x = params.get("spx").cloned().filter(|s| !s.is_empty());
    let pqv = params.get("pqv").cloned().filter(|s| !s.is_empty());
    let path = params.get("path").cloned().filter(|s| !s.is_empty());
    let host_header = params.get("host").cloned().filter(|s| !s.is_empty());
    let service_name = params.get("servicename").cloned().filter(|s| !s.is_empty());
    let grpc_authority = params.get("authority").cloned().filter(|s| !s.is_empty());
    let grpc_multi_mode = network == "grpc"
        && params
            .get("mode")
            .is_some_and(|m| m.eq_ignore_ascii_case("multi"));
    let kcp_seed = params.get("seed").cloned().filter(|s| !s.is_empty());
    let ws_early_data = params
        .get("ed")
        .or_else(|| params.get("maxearlydata"))
        .and_then(|s| s.parse::<u32>().ok());
    let ws_early_data_header = params.get("eh").cloned().filter(|s| !s.is_empty());
    let header_type = params
        .get("headertype")
        .cloned()
        .filter(|s| !s.is_empty() && s != "none");
    let xhttp_mode = params
        .get("mode")
        .filter(|_| network == "xhttp")
        .cloned()
        .filter(|s| !s.is_empty());
    let xhttp_extra = params
        .get("extra")
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .map(|mut v| {
            super::raw_json::sanitize_xray_outbound_v26(&mut v);
            v
        });
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
        .get("allowinsecure")
        .or_else(|| params.get("insecure"))
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let pinned_cert_sha256 = params
        .get("pcs")
        .or_else(|| params.get("pinnedpeercertsha256"))
        .cloned()
        .filter(|s| !s.is_empty());
    let verify_peer_cert_by_name = params
        .get("vcn")
        .or_else(|| params.get("verifypeercertbyname"))
        .cloned()
        .filter(|s| !s.is_empty());

    if security == "reality" && public_key.is_none() {
        return Err(
            "В VLESS Reality ключе отсутствует обязательный параметр pbk (Public Key)".to_string(),
        );
    }

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
        protocol: ProtocolType::Vless,
        address: host,
        port,
        country_code,
        subscription_id,
        latency_ms: None,
        details: ProtocolDetails::Vless(VlessDetails {
            uuid,
            encryption,
            flow,
            network,
            security,
            sni,
            fingerprint,
            public_key,
            short_id,
            spider_x,
            path,
            host_header,
            service_name,
            alpn,
            allow_insecure,
            pinned_cert_sha256,
            verify_peer_cert_by_name,
            header_type,
            xhttp_mode,
            xhttp_extra,
            pqv,
            grpc_authority,
            grpc_multi_mode,
            kcp_seed,
            ws_early_data,
            ws_early_data_header,
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
    use super::parse_vless;

    #[test]
    fn parses_vless_reality_vision() {
        let uri = "vless://11111111-2222-3333-4444-555555555555@185.10.20.30:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.apple.com&fp=chrome&pbk=pubKey123456&sid=01ab&spx=%2F&type=tcp#NL%20Fast";
        let profile = parse_vless(uri, None).expect("valid vless reality");
        assert_eq!(profile.name, "NL Fast");
        assert_eq!(profile.address, "185.10.20.30");
        assert_eq!(profile.port, 443);
        assert_eq!(profile.country_code.as_deref(), Some("NL"));
    }

    #[test]
    fn parses_vless_non_uuid_string_id() {
        let uri = "vless://custom-tg-user-id@cdn.example.com:443?security=tls&type=xhttp&mode=packet-up&path=%2Fxhttp#CustomID";
        let profile = parse_vless(uri, None).expect("valid custom string id");
        assert_eq!(profile.name, "CustomID");
    }

    #[test]
    fn rejects_reality_without_pbk() {
        let uri = "vless://11111111-2222-3333-4444-555555555555@185.10.20.30:443?security=reality&sni=www.apple.com";
        let err = parse_vless(uri, None).unwrap_err();
        assert!(err.contains("pbk"));
    }
}
