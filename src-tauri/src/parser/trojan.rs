use super::{clean_host, extract_country_code, percent_decode};
use crate::models::{ProtocolDetails, ProtocolType, ServerProfile, TrojanDetails};
use chrono::Utc;
use std::collections::HashMap;
use url::Url;

pub fn parse_trojan(uri: &str, subscription_id: Option<String>) -> Result<ServerProfile, String> {
    let parsed = Url::parse(uri).map_err(|_| "Некорректный формат Trojan URL".to_string())?;
    if !parsed.scheme().eq_ignore_ascii_case("trojan") {
        return Err("Ожидалась схема trojan://".to_string());
    }

    let password = match parsed.password() {
        Some(pw) if !pw.is_empty() => format!(
            "{}:{}",
            percent_decode(parsed.username()),
            percent_decode(pw)
        ),
        _ => percent_decode(parsed.username()),
    };
    if password.is_empty() {
        return Err("В Trojan-ключе отсутствует пароль".to_string());
    }

    let host = parsed
        .host_str()
        .map(clean_host)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "В Trojan-ключе не указан адрес сервера".to_string())?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("Некорректный порт Trojan-сервера".to_string());
    }

    let params: HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.into_owned()))
        .collect();

    let security = params
        .get("security")
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "tls".to_string());

    let mut network = params
        .get("type")
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "tcp".to_string());
    if network == "splithttp" {
        network = "xhttp".to_string();
    }

    let sni = params.get("sni").cloned().filter(|s| !s.is_empty());
    let fingerprint = params.get("fp").cloned().filter(|s| !s.is_empty());
    let public_key = params.get("pbk").cloned().filter(|s| !s.is_empty());
    let short_id = params.get("sid").cloned().filter(|s| !s.is_empty());
    let spider_x = params.get("spx").cloned().filter(|s| !s.is_empty());
    let path = params.get("path").cloned().filter(|s| !s.is_empty());
    let host_header = params.get("host").cloned().filter(|s| !s.is_empty());
    let service_name = params.get("servicename").cloned().filter(|s| !s.is_empty());
    let header_type = params
        .get("headertype")
        .cloned()
        .filter(|s| !s.is_empty() && s != "none");
    let grpc_authority = params.get("authority").cloned().filter(|s| !s.is_empty());
    let grpc_multi_mode = network == "grpc"
        && params
            .get("mode")
            .is_some_and(|m| m.eq_ignore_ascii_case("multi"));
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
    if security == "reality" && public_key.is_none() {
        return Err(
            "В Trojan Reality ключе отсутствует обязательный параметр pbk (Public Key)".to_string(),
        );
    }
    let alpn = params
        .get("alpn")
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
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
        protocol: ProtocolType::Trojan,
        address: host,
        port,
        country_code,
        subscription_id,
        latency_ms: None,
        details: ProtocolDetails::Trojan(TrojanDetails {
            password,
            network,
            security,
            sni,
            fingerprint,
            public_key,
            short_id,
            path,
            host_header,
            service_name,
            alpn,
            allow_insecure,
            pinned_cert_sha256,
            verify_peer_cert_by_name,
            spider_x,
            header_type,
            grpc_authority,
            grpc_multi_mode,
            xhttp_mode,
            xhttp_extra,
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
