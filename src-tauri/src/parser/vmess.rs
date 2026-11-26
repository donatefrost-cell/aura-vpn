use super::{clean_host, decode_base64_text, extract_country_code};
use crate::models::{ProtocolDetails, ProtocolType, ServerProfile, VmessDetails};
use chrono::Utc;
use serde_json::Value;

fn val_as_str(val: Option<&Value>) -> Option<String> {
    match val {
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

fn val_as_u16(val: Option<&Value>) -> Option<u16> {
    match val {
        Some(Value::Number(n)) => n.as_u64().and_then(|x| u16::try_from(x).ok()),
        Some(Value::String(s)) => s.trim().parse::<u16>().ok(),
        _ => None,
    }
}

pub fn parse_vmess(uri: &str, subscription_id: Option<String>) -> Result<ServerProfile, String> {
    let encoded = uri
        .trim()
        .strip_prefix("vmess://")
        .or_else(|| uri.trim().strip_prefix("VMESS://"))
        .ok_or_else(|| "Ожидалась схема vmess://".to_string())?;

    let json_text = decode_base64_text(encoded)
        .map_err(|_| "Не удалось декодировать VMess Base64-полезную нагрузку".to_string())?;
    let json: Value = serde_json::from_str(&json_text)
        .map_err(|_| "Некорректный JSON внутри VMess-ключа".to_string())?;

    let address = val_as_str(json.get("add"))
        .map(|s| clean_host(&s))
        .ok_or_else(|| "В VMess-ключе отсутствует адрес сервера (add)".to_string())?;
    let port = val_as_u16(json.get("port"))
        .filter(|p| *p > 0)
        .ok_or_else(|| "В VMess-ключе указан некорректный порт".to_string())?;
    let uuid = val_as_str(json.get("id"))
        .filter(|id| uuid::Uuid::parse_str(id).is_ok())
        .ok_or_else(|| "Неверный или отсутствующий UUID в VMess-ключе".to_string())?;

    let alter_id = val_as_u16(json.get("aid")).unwrap_or(0);
    let cipher = val_as_str(json.get("scy")).unwrap_or_else(|| "auto".to_string());
    let mut network = val_as_str(json.get("net"))
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "tcp".to_string());
    if network == "splithttp" {
        network = "xhttp".to_string();
    } else if network == "h2" {
        network = "http".to_string();
    } else if network == "mkcp" {
        network = "kcp".to_string();
    }
    let security = val_as_str(json.get("tls"))
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| s == "tls")
        .unwrap_or_else(|| "none".to_string());
    let sni = val_as_str(json.get("sni"));
    let fingerprint = val_as_str(json.get("fp"));
    let path = val_as_str(json.get("path"));
    let host_header = val_as_str(json.get("host"));
    let header_type = val_as_str(json.get("type")).filter(|s| s != "none");
    let service_name =
        val_as_str(json.get("serviceName")).or_else(|| val_as_str(json.get("servicename")));
    let grpc_authority = val_as_str(json.get("authority"));
    let grpc_multi_mode = network == "grpc"
        && header_type
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case("multi"));
    let kcp_seed = val_as_str(json.get("seed"));
    let xhttp_mode = val_as_str(json.get("mode")).filter(|_| network == "xhttp");
    let xhttp_extra = json.get("extra").cloned().filter(|v| v.is_object());
    let alpn = val_as_str(json.get("alpn"))
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|list| !list.is_empty());

    let allow_insecure = json
        .get("allowInsecure")
        .and_then(|v| match v {
            Value::Bool(b) => Some(*b),
            Value::Number(n) => Some(n.as_u64() == Some(1)),
            Value::String(s) => Some(s == "1" || s.eq_ignore_ascii_case("true")),
            _ => None,
        })
        .unwrap_or(false);
    let pinned_cert_sha256 =
        val_as_str(json.get("pcs")).or_else(|| val_as_str(json.get("pinnedPeerCertSha256")));
    let verify_peer_cert_by_name =
        val_as_str(json.get("vcn")).or_else(|| val_as_str(json.get("verifyPeerCertByName")));

    let name = val_as_str(json.get("ps")).unwrap_or_else(|| format!("{address}:{port}"));
    let country_code = extract_country_code(&name);

    Ok(ServerProfile {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        protocol: ProtocolType::Vmess,
        address,
        port,
        country_code,
        subscription_id,
        latency_ms: None,
        details: ProtocolDetails::Vmess(VmessDetails {
            uuid,
            alter_id,
            cipher,
            network,
            security,
            sni,
            fingerprint,
            path,
            host_header,
            alpn,
            allow_insecure,
            pinned_cert_sha256,
            verify_peer_cert_by_name,
            header_type,
            service_name,
            grpc_authority,
            grpc_multi_mode,
            kcp_seed,
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
