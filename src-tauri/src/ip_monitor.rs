use crate::logger::redact_secrets;
use crate::models::{ConnectionMode, IpEndpointInfo, IpMonitorState, IpProviderId};
use crate::storage::AppStorage;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, Instant};

const MAX_IP_RESPONSE_BYTES: usize = 12288;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct StoredIpMonitor {
    pub original_ip: Option<IpEndpointInfo>,
    pub vpn_ip: Option<IpEndpointInfo>,
    pub mask_ip: bool,
    pub provider: IpProviderId,
}

impl StoredIpMonitor {
    pub fn to_state(&self, is_connected: bool) -> IpMonitorState {
        let vpn_ip = if is_connected {
            self.vpn_ip.clone()
        } else {
            None
        };
        let ip_changed = match (&vpn_ip, &self.original_ip) {
            (Some(v), Some(o)) => Some(v.ip != o.ip),
            _ => None,
        };
        let ipv6_changed = match (
            vpn_ip.as_ref().and_then(|v| v.ipv6.as_ref()),
            self.original_ip.as_ref().and_then(|o| o.ipv6.as_ref()),
        ) {
            (Some(v6), Some(o6)) => Some(v6 != o6),
            _ => None,
        };
        let comparison_note = match (&vpn_ip, &self.original_ip) {
            (Some(v), Some(o)) if v.ip != o.ip => {
                Some("Выходной IPv4 отличается от сохранённого исходного адреса.".into())
            }
            (Some(v), Some(o)) if v.ip == o.ip => {
                Some("Внимание: выходной IPv4 совпадает с сохранённым исходным адресом.".into())
            }
            (Some(_), Some(_)) => None,
            (Some(_), None) => Some(
                "Исходный IP не сохранён — при необходимости проверьте его при отключённом VPN."
                    .into(),
            ),
            (None, Some(_)) => {
                Some("Подключите VPN и обновите проверку, чтобы сравнить адреса.".into())
            }
            (None, None) => None,
        };
        IpMonitorState {
            vpn_ip,
            original_ip: self.original_ip.clone(),
            ip_changed,
            ipv6_changed,
            mask_ip: self.mask_ip,
            provider: self.provider,
            comparison_note,
        }
    }
}

pub fn load_ip_monitor(storage: &AppStorage) -> StoredIpMonitor {
    storage.read_dpapi_or_legacy_json("ip-monitor.json")
}

pub fn save_ip_monitor(storage: &AppStorage, data: &StoredIpMonitor) {
    let _ = storage.write_dpapi_json_atomic("ip-monitor.json", data);
}

async fn read_bounded_bytes(mut resp: reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length() {
        if len as usize > limit {
            return Err("Ответ IP-сервиса превышает допустимый размер".into());
        }
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| redact_secrets(&e.to_string()))?
    {
        if buf.len().saturating_add(chunk.len()) > limit {
            return Err("Ответ IP-сервиса слишком велик".into());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

fn build_ip_client(http_port: Option<u16>, timeout_secs: u64) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(port) = http_port {
        let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))
            .map_err(|e| format!("Ошибка настройки прокси: {e}"))?;
        builder = builder.proxy(proxy);
    } else {
        builder = builder.no_proxy();
    }
    builder
        .build()
        .map_err(|e| format!("Ошибка создания HTTP-клиента: {e}"))
}

#[derive(Deserialize)]
struct IpWhoResponse {
    success: Option<bool>,
    ip: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
    region: Option<String>,
    city: Option<String>,
    #[serde(rename = "type")]
    ip_type: Option<String>,
    connection: Option<IpWhoConn>,
    timezone: Option<IpWhoTz>,
}

#[derive(Deserialize)]
struct IpWhoConn {
    asn: Option<u64>,
    isp: Option<String>,
    org: Option<String>,
}

#[derive(Deserialize)]
struct IpWhoTz {
    id: Option<String>,
    utc: Option<String>,
}

#[derive(Deserialize)]
struct IpApiCoResponse {
    ip: Option<String>,
    country_name: Option<String>,
    country_code: Option<String>,
    region: Option<String>,
    city: Option<String>,
    org: Option<String>,
    asn: Option<String>,
    timezone: Option<String>,
    error: Option<bool>,
}

#[derive(Deserialize)]
struct IpInfoResponse {
    ip: Option<String>,
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
    org: Option<String>,
    timezone: Option<String>,
}

#[derive(Deserialize)]
struct IpifyJson {
    ip: String,
}

async fn try_ipwho(
    client: &reqwest::Client,
    ipv6: Option<String>,
    via_vpn: bool,
    mode: ConnectionMode,
    started: Instant,
) -> Option<IpEndpointInfo> {
    let resp = client.get("https://ipwho.is/").send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let bytes = read_bounded_bytes(resp, MAX_IP_RESPONSE_BYTES).await.ok()?;
    let parsed: IpWhoResponse = serde_json::from_slice(&bytes).ok()?;
    if !parsed.success.unwrap_or(true) {
        return None;
    }
    let addr = parsed.ip?.trim().parse::<IpAddr>().ok()?;
    let conn = parsed.connection;
    let asn = conn.as_ref().and_then(|c| c.asn).map(|n| format!("AS{n}"));
    let org = conn
        .as_ref()
        .and_then(|c| c.org.clone())
        .filter(|s| !s.trim().is_empty());
    let isp = conn
        .and_then(|c| c.isp.or(c.org))
        .filter(|s| !s.trim().is_empty());
    let tz = parsed.timezone.and_then(|t| match (t.id, t.utc) {
        (Some(id), Some(utc)) if !id.trim().is_empty() => Some(format!("{id} ({utc})")),
        (Some(id), _) if !id.trim().is_empty() => Some(id),
        _ => None,
    });
    Some(IpEndpointInfo {
        ip: addr.to_string(),
        ipv6,
        country: parsed.country.filter(|s| !s.trim().is_empty()),
        country_code: parsed
            .country_code
            .map(|s| s.trim().to_ascii_uppercase())
            .filter(|s| s.len() == 2),
        region: parsed.region.filter(|s| !s.trim().is_empty()),
        city: parsed.city.filter(|s| !s.trim().is_empty()),
        isp,
        org,
        asn,
        timezone: tz,
        network_type: parsed.ip_type.filter(|s| !s.trim().is_empty()),
        latency_ms: Some(started.elapsed().as_millis().max(1) as u64),
        checked_at: Utc::now().to_rfc3339(),
        source: "ipwho.is".to_string(),
        via_vpn,
        mode,
    })
}

async fn try_ipapico(
    client: &reqwest::Client,
    ipv6: Option<String>,
    via_vpn: bool,
    mode: ConnectionMode,
    started: Instant,
) -> Option<IpEndpointInfo> {
    let resp = client
        .get("https://ipapi.co/json/")
        .header("User-Agent", "AURA-VPN/0.8")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let bytes = read_bounded_bytes(resp, MAX_IP_RESPONSE_BYTES).await.ok()?;
    let parsed: IpApiCoResponse = serde_json::from_slice(&bytes).ok()?;
    if parsed.error.unwrap_or(false) {
        return None;
    }
    let addr = parsed.ip?.trim().parse::<IpAddr>().ok()?;
    Some(IpEndpointInfo {
        ip: addr.to_string(),
        ipv6,
        country: parsed.country_name.filter(|s| !s.trim().is_empty()),
        country_code: parsed
            .country_code
            .map(|s| s.trim().to_ascii_uppercase())
            .filter(|s| s.len() == 2),
        region: parsed.region.filter(|s| !s.trim().is_empty()),
        city: parsed.city.filter(|s| !s.trim().is_empty()),
        isp: parsed.org.clone().filter(|s| !s.trim().is_empty()),
        org: parsed.org.filter(|s| !s.trim().is_empty()),
        asn: parsed.asn.filter(|s| !s.trim().is_empty()),
        timezone: parsed.timezone.filter(|s| !s.trim().is_empty()),
        network_type: None,
        latency_ms: Some(started.elapsed().as_millis().max(1) as u64),
        checked_at: Utc::now().to_rfc3339(),
        source: "ipapi.co".to_string(),
        via_vpn,
        mode,
    })
}

async fn try_ipinfo(
    client: &reqwest::Client,
    ipv6: Option<String>,
    via_vpn: bool,
    mode: ConnectionMode,
    started: Instant,
) -> Option<IpEndpointInfo> {
    let resp = client.get("https://ipinfo.io/json").send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let bytes = read_bounded_bytes(resp, MAX_IP_RESPONSE_BYTES).await.ok()?;
    let parsed: IpInfoResponse = serde_json::from_slice(&bytes).ok()?;
    let addr = parsed.ip?.trim().parse::<IpAddr>().ok()?;
    let raw_org = parsed.org.unwrap_or_default();
    let (asn, org_name) = if let Some((first, rest)) = raw_org.trim().split_once(' ') {
        if first.starts_with("AS") {
            (Some(first.to_string()), Some(rest.trim().to_string()))
        } else {
            (None, Some(raw_org.trim().to_string()))
        }
    } else if raw_org.trim().starts_with("AS") {
        (Some(raw_org.trim().to_string()), None)
    } else if !raw_org.trim().is_empty() {
        (None, Some(raw_org.trim().to_string()))
    } else {
        (None, None)
    };
    Some(IpEndpointInfo {
        ip: addr.to_string(),
        ipv6,
        country: parsed.country.clone().filter(|s| !s.trim().is_empty()),
        country_code: parsed
            .country
            .map(|s| s.trim().to_ascii_uppercase())
            .filter(|s| s.len() == 2),
        region: parsed.region.filter(|s| !s.trim().is_empty()),
        city: parsed.city.filter(|s| !s.trim().is_empty()),
        isp: org_name.clone(),
        org: org_name,
        asn,
        timezone: parsed.timezone.filter(|s| !s.trim().is_empty()),
        network_type: None,
        latency_ms: Some(started.elapsed().as_millis().max(1) as u64),
        checked_at: Utc::now().to_rfc3339(),
        source: "ipinfo.io".to_string(),
        via_vpn,
        mode,
    })
}

pub async fn fetch_ip_info(
    http_port: Option<u16>,
    include_ipv6: bool,
    via_vpn: bool,
    mode: ConnectionMode,
    provider: IpProviderId,
) -> Result<IpEndpointInfo, String> {
    let client = build_ip_client(http_port, 7)?;
    let started = Instant::now();

    let ipv6 = if include_ipv6 {
        let client_v6 = build_ip_client(http_port, 4)?;
        match client_v6
            .get("https://api6.ipify.org?format=json")
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(bytes) = read_bounded_bytes(resp, 512).await {
                    serde_json::from_slice::<IpifyJson>(&bytes)
                        .ok()
                        .and_then(|j| j.ip.trim().parse::<IpAddr>().ok())
                        .filter(|ip| ip.is_ipv6())
                        .map(|ip| ip.to_string())
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        None
    };

    match provider {
        IpProviderId::IpWhoIs => {
            if let Some(info) = try_ipwho(&client, ipv6.clone(), via_vpn, mode, started).await {
                return Ok(info);
            }
        }
        IpProviderId::IpApiCo => {
            if let Some(info) = try_ipapico(&client, ipv6.clone(), via_vpn, mode, started).await {
                return Ok(info);
            }
        }
        IpProviderId::IpInfoIo => {
            if let Some(info) = try_ipinfo(&client, ipv6.clone(), via_vpn, mode, started).await {
                return Ok(info);
            }
        }
        IpProviderId::IpifyOnly => {}
        IpProviderId::Auto => {
            if let Some(info) = try_ipwho(&client, ipv6.clone(), via_vpn, mode, started).await {
                return Ok(info);
            }
            if let Some(info) = try_ipinfo(&client, ipv6.clone(), via_vpn, mode, started).await {
                return Ok(info);
            }
            if let Some(info) = try_ipapico(&client, ipv6.clone(), via_vpn, mode, started).await {
                return Ok(info);
            }
        }
    }

    // Minimal fallback: api.ipify.org
    let resp = client
        .get("https://api.ipify.org?format=json")
        .send()
        .await
        .map_err(|e| {
            format!(
                "Не удалось запросить внешний IP: {}",
                redact_secrets(&e.to_string())
            )
        })?;
    if !resp.status().is_success() {
        return Err(format!(
            "Сервис определения IP вернул HTTP {}",
            resp.status().as_u16()
        ));
    }
    let bytes = read_bounded_bytes(resp, MAX_IP_RESPONSE_BYTES).await?;
    let parsed: IpifyJson = serde_json::from_slice(&bytes)
        .map_err(|_| "Некорректный формат ответа сервиса определения IP".to_string())?;
    let addr: IpAddr = parsed
        .ip
        .trim()
        .parse()
        .map_err(|_| "Сервис вернул некорректный IP-адрес".to_string())?;

    Ok(IpEndpointInfo {
        ip: addr.to_string(),
        ipv6,
        country: None,
        country_code: None,
        region: None,
        city: None,
        isp: None,
        org: None,
        asn: None,
        timezone: None,
        network_type: None,
        latency_ms: Some(started.elapsed().as_millis().max(1) as u64),
        checked_at: Utc::now().to_rfc3339(),
        source: "api.ipify.org".to_string(),
        via_vpn,
        mode,
    })
}
