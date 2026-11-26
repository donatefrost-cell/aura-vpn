use crate::parser::unwrap_deeplink_target;
use reqwest::redirect::Policy;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use url::Url;

pub const MAX_REDIRECT_HOPS: usize = 5;

#[derive(Debug)]
pub enum FetchError {
    Fatal(String),
    Retryable(String),
}

impl FetchError {
    pub fn into_message(self) -> String {
        match self {
            Self::Fatal(m) | Self::Retryable(m) => m,
        }
    }
}

pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_forbidden_ip(IpAddr::V4(v4));
            }
            if let Some(v4) = v6.to_ipv4() {
                return is_forbidden_ip(IpAddr::V4(v4));
            }
            let seg = v6.segments();
            let is_nat64_well_known = seg[0] == 0x0064
                && seg[1] == 0xff9b
                && seg[2] == 0
                && seg[3] == 0
                && seg[4] == 0
                && seg[5] == 0;
            let is_nat64_local = seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001;
            let is_teredo = seg[0] == 0x2001 && seg[1] == 0x0000;
            let is_6to4 = seg[0] == 0x2002;
            let is_doc = seg[0] == 0x2001 && seg[1] == 0x0db8;
            if is_6to4 {
                let embedded = std::net::Ipv4Addr::new(
                    (seg[1] >> 8) as u8,
                    (seg[1] & 0xff) as u8,
                    (seg[2] >> 8) as u8,
                    (seg[2] & 0xff) as u8,
                );
                if is_forbidden_ip(IpAddr::V4(embedded)) {
                    return true;
                }
            }
            if is_nat64_well_known || is_nat64_local {
                let embedded = std::net::Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    (seg[6] & 0xff) as u8,
                    (seg[7] >> 8) as u8,
                    (seg[7] & 0xff) as u8,
                );
                if is_forbidden_ip(IpAddr::V4(embedded)) {
                    return true;
                }
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00
                || (seg[0] & 0xffc0) == 0xfe80
                || is_teredo
                || is_doc
        }
    }
}

pub fn validate_http_url(
    raw_url: &str,
    https_only: bool,
    allow_loopback_for_test: bool,
) -> Result<Url, String> {
    let trimmed = raw_url.trim();
    let unwrapped = unwrap_deeplink_target(trimmed).unwrap_or_else(|| trimmed.to_string());
    let parsed = Url::parse(&unwrapped)
        .map_err(|_| "Некорректная ссылка URL. Проверьте формат адреса.".to_string())?;

    let is_https = parsed.scheme().eq_ignore_ascii_case("https");
    let is_http = parsed.scheme().eq_ignore_ascii_case("http");
    if https_only {
        if !is_https {
            return Err("Разрешены только защищённые HTTPS-ссылки (https://)".to_string());
        }
    } else if !is_https && !is_http {
        return Err(
            "Поддерживаются только протоколы HTTPS или HTTP (https:// / http://)".to_string(),
        );
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "В ссылке URL не указан домен".to_string())?;
    if !allow_loopback_for_test {
        let lower_host = host.trim_end_matches('.').to_ascii_lowercase();
        if lower_host == "localhost"
            || lower_host.ends_with(".local")
            || lower_host.ends_with(".internal")
            || lower_host.ends_with(".localhost")
        {
            return Err("Локальные и внутренние адреса запрещены".to_string());
        }

        if let Ok(ip) = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            if is_forbidden_ip(ip) {
                return Err("Приватные и loopback IP-адреса запрещены".to_string());
            }
        }
    }

    Ok(parsed)
}

pub async fn resolve_and_pin_addrs(
    url: &Url,
    allow_loopback_for_test: bool,
) -> Result<(String, Vec<SocketAddr>), FetchError> {
    let host_raw = url
        .host_str()
        .ok_or_else(|| FetchError::Fatal("В URL отсутствует имя хоста".to_string()))?;
    let host_clean = host_raw
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);

    if let Ok(ip) = host_clean.parse::<IpAddr>() {
        if !allow_loopback_for_test && is_forbidden_ip(ip) {
            return Err(FetchError::Fatal(
                "Удалённый адрес относится к локальной или приватной сети".to_string(),
            ));
        }
        return Ok((host_clean, vec![SocketAddr::new(ip, port)]));
    }

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host_clean.as_str(), port))
        .await
        .map_err(|_| {
            FetchError::Retryable(
                "Не удалось разрешить домен сервера. Проверьте интернет-соединение и URL."
                    .to_string(),
            )
        })?
        .collect();

    if addrs.is_empty() {
        return Err(FetchError::Retryable(
            "DNS не вернул ни одного IP-адреса для указанного домена".to_string(),
        ));
    }

    if !allow_loopback_for_test {
        for addr in &addrs {
            if is_forbidden_ip(addr.ip()) {
                return Err(FetchError::Fatal(
                    "Домен указывает на локальный или приватный IP-адрес".to_string(),
                ));
            }
        }
    }

    Ok((host_clean, addrs))
}

pub fn build_pinned_client(
    host: &str,
    addrs: &[SocketAddr],
    user_agent: &str,
    timeout: Duration,
) -> Result<reqwest::Client, FetchError> {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .no_proxy()
        .redirect(Policy::none())
        .user_agent(user_agent)
        .resolve_to_addrs(host, addrs)
        .build()
        .map_err(|e| FetchError::Fatal(format!("Ошибка инициализации HTTP-клиента: {e}")))
}

pub async fn read_body_limited(
    mut response: reqwest::Response,
    max_bytes: usize,
    too_large_msg: &str,
) -> Result<Vec<u8>, FetchError> {
    if let Some(len) = response.content_length() {
        if len > max_bytes as u64 {
            return Err(FetchError::Fatal(too_large_msg.to_string()));
        }
    }

    let mut out = Vec::with_capacity(
        response
            .content_length()
            .and_then(|l| usize::try_from(l).ok())
            .unwrap_or(8192)
            .min(max_bytes),
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| FetchError::Retryable("Ошибка чтения сетевого ответа".to_string()))?
    {
        if out.len().saturating_add(chunk.len()) > max_bytes {
            return Err(FetchError::Fatal(too_large_msg.to_string()));
        }
        out.extend_from_slice(&chunk);
    }

    Ok(out)
}

pub async fn fetch_https_bytes_safe(
    raw_url: &str,
    user_agent: &str,
    max_bytes: usize,
    timeout: Duration,
    too_large_msg: &str,
    allow_loopback_for_test: bool,
) -> Result<(Url, Vec<u8>), String> {
    let mut current_url =
        validate_http_url(raw_url, !allow_loopback_for_test, allow_loopback_for_test)?;

    let overall_budget = timeout.saturating_mul(2).max(Duration::from_secs(30));
    tokio::time::timeout(overall_budget, async {
        for _hop in 0..=MAX_REDIRECT_HOPS {
            let (host, addrs) = resolve_and_pin_addrs(&current_url, allow_loopback_for_test)
                .await
                .map_err(FetchError::into_message)?;
            let client = build_pinned_client(&host, &addrs, user_agent, timeout)
                .map_err(FetchError::into_message)?;

            let resp = client
                .get(current_url.clone())
                .header("Accept", "application/json, text/plain, */*")
                .send()
                .await
                .map_err(|e| {
                    if e.is_timeout() {
                        "Удалённый сервер не ответил вовремя".to_string()
                    } else {
                        "Не удалось связаться с удалённым сервером".to_string()
                    }
                })?;

            let status = resp.status();
            if status.is_redirection() {
                let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) else {
                    return Err(format!(
                        "Перенаправление HTTP {} без Location",
                        status.as_u16()
                    ));
                };
                let next = current_url
                    .join(loc.trim())
                    .map_err(|_| "Некорректный URL перенаправления".to_string())?;
                current_url = validate_http_url(
                    next.as_str(),
                    !allow_loopback_for_test,
                    allow_loopback_for_test,
                )?;
                continue;
            }

            if !status.is_success() {
                return Err(format!("Сервер вернул HTTP {}", status.as_u16()));
            }

            let bytes = read_body_limited(resp, max_bytes, too_large_msg)
                .await
                .map_err(FetchError::into_message)?;
            return Ok((current_url, bytes));
        }

        Err("Превышен лимит HTTP-перенаправлений".to_string())
    })
    .await
    .map_err(|_| "Превышено общее время загрузки удалённого ресурса".to_string())?
}

pub fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme().eq_ignore_ascii_case(b.scheme())
        && a.host_str().map(|h| h.to_ascii_lowercase())
            == b.host_str().map(|h| h.to_ascii_lowercase())
        && a.port_or_known_default() == b.port_or_known_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_extended_ipv6_ssrf_tunnels_and_documentation_ranges() {
        assert!(is_forbidden_ip("64:ff9b::127.0.0.1".parse().unwrap()));
        assert!(is_forbidden_ip("2002:7f00:0001::".parse().unwrap()));
        assert!(is_forbidden_ip(
            "2001:0000:4136:e378:8000:63bf:3fff:fdd2".parse().unwrap()
        ));
        assert!(is_forbidden_ip("::127.0.0.1".parse().unwrap()));
        assert!(is_forbidden_ip("2001:db8::1".parse().unwrap()));
        assert!(!is_forbidden_ip("2606:4700:4700::1111".parse().unwrap()));
    }
}
