use crate::hwid::DeviceIdentity;
use crate::models::{ServerProfile, Subscription, SubscriptionUserInfo};
use crate::net_fetch::{
    build_pinned_client, read_body_limited, resolve_and_pin_addrs, same_origin, validate_http_url,
    FetchError, MAX_REDIRECT_HOPS,
};
use crate::parser::{decode_base64_text, parse_import_text, unwrap_deeplink_target};
use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderValue};
use std::time::Duration;
use url::Url;

const MAX_SUBSCRIPTION_BYTES: usize = 5 * 1024 * 1024;

pub fn validate_subscription_url(raw_url: &str) -> Result<Url, String> {
    validate_subscription_url_with_options(raw_url, false)
}

pub fn validate_subscription_url_with_options(
    raw_url: &str,
    allow_loopback_for_test: bool,
) -> Result<Url, String> {
    validate_http_url(raw_url, false, allow_loopback_for_test)
}

pub fn decode_profile_title(raw: &str) -> String {
    let t = raw.trim();
    if let Some(b64) = t.strip_prefix("base64:") {
        if let Ok(decoded) = decode_base64_text(b64) {
            let clean = decoded.trim();
            if !clean.is_empty() {
                return clean.to_string();
            }
        }
    }
    t.to_string()
}

pub fn parse_userinfo_value(raw: &str) -> Option<SubscriptionUserInfo> {
    let mut info = SubscriptionUserInfo::default();
    let mut found_any = false;

    for pair in raw.split(';') {
        let Some((k, v)) = pair.trim().split_once('=') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim();
        match key.as_str() {
            "upload" => {
                if let Ok(n) = val.parse::<u64>() {
                    info.upload_bytes = Some(n);
                    found_any = true;
                }
            }
            "download" => {
                if let Ok(n) = val.parse::<u64>() {
                    info.download_bytes = Some(n);
                    found_any = true;
                }
            }
            "total" => {
                if let Ok(n) = val.parse::<u64>() {
                    info.total_bytes = Some(n);
                    found_any = true;
                }
            }
            "expire" => {
                if let Ok(n) = val.parse::<i64>() {
                    info.expire_timestamp = Some(n);
                    found_any = true;
                }
            }
            _ => {}
        }
    }

    if found_any {
        Some(info)
    } else {
        None
    }
}

pub struct FetchedSubscription {
    pub subscription: Subscription,
    pub servers: Vec<ServerProfile>,
}

pub fn extract_metadata_from_body(
    body: &str,
) -> (Option<String>, Option<SubscriptionUserInfo>, Option<u32>) {
    let mut title = None;
    let mut user_info = None;
    let mut interval = None;

    for line in body.lines().take(25) {
        let trimmed = line.trim();
        if !trimmed.starts_with('#') {
            continue;
        }
        let comment = trimmed.trim_start_matches('#').trim();
        if let Some((k, v)) = comment.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            match key.as_str() {
                "profile-title" => {
                    if !val.is_empty() {
                        title = Some(decode_profile_title(val));
                    }
                }
                "subscription-userinfo" => {
                    user_info = parse_userinfo_value(val);
                }
                "profile-update-interval" => {
                    interval = val.parse::<u32>().ok();
                }
                _ => {}
            }
        }
    }

    (title, user_info, interval)
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn header_is_true(headers: &HeaderMap, name: &str) -> bool {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            let t = s.trim();
            t.eq_ignore_ascii_case("true") || t == "1"
        })
        .unwrap_or(false)
}

pub fn is_hwid_unsupported_placeholder(servers: &[ServerProfile]) -> bool {
    if servers.len() != 1 {
        return false;
    }
    let name = servers[0].name.to_lowercase();
    let mentions_hwid = name.contains("hwid");
    let indicates_unsupported = [
        "не поддерж",
        "not support",
        "unsupport",
        "требует",
        "required",
        "не указан",
        "missing",
    ]
    .iter()
    .any(|pat| name.contains(pat));
    mentions_hwid && indicates_unsupported
}

enum RedirectFetchOutcome {
    Response {
        final_url: Url,
        headers: HeaderMap,
        body: String,
    },
    DirectConfig {
        final_url: Url,
        body: String,
    },
}

async fn fetch_with_safe_redirects(
    initial_url: Url,
    user_agent: &str,
    identity: Option<&DeviceIdentity>,
    allow_loopback_for_test: bool,
) -> Result<RedirectFetchOutcome, FetchError> {
    let mut current_url = initial_url.clone();

    for _hop in 0..=MAX_REDIRECT_HOPS {
        let (host, addrs) = tokio::time::timeout(
            Duration::from_secs(10),
            resolve_and_pin_addrs(&current_url, allow_loopback_for_test),
        )
        .await
        .map_err(|_| {
            FetchError::Fatal("Превышен таймаут DNS-разрешения сервера подписки".into())
        })??;
        let client = build_pinned_client(&host, &addrs, user_agent, Duration::from_secs(15))?;

        let mut req = client
            .get(current_url.clone())
            .header("User-Agent", user_agent)
            .header("Accept", "*/*");

        // Send device HWID headers only over HTTPS (unless local loopback test) and only to the initial origin
        let send_identity = (current_url.scheme().eq_ignore_ascii_case("https")
            || allow_loopback_for_test)
            && same_origin(&current_url, &initial_url);

        if send_identity {
            if let Some(id) = identity {
                if let Ok(v) = HeaderValue::from_str(&id.hwid) {
                    req = req.header("x-hwid", v);
                }
                if let Ok(v) = HeaderValue::from_str(&id.device_os) {
                    req = req.header("x-device-os", v);
                }
                if let Ok(v) = HeaderValue::from_str(&id.ver_os) {
                    req = req.header("x-ver-os", v);
                }
                if let Ok(v) = HeaderValue::from_str(&id.device_model) {
                    req = req.header("x-device-model", v);
                }
            }
        }

        let response = req.send().await.map_err(|e| {
            FetchError::Retryable(if e.is_timeout() {
                "Сервер подписки не ответил за 15 секунд".to_string()
            } else if e.is_connect() {
                "Не удалось подключиться к серверу подписки".to_string()
            } else {
                "Не удалось загрузить подписку по сети".to_string()
            })
        })?;

        let status = response.status();
        if status.is_redirection() {
            let Some(loc) = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
            else {
                return Err(FetchError::Retryable(format!(
                    "Сервер вернул перенаправление HTTP {} без заголовка Location",
                    status.as_u16()
                )));
            };
            let loc_trimmed = loc.trim();

            if let Some(unwrapped) = unwrap_deeplink_target(loc_trimmed) {
                let low = unwrapped.to_ascii_lowercase();
                if low.starts_with("http://") || low.starts_with("https://") {
                    let next_url =
                        validate_subscription_url_with_options(&unwrapped, allow_loopback_for_test)
                            .map_err(FetchError::Fatal)?;
                    if !allow_loopback_for_test
                        && current_url.scheme().eq_ignore_ascii_case("https")
                        && next_url.scheme().eq_ignore_ascii_case("http")
                    {
                        return Err(FetchError::Fatal(
                            "Сервер попытался понизить защищённое соединение HTTPS до HTTP"
                                .to_string(),
                        ));
                    }
                    current_url = next_url;
                    continue;
                }
                return Ok(RedirectFetchOutcome::DirectConfig {
                    final_url: current_url,
                    body: unwrapped,
                });
            }

            let low_loc = loc_trimmed.to_ascii_lowercase();
            if low_loc.starts_with("vless://")
                || low_loc.starts_with("vmess://")
                || low_loc.starts_with("trojan://")
                || low_loc.starts_with("ss://")
                || low_loc.starts_with("hy2://")
                || low_loc.starts_with("hysteria2://")
                || low_loc.starts_with("vpn://")
            {
                return Ok(RedirectFetchOutcome::DirectConfig {
                    final_url: current_url,
                    body: loc_trimmed.to_string(),
                });
            }

            let joined = current_url.join(loc_trimmed).map_err(|_| {
                FetchError::Fatal(
                    "Некорректный адрес перенаправления Location от сервера подписки".to_string(),
                )
            })?;
            let next_url =
                validate_subscription_url_with_options(joined.as_str(), allow_loopback_for_test)
                    .map_err(FetchError::Fatal)?;
            if !allow_loopback_for_test
                && current_url.scheme().eq_ignore_ascii_case("https")
                && next_url.scheme().eq_ignore_ascii_case("http")
            {
                return Err(FetchError::Fatal(
                    "Запрещено перенаправление с HTTPS на незащищённый HTTP".to_string(),
                ));
            }
            current_url = next_url;
            continue;
        }

        let headers = response.headers().clone();

        if header_is_true(&headers, "x-hwid-max-devices-reached") {
            return Err(FetchError::Fatal(
                "Достигнут лимит устройств по HWID для этой подписки. Удалите лишнее устройство в боте или панели VPN и нажмите «Обновить»."
                    .to_string(),
            ));
        }

        if !status.is_success() {
            if header_is_true(&headers, "x-hwid-not-supported")
                || (status.as_u16() == 404 && header_is_true(&headers, "x-hwid-active"))
            {
                if identity.is_none() {
                    return Err(FetchError::Fatal(
                        "Сервер подписки требует передачу HWID устройства. Включите «Передавать HWID» в Настройках и обновите подписку."
                            .to_string(),
                    ));
                }
                return Err(FetchError::Retryable(
                    "Сервер подписки отклонил HWID или User-Agent клиента".to_string(),
                ));
            }
            return Err(FetchError::Retryable(format!(
                "Сервер подписки вернул ошибку HTTP {}",
                status.as_u16()
            )));
        }

        let bytes = read_body_limited(
            response,
            MAX_SUBSCRIPTION_BYTES,
            "Файл подписки превышает допустимый лимит 5 МБ",
        )
        .await?;

        let raw_text = String::from_utf8(bytes).map_err(|_| {
            FetchError::Fatal("Ответ подписки не является корректным UTF-8 текстом".to_string())
        })?;

        return Ok(RedirectFetchOutcome::Response {
            final_url: current_url,
            headers,
            body: raw_text,
        });
    }

    Err(FetchError::Retryable(
        "Слишком много перенаправлений (HTTP 301/302) при загрузке подписки".to_string(),
    ))
}

pub async fn fetch_subscription(
    raw_url: &str,
    existing_id: Option<String>,
    existing_title: Option<String>,
    identity: Option<&DeviceIdentity>,
) -> Result<FetchedSubscription, String> {
    fetch_subscription_with_options(raw_url, existing_id, existing_title, identity, false).await
}

pub async fn fetch_subscription_with_options(
    raw_url: &str,
    existing_id: Option<String>,
    existing_title: Option<String>,
    identity: Option<&DeviceIdentity>,
    allow_loopback_for_test: bool,
) -> Result<FetchedSubscription, String> {
    let url = validate_subscription_url_with_options(raw_url, allow_loopback_for_test)?;

    // Panels like Remnawave / Marzban / 3x-ui return raw subscription configs for known VPN User-Agents
    // and return HTML web pages (or 302 redirects / HWID stubs) for unknown User-Agents.
    let user_agents = [
        "Happ/2.3.1/Windows",
        "Happ/2.0 (Windows; x64)",
        "v2RayTun/3.0.0",
        "v2rayN/7.10",
    ];
    let mut last_err = None;

    for ua in user_agents {
        let outcome =
            match fetch_with_safe_redirects(url.clone(), ua, identity, allow_loopback_for_test)
                .await
            {
                Ok(o) => o,
                Err(FetchError::Fatal(msg)) => return Err(msg),
                Err(FetchError::Retryable(err)) => {
                    // Retry alternate User-Agent only on panel filtering (403/404/406) or HWID stub, not transient 5xx/network outage
                    let allow_ua_retry = err.contains("HTTP 403")
                        || err.contains("HTTP 404")
                        || err.contains("HTTP 406");
                    if !allow_ua_retry {
                        return Err(err);
                    }
                    last_err = Some(err);
                    continue;
                }
            };

        let (final_url, headers, raw_text) = match outcome {
            RedirectFetchOutcome::DirectConfig { final_url, body } => {
                (final_url, HeaderMap::new(), body)
            }
            RedirectFetchOutcome::Response {
                final_url,
                headers,
                body,
            } => (final_url, headers, body),
        };

        if header_is_true(&headers, "x-hwid-max-devices-reached") {
            return Err(
                "Достигнут лимит устройств по HWID для этой подписки. Удалите лишнее устройство в боте или панели VPN и нажмите «Обновить»."
                    .to_string(),
            );
        }

        let lower_preview = raw_text.trim_start().to_ascii_lowercase();
        if lower_preview.starts_with("<!doctype html") || lower_preview.starts_with("<html") {
            last_err = Some(
                "Сервер вернул HTML-страницу вместо подписки — возможно, сработала защита панели или ссылка ведёт на веб-сайт"
                    .to_string(),
            );
            continue;
        }

        let has_clash_proxies = raw_text
            .lines()
            .any(|l| l.trim_start().starts_with("proxies:"));
        let decoded_body = if !raw_text.contains("://")
            && !raw_text.trim_start().starts_with('#')
            && !raw_text.trim_start().starts_with('{')
            && !raw_text.trim_start().starts_with('[')
            && !has_clash_proxies
            && !raw_text.contains("[Interface]")
        {
            decode_base64_text(&raw_text).unwrap_or(raw_text)
        } else {
            raw_text
        };

        let (body_title, body_userinfo, body_interval) = extract_metadata_from_body(&decoded_body);
        let header_title = header_str(&headers, "profile-title").map(|v| decode_profile_title(&v));
        let header_userinfo =
            header_str(&headers, "subscription-userinfo").and_then(|v| parse_userinfo_value(&v));
        let header_interval =
            header_str(&headers, "profile-update-interval").and_then(|v| v.parse::<u32>().ok());

        let sub_id = existing_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let imported = parse_import_text(&decoded_body, Some(sub_id.clone()));

        if is_hwid_unsupported_placeholder(&imported.imported_servers) {
            if identity.is_none() {
                return Err(
                    "Сервер подписки требует передачу HWID устройства. Включите «Передавать HWID» в Настройках и обновите подписку."
                        .to_string(),
                );
            }
            last_err = Some(
                "Сервер подписки вернул заглушку «Приложение не поддерживает HWID». Проверьте настройки HWID или лимит устройств в панели VPN."
                    .to_string(),
            );
            continue;
        }

        if imported.imported_servers.is_empty() {
            last_err =
                Some(
                    imported.errors.into_iter().next().unwrap_or_else(|| {
                        "Подписка не содержит поддерживаемых серверов".to_string()
                    }),
                );
            continue;
        }

        let fallback_host = final_url
            .host_str()
            .or_else(|| url.host_str())
            .unwrap_or("Подписка")
            .to_string();
        let title = header_title
            .or(body_title)
            .or(existing_title)
            .unwrap_or(fallback_host);

        let subscription = Subscription {
            id: sub_id,
            title,
            url: url.to_string(),
            updated_at: Utc::now().to_rfc3339(),
            server_count: imported.imported_servers.len(),
            update_interval_hours: header_interval.or(body_interval),
            user_info: header_userinfo.or(body_userinfo),
            last_error: None,
            enabled: true,
            auto_update: true,
            error_history: Vec::new(),
            sync_history: Vec::new(),
        };

        return Ok(FetchedSubscription {
            subscription,
            servers: imported.imported_servers,
        });
    }

    Err(last_err.unwrap_or_else(|| "Не удалось загрузить подписку".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn rejects_private_and_non_http_urls() {
        assert!(validate_subscription_url("ftp://example.com/sub").is_err());
        assert!(validate_subscription_url("https://localhost/sub").is_err());
        assert!(validate_subscription_url("https://127.0.0.1/sub").is_err());
        assert!(validate_subscription_url("https://192.168.1.10/sub").is_err());
        assert!(validate_subscription_url("https://10.0.0.1/sub").is_err());
        assert!(validate_subscription_url("https://169.254.169.254/latest").is_err());
        assert!(validate_subscription_url("https://sub.example.com/u/123").is_ok());
        assert!(validate_subscription_url("http://sub.example.com/u/123").is_ok());
    }

    #[test]
    fn parses_happ_headers_and_body_metadata() {
        let body = "#profile-title: base64:QVVSQSBQcmVtaXVt\n#subscription-userinfo: upload=1024; download=2048; total=1048576; expire=1800000000\n#profile-update-interval: 12\nvless://11111111-2222-3333-4444-555555555555@1.2.3.4:443#Test";
        let (title, info, interval) = extract_metadata_from_body(body);
        assert_eq!(title.as_deref(), Some("AURA Premium"));
        let info = info.expect("user info parsed");
        assert_eq!(info.upload_bytes, Some(1024));
        assert_eq!(info.download_bytes, Some(2048));
        assert_eq!(info.total_bytes, Some(1048576));
        assert_eq!(info.expire_timestamp, Some(1800000000));
        assert_eq!(interval, Some(12));
    }

    #[tokio::test]
    async fn follows_302_redirect_and_unwraps_happ_deeplink() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");

                    let resp = if path == "/start" {
                        format!(
                            "HTTP/1.1 302 Found\r\nLocation: happ://add/http://127.0.0.1:{port}/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    } else {
                        let sub_text = "vless://11111111-2222-3333-4444-555555555555@nl.example.com:443?security=reality&pbk=PubKey123&sni=www.microsoft.com#Redirected%20NL";
                        let b64 = STANDARD.encode(sub_text.as_bytes());
                        format!(
                            "HTTP/1.1 200 OK\r\nprofile-title: TG Bot Sub\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            b64.len(),
                            b64
                        )
                    };
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let test_identity = DeviceIdentity {
            hwid: "a1b2c3d4-e5f6-4789-8abc-0123456789ef".to_string(),
            device_os: "Windows".to_string(),
            ver_os: "10.0.26300".to_string(),
            device_model: "Test-PC".to_string(),
        };

        let fetched = fetch_subscription_with_options(
            &format!("http://127.0.0.1:{port}/start"),
            None,
            None,
            Some(&test_identity),
            true,
        )
        .await
        .expect("302 + happ://add redirect chain must succeed");

        assert_eq!(fetched.subscription.title, "TG Bot Sub");
        assert_eq!(fetched.servers.len(), 1);
        assert_eq!(fetched.servers[0].name, "Redirected NL");

        server_task.abort();
    }

    #[tokio::test]
    async fn sends_hwid_headers_across_redirects_and_gets_real_nodes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");

                    let lower_req = req.to_ascii_lowercase();
                    let has_hwid =
                        lower_req.contains("x-hwid: 11112222-3333-4444-8555-666677778888");
                    let has_os = lower_req.contains("x-device-os: windows");
                    let has_ver = lower_req.contains("x-ver-os: 10.0.26300");
                    let has_model = lower_req.contains("x-device-model: custom-pc");

                    let resp = if path == "/go" {
                        format!(
                            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/sub\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    } else if has_hwid && has_os && has_ver && has_model {
                        let body = "vless://11111111-2222-3333-4444-555555555555@nl.example.com:443?security=reality&pbk=PubKey123&sni=www.microsoft.com#Netherlands%20Premium";
                        format!(
                            "HTTP/1.1 200 OK\r\nprofile-title: HWID Ok\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    } else {
                        let dummy = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:443?security=none#%D0%9F%D1%80%D0%B8%D0%BB%D0%BE%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5%20%D0%BD%D0%B5%20%D0%BF%D0%BE%D0%B4%D0%B4%D0%B5%D1%80%D0%B6%D0%B8%D0%B2%D0%B0%D0%B5%D1%82%20HWID";
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            dummy.len(),
                            dummy
                        )
                    };
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let identity = DeviceIdentity {
            hwid: "11112222-3333-4444-8555-666677778888".to_string(),
            device_os: "Windows".to_string(),
            ver_os: "10.0.26300".to_string(),
            device_model: "Custom-PC".to_string(),
        };

        let fetched = fetch_subscription_with_options(
            &format!("http://127.0.0.1:{port}/go"),
            None,
            None,
            Some(&identity),
            true,
        )
        .await
        .expect("HWID redirect chain must import real node");
        assert_eq!(fetched.servers.len(), 1);
        assert_eq!(fetched.servers[0].name, "Netherlands Premium");

        let no_hwid_err = fetch_subscription_with_options(
            &format!("http://127.0.0.1:{port}/go"),
            None,
            None,
            None,
            true,
        )
        .await
        .err()
        .expect("Missing HWID must fail instead of importing dummy placeholder");
        assert!(no_hwid_err.contains("HWID"));

        server_task.abort();
    }

    #[tokio::test]
    async fn handles_remnawave_max_devices_reached_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_task = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let resp = "HTTP/1.1 404 Not Found\r\nx-hwid-active: true\r\nx-hwid-max-devices-reached: true\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let identity = DeviceIdentity {
            hwid: "11112222-3333-4444-8555-666677778888".to_string(),
            device_os: "Windows".to_string(),
            ver_os: "10.0.26300".to_string(),
            device_model: "Custom-PC".to_string(),
        };

        let err = fetch_subscription_with_options(
            &format!("http://127.0.0.1:{port}/sub"),
            None,
            None,
            Some(&identity),
            true,
        )
        .await
        .err()
        .expect("Max devices reached header must return error");
        assert!(err.contains("лимит устройств по HWID"));

        server_task.abort();
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6_ssrf() {
        assert!(validate_subscription_url("https://[::ffff:127.0.0.1]/sub").is_err());
        assert!(validate_subscription_url("https://[::ffff:169.254.169.254]/latest").is_err());
        assert!(validate_subscription_url("https://[::ffff:192.168.1.1]/").is_err());
    }
}
