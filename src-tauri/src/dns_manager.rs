use crate::logger::redact_secrets;
use crate::models::{
    AppSettings, ConnectionMode, ConnectionSnapshot, ConnectionStatus, DnsConfigAnalysis,
    DnsInspectorReport, DnsLiveLookupResult, DnsServerTestResult, RoutingProfile, ServerProfile,
};
use crate::routing_rules::{collect_active_ru_domains, RulepackData};
use chrono::Utc;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};

fn classify_dns_scheme(server: &str) -> &'static str {
    let low = server.trim().to_ascii_lowercase();
    if low.starts_with("https://") || low.starts_with("https+local://") {
        "doh"
    } else if low.starts_with("tls://") || low.starts_with("tls+local://") {
        "dot"
    } else if low.starts_with("quic://") || low.starts_with("quic+local://") {
        "doq"
    } else if low.starts_with("tcp://") || low.starts_with("tcp+local://") {
        "tcp"
    } else {
        "plain"
    }
}

pub fn build_dns_config_analysis(
    settings: &AppSettings,
    active_profile: Option<&ServerProfile>,
    snap: &ConnectionSnapshot,
    pack: &RulepackData,
) -> DnsConfigAnalysis {
    let mode = settings.dns.mode.trim().to_ascii_lowercase();
    let effective_mode = match mode.as_str() {
        "auto" => "hybrid".to_string(),
        other => other.to_string(),
    };

    let custom_override = active_profile
        .and_then(|p| p.overrides.as_ref())
        .and_then(|o| o.custom_dns.as_ref())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let profile_dns = active_profile.and_then(|p| match &p.details {
        crate::models::ProtocolDetails::Wireguard(w) => w.dns.first().cloned(),
        crate::models::ProtocolDetails::AmneziaWg(a) => a.dns.first().cloned(),
        _ => None,
    });

    let mut active_servers = Vec::new();
    if effective_mode == "config" {
        if let Some(pd) = profile_dns {
            active_servers.push(pd);
        } else {
            active_servers.push(settings.dns.primary_dns.clone());
        }
    } else if effective_mode == "system" {
        active_servers.push("localhost (Системный DNS Windows)".into());
    } else if effective_mode == "direct" {
        active_servers.push(settings.dns.direct_dns.clone());
        if let Some(ref fb) = settings.dns.direct_fallback_dns {
            if !fb.trim().is_empty() {
                active_servers.push(fb.trim().to_string());
            }
        }
    } else {
        if let Some(ov) = custom_override {
            active_servers.push(format!("{ov} (override профиля)"));
        } else {
            active_servers.push(settings.dns.primary_dns.clone());
        }
        if let Some(ref fb) = settings.dns.fallback_dns {
            if !fb.trim().is_empty() {
                active_servers.push(fb.trim().to_string());
            }
        }
    }

    let direct_servers = if effective_mode != "vpn" {
        let mut d = vec![settings.dns.direct_dns.clone()];
        if let Some(ref fb) = settings.dns.direct_fallback_dns {
            if !fb.trim().is_empty() {
                d.push(fb.trim().to_string());
            }
        }
        d
    } else {
        Vec::new()
    };

    let ru_domains = collect_active_ru_domains(&settings.routing, pack);
    let effective_conn_mode = if snap.status == ConnectionStatus::Connected {
        snap.mode
    } else {
        settings.connection_mode
    };
    let tun_hijack = effective_conn_mode == ConnectionMode::Tun;

    let mut warnings = Vec::new();
    if effective_mode == "direct" {
        warnings.push("Режим «Прямой DNS» отправляет все DNS-запросы в обход VPN — возможна видимость доменов для провайдера.".into());
    }
    if effective_mode == "system" && effective_conn_mode == ConnectionMode::Tun {
        warnings.push("В TUN с режимом «Системный DNS» Xray обращается к localhost — убедитесь, что системный резолвер не блокируется Kill Switch.".into());
    }
    if settings.dns.disable_fallback {
        warnings.push("Отключён резервный DNS: при недоступности основного DNS-сервера сайты перестанут открываться до смены сервера.".into());
    }
    if effective_conn_mode == ConnectionMode::SystemProxy
        && !settings.routing.bypass_ru_domains
        && settings.routing.profile != RoutingProfile::RuDirect
    {
        warnings.push("В режиме «Системный прокси» браузер по-прежнему может использовать локальный DNS до установки SOCKS5/HTTP соединения, если у браузера не включён DoH.".into());
    }

    let leak_risk_level = if effective_mode == "direct" || effective_mode == "system" {
        "medium".into()
    } else if tun_hijack && (effective_mode == "vpn" || effective_mode == "hybrid") {
        "low".into()
    } else {
        "moderate_proxy".into()
    };

    let system_proxy_dns_note = if tun_hijack {
        "Перехват порта UDP/TCP :53 активен в Wintun (dns-out): сторонние приложения принудительно используют настроенный DNS.".into()
    } else {
        "В режиме Системного прокси доменные запросы HTTP/SOCKS передаются в Xray, однако прямые UDP :53 запросы ОС без TUN не перехватываются.".into()
    };

    DnsConfigAnalysis {
        effective_mode,
        active_servers,
        direct_servers,
        direct_domains_count: ru_domains.len(),
        tun_dns_hijack_active: tun_hijack,
        system_proxy_dns_note,
        cache_enabled: !settings.dns.disable_cache,
        fallback_enabled: !settings.dns.disable_fallback,
        ipv6_query_strategy: settings.dns.query_strategy.clone().unwrap_or_else(|| {
            if settings.ipv6_enabled {
                "UseIP".into()
            } else {
                "UseIPv4".into()
            }
        }),
        leak_risk_level,
        warnings,
    }
}

pub fn build_dns_inspector_report(
    settings: &AppSettings,
    active_profile: Option<&ServerProfile>,
    snap: &ConnectionSnapshot,
    pack: &RulepackData,
    live_lookup: Option<DnsLiveLookupResult>,
) -> DnsInspectorReport {
    DnsInspectorReport {
        checked_at: Utc::now().to_rfc3339(),
        config_analysis: build_dns_config_analysis(settings, active_profile, snap, pack),
        live_lookup,
    }
}

fn build_dns_query_packet(domain: &str, id: u16) -> Result<Vec<u8>, String> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // QDCOUNT=1
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("Некорректное доменное имя для DNS-запроса".into());
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
    Ok(pkt)
}

fn parse_dns_a_answers(resp: &[u8]) -> Vec<String> {
    if resp.len() < 12 {
        return Vec::new();
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let mut pos = 12usize;
    // Skip question section
    while pos < resp.len() {
        let len = resp[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        pos = pos.saturating_add(len);
    }
    pos = pos.saturating_add(4); // QTYPE + QCLASS

    let mut ips = Vec::new();
    for _ in 0..ancount {
        if pos >= resp.len() {
            break;
        }
        if resp[pos] & 0xC0 == 0xC0 {
            pos = pos.saturating_add(2);
        } else {
            while pos < resp.len() {
                let len = resp[pos] as usize;
                pos += 1;
                if len == 0 {
                    break;
                }
                pos = pos.saturating_add(len);
            }
        }
        if pos + 10 > resp.len() {
            break;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > resp.len() {
            break;
        }
        if rtype == 1 && rdlength == 4 {
            ips.push(format!(
                "{}.{}.{}.{}",
                resp[pos],
                resp[pos + 1],
                resp[pos + 2],
                resp[pos + 3]
            ));
        }
        pos += rdlength;
    }
    ips
}

pub async fn test_dns_server_live(
    server: &str,
    domain: Option<&str>,
    snap: &ConnectionSnapshot,
    settings: &AppSettings,
) -> DnsServerTestResult {
    let clean = server.trim();
    let proto = classify_dns_scheme(clean).to_string();
    let test_domain = domain
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("one.one.one.one");

    if test_domain.len() > 253
        || !test_domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return DnsServerTestResult {
            server: clean.to_string(),
            protocol: proto,
            reachable: false,
            latency_ms: None,
            resolved_ips: Vec::new(),
            error: Some("Некорректный тестовый домен для DNS-проверки.".into()),
            via_vpn: false,
        };
    }

    if snap.kill_switch.blocking_active || snap.kill_switch_engaged {
        return DnsServerTestResult {
            server: clean.to_string(),
            protocol: proto,
            reachable: false,
            latency_ms: None,
            resolved_ips: Vec::new(),
            error: Some("Проверка заблокирована активным Kill Switch.".into()),
            via_vpn: false,
        };
    }

    let is_connected = snap.status == ConnectionStatus::Connected;
    let proxy_port = if is_connected && snap.mode == ConnectionMode::SystemProxy {
        snap.local_http_port.or(Some(settings.http_port))
    } else {
        None
    };

    let started = Instant::now();
    if proto == "doh" {
        let https_url = clean.replace("https+local://", "https://");
        let parsed_url = match crate::net_fetch::validate_http_url(&https_url, true, false) {
            Ok(u) => u,
            Err(_) => {
                return DnsServerTestResult {
                    server: clean.to_string(),
                    protocol: proto,
                    reachable: false,
                    latency_ms: None,
                    resolved_ips: Vec::new(),
                    error: Some(
                        "DoH URL отклонён политикой безопасности (допустим только публичный HTTPS)."
                            .into(),
                    ),
                    via_vpn: false,
                };
            }
        };
        let query_url = if https_url.contains('?') {
            format!("{https_url}&name={test_domain}&type=A")
        } else {
            format!("{https_url}?name={test_domain}&type=A")
        };
        let client_res = if let Some(p) = proxy_port {
            let mut builder = reqwest::Client::builder()
                .timeout(Duration::from_secs(6))
                .redirect(reqwest::redirect::Policy::none());
            if let Ok(pr) = reqwest::Proxy::all(format!("http://127.0.0.1:{p}")) {
                builder = builder.proxy(pr);
            }
            builder.build().map_err(|e| e.to_string())
        } else {
            match crate::net_fetch::resolve_and_pin_addrs(&parsed_url, false).await {
                Ok((pinned_host, pinned_addrs)) => crate::net_fetch::build_pinned_client(
                    &pinned_host,
                    &pinned_addrs,
                    "AURA-VPN-DNS/1.0",
                    Duration::from_secs(6),
                )
                .map_err(|e| e.into_message()),
                Err(e) => Err(e.into_message()),
            }
        };
        match client_res {
            Ok(client) => match client
                .get(&query_url)
                .header("Accept", "application/dns-json")
                .send()
                .await
            {
                Ok(mut resp) => {
                    let status_code = resp.status().as_u16();
                    let is_success = resp.status().is_success();
                    let ok = is_success || status_code == 400;
                    let mut ips = Vec::new();
                    if is_success {
                        const MAX_DOH_BYTES: usize = 64 * 1024;
                        let within_header = resp
                            .content_length()
                            .is_none_or(|l| l as usize <= MAX_DOH_BYTES);
                        if within_header {
                            let mut buf = Vec::new();
                            while let Ok(Some(chunk)) = resp.chunk().await {
                                if buf.len().saturating_add(chunk.len()) > MAX_DOH_BYTES {
                                    buf.clear();
                                    break;
                                }
                                buf.extend_from_slice(&chunk);
                            }
                            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&buf) {
                                if let Some(arr) = v.get("Answer").and_then(|a| a.as_array()) {
                                    for item in arr {
                                        if let Some(data) =
                                            item.get("data").and_then(|d| d.as_str())
                                        {
                                            if data.parse::<IpAddr>().is_ok() {
                                                ips.push(data.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    DnsServerTestResult {
                        server: clean.to_string(),
                        protocol: proto,
                        reachable: ok,
                        latency_ms: Some(started.elapsed().as_millis().max(1) as u64),
                        resolved_ips: ips,
                        error: (!ok).then(|| format!("HTTP {status_code}")),
                        via_vpn: is_connected,
                    }
                }
                Err(e) => DnsServerTestResult {
                    server: clean.to_string(),
                    protocol: proto,
                    reachable: false,
                    latency_ms: None,
                    resolved_ips: Vec::new(),
                    error: Some(redact_secrets(&e.to_string())),
                    via_vpn: is_connected,
                },
            },
            Err(e) => DnsServerTestResult {
                server: clean.to_string(),
                protocol: proto,
                reachable: false,
                latency_ms: None,
                resolved_ips: Vec::new(),
                error: Some(e.to_string()),
                via_vpn: is_connected,
            },
        }
    } else if proto == "dot" || proto == "doq" {
        let authority = clean
            .trim_start_matches("tls+local://")
            .trim_start_matches("tls://")
            .trim_start_matches("quic+local://")
            .trim_start_matches("quic://")
            .split('/')
            .next()
            .unwrap_or("")
            .trim();
        let (host_only, port_num): (&str, u16) = if authority.starts_with('[') {
            if let Some((h, rest)) = authority.split_once(']') {
                let p = rest
                    .strip_prefix(':')
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(853);
                (&h[1..], p)
            } else {
                (authority, 853)
            }
        } else if let Some((h, p_str)) = authority.rsplit_once(':') {
            (h, p_str.parse::<u16>().unwrap_or(853))
        } else {
            (authority, 853)
        };
        if host_only.is_empty() || port_num == 0 {
            return DnsServerTestResult {
                server: clean.to_string(),
                protocol: proto,
                reachable: false,
                latency_ms: None,
                resolved_ips: Vec::new(),
                error: Some("Некорректный адрес DoT/DoQ-сервера.".into()),
                via_vpn: is_connected,
            };
        }
        if proto == "doq" {
            return DnsServerTestResult {
                server: clean.to_string(),
                protocol: proto,
                reachable: false,
                latency_ms: None,
                resolved_ips: Vec::new(),
                error: Some("Прямой QUIC-рукопожатие тест вне Xray не выполняется; формат DoQ поддерживается ядром Xray.".into()),
                via_vpn: is_connected,
            };
        }
        let resolved_target: Option<SocketAddr> = if let Ok(ip) = host_only.parse::<IpAddr>() {
            if crate::net_fetch::is_forbidden_ip(ip) {
                None
            } else {
                Some(SocketAddr::new(ip, port_num))
            }
        } else {
            match tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::lookup_host((host_only, port_num)),
            )
            .await
            {
                Ok(Ok(mut addrs)) => addrs.find(|a| !crate::net_fetch::is_forbidden_ip(a.ip())),
                _ => None,
            }
        };
        let Some(target_addr) = resolved_target else {
            return DnsServerTestResult {
                server: clean.to_string(),
                protocol: proto,
                reachable: false,
                latency_ms: None,
                resolved_ips: Vec::new(),
                error: Some(
                    "Локальные/приватные адреса и неразрешимые хосты запрещены для DoT-проверки."
                        .into(),
                ),
                via_vpn: false,
            };
        };
        match tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(target_addr)).await {
            Ok(Ok(_)) => DnsServerTestResult {
                server: clean.to_string(),
                protocol: proto,
                reachable: true,
                latency_ms: Some(started.elapsed().as_millis().max(1) as u64),
                resolved_ips: Vec::new(),
                error: None,
                via_vpn: false,
            },
            _ => DnsServerTestResult {
                server: clean.to_string(),
                protocol: proto,
                reachable: false,
                latency_ms: None,
                resolved_ips: Vec::new(),
                error: Some(format!("TCP :{port_num} до {host_only} не отвечает")),
                via_vpn: false,
            },
        }
    } else {
        let raw_ip = clean
            .trim_start_matches("tcp+local://")
            .trim_start_matches("tcp://")
            .split(':')
            .next()
            .unwrap_or(clean);
        let Ok(ip) = raw_ip.parse::<IpAddr>() else {
            return DnsServerTestResult {
                server: clean.to_string(),
                protocol: proto,
                reachable: false,
                latency_ms: None,
                resolved_ips: Vec::new(),
                error: Some("Укажите корректный IP или DoH/DoT URL".into()),
                via_vpn: false,
            };
        };
        if crate::net_fetch::is_forbidden_ip(ip) {
            return DnsServerTestResult {
                server: clean.to_string(),
                protocol: proto,
                reachable: false,
                latency_ms: None,
                resolved_ips: Vec::new(),
                error: Some("Локальные/приватные IP запрещены для прямого UDP DNS-теста.".into()),
                via_vpn: false,
            };
        }
        let target = SocketAddr::new(ip, 53);
        let pkt = match build_dns_query_packet(test_domain, 0xA470) {
            Ok(p) => p,
            Err(e) => {
                return DnsServerTestResult {
                    server: clean.to_string(),
                    protocol: proto,
                    reachable: false,
                    latency_ms: None,
                    resolved_ips: Vec::new(),
                    error: Some(e),
                    via_vpn: false,
                }
            }
        };
        let bind_addr = if ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        match UdpSocket::bind(bind_addr).await {
            Ok(sock) => {
                let mut buf = [0u8; 512];
                let io_res = tokio::time::timeout(Duration::from_secs(3), async {
                    sock.send_to(&pkt, target).await?;
                    sock.recv_from(&mut buf).await
                })
                .await;
                match io_res {
                    Ok(Ok((n, _))) => {
                        let ips = parse_dns_a_answers(&buf[..n]);
                        DnsServerTestResult {
                            server: clean.to_string(),
                            protocol: proto,
                            reachable: true,
                            latency_ms: Some(started.elapsed().as_millis().max(1) as u64),
                            resolved_ips: ips,
                            error: None,
                            via_vpn: is_connected && snap.mode == ConnectionMode::Tun,
                        }
                    }
                    _ => DnsServerTestResult {
                        server: clean.to_string(),
                        protocol: proto,
                        reachable: false,
                        latency_ms: None,
                        resolved_ips: Vec::new(),
                        error: Some(format!("UDP :53 сервер {ip} не ответил за 3 с")),
                        via_vpn: is_connected && snap.mode == ConnectionMode::Tun,
                    },
                }
            }
            Err(e) => DnsServerTestResult {
                server: clean.to_string(),
                protocol: proto,
                reachable: false,
                latency_ms: None,
                resolved_ips: Vec::new(),
                error: Some(e.to_string()),
                via_vpn: false,
            },
        }
    }
}

pub async fn run_dns_lookup_honest(
    domain: &str,
    settings: &AppSettings,
    snap: &ConnectionSnapshot,
) -> DnsLiveLookupResult {
    let clean = domain.trim();
    if snap.kill_switch.blocking_active || snap.kill_switch_engaged {
        return DnsLiveLookupResult {
            domain: clean.to_string(),
            resolver_used: "Заблокировано Kill Switch".into(),
            resolved_ips: Vec::new(),
            latency_ms: None,
            bypassed_vpn_warning: false,
            error: Some("Активный Kill Switch блокирует внешние DNS-проверки.".into()),
        };
    }

    let is_conn = snap.status == ConnectionStatus::Connected;
    let started = Instant::now();

    if is_conn
        && snap.mode == ConnectionMode::SystemProxy
        && settings.dns.primary_dns.starts_with("https")
    {
        let r = test_dns_server_live(&settings.dns.primary_dns, Some(clean), snap, settings).await;
        return DnsLiveLookupResult {
            domain: clean.to_string(),
            resolver_used: format!("DoH через активный прокси ({})", settings.dns.primary_dns),
            resolved_ips: r.resolved_ips,
            latency_ms: r.latency_ms,
            bypassed_vpn_warning: false,
            error: r.error,
        };
    }

    let resolver_used = if is_conn && snap.mode == ConnectionMode::Tun {
        format!(
            "Системный резолвер через TUN ({})",
            settings.tun.adapter_name
        )
    } else if is_conn {
        "Системный резолвер Windows (в режиме Системного прокси не проходит через Xray SOCKS/HTTP)"
            .into()
    } else {
        "Системный резолвер Windows (без VPN)".into()
    };
    let bypassed = is_conn && snap.mode == ConnectionMode::SystemProxy;

    match tokio::time::timeout(
        Duration::from_secs(4),
        tokio::net::lookup_host(format!("{clean}:443")),
    )
    .await
    {
        Ok(Ok(addrs)) => {
            let mut ips = Vec::new();
            for sa in addrs {
                let ip = sa.ip().to_string();
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            DnsLiveLookupResult {
                domain: clean.to_string(),
                resolver_used,
                resolved_ips: ips,
                latency_ms: Some(started.elapsed().as_millis().max(1) as u64),
                bypassed_vpn_warning: bypassed,
                error: None,
            }
        }
        Ok(Err(e)) => DnsLiveLookupResult {
            domain: clean.to_string(),
            resolver_used,
            resolved_ips: Vec::new(),
            latency_ms: None,
            bypassed_vpn_warning: bypassed,
            error: Some(e.to_string()),
        },
        Err(_) => DnsLiveLookupResult {
            domain: clean.to_string(),
            resolver_used,
            resolved_ips: Vec::new(),
            latency_ms: None,
            bypassed_vpn_warning: bypassed,
            error: Some("Таймаут DNS-разрешения (4 с)".into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blocks_ssrf_and_invalid_domain_in_live_dns_test() {
        let snap = ConnectionSnapshot::default();
        let settings = AppSettings::default();

        let res_ssrf =
            test_dns_server_live("https://127.0.0.1/dns-query", None, &snap, &settings).await;
        assert!(!res_ssrf.reachable);
        assert!(res_ssrf.error.as_deref().unwrap_or("").contains("отклонён"));

        let res_udp_local = test_dns_server_live("192.168.1.1", None, &snap, &settings).await;
        assert!(!res_udp_local.reachable);

        let res_bad_dom = test_dns_server_live(
            "https://dns.google/dns-query",
            Some("evil.com&extra=1"),
            &snap,
            &settings,
        )
        .await;
        assert!(!res_bad_dom.reachable);
    }
}
