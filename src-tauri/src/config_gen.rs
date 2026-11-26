use crate::models::{
    AdvancedVpnSettings, AmneziaWgDetails, AppSettings, ConnectionMode, CoreSelectionMode,
    DnsConfig, Hysteria2Details, MtuMode, ProtocolDetails, RoutingConfig, RuleAction,
    RuleMatchType, ServerProfile, SplitTunnelMode, TrojanDetails, TunSettings, VlessDetails,
    VmessDetails, WireguardDetails,
};
use crate::routing_rules::{
    collect_active_ru_domains, default_rulepack, effective_split_mode, RulepackData,
};
use serde_json::{json, Map, Value};

fn apply_v26_tls_pinning(
    tls: &mut Map<String, Value>,
    pinned_cert_sha256: Option<&str>,
    verify_peer_cert_by_name: Option<&str>,
) {
    // Note: Xray-core v26 removed `allowInsecure`; never emit it.
    if let Some(pcs) = pinned_cert_sha256 {
        if !pcs.trim().is_empty() {
            tls.insert("pinnedPeerCertSha256".to_string(), json!(pcs.trim()));
        }
    }
    if let Some(vcn) = verify_peer_cert_by_name {
        if !vcn.trim().is_empty() {
            tls.insert("verifyPeerCertByName".to_string(), json!(vcn.trim()));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_transport_stream_settings(
    network: &str,
    security: &str,
    sni: Option<&str>,
    fingerprint: Option<&str>,
    public_key: Option<&str>,
    short_id: Option<&str>,
    spider_x: Option<&str>,
    path: Option<&str>,
    host_header: Option<&str>,
    service_name: Option<&str>,
    alpn: Option<&Vec<String>>,
    pinned_cert_sha256: Option<&str>,
    verify_peer_cert_by_name: Option<&str>,
    header_type: Option<&str>,
    xhttp_mode: Option<&str>,
    xhttp_extra: Option<&Value>,
    pqv: Option<&str>,
    grpc_authority: Option<&str>,
    grpc_multi_mode: bool,
    kcp_seed: Option<&str>,
    fallback_server_name: &str,
) -> Value {
    let normalized_net = match network {
        "tcp" | "raw" | "" => "raw",
        other => other,
    };

    let mut stream = Map::new();
    stream.insert("network".to_string(), json!(normalized_net));
    stream.insert("security".to_string(), json!(security));

    match security {
        "tls" => {
            let mut tls = Map::new();
            tls.insert(
                "serverName".to_string(),
                json!(sni.unwrap_or(fallback_server_name)),
            );
            apply_v26_tls_pinning(&mut tls, pinned_cert_sha256, verify_peer_cert_by_name);
            if let Some(fp) = fingerprint {
                tls.insert("fingerprint".to_string(), json!(fp));
            }
            if let Some(alpn_list) = alpn {
                tls.insert("alpn".to_string(), json!(alpn_list));
            }
            stream.insert("tlsSettings".to_string(), Value::Object(tls));
        }
        "reality" => {
            let mut reality = Map::new();
            reality.insert(
                "serverName".to_string(),
                json!(sni.unwrap_or(fallback_server_name)),
            );
            reality.insert(
                "fingerprint".to_string(),
                json!(fingerprint.unwrap_or("chrome")),
            );
            reality.insert("publicKey".to_string(), json!(public_key.unwrap_or("")));
            reality.insert("shortId".to_string(), json!(short_id.unwrap_or("")));
            reality.insert("spiderX".to_string(), json!(spider_x.unwrap_or("")));
            if let Some(pqv_val) = pqv.map(str::trim).filter(|s| !s.is_empty()) {
                reality.insert("mldsa65Verify".to_string(), json!(pqv_val));
            }
            stream.insert("realitySettings".to_string(), Value::Object(reality));
        }
        _ => {}
    }

    match normalized_net {
        "raw" => {
            if let Some("http") = header_type {
                let mut req = Map::new();
                if let Some(p) = path {
                    let paths: Vec<&str> = p
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !paths.is_empty() {
                        req.insert("path".to_string(), json!(paths));
                    }
                }
                if let Some(h) = host_header {
                    let hosts: Vec<&str> = h
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !hosts.is_empty() {
                        req.insert("headers".to_string(), json!({ "Host": hosts }));
                    }
                }
                stream.insert(
                    "rawSettings".to_string(),
                    json!({
                        "header": {
                            "type": "http",
                            "request": Value::Object(req)
                        }
                    }),
                );
            }
        }
        "ws" => {
            let mut ws = Map::new();
            let raw_path = path.unwrap_or("/");
            ws.insert("path".to_string(), json!(raw_path));
            if let Some(host) = host_header.map(str::trim).filter(|s| !s.is_empty()) {
                ws.insert("host".to_string(), json!(host));
            }
            stream.insert("wsSettings".to_string(), Value::Object(ws));
        }
        "grpc" => {
            let mut grpc = Map::new();
            grpc.insert(
                "serviceName".to_string(),
                json!(service_name.or(path).unwrap_or("")),
            );
            if grpc_multi_mode {
                grpc.insert("multiMode".to_string(), json!(true));
            }
            if let Some(auth) = grpc_authority.map(str::trim).filter(|s| !s.is_empty()) {
                grpc.insert("authority".to_string(), json!(auth));
            }
            stream.insert("grpcSettings".to_string(), Value::Object(grpc));
        }
        "httpupgrade" => {
            let mut hu = Map::new();
            hu.insert("path".to_string(), json!(path.unwrap_or("/")));
            if let Some(host) = host_header.map(str::trim).filter(|s| !s.is_empty()) {
                hu.insert("host".to_string(), json!(host));
            }
            stream.insert("httpupgradeSettings".to_string(), Value::Object(hu));
        }
        "xhttp" => {
            let mut xhttp = Map::new();
            xhttp.insert("path".to_string(), json!(path.unwrap_or("/")));
            if let Some(host) = host_header.map(str::trim).filter(|s| !s.is_empty()) {
                xhttp.insert("host".to_string(), json!(host));
            }
            if let Some(mode) = xhttp_mode {
                xhttp.insert("mode".to_string(), json!(mode));
            }
            if let Some(extra) = xhttp_extra {
                let mut clean_extra = extra.clone();
                crate::parser::raw_json::sanitize_xray_outbound_v26(&mut clean_extra);
                xhttp.insert("extra".to_string(), clean_extra);
            }
            stream.insert("xhttpSettings".to_string(), Value::Object(xhttp));
        }
        "http" => {
            let mut http = Map::new();
            http.insert("path".to_string(), json!(path.unwrap_or("/")));
            if let Some(host) = host_header.map(str::trim).filter(|s| !s.is_empty()) {
                let hosts: Vec<&str> = host
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect();
                if !hosts.is_empty() {
                    http.insert("host".to_string(), json!(hosts));
                }
            }
            stream.insert("httpSettings".to_string(), Value::Object(http));
        }
        "kcp" => {
            let mut kcp = Map::new();
            if let Some(ht) = header_type {
                kcp.insert("header".to_string(), json!({ "type": ht }));
            }
            if let Some(seed) = kcp_seed.map(str::trim).filter(|s| !s.is_empty()) {
                kcp.insert("seed".to_string(), json!(seed));
            }
            stream.insert("kcpSettings".to_string(), Value::Object(kcp));
        }
        _ => {}
    }

    Value::Object(stream)
}

fn build_vless_outbound(profile: &ServerProfile, d: &VlessDetails) -> Value {
    let mut user = Map::new();
    user.insert("id".to_string(), json!(d.uuid));
    user.insert("encryption".to_string(), json!(d.encryption));
    user.insert("level".to_string(), json!(0));
    let has_vless_enc =
        !d.encryption.eq_ignore_ascii_case("none") && !d.encryption.trim().is_empty();
    if (matches!(d.network.as_str(), "tcp" | "raw")
        && matches!(d.security.as_str(), "tls" | "reality"))
        || has_vless_enc
    {
        if let Some(flow) = &d.flow {
            if !flow.is_empty() {
                user.insert("flow".to_string(), json!(flow));
            }
        }
    }

    let mut stream = build_transport_stream_settings(
        &d.network,
        &d.security,
        d.sni.as_deref(),
        d.fingerprint.as_deref(),
        d.public_key.as_deref(),
        d.short_id.as_deref(),
        d.spider_x.as_deref(),
        d.path.as_deref(),
        d.host_header.as_deref(),
        d.service_name.as_deref(),
        d.alpn.as_ref(),
        d.pinned_cert_sha256.as_deref(),
        d.verify_peer_cert_by_name.as_deref(),
        d.header_type.as_deref(),
        d.xhttp_mode.as_deref(),
        d.xhttp_extra.as_ref(),
        d.pqv.as_deref(),
        d.grpc_authority.as_deref(),
        d.grpc_multi_mode,
        d.kcp_seed.as_deref(),
        &profile.address,
    );
    if d.network == "ws" {
        if let Some(ed) = d.ws_early_data.filter(|&v| v > 0) {
            if let Some(ws) = stream.get_mut("wsSettings").and_then(|v| v.as_object_mut()) {
                let p = ws
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/")
                    .to_string();
                if !p.contains("ed=") {
                    let sep = if p.contains('?') { '&' } else { '?' };
                    ws.insert("path".to_string(), json!(format!("{p}{sep}ed={ed}")));
                }
                if let Some(hdr) = d
                    .ws_early_data_header
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    ws.insert("earlyDataHeaderName".to_string(), json!(hdr));
                }
            }
        }
    }

    json!({
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": profile.address,
                    "port": profile.port,
                    "users": [Value::Object(user)]
                }
            ]
        },
        "streamSettings": stream
    })
}

fn build_vmess_outbound(profile: &ServerProfile, d: &VmessDetails) -> Value {
    let stream = build_transport_stream_settings(
        &d.network,
        &d.security,
        d.sni.as_deref(),
        d.fingerprint.as_deref(),
        None,
        None,
        None,
        d.path.as_deref(),
        d.host_header.as_deref(),
        d.service_name.as_deref(),
        d.alpn.as_ref(),
        d.pinned_cert_sha256.as_deref(),
        d.verify_peer_cert_by_name.as_deref(),
        d.header_type.as_deref(),
        d.xhttp_mode.as_deref(),
        d.xhttp_extra.as_ref(),
        None,
        d.grpc_authority.as_deref(),
        d.grpc_multi_mode,
        d.kcp_seed.as_deref(),
        &profile.address,
    );

    json!({
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": profile.address,
                    "port": profile.port,
                    "users": [
                        {
                            "id": d.uuid,
                            "alterId": d.alter_id,
                            "security": d.cipher,
                            "level": 0
                        }
                    ]
                }
            ]
        },
        "streamSettings": stream
    })
}

fn build_trojan_outbound(profile: &ServerProfile, d: &TrojanDetails) -> Value {
    let stream = build_transport_stream_settings(
        &d.network,
        &d.security,
        d.sni.as_deref(),
        d.fingerprint.as_deref(),
        d.public_key.as_deref(),
        d.short_id.as_deref(),
        d.spider_x.as_deref(),
        d.path.as_deref(),
        d.host_header.as_deref(),
        d.service_name.as_deref(),
        d.alpn.as_ref(),
        d.pinned_cert_sha256.as_deref(),
        d.verify_peer_cert_by_name.as_deref(),
        d.header_type.as_deref(),
        d.xhttp_mode.as_deref(),
        d.xhttp_extra.as_ref(),
        None,
        d.grpc_authority.as_deref(),
        d.grpc_multi_mode,
        None,
        &profile.address,
    );

    json!({
        "tag": "proxy",
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": profile.address,
                    "port": profile.port,
                    "password": d.password,
                    "level": 0
                }
            ]
        },
        "streamSettings": stream
    })
}

fn build_shadowsocks_outbound(
    profile: &ServerProfile,
    d: &crate::models::ShadowsocksDetails,
) -> Value {
    json!({
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {
                    "address": profile.address,
                    "port": profile.port,
                    "method": d.method,
                    "password": d.password,
                    "uot": d.uot
                }
            ]
        }
    })
}

fn build_hysteria2_outbound(profile: &ServerProfile, d: &Hysteria2Details) -> Value {
    let mut hy_settings = Map::new();
    hy_settings.insert("version".to_string(), json!(2));
    hy_settings.insert("auth".to_string(), json!(d.password));
    if let Some(up) = d.up_mbps {
        hy_settings.insert("up".to_string(), json!(format!("{up} mbps")));
    }
    if let Some(down) = d.down_mbps {
        hy_settings.insert("down".to_string(), json!(format!("{down} mbps")));
    }
    if let Some(mp) = d.mport.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        hy_settings.insert(
            "udphop".to_string(),
            json!({
                "port": mp,
                "interval": d.hop_interval_secs.unwrap_or(30)
            }),
        );
    }

    let mut tls = Map::new();
    tls.insert(
        "serverName".to_string(),
        json!(d.sni.as_deref().unwrap_or(&profile.address)),
    );
    apply_v26_tls_pinning(
        &mut tls,
        d.pinned_cert_sha256.as_deref(),
        d.verify_peer_cert_by_name.as_deref(),
    );
    if let Some(alpn) = &d.alpn {
        tls.insert("alpn".to_string(), json!(alpn));
    }

    let mut stream = Map::new();
    stream.insert("network".to_string(), json!("hysteria"));
    stream.insert("hysteriaSettings".to_string(), Value::Object(hy_settings));
    stream.insert("security".to_string(), json!("tls"));
    stream.insert("tlsSettings".to_string(), Value::Object(tls));

    if let (Some(obfs), Some(obfs_pass)) = (&d.obfs, &d.obfs_password) {
        if obfs == "salamander" {
            stream.insert(
                "udpmasks".to_string(),
                json!([{
                    "type": "salamander",
                    "settings": { "password": obfs_pass }
                }]),
            );
        }
    }

    json!({
        "tag": "proxy",
        "protocol": "hysteria",
        "settings": {
            "version": 2,
            "address": profile.address,
            "port": profile.port
        },
        "streamSettings": Value::Object(stream)
    })
}

fn build_wireguard_outbound(
    profile: &ServerProfile,
    d: &WireguardDetails,
    ipv6_enabled: bool,
) -> Value {
    let mut peer = Map::new();
    peer.insert("publicKey".to_string(), json!(d.public_key));
    peer.insert("endpoint".to_string(), json!(d.endpoint));
    if let Some(psk) = &d.preshared_key {
        peer.insert("preSharedKey".to_string(), json!(psk));
    }
    if let Some(ka) = d.keepalive {
        if ka > 0 {
            peer.insert("keepAlive".to_string(), json!(ka));
        }
    }

    let mut settings = Map::new();
    settings.insert("secretKey".to_string(), json!(d.secret_key));
    settings.insert("address".to_string(), json!(d.address));
    settings.insert("peers".to_string(), json!([Value::Object(peer)]));
    if !ipv6_enabled {
        settings.insert("domainStrategy".to_string(), json!("ForceIPv4"));
    }
    let effective_mtu = profile
        .overrides
        .as_ref()
        .and_then(|o| o.mtu)
        .map(|m| m.clamp(1280, 1500))
        .or(d.mtu);
    if let Some(mtu) = effective_mtu {
        settings.insert("mtu".to_string(), json!(mtu));
    }
    if let Some(res) = &d.reserved {
        settings.insert("reserved".to_string(), json!(res));
    }

    json!({
        "tag": "proxy",
        "protocol": "wireguard",
        "settings": Value::Object(settings)
    })
}

fn build_socks_chain_outbound(socks_port: u16) -> Value {
    json!({
        "tag": "proxy",
        "protocol": "socks",
        "settings": {
            "servers": [{
                "address": "127.0.0.1",
                "port": socks_port
            }]
        }
    })
}

pub fn generate_wireproxy_awg_config(
    d: &AmneziaWgDetails,
    socks_port: u16,
) -> Result<String, String> {
    generate_wireproxy_awg_config_with_dns(d, socks_port, None)
}

pub fn generate_wireproxy_awg_config_with_dns(
    d: &AmneziaWgDetails,
    socks_port: u16,
    user_primary_dns: Option<&str>,
) -> Result<String, String> {
    crate::parser::wireguard::validate_awg_details(d)?;

    let mut lines = Vec::new();
    lines.push("[Interface]".to_string());
    lines.push(format!("PrivateKey = {}", d.secret_key.trim()));
    lines.push(format!("Address = {}", d.address.join(", ")));

    let user_ip_dns = user_primary_dns
        .map(|s| s.trim())
        .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
        .map(|s| s.to_string());

    if let Some(override_dns) = user_ip_dns {
        lines.push(format!("DNS = {override_dns}"));
    } else if !d.dns.is_empty() {
        lines.push(format!("DNS = {}", d.dns.join(", ")));
    } else {
        lines.push("DNS = 1.1.1.1".to_string());
    }
    if let Some(mtu) = d.mtu {
        lines.push(format!("MTU = {mtu}"));
    }
    for (k, opt) in [
        ("Jc", &d.jc),
        ("Jmin", &d.jmin),
        ("Jmax", &d.jmax),
        ("S1", &d.s1),
        ("S2", &d.s2),
        ("H1", &d.h1),
        ("H2", &d.h2),
        ("H3", &d.h3),
        ("H4", &d.h4),
    ] {
        if let Some(v) = opt {
            if !v.trim().is_empty() {
                lines.push(format!("{k} = {}", v.trim()));
            }
        }
    }
    for (k, v) in &d.extra_params {
        if !v.trim().is_empty() {
            lines.push(format!("{} = {}", k.trim().to_ascii_uppercase(), v.trim()));
        }
    }

    lines.push(String::new());
    lines.push("[Peer]".to_string());
    lines.push(format!("PublicKey = {}", d.public_key.trim()));
    if let Some(psk) = &d.preshared_key {
        if !psk.trim().is_empty() {
            lines.push(format!("PresharedKey = {}", psk.trim()));
        }
    }
    lines.push(format!("Endpoint = {}", d.endpoint.trim()));
    lines.push("AllowedIPs = 0.0.0.0/0, ::/0".to_string());
    lines.push(format!(
        "PersistentKeepalive = {}",
        d.keepalive.unwrap_or(25)
    ));

    lines.push(String::new());
    lines.push("[Socks5]".to_string());
    lines.push(format!("BindAddress = 127.0.0.1:{socks_port}"));
    Ok(lines.join("\n"))
}

enum ProxyRouteTarget {
    Outbound(String),
    Balancer(String),
}

impl ProxyRouteTarget {
    fn apply_to_rule(&self, rule: &mut Map<String, Value>) {
        match self {
            Self::Outbound(tag) => {
                rule.insert("outboundTag".to_string(), json!(tag));
            }
            Self::Balancer(tag) => {
                rule.insert("balancerTag".to_string(), json!(tag));
            }
        }
    }
}

fn sanitize_dns_address(raw: &str, fallback: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 253
        || !trimmed.is_ascii()
        || trimmed.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return fallback.to_string();
    }
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        if !ip.is_unspecified() && !ip.is_multicast() {
            return ip.to_string();
        }
        return fallback.to_string();
    }
    if let Ok(url) = reqwest::Url::parse(trimmed) {
        let scheme = url.scheme().to_ascii_lowercase();
        let allowed_scheme = matches!(
            scheme.as_str(),
            "https" | "https+local" | "tls" | "quic" | "tcp" | "udp"
        );
        if allowed_scheme && url.has_host() && url.username().is_empty() && url.password().is_none()
        {
            return trimmed.to_string();
        }
    }
    fallback.to_string()
}

fn build_routing_rules(
    routing: &RoutingConfig,
    mode: ConnectionMode,
    route_private_direct: bool,
    proxy_target: &ProxyRouteTarget,
    active_ru_domains: &[String],
    ipv6_enabled: bool,
) -> Vec<Value> {
    let mut rules = Vec::new();
    let split_mode = effective_split_mode(routing);
    let is_tun = mode == ConnectionMode::Tun;

    // Priority 0: Hijack all TUN DNS (port 53 TCP/UDP) into Xray's built-in DNS outbound
    if is_tun {
        rules.push(json!({
            "type": "field",
            "inboundTag": ["tun-in"],
            "network": "tcp,udp",
            "port": "53",
            "outboundTag": "dns-out"
        }));
    }

    // Priority 1a: Prevent Xray/wireproxy process loops (only needed/supported in TUN mode)
    if is_tun {
        rules.push(json!({
            "type": "field",
            "process": ["self/", "xray/", "wireproxy-awg"],
            "outboundTag": "direct"
        }));
    }

    // Priority 1b: Private LAN IPv4 & IPv6 ranges directly
    if route_private_direct && routing.bypass_lan {
        rules.push(json!({
            "type": "field",
            "ip": [
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "::1/128",
                "fc00::/7",
                "fe80::/10"
            ],
            "outboundTag": "direct"
        }));
    }

    // Priority 1c: Fail-closed IPv6 leak block in TUN mode when IPv6 is disabled
    if is_tun && !ipv6_enabled {
        rules.push(json!({
            "type": "field",
            "ip": ["::/0"],
            "outboundTag": "block"
        }));
    }

    // Priority 2: User custom rules (ordered top-to-bottom, overrides RU categories)
    for rule in &routing.custom_rules {
        if !rule.enabled {
            continue;
        }
        let pattern = rule.pattern.trim();
        if pattern.is_empty() {
            continue;
        }
        if crate::routing_rules::validate_routing_rule(rule).is_err() {
            continue;
        }
        let mut rule_map = Map::new();
        rule_map.insert("type".to_string(), json!("field"));
        match rule.match_type {
            RuleMatchType::Domain => {
                rule_map.insert("domain".to_string(), json!([pattern]));
            }
            RuleMatchType::Ip => {
                rule_map.insert("ip".to_string(), json!([pattern]));
            }
            RuleMatchType::Process => {
                // Per-process split tunneling is enforced reliably only in TUN mode.
                if !is_tun {
                    continue;
                }
                rule_map.insert("process".to_string(), json!([pattern]));
            }
        }
        match rule.action {
            RuleAction::Proxy => proxy_target.apply_to_rule(&mut rule_map),
            RuleAction::Direct => {
                rule_map.insert("outboundTag".to_string(), json!("direct"));
            }
            RuleAction::Block => {
                rule_map.insert("outboundTag".to_string(), json!("block"));
            }
        }
        rules.push(Value::Object(rule_map));
    }

    // Priority 3: Process-based Split Tunneling (enforced only in TUN mode to avoid SystemProxy bypass)
    let cleaned_apps: Vec<String> = routing
        .split_apps
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if is_tun && !cleaned_apps.is_empty() {
        match split_mode {
            SplitTunnelMode::AllVpn => {}
            SplitTunnelMode::BypassApps => {
                rules.push(json!({
                    "type": "field",
                    "process": cleaned_apps,
                    "outboundTag": "direct"
                }));
            }
            SplitTunnelMode::OnlyApps => {
                let mut only_rule = Map::new();
                only_rule.insert("type".to_string(), json!("field"));
                only_rule.insert("process".to_string(), json!(cleaned_apps));
                proxy_target.apply_to_rule(&mut only_rule);
                rules.push(Value::Object(only_rule));
                rules.push(json!({
                    "type": "field",
                    "network": "tcp,udp",
                    "port": "0-65535",
                    "outboundTag": "direct"
                }));
            }
        }
    }

    // Priority 4: Active Russian services directly
    if !active_ru_domains.is_empty() {
        rules.push(json!({
            "type": "field",
            "domain": active_ru_domains,
            "outboundTag": "direct"
        }));
    }

    let catch_all_already_added =
        is_tun && !cleaned_apps.is_empty() && split_mode == SplitTunnelMode::OnlyApps;
    if !catch_all_already_added {
        if let ProxyRouteTarget::Balancer(bal_tag) = proxy_target {
            rules.push(json!({
                "type": "field",
                "network": "tcp,udp",
                "port": "0-65535",
                "balancerTag": bal_tag
            }));
        }
    }

    rules
}

pub fn generate_xray_config(
    profile: &ServerProfile,
    internal_http_port: u16,
    internal_socks_port: u16,
) -> Value {
    let pack = default_rulepack();
    generate_xray_config_full(
        profile,
        ConnectionMode::SystemProxy,
        internal_http_port,
        internal_socks_port,
        None,
        None,
        &RoutingConfig::default(),
        true,
        &DnsConfig::default(),
        false,
        "warning",
        &pack,
    )
}

#[derive(Debug, Clone)]
pub struct XrayGenOptions {
    pub tun: TunSettings,
    pub advanced: AdvancedVpnSettings,
    pub effective_mtu: u16,
}

impl Default for XrayGenOptions {
    fn default() -> Self {
        Self {
            tun: TunSettings::default(),
            advanced: AdvancedVpnSettings::default(),
            effective_mtu: 1500,
        }
    }
}

impl XrayGenOptions {
    pub fn from_settings(settings: &AppSettings) -> Self {
        let tun_mtu = if settings.tun.mtu_mode == MtuMode::Manual {
            settings.tun.mtu.clamp(1280, 1500)
        } else if settings.advanced.mtu_mode == MtuMode::Manual {
            settings
                .advanced
                .manual_mtu
                .unwrap_or(1500)
                .clamp(1280, 1500)
        } else {
            1500
        };
        Self {
            tun: settings.tun.clone(),
            advanced: settings.advanced.clone(),
            effective_mtu: tun_mtu,
        }
    }
}

pub fn resolve_effective_mtu(profile: &ServerProfile, settings: &AppSettings) -> (u16, String) {
    if let Some(m) = profile.overrides.as_ref().and_then(|o| o.mtu) {
        return (m.clamp(1280, 1500), "Индивидуально в профиле".into());
    }
    let profile_mtu = match &profile.details {
        ProtocolDetails::Wireguard(w) => w.mtu,
        ProtocolDetails::AmneziaWg(a) => a.mtu,
        _ => None,
    };
    if settings.advanced.mtu_mode == MtuMode::Manual {
        if let Some(m) = settings.advanced.manual_mtu {
            return (
                m.clamp(1280, 1500),
                "Ручной MTU (расширенные настройки)".into(),
            );
        }
    }
    if settings.advanced.mtu_mode == MtuMode::Profile {
        if let Some(pm) = profile_mtu {
            return (pm.clamp(1280, 1500), "Из конфигурации узла".into());
        }
    }
    if settings.tun.mtu_mode == MtuMode::Manual {
        return (
            settings.tun.mtu.clamp(1280, 1500),
            "Из настроек TUN-адаптера".into(),
        );
    }
    if let Some(pm) = profile_mtu {
        return (pm.clamp(1280, 1500), "Из конфигурации узла (Авто)".into());
    }
    let default_val = match profile.protocol {
        crate::models::ProtocolType::Wireguard | crate::models::ProtocolType::AmneziaWg => 1420,
        _ => 1500,
    };
    (default_val, "Автоматически".into())
}

pub fn build_primary_outbound_only(profile: &ServerProfile, ipv6_enabled: bool) -> Value {
    match &profile.details {
        ProtocolDetails::Vless(d) => build_vless_outbound(profile, d),
        ProtocolDetails::Vmess(d) => build_vmess_outbound(profile, d),
        ProtocolDetails::Trojan(d) => build_trojan_outbound(profile, d),
        ProtocolDetails::Shadowsocks(d) => build_shadowsocks_outbound(profile, d),
        ProtocolDetails::Hysteria2(d) => build_hysteria2_outbound(profile, d),
        ProtocolDetails::Wireguard(d) => build_wireguard_outbound(profile, d, ipv6_enabled),
        ProtocolDetails::AmneziaWg(d) => {
            let mut merged = d.clone();
            if let Some(m) = profile.overrides.as_ref().and_then(|o| o.mtu) {
                merged.mtu = Some(m.clamp(1280, 1500));
            }
            json!({
                "tag": "proxy",
                "protocol": "amneziawg-wireproxy",
                "settings": {
                    "endpoint": merged.endpoint,
                    "address": merged.address,
                    "mtu": merged.mtu,
                    "keepalive": merged.keepalive,
                    "jc": merged.jc,
                    "s1": merged.s1,
                    "s2": merged.s2
                }
            })
        }
        ProtocolDetails::RawXray(d) => {
            let mut ob = d.outbound_json.clone();
            crate::parser::raw_json::sanitize_xray_outbound_v26(&mut ob);
            ob
        }
    }
}

fn is_mux_compatible_outbound(profile: &ServerProfile, ob: &Value) -> bool {
    if matches!(
        profile.details,
        ProtocolDetails::Hysteria2(_)
            | ProtocolDetails::Wireguard(_)
            | ProtocolDetails::AmneziaWg(_)
    ) {
        return false;
    }
    if let ProtocolDetails::Vless(ref v) = profile.details {
        if v.flow
            .as_deref()
            .is_some_and(|f| f.to_ascii_lowercase().contains("vision"))
        {
            return false;
        }
        if matches!(v.network.as_str(), "grpc" | "xhttp") {
            return false;
        }
    }
    if let Some(flow) = ob
        .get("settings")
        .and_then(|s| s.get("vnext"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|n| n.get("users"))
        .and_then(|u| u.as_array())
        .and_then(|u| u.first())
        .and_then(|u| u.get("flow"))
        .and_then(|f| f.as_str())
    {
        if flow.to_ascii_lowercase().contains("vision") {
            return false;
        }
    }
    ob.get("mux").is_none()
}

fn apply_advanced_outbound_options(
    profile: &ServerProfile,
    ob: &mut Value,
    adv: &AdvancedVpnSettings,
) {
    if matches!(
        profile.details,
        ProtocolDetails::Wireguard(_) | ProtocolDetails::AmneziaWg(_)
    ) {
        return;
    }
    let proto_str = ob
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(
        proto_str.as_str(),
        "wireguard" | "socks" | "freedom" | "blackhole"
    ) {
        return;
    }

    // Apply safe TCP sockopt when enabled
    let is_tcp_transport = proto_str != "hysteria";
    if is_tcp_transport {
        if let Some(obj) = ob.as_object_mut() {
            let stream = obj
                .entry("streamSettings")
                .or_insert_with(|| Value::Object(Map::new()));
            if let Some(sm) = stream.as_object_mut() {
                let sock = sm
                    .entry("sockopt")
                    .or_insert_with(|| Value::Object(Map::new()));
                if let Some(sock_map) = sock.as_object_mut() {
                    if !sock_map.contains_key("tcpNoDelay") {
                        sock_map.insert("tcpNoDelay".to_string(), json!(adv.tcp_no_delay));
                    }
                    if adv.dialer_domain_strategy != "AsIs"
                        && !sock_map.contains_key("domainStrategy")
                    {
                        sock_map.insert(
                            "domainStrategy".to_string(),
                            json!(adv.dialer_domain_strategy),
                        );
                    }
                    if adv.tcp_keepalive_interval_secs > 0
                        && !sock_map.contains_key("tcpKeepAliveInterval")
                    {
                        let ka = adv.tcp_keepalive_interval_secs.clamp(5, 120);
                        sock_map.insert("tcpKeepAliveInterval".to_string(), json!(ka));
                        sock_map
                            .entry("tcpKeepAliveIdle")
                            .or_insert_with(|| json!((ka * 2).min(180)));
                    }
                    if adv.tcp_fast_open && !sock_map.contains_key("tcpFastOpen") {
                        sock_map.insert("tcpFastOpen".to_string(), json!(true));
                    }
                }
            }
        }
    }

    // Protocol-safe Mux
    let want_mux = profile
        .overrides
        .as_ref()
        .and_then(|o| o.mux_override)
        .unwrap_or(adv.mux_enabled);
    if want_mux && is_mux_compatible_outbound(profile, ob) {
        if let Some(obj) = ob.as_object_mut() {
            obj.insert(
                "mux".to_string(),
                json!({
                    "enabled": true,
                    "concurrency": adv.mux_concurrency.clamp(1, 16),
                    "xudpConcurrency": adv.mux_xudp_concurrency.clamp(1, 16),
                    "xudpProxyUDP443": "reject"
                }),
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn generate_xray_config_full(
    profile: &ServerProfile,
    mode: ConnectionMode,
    internal_http_port: u16,
    internal_socks_port: u16,
    stats_api_port: Option<u16>,
    awg_socks_port: Option<u16>,
    routing: &RoutingConfig,
    route_private_direct: bool,
    dns_cfg: &DnsConfig,
    ipv6_enabled: bool,
    log_level: &str,
    rulepack: &RulepackData,
) -> Value {
    generate_xray_config_with_options(
        profile,
        mode,
        internal_http_port,
        internal_socks_port,
        stats_api_port,
        awg_socks_port,
        routing,
        route_private_direct,
        dns_cfg,
        ipv6_enabled,
        log_level,
        rulepack,
        XrayGenOptions::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn generate_xray_config_with_options(
    profile: &ServerProfile,
    mode: ConnectionMode,
    internal_http_port: u16,
    internal_socks_port: u16,
    stats_api_port: Option<u16>,
    awg_socks_port: Option<u16>,
    routing: &RoutingConfig,
    route_private_direct: bool,
    dns_cfg: &DnsConfig,
    ipv6_enabled: bool,
    log_level: &str,
    rulepack: &RulepackData,
    options: XrayGenOptions,
) -> Value {
    let mut extra_outbounds: Vec<Value> = Vec::new();
    let mut valid_balancers: Vec<Value> = Vec::new();
    let mut observatory_cfg: Option<Value> = None;
    let mut burst_observatory_cfg: Option<Value> = None;
    let mut primary_tag = "proxy".to_string();

    let mut primary_outbound = match &profile.details {
        ProtocolDetails::Vless(d) => build_vless_outbound(profile, d),
        ProtocolDetails::Vmess(d) => build_vmess_outbound(profile, d),
        ProtocolDetails::Trojan(d) => build_trojan_outbound(profile, d),
        ProtocolDetails::Shadowsocks(d) => build_shadowsocks_outbound(profile, d),
        ProtocolDetails::Hysteria2(d) => build_hysteria2_outbound(profile, d),
        ProtocolDetails::Wireguard(d) => {
            let prefer_awg_bridge = awg_socks_port.is_some()
                && (profile
                    .overrides
                    .as_ref()
                    .and_then(|o| o.preferred_core)
                    .filter(|&c| c != CoreSelectionMode::Auto)
                    .unwrap_or(options.advanced.core_selection)
                    == CoreSelectionMode::WireproxyAwg);
            if prefer_awg_bridge {
                build_socks_chain_outbound(awg_socks_port.unwrap_or(10899))
            } else {
                build_wireguard_outbound(profile, d, ipv6_enabled)
            }
        }
        ProtocolDetails::AmneziaWg(_) => {
            build_socks_chain_outbound(awg_socks_port.unwrap_or(10899))
        }
        ProtocolDetails::RawXray(d) => {
            let ensure_tag = |ob: &mut Value, fallback: &str| -> String {
                let existing = ob
                    .get("tag")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim())
                    .unwrap_or("");
                let reserved = existing.is_empty()
                    || existing.eq_ignore_ascii_case("direct")
                    || existing.eq_ignore_ascii_case("block");
                if reserved {
                    if let Some(m) = ob.as_object_mut() {
                        m.insert("tag".to_string(), json!(fallback));
                    }
                    fallback.to_string()
                } else {
                    existing.to_string()
                }
            };

            let mut ob = d.outbound_json.clone();
            crate::parser::raw_json::sanitize_xray_outbound_v26(&mut ob);
            primary_tag = ensure_tag(&mut ob, "proxy");

            let mut dialer_targets: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            let collect_dialer = |node: &Value, set: &mut std::collections::HashSet<String>| {
                if let Some(dp) = node
                    .as_object()
                    .and_then(|m| {
                        m.iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("streamSettings"))
                    })
                    .and_then(|(_, s)| s.as_object())
                    .and_then(|m| m.iter().find(|(k, _)| k.eq_ignore_ascii_case("sockopt")))
                    .and_then(|(_, s)| s.as_object())
                    .and_then(|m| {
                        m.iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("dialerProxy"))
                    })
                    .and_then(|(_, v)| v.as_str())
                    .map(str::trim)
                    .filter(|s| {
                        let sl = s.to_ascii_lowercase();
                        !sl.is_empty()
                            && sl != "direct"
                            && sl != "block"
                            && sl != "dns-out"
                            && sl != "api"
                    })
                {
                    set.insert(dp.to_string());
                }
            };
            collect_dialer(&ob, &mut dialer_targets);
            for extra in &d.extra_outbounds {
                collect_dialer(extra, &mut dialer_targets);
            }

            // Track ONLY verified proxy protocol outbound tags so balancers can never route traffic through a freedom helper.
            // Force non-proxy helpers onto dedicated "helper-dial-*" tags and rewrite dialerProxy links cleanly.
            let mut used_tags_lc: std::collections::HashSet<String> =
                ["direct", "block", "dns-out", "api"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
            used_tags_lc.insert(primary_tag.to_ascii_lowercase());

            let mut kept_proxy_tags = vec![primary_tag.clone()];
            let mut non_proxy_tags: Vec<String> = Vec::new();
            let mut helper_tag_renames: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();

            for (idx, extra) in d.extra_outbounds.iter().enumerate() {
                let is_proxy = crate::parser::raw_json::is_allowed_proxy_protocol(extra);
                let is_freedom_dialer = extra
                    .get("protocol")
                    .and_then(|v| v.as_str())
                    .map(|p| p.eq_ignore_ascii_case("freedom"))
                    .unwrap_or(false)
                    && extra
                        .get("tag")
                        .and_then(|v| v.as_str())
                        .map(|t| dialer_targets.contains(t.trim()))
                        .unwrap_or(false);
                let is_safe_helper = crate::parser::raw_json::is_freedom_with_dpi_settings(extra)
                    || is_freedom_dialer;
                if !is_proxy && !is_safe_helper {
                    continue;
                }
                let mut clean_extra = extra.clone();
                crate::parser::raw_json::sanitize_xray_outbound_v26(&mut clean_extra);

                if is_proxy {
                    let mut tag = ensure_tag(&mut clean_extra, &format!("proxy-node-{}", idx + 2));
                    let mut suffix = idx + 2;
                    while !used_tags_lc.insert(tag.to_ascii_lowercase()) {
                        suffix += 1;
                        tag = format!("proxy-node-{suffix}");
                        if let Some(m) = clean_extra.as_object_mut() {
                            m.insert("tag".to_string(), json!(tag.clone()));
                        }
                    }
                    kept_proxy_tags.push(tag);
                } else {
                    let orig_tag = clean_extra
                        .get("tag")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();
                    let mut suffix = idx + 1;
                    let mut safe_helper_tag = format!("helper-dial-{suffix}");
                    while !used_tags_lc.insert(safe_helper_tag.to_ascii_lowercase()) {
                        suffix += 1;
                        safe_helper_tag = format!("helper-dial-{suffix}");
                    }
                    if let Some(m) = clean_extra.as_object_mut() {
                        m.insert("tag".to_string(), json!(safe_helper_tag.clone()));
                    }
                    if !orig_tag.is_empty() && orig_tag != safe_helper_tag {
                        helper_tag_renames.insert(orig_tag, safe_helper_tag.clone());
                    }
                    non_proxy_tags.push(safe_helper_tag);
                }
                extra_outbounds.push(clean_extra);
            }

            if !helper_tag_renames.is_empty() {
                let rewrite_dialer = |node: &mut Value| {
                    if let Some(dp_val) = node
                        .as_object_mut()
                        .and_then(|m| {
                            m.iter_mut()
                                .find(|(k, _)| k.eq_ignore_ascii_case("streamSettings"))
                        })
                        .and_then(|(_, s)| s.as_object_mut())
                        .and_then(|m| {
                            m.iter_mut()
                                .find(|(k, _)| k.eq_ignore_ascii_case("sockopt"))
                        })
                        .and_then(|(_, s)| s.as_object_mut())
                        .and_then(|m| {
                            m.iter_mut()
                                .find(|(k, _)| k.eq_ignore_ascii_case("dialerProxy"))
                        })
                        .map(|(_, v)| v)
                    {
                        if let Some(cur) = dp_val.as_str().map(str::trim) {
                            if let Some(mapped) = helper_tag_renames.get(cur) {
                                *dp_val = json!(mapped);
                            }
                        }
                    }
                };
                rewrite_dialer(&mut ob);
                for ex in &mut extra_outbounds {
                    rewrite_dialer(ex);
                }
            }

            let mut selector_prefixes: Vec<String> = Vec::new();
            let mut needs_observatory = false;

            for bal in &d.balancers {
                let Some(bal_tag) = bal
                    .get("tag")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                else {
                    continue;
                };
                let Some(selectors) = bal.get("selector").and_then(|v| v.as_array()) else {
                    continue;
                };
                let mut safe_selectors: Vec<String> = Vec::new();
                for sel in selectors {
                    if let Some(prefix) = sel.as_str().map(|s| s.trim()).filter(|s| !s.is_empty()) {
                        let p_lc = prefix.to_ascii_lowercase();
                        let collides_reserved = "direct".starts_with(&p_lc)
                            || "block".starts_with(&p_lc)
                            || "dns-out".starts_with(&p_lc)
                            || "api".starts_with(&p_lc);
                        let collides_helper = "helper-dial".starts_with(&p_lc)
                            || non_proxy_tags
                                .iter()
                                .any(|nt| nt.to_ascii_lowercase().starts_with(&p_lc));
                        if !collides_reserved
                            && !collides_helper
                            && kept_proxy_tags.iter().any(|t| t.starts_with(prefix))
                            && !safe_selectors.iter().any(|x| x == prefix)
                        {
                            safe_selectors.push(prefix.to_string());
                        }
                    }
                }
                if safe_selectors.is_empty() {
                    continue;
                }

                let mut clean_bal = bal.clone();
                if let Some(m) = clean_bal.as_object_mut() {
                    m.insert("selector".to_string(), json!(safe_selectors));
                    if let Some(fb) = m
                        .get("fallbackTag")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                    {
                        if !kept_proxy_tags.iter().any(|t| t == &fb) {
                            m.insert("fallbackTag".to_string(), json!(primary_tag));
                        }
                    }
                }

                if let Some(strat) = clean_bal
                    .get("strategy")
                    .and_then(|s| s.get("type"))
                    .and_then(|t| t.as_str())
                {
                    if matches!(strat, "leastPing" | "leastLoad") {
                        needs_observatory = true;
                    }
                }

                for s in &safe_selectors {
                    if !selector_prefixes.iter().any(|existing| existing == s) {
                        selector_prefixes.push(s.clone());
                    }
                }

                let _ = bal_tag;
                valid_balancers.push(clean_bal);
            }

            if !valid_balancers.is_empty() {
                if let Some(bo) = crate::parser::raw_json::sanitize_burst_observatory(
                    d.burst_observatory.as_ref(),
                    &kept_proxy_tags,
                    &non_proxy_tags,
                ) {
                    burst_observatory_cfg = Some(bo);
                } else if let Some(obs) = crate::parser::raw_json::sanitize_burst_observatory(
                    d.observatory.as_ref(),
                    &kept_proxy_tags,
                    &non_proxy_tags,
                ) {
                    observatory_cfg = Some(obs);
                } else if needs_observatory && !selector_prefixes.is_empty() {
                    burst_observatory_cfg = Some(json!({
                        "subjectSelector": selector_prefixes,
                        "pingConfig": {
                            "destination": "https://www.gstatic.com/generate_204",
                            "interval": "5m"
                        }
                    }));
                }
            }

            ob
        }
    };

    apply_advanced_outbound_options(profile, &mut primary_outbound, &options.advanced);

    let proxy_target = if let Some(bal_tag) = valid_balancers
        .first()
        .and_then(|b| b.get("tag"))
        .and_then(|v| v.as_str())
    {
        ProxyRouteTarget::Balancer(bal_tag.to_string())
    } else {
        ProxyRouteTarget::Outbound(primary_tag)
    };

    let config_dns_from_profile = match &profile.details {
        ProtocolDetails::Wireguard(w) => w.dns.first().map(|s| s.as_str()),
        ProtocolDetails::AmneziaWg(a) => a.dns.first().map(|s| s.as_str()),
        _ => None,
    };

    let mut dns_mode = profile
        .overrides
        .as_ref()
        .and_then(|o| o.dns_mode_override)
        .map(|m| {
            match m {
                crate::models::DnsMode::Auto => "hybrid",
                crate::models::DnsMode::Config => "config",
                crate::models::DnsMode::System => "system",
                crate::models::DnsMode::Vpn => "vpn",
                crate::models::DnsMode::Hybrid => "hybrid",
                crate::models::DnsMode::Custom => "custom",
            }
            .to_string()
        })
        .unwrap_or_else(|| dns_cfg.mode.trim().to_ascii_lowercase());
    if dns_mode == "auto" {
        dns_mode = "hybrid".to_string();
    }

    let raw_primary_dns = profile
        .overrides
        .as_ref()
        .and_then(|o| o.custom_dns.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            (dns_mode == "config")
                .then_some(config_dns_from_profile)
                .flatten()
        })
        .unwrap_or(&dns_cfg.primary_dns);
    let primary_dns = if dns_mode == "system" {
        "localhost".to_string()
    } else {
        sanitize_dns_address(raw_primary_dns, "1.1.1.1")
    };
    let fallback_dns = dns_cfg
        .fallback_dns
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| sanitize_dns_address(s, "8.8.8.8"))
        .filter(|s| s != &primary_dns);
    let direct_dns = sanitize_dns_address(&dns_cfg.direct_dns, "77.88.8.8");
    let direct_fallback_dns = dns_cfg
        .direct_fallback_dns
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| sanitize_dns_address(s, "77.88.8.1"))
        .filter(|s| s != &direct_dns);

    let effective_tun_mtu = profile
        .overrides
        .as_ref()
        .and_then(|o| o.mtu)
        .map(|m| m.clamp(1280, 1500))
        .unwrap_or(options.effective_mtu.clamp(1280, 1500));

    let extract_plain_ip = |val: &str| -> Option<String> {
        if val.parse::<std::net::IpAddr>().is_ok() {
            return Some(val.to_string());
        }
        if let Ok(u) = reqwest::Url::parse(val) {
            if let Some(h) = u.host_str() {
                let clean = h.trim_matches(|c| c == '[' || c == ']');
                if clean.parse::<std::net::IpAddr>().is_ok() {
                    return Some(clean.to_string());
                }
            }
        }
        None
    };

    let extract_url_host = |val: &str| -> Option<String> {
        let u = reqwest::Url::parse(val).ok()?;
        let h = u.host_str()?.trim_matches(|c| c == '[' || c == ']');
        if h.parse::<std::net::IpAddr>().is_err() && !h.is_empty() {
            Some(h.to_string())
        } else {
            None
        }
    };

    let tun_dns_list: Vec<String> = if dns_mode == "direct" {
        if let Some(ip) = extract_plain_ip(&direct_dns) {
            vec![ip, "77.88.8.8".to_string()]
        } else {
            vec!["77.88.8.8".to_string(), "1.1.1.1".to_string()]
        }
    } else if let Some(ip) = extract_plain_ip(&primary_dns) {
        if ip == "1.1.1.1" {
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
        } else {
            vec![ip, "1.1.1.1".to_string()]
        }
    } else {
        vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
    };

    let tun_name = {
        let clean = options.tun.adapter_name.trim();
        if !clean.is_empty()
            && clean.len() <= 32
            && clean
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            clean.to_string()
        } else {
            "aura_tun".to_string()
        }
    };
    let tun_gateways = if ipv6_enabled && options.tun.enable_ipv6 {
        json!([options.tun.ipv4_address, options.tun.ipv6_address])
    } else {
        json!([options.tun.ipv4_address])
    };
    let tun_routes = if !(options.tun.auto_route || options.tun.strict_route) {
        json!([])
    } else {
        // Capture ::/0 into TUN even when IPv6 is disabled so Xray/block sinkholes IPv6 leaks.
        json!(["0.0.0.0/0", "::/0"])
    };

    let inbounds = match mode {
        ConnectionMode::SystemProxy => json!([
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": internal_socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": true
                },
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": true
                }
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": internal_http_port,
                "protocol": "http",
                "settings": {
                    "allowTransparent": false
                },
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls"],
                    "routeOnly": true
                }
            }
        ]),
        ConnectionMode::Tun => json!([
            {
                "tag": "tun-in",
                "protocol": "tun",
                "settings": {
                    "name": tun_name,
                    "MTU": effective_tun_mtu,
                    "gateway": tun_gateways,
                    "dns": tun_dns_list,
                    "autoSystemRoutingTable": tun_routes,
                    "autoOutboundsInterface": "auto"
                },
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": false
                }
            }
        ]),
    };

    let active_ru_domains = collect_active_ru_domains(routing, rulepack);
    let effective_private_direct =
        route_private_direct && (mode != ConnectionMode::Tun || options.tun.bypass_lan);
    let mut rules = build_routing_rules(
        routing,
        mode,
        effective_private_direct,
        &proxy_target,
        &active_ru_domains,
        ipv6_enabled,
    );

    let dns_needed = mode == ConnectionMode::Tun
        || matches!(
            dns_mode.as_str(),
            "custom" | "hybrid" | "vpn" | "direct" | "config" | "system"
        )
        || !active_ru_domains.is_empty()
        || profile
            .overrides
            .as_ref()
            .and_then(|o| o.custom_dns.as_ref())
            .is_some();

    let valid_log_level = match log_level.trim().to_ascii_lowercase().as_str() {
        "debug" | "info" | "warning" | "error" | "none" => log_level.trim().to_ascii_lowercase(),
        _ => "warning".to_string(),
    };
    let mut root = Map::new();
    root.insert("log".to_string(), json!({ "loglevel": valid_log_level }));

    if dns_needed {
        let mut servers: Vec<Value> = match dns_mode.as_str() {
            "direct" => {
                let mut v = vec![json!(direct_dns)];
                if let Some(ref fb) = direct_fallback_dns {
                    v.push(json!(fb));
                }
                v
            }
            "vpn" => {
                let mut v = vec![json!(primary_dns)];
                if let Some(ref fb) = fallback_dns {
                    v.push(json!(fb));
                }
                v
            }
            "system" => vec![json!("localhost")],
            _ => {
                let mut v = vec![json!(primary_dns)];
                if let Some(ref fb) = fallback_dns {
                    v.push(json!(fb));
                }
                if !active_ru_domains.is_empty() {
                    v.push(json!({
                        "address": direct_dns,
                        "domains": active_ru_domains,
                        "skipFallback": true
                    }));
                }
                v
            }
        };
        if servers.is_empty() {
            servers.push(json!("1.1.1.1"));
        }

        let mut dns_rules: Vec<Value> = Vec::new();
        if profile.address.parse::<std::net::IpAddr>().is_err()
            && !profile.address.trim().is_empty()
        {
            dns_rules.push(json!({
                "type": "field",
                "inboundTag": ["dns-query"],
                "domain": [format!("full:{}", profile.address.trim())],
                "outboundTag": "direct"
            }));
        }
        if dns_mode == "direct" || dns_mode == "system" {
            dns_rules.push(json!({
                "type": "field",
                "inboundTag": ["dns-query"],
                "outboundTag": "direct"
            }));
        } else {
            if !active_ru_domains.is_empty() && dns_mode != "vpn" {
                if let Some(direct_ip) = extract_plain_ip(&direct_dns) {
                    dns_rules.push(json!({
                        "type": "field",
                        "inboundTag": ["dns-query"],
                        "ip": [direct_ip],
                        "outboundTag": "direct"
                    }));
                } else if let Some(direct_host) = extract_url_host(&direct_dns) {
                    dns_rules.push(json!({
                        "type": "field",
                        "inboundTag": ["dns-query"],
                        "domain": [format!("full:{direct_host}")],
                        "outboundTag": "direct"
                    }));
                }
            }
            let mut vpn_dns_rule = Map::new();
            vpn_dns_rule.insert("type".to_string(), json!("field"));
            vpn_dns_rule.insert("inboundTag".to_string(), json!(["dns-query"]));
            proxy_target.apply_to_rule(&mut vpn_dns_rule);
            dns_rules.push(Value::Object(vpn_dns_rule));
        }

        // Prepend DNS query rules right after TUN DNS hijack / loop protection rules
        let insert_at = rules
            .iter()
            .take(3)
            .position(|r| {
                r.get("outboundTag")
                    .and_then(|v| v.as_str())
                    .map(|t| t == "block")
                    .unwrap_or(false)
                    || r.get("ip").is_some()
            })
            .unwrap_or(rules.len().min(2));
        for (offset, rule) in dns_rules.into_iter().enumerate() {
            rules.insert(insert_at + offset, rule);
        }

        let qs = dns_cfg
            .query_strategy
            .as_deref()
            .filter(|s| matches!(*s, "UseIP" | "UseIPv4" | "UseIPv6"))
            .unwrap_or(if ipv6_enabled { "UseIP" } else { "UseIPv4" });

        let mut dns_obj = Map::new();
        dns_obj.insert("tag".to_string(), json!("dns-query"));
        dns_obj.insert("queryStrategy".to_string(), json!(qs));
        dns_obj.insert("servers".to_string(), Value::Array(servers));
        if dns_cfg.disable_cache {
            dns_obj.insert("disableCache".to_string(), json!(true));
        }
        if dns_cfg.disable_fallback {
            dns_obj.insert("disableFallback".to_string(), json!(true));
        }
        root.insert("dns".to_string(), Value::Object(dns_obj));
    }

    if let Some(api_port) = stats_api_port {
        root.insert("stats".to_string(), json!({}));
        root.insert(
            "api".to_string(),
            json!({
                "tag": "api",
                "listen": format!("127.0.0.1:{api_port}"),
                "services": ["StatsService"]
            }),
        );
        root.insert(
            "policy".to_string(),
            json!({
                "system": {
                    "statsOutboundUplink": true,
                    "statsOutboundDownlink": true
                }
            }),
        );
    }

    if let Some(bo) = burst_observatory_cfg {
        root.insert("burstObservatory".to_string(), bo);
    } else if let Some(obs) = observatory_cfg {
        root.insert("observatory".to_string(), obs);
    }

    let mut all_outbounds = Vec::with_capacity(4 + extra_outbounds.len());
    all_outbounds.push(primary_outbound);
    all_outbounds.extend(extra_outbounds);
    all_outbounds.push(json!({
        "tag": "direct",
        "protocol": "freedom",
        "settings": {}
    }));
    all_outbounds.push(json!({
        "tag": "block",
        "protocol": "blackhole",
        "settings": {}
    }));
    if mode == ConnectionMode::Tun {
        all_outbounds.push(json!({
            "tag": "dns-out",
            "protocol": "dns"
        }));
    }

    let mut routing_obj = Map::new();
    routing_obj.insert(
        "domainStrategy".to_string(),
        json!(if mode == ConnectionMode::Tun {
            "IPIfNonMatch"
        } else {
            "AsIs"
        }),
    );
    routing_obj.insert("rules".to_string(), json!(rules));
    if !valid_balancers.is_empty() {
        routing_obj.insert("balancers".to_string(), json!(valid_balancers));
    }

    root.insert("inbounds".to_string(), inbounds);
    root.insert("outbounds".to_string(), Value::Array(all_outbounds));
    root.insert("routing".to_string(), Value::Object(routing_obj));

    Value::Object(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ProfileOverrides, ProtocolType, ShadowsocksDetails};
    use std::collections::HashMap;

    fn sample_vless_profile() -> ServerProfile {
        ServerProfile {
            id: "vless-1".to_string(),
            name: "Test VLESS".to_string(),
            protocol: ProtocolType::Vless,
            address: "edge.example.com".to_string(),
            port: 443,
            country_code: Some("NL".to_string()),
            subscription_id: None,
            latency_ms: None,
            details: ProtocolDetails::Vless(VlessDetails {
                uuid: "11111111-2222-3333-4444-555555555555".to_string(),
                encryption: "none".to_string(),
                flow: Some("xtls-rprx-vision".to_string()),
                network: "grpc".to_string(),
                security: "reality".to_string(),
                sni: Some("sni.example.com".to_string()),
                fingerprint: Some("chrome".to_string()),
                public_key: Some("pbk".to_string()),
                short_id: Some("abcd".to_string()),
                spider_x: Some("/".to_string()),
                path: None,
                host_header: None,
                service_name: Some("svc".to_string()),
                alpn: None,
                allow_insecure: false,
                pinned_cert_sha256: None,
                verify_peer_cert_by_name: None,
                header_type: None,
                xhttp_mode: None,
                xhttp_extra: None,
                pqv: Some("pq-verify-token".to_string()),
                grpc_authority: Some("auth.example.com".to_string()),
                grpc_multi_mode: true,
                kcp_seed: None,
                ws_early_data: None,
                ws_early_data_header: None,
            }),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            favorite: false,
            last_used_at: None,
            fingerprint_key: None,
            custom_name: None,
            overrides: None,
            original_source: None,
            config_revision: 0,
        }
    }

    #[test]
    fn generates_vless_pqv_grpc_multimode_and_authority() {
        let cfg = generate_xray_config(&sample_vless_profile(), 10808, 10809);
        let stream = &cfg["outbounds"][0]["streamSettings"];
        assert_eq!(
            stream["realitySettings"]["mldsa65Verify"],
            "pq-verify-token"
        );
        assert_eq!(stream["grpcSettings"]["multiMode"], true);
        assert_eq!(stream["grpcSettings"]["authority"], "auth.example.com");
    }

    #[test]
    fn generates_dns_modes_and_direct_dns_rule() {
        let p = sample_vless_profile();
        let pack = default_rulepack();
        let dns_vpn = DnsConfig {
            mode: "vpn".to_string(),
            primary_dns: "9.9.9.9".to_string(),
            fallback_dns: None,
            ..Default::default()
        };
        let cfg_vpn = generate_xray_config_full(
            &p,
            ConnectionMode::Tun,
            10808,
            10809,
            None,
            None,
            &RoutingConfig::default(),
            true,
            &dns_vpn,
            false,
            "warning",
            &pack,
        );
        assert_eq!(cfg_vpn["dns"]["servers"].as_array().unwrap().len(), 1);
        assert_eq!(cfg_vpn["dns"]["servers"][0], "9.9.9.9");
        assert_eq!(cfg_vpn["inbounds"][0]["settings"]["dns"][0], "9.9.9.9");

        let dns_vpn_with_fb = DnsConfig {
            mode: "vpn".to_string(),
            primary_dns: "9.9.9.9".to_string(),
            ..Default::default()
        };
        let cfg_vpn_fb = generate_xray_config_full(
            &p,
            ConnectionMode::Tun,
            10808,
            10809,
            None,
            None,
            &RoutingConfig::default(),
            true,
            &dns_vpn_with_fb,
            false,
            "warning",
            &pack,
        );
        assert_eq!(cfg_vpn_fb["dns"]["servers"].as_array().unwrap().len(), 2);
        assert_eq!(cfg_vpn_fb["dns"]["servers"][1], "8.8.8.8");

        let dns_direct = DnsConfig {
            mode: "direct".to_string(),
            direct_dns: "77.88.8.8".to_string(),
            ..Default::default()
        };
        let cfg_dir = generate_xray_config_full(
            &p,
            ConnectionMode::Tun,
            10808,
            10809,
            None,
            None,
            &RoutingConfig::default(),
            true,
            &dns_direct,
            false,
            "warning",
            &pack,
        );
        assert_eq!(cfg_dir["dns"]["servers"][0], "77.88.8.8");
    }

    #[test]
    fn generates_ss_uot_hy2_udphop_and_wg_override_mtu() {
        let mut wg = ServerProfile {
            id: "wg-1".to_string(),
            name: "WG".to_string(),
            protocol: ProtocolType::Wireguard,
            address: "1.2.3.4".to_string(),
            port: 51820,
            country_code: None,
            subscription_id: None,
            latency_ms: None,
            details: ProtocolDetails::Wireguard(WireguardDetails {
                secret_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
                address: vec!["10.0.0.2/32".to_string()],
                public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string(),
                preshared_key: None,
                endpoint: "1.2.3.4:51820".to_string(),
                mtu: Some(1420),
                dns: vec![],
                reserved: None,
                keepalive: Some(25),
            }),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            favorite: false,
            last_used_at: None,
            fingerprint_key: None,
            custom_name: None,
            overrides: Some(ProfileOverrides {
                mtu: Some(1280),
                custom_dns: Some("1.1.1.1".to_string()),
                preferred_mode: None,
                ..Default::default()
            }),
            original_source: None,
            config_revision: 0,
        };
        let cfg_wg = generate_xray_config(&wg, 10808, 10809);
        assert_eq!(cfg_wg["outbounds"][0]["settings"]["mtu"], 1280);
        assert_eq!(
            cfg_wg["outbounds"][0]["settings"]["domainStrategy"],
            "ForceIPv4"
        );
        assert_eq!(
            cfg_wg["outbounds"][0]["settings"]["peers"][0]["keepAlive"],
            25
        );

        wg.details = ProtocolDetails::Shadowsocks(ShadowsocksDetails {
            method: "2022-blake3-aes-128-gcm".to_string(),
            password: "secret".to_string(),
            uot: true,
            plugin: None,
            plugin_opts: None,
        });
        let cfg_ss = generate_xray_config(&wg, 10808, 10809);
        assert_eq!(
            cfg_ss["outbounds"][0]["settings"]["servers"][0]["uot"],
            true
        );

        wg.details = ProtocolDetails::Hysteria2(Hysteria2Details {
            password: "pw".to_string(),
            sni: None,
            obfs: None,
            obfs_password: None,
            up_mbps: None,
            down_mbps: None,
            alpn: None,
            allow_insecure: false,
            pinned_cert_sha256: None,
            verify_peer_cert_by_name: None,
            mport: Some("20000-20500".to_string()),
            hop_interval_secs: Some(45),
        });
        let cfg_hy = generate_xray_config(&wg, 10808, 10809);
        assert_eq!(
            cfg_hy["outbounds"][0]["streamSettings"]["hysteriaSettings"]["udphop"]["port"],
            "20000-20500"
        );
        assert_eq!(
            cfg_hy["outbounds"][0]["streamSettings"]["hysteriaSettings"]["udphop"]["interval"],
            45
        );
        let _ = HashMap::<String, String>::new();
    }

    #[test]
    fn v080_advanced_sockopt_mux_vision_guardrail_and_doh_direct_rule() {
        let mut p = sample_vless_profile();
        if let ProtocolDetails::Vless(ref mut v) = p.details {
            v.flow = Some("xtls-rprx-vision".to_string());
            v.network = "tcp".to_string();
        }
        let mut opts = XrayGenOptions::default();
        opts.advanced.mux_enabled = true;
        opts.advanced.tcp_keepalive_interval_secs = 25;
        opts.advanced.tcp_fast_open = true;

        let dns = DnsConfig {
            mode: "hybrid".to_string(),
            primary_dns: "https://cloudflare-dns.com/dns-query".to_string(),
            direct_dns: "https://common.dot.dns.yandex.net/dns-query".to_string(),
            ..Default::default()
        };
        let routing = RoutingConfig {
            bypass_ru_domains: true,
            profile: crate::models::RoutingProfile::RuDirect,
            ..Default::default()
        };

        let cfg = generate_xray_config_with_options(
            &p,
            ConnectionMode::SystemProxy,
            10808,
            10809,
            None,
            None,
            &routing,
            true,
            &dns,
            false,
            "warning",
            &default_rulepack(),
            opts.clone(),
        );
        // Must NEVER apply mux to VLESS+vision
        assert!(cfg["outbounds"][0].get("mux").is_none());
        assert_eq!(
            cfg["outbounds"][0]["streamSettings"]["sockopt"]["tcpKeepAliveInterval"],
            25
        );
        // Must emit direct rule for DoH hostname so RU DNS never loops into VPN
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| {
            r.get("outboundTag").and_then(|v| v.as_str()) == Some("direct")
                && r.get("domain")
                    .and_then(|d| d.as_array())
                    .is_some_and(|arr| arr.iter().any(|x| x == "full:common.dot.dns.yandex.net"))
        }));

        // Plain WS without vision DOES get mux and ws early-data ?ed=N
        if let ProtocolDetails::Vless(ref mut v) = p.details {
            v.flow = None;
            v.network = "ws".to_string();
            v.ws_early_data = Some(2048);
        }
        let cfg_ws = generate_xray_config_with_options(
            &p,
            ConnectionMode::SystemProxy,
            10808,
            10809,
            None,
            None,
            &routing,
            true,
            &dns,
            false,
            "warning",
            &default_rulepack(),
            opts,
        );
        assert_eq!(cfg_ws["outbounds"][0]["mux"]["enabled"], true);
        assert!(
            cfg_ws["outbounds"][0]["streamSettings"]["wsSettings"]["path"]
                .as_str()
                .unwrap()
                .contains("ed=2048")
        );
    }

    #[test]
    fn applies_tcp_nodelay_dialer_strategy_and_blocks_short_direct_prefix_balancer() {
        let mut p = sample_vless_profile();
        if let ProtocolDetails::Vless(ref mut v) = p.details {
            v.flow = None;
            v.network = "tcp".to_string();
        }
        let mut opts = XrayGenOptions::default();
        opts.advanced.tcp_no_delay = false;
        opts.advanced.dialer_domain_strategy = "UseIPv4".to_string();
        let cfg = generate_xray_config_with_options(
            &p,
            ConnectionMode::SystemProxy,
            10808,
            10809,
            None,
            None,
            &RoutingConfig::default(),
            true,
            &DnsConfig::default(),
            false,
            "warning",
            &default_rulepack(),
            opts,
        );
        let sockopt = &cfg["outbounds"][0]["streamSettings"]["sockopt"];
        assert_eq!(sockopt["tcpNoDelay"], false);
        assert_eq!(sockopt["domainStrategy"], "UseIPv4");

        // Balancer selector "d" that would prefix-match Xray's built-in "direct" outbound must be dropped
        let evil_bal = crate::parser::raw_json::parse_xray_json_value(
            &json!({
                "outbounds": [{
                    "tag": "d",
                    "protocol": "vless",
                    "settings": { "vnext": [{ "address": "1.1.1.1", "port": 443, "users": [{ "id": "11111111-2222-3333-4444-555555555555" }] }] },
                    "streamSettings": { "network": "tcp", "security": "tls" }
                }],
                "routing": {
                    "balancers": [{ "tag": "b1", "selector": ["d"], "strategy": { "type": "leastPing" } }]
                }
            }),
            None,
            None,
        )
        .unwrap();
        let cfg_bal = generate_xray_config(&evil_bal[0], 10808, 10809);
        assert!(cfg_bal["routing"].get("balancers").is_none());
    }

    #[test]
    fn isolates_freedom_helper_tags_from_balancer_prefix_and_rewrites_dialer_proxy() {
        let evil = crate::parser::raw_json::parse_xray_json_value(
            &json!({
                "outbounds": [
                    {
                        "tag": "proxy-1",
                        "protocol": "vless",
                        "settings": { "vnext": [{ "address": "1.1.1.1", "port": 443, "users": [{ "id": "11111111-2222-3333-4444-555555555555" }] }] },
                        "streamSettings": { "network": "tcp", "security": "tls", "sockopt": { "dialerProxy": "proxy-leak" } }
                    },
                    {
                        "tag": "proxy-leak",
                        "protocol": "freedom",
                        "settings": { "fragment": { "packets": "tlshello", "length": "10-20", "interval": "10-20" } }
                    }
                ],
                "routing": {
                    "balancers": [{ "tag": "b1", "selector": ["proxy-"], "strategy": { "type": "leastPing" } }]
                }
            }),
            None,
            None,
        )
        .unwrap();
        let cfg = generate_xray_config(&evil[0], 10808, 10809);
        let outbounds = cfg["outbounds"].as_array().unwrap();
        let freedom_helpers: Vec<&Value> = outbounds
            .iter()
            .filter(|ob| ob["protocol"] == "freedom" && ob["tag"] != "direct")
            .collect();
        assert_eq!(freedom_helpers.len(), 1);
        let helper_tag = freedom_helpers[0]["tag"].as_str().unwrap();
        assert!(helper_tag.starts_with("helper-dial-"));
        assert_ne!(helper_tag, "proxy-leak");
        assert_eq!(
            outbounds[0]["streamSettings"]["sockopt"]["dialerProxy"].as_str(),
            Some(helper_tag)
        );
        // Balancer selector ["proxy-"] only matches "proxy-1" and cannot match "helper-dial-*"
        assert_eq!(
            cfg["routing"]["balancers"][0]["selector"][0].as_str(),
            Some("proxy-")
        );
    }
}
