use crate::models::{
    AppSettings, ConfigAdaptationProposal, ConnectionMode, CoreDiagnostics, ProfileAnalysisReport,
    ProfileCapabilities, ProfileCompatibilityStatus, ProtocolDetails, ProtocolType, ServerProfile,
};

/// Analyzes an imported/stored ServerProfile cleanly without altering security posture.
/// Trust boundary: NEVER emits proposals to disable Kill Switch, bypass routing, expose non-loopback ports,
/// alter HWID/privacy, or mutate update URLs.
pub fn analyze_server_profile(
    profile: &ServerProfile,
    settings: &AppSettings,
    diagnostics: &CoreDiagnostics,
) -> ProfileAnalysisReport {
    let mut warnings = Vec::new();
    let mut unsupported_fields = Vec::new();
    let mut proposals = Vec::new();
    let mut features = Vec::new();

    let (
        transport,
        security,
        requires_udp,
        supports_system_proxy,
        supports_tun,
        mtu,
        dns_servers,
        node_count,
        has_balancer,
        min_core_requirement,
        protocol_supported,
    ) = match &profile.details {
        ProtocolDetails::Vless(d) => {
            if let Some(ref flow) = d.flow {
                if !flow.is_empty() {
                    features.push(format!("Flow: {flow}"));
                }
            }
            if d.security.eq_ignore_ascii_case("reality") {
                features.push("REALITY".into());
                if d.public_key.as_deref().unwrap_or("").trim().is_empty() {
                    warnings.push(
                        "Отсутствует Reality Public Key (pbk) — рукопожатие не пройдёт.".into(),
                    );
                }
            }
            if d.pqv.as_deref().is_some_and(|s| !s.is_empty()) {
                features.push("ML-DSA-65 PQ".into());
            }
            if d.network.eq_ignore_ascii_case("xhttp") {
                features.push(format!(
                    "XHTTP ({})",
                    d.xhttp_mode.as_deref().unwrap_or("auto")
                ));
            }
            if d.allow_insecure && d.pinned_cert_sha256.is_none() {
                warnings.push(
                    "Профиль содержит allowInsecure=true без закрепления SHA-256 — проверка сертификата TLS ослаблена (Xray v26 рекомендует verifyPeerCert)."
                        .into(),
                );
            }
            if d.security.eq_ignore_ascii_case("none") && d.encryption.eq_ignore_ascii_case("none")
            {
                warnings.push(
                    "VLESS без TLS/Reality/VLESS-encryption не принимается Xray для публичных серверов.".into(),
                );
            }
            (
                d.network.to_uppercase(),
                d.security.to_uppercase(),
                false,
                true,
                true,
                None,
                Vec::new(),
                1,
                false,
                "Xray-core >= v25.10".to_string(),
                diagnostics.core_available,
            )
        }
        ProtocolDetails::Vmess(d) => {
            features.push(format!("Cipher: {}", d.cipher));
            if d.allow_insecure && d.pinned_cert_sha256.is_none() {
                warnings.push("Включён allowInsecure=true без закрепления сертификата.".into());
            }
            (
                d.network.to_uppercase(),
                d.security.to_uppercase(),
                false,
                true,
                true,
                None,
                Vec::new(),
                1,
                false,
                "Xray-core >= v24.1".to_string(),
                diagnostics.core_available,
            )
        }
        ProtocolDetails::Trojan(d) => {
            if d.security.eq_ignore_ascii_case("reality") {
                features.push("Trojan + REALITY".into());
                if d.public_key.as_deref().unwrap_or("").trim().is_empty() {
                    warnings.push("Trojan Reality без Public Key (pbk).".into());
                }
            }
            if d.allow_insecure && d.pinned_cert_sha256.is_none() {
                warnings.push("Включён allowInsecure=true для Trojan TLS.".into());
            }
            (
                d.network.to_uppercase(),
                d.security.to_uppercase(),
                false,
                true,
                true,
                None,
                Vec::new(),
                1,
                false,
                "Xray-core >= v25.10".to_string(),
                diagnostics.core_available,
            )
        }
        ProtocolDetails::Shadowsocks(d) => {
            features.push(format!("Метод: {}", d.method));
            if d.uot {
                features.push("UoT".into());
            }
            if let Some(ref plug) = d.plugin {
                if !plug.trim().is_empty() {
                    unsupported_fields.push(format!("plugin={plug}"));
                    warnings.push(format!(
                        "Обнаружен внешний SIP003 плагин «{plug}», который не встроен в клиент."
                    ));
                }
            }
            (
                "TCP/UDP".to_string(),
                d.method.clone(),
                false,
                true,
                true,
                None,
                Vec::new(),
                1,
                false,
                "Xray-core >= v24.1".to_string(),
                diagnostics.core_available,
            )
        }
        ProtocolDetails::Hysteria2(d) => {
            features.push("QUIC".into());
            if let Some(ref obfs) = d.obfs {
                features.push(format!("Obfs: {obfs}"));
            }
            if let Some(ref mp) = d.mport {
                features.push(format!("Port Hopping: {mp}"));
            }
            if let (Some(up), Some(down)) = (d.up_mbps, d.down_mbps) {
                features.push(format!("Лимит: {down}/{up} Мбит/с"));
            }
            if d.allow_insecure && d.pinned_cert_sha256.is_none() {
                warnings.push("Hysteria2 использует allowInsecure=true без pinSHA256.".into());
            }
            (
                "QUIC (UDP)".to_string(),
                "TLS".to_string(),
                true,
                true,
                true,
                None,
                Vec::new(),
                1,
                false,
                "Xray-core >= v26.1".to_string(),
                diagnostics.core_available,
            )
        }
        ProtocolDetails::Wireguard(d) => {
            features.push("WireGuard Kernel/Userspace".into());
            if let Some(m) = d.mtu {
                features.push(format!("MTU: {m}"));
            }
            if d.reserved.is_some() {
                features.push("WARP Reserved".into());
            }
            if let Some(ka) = d.keepalive {
                features.push(format!("Keepalive: {ka} с"));
            }
            (
                "UDP".to_string(),
                "Noise_IK".to_string(),
                true,
                true,
                true,
                d.mtu,
                d.dns.clone(),
                1,
                false,
                "Xray-core >= v24.1".to_string(),
                diagnostics.core_available,
            )
        }
        ProtocolDetails::AmneziaWg(d) => {
            features.push("AmneziaWG Obfuscation".into());
            if let Some(ref jc) = d.jc {
                features.push(format!("Jc={jc}"));
            }
            if d.extra_params.keys().any(|k| k.starts_with('I')) {
                features.push("AWG 1.5 CPS".into());
            }
            if [d.h1.as_ref(), d.h2.as_ref(), d.h3.as_ref(), d.h4.as_ref()]
                .into_iter()
                .flatten()
                .any(|v| v.contains('-'))
            {
                features.push("AWG 2.0 Ranges".into());
            }
            (
                "UDP (AWG)".to_string(),
                "Noise_IK + DPI Obfuscation".to_string(),
                true,
                true,
                true,
                d.mtu,
                d.dns.clone(),
                1,
                false,
                "wireproxy-awg v1.0.18 + Xray-core".to_string(),
                diagnostics.core_available && diagnostics.awg_available,
            )
        }
        ProtocolDetails::RawXray(d) => {
            let count = d.node_count.unwrap_or_else(|| 1 + d.extra_outbounds.len());
            let has_bal = !d.balancers.is_empty();
            if has_bal {
                features.push("Автобалансировщик".into());
            }
            features.push(format!("Raw JSON ({count} узл.)"));
            let inner_proto = d
                .outbound_json
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("xray")
                .to_ascii_uppercase();
            let inner_udp = matches!(inner_proto.as_str(), "HYSTERIA" | "WIREGUARD");
            (
                d.transport_summary.clone().unwrap_or_else(|| "JSON".into()),
                inner_proto,
                inner_udp,
                true,
                true,
                None,
                Vec::new(),
                count,
                has_bal,
                "Xray-core v26.11.9".to_string(),
                diagnostics.core_available,
            )
        }
    };

    // Safe adaptation proposals (per-profile only!)
    if let Some(prof_mtu) = mtu {
        let cur_mtu = profile
            .overrides
            .as_ref()
            .and_then(|o| o.mtu)
            .map(|m| m.to_string())
            .unwrap_or_else(|| "Авто".into());
        if profile.overrides.as_ref().and_then(|o| o.mtu) != Some(prof_mtu) {
            proposals.push(ConfigAdaptationProposal {
                field: "mtu".into(),
                label: "MTU профиля".into(),
                current_value: cur_mtu,
                proposed_value: prof_mtu.to_string(),
                reason: "Явно указано в импортированной конфигурации для предотвращения фрагментации пакетов.".into(),
                requires_confirmation: false,
                safe_to_auto_apply: true,
            });
        }
    }

    if let Some(first_dns) = dns_servers.first() {
        let cur_dns = profile
            .overrides
            .as_ref()
            .and_then(|o| o.custom_dns.clone())
            .unwrap_or_else(|| settings.dns.primary_dns.clone());
        if profile
            .overrides
            .as_ref()
            .and_then(|o| o.custom_dns.as_ref())
            != Some(first_dns)
            && !first_dns.eq_ignore_ascii_case(&settings.dns.primary_dns)
        {
            proposals.push(ConfigAdaptationProposal {
                field: "customDns".into(),
                label: "DNS профиля".into(),
                current_value: cur_dns,
                proposed_value: first_dns.clone(),
                reason: "Конфигурация содержит собственный DNS-резолвер (полезно для корпоративных/внутренних подсетей AWG).".into(),
                requires_confirmation: true,
                safe_to_auto_apply: false,
            });
        }
    }

    if requires_udp
        && settings.connection_mode == ConnectionMode::SystemProxy
        && profile.overrides.as_ref().and_then(|o| o.preferred_mode) != Some(ConnectionMode::Tun)
    {
        proposals.push(ConfigAdaptationProposal {
            field: "preferredMode".into(),
            label: "Режим перехвата".into(),
            current_value: "Системный прокси".into(),
            proposed_value: "TUN (весь ПК)".into(),
            reason: if diagnostics.is_elevated {
                "Протокол ориентирован на UDP/QUIC — в TUN-режиме будут перехватываться игры, звонки и весь UDP-трафик."
            } else {
                "Протокол ориентирован на UDP/QUIC — TUN обеспечит полный перехват UDP (при запуске потребуются права UAC)."
            }
            .into(),
            requires_confirmation: true,
            safe_to_auto_apply: false,
        });
    }

    if !diagnostics.core_available {
        warnings.push("Бинарный файл Xray-core не найден в каталоге ядра.".into());
    }
    if matches!(profile.protocol, ProtocolType::AmneziaWg) && !diagnostics.awg_available {
        warnings.push("Модуль wireproxy-awg.exe не найден для AmneziaWG.".into());
    }

    let status = if !protocol_supported {
        ProfileCompatibilityStatus::Incompatible
    } else if proposals.iter().any(|p| p.requires_confirmation) || !unsupported_fields.is_empty() {
        ProfileCompatibilityStatus::NeedsAdaptation
    } else if !warnings.is_empty() {
        ProfileCompatibilityStatus::ValidWithWarnings
    } else {
        ProfileCompatibilityStatus::Valid
    };

    ProfileAnalysisReport {
        server_id: if profile.id.is_empty() {
            None
        } else {
            Some(profile.id.clone())
        },
        status,
        core_available: diagnostics.core_available,
        protocol_supported,
        capabilities: ProfileCapabilities {
            protocol: format!("{:?}", profile.protocol),
            transport,
            security,
            requires_udp,
            supports_system_proxy,
            supports_tun,
            mtu,
            dns_servers,
            node_count,
            has_balancer,
            min_core_requirement,
            features,
        },
        warnings,
        unsupported_fields,
        proposals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ShadowsocksDetails, WireguardDetails};

    fn base_diag() -> CoreDiagnostics {
        CoreDiagnostics {
            core_name: "Xray-core".into(),
            core_version: "26.11.9".into(),
            core_path: "xray.exe".into(),
            core_available: true,
            wintun_available: true,
            awg_available: true,
            is_elevated: true,
            kill_switch_engaged: false,
            system_proxy_active: false,
            active_proxy_endpoint: None,
            config_dir: ".".into(),
            core_integrity_ok: true,
            awg_integrity_ok: true,
            wintun_integrity_ok: true,
            integrity_note: None,
        }
    }

    #[test]
    fn wireguard_mtu_and_dns_generate_only_safe_profile_proposals() {
        let profile = ServerProfile {
            id: "wg-1".into(),
            name: "Corp WG".into(),
            protocol: ProtocolType::Wireguard,
            address: "198.51.100.1".into(),
            port: 51820,
            country_code: Some("DE".into()),
            subscription_id: None,
            latency_ms: None,
            details: ProtocolDetails::Wireguard(WireguardDetails {
                secret_key: "A".repeat(43) + "=",
                address: vec!["10.7.0.2/32".into()],
                public_key: "B".repeat(43) + "=",
                preshared_key: None,
                endpoint: "198.51.100.1:51820".into(),
                mtu: Some(1280),
                dns: vec!["10.7.0.1".into()],
                reserved: None,
                keepalive: Some(25),
            }),
            created_at: "2026-11-25T00:00:00Z".into(),
            favorite: false,
            last_used_at: None,
            fingerprint_key: None,
            custom_name: None,
            overrides: None,
            original_source: None,
            config_revision: 0,
        };

        let settings = AppSettings::default();
        let report = analyze_server_profile(&profile, &settings, &base_diag());
        assert_eq!(report.status, ProfileCompatibilityStatus::NeedsAdaptation);
        assert!(report.proposals.iter().any(|p| p.field == "mtu"));
        assert!(report.proposals.iter().any(|p| p.field == "customDns"));
        assert!(report.proposals.iter().any(|p| p.field == "preferredMode"));
        // Trust boundary guarantee: never touch global security knobs
        assert!(report
            .proposals
            .iter()
            .all(|p| !p.field.contains("killSwitch") && !p.field.contains("update")));
    }

    #[test]
    fn shadowsocks_external_plugin_is_flagged_as_unsupported_field() {
        let profile = ServerProfile {
            id: "ss-1".into(),
            name: "SS Plugin".into(),
            protocol: ProtocolType::Shadowsocks,
            address: "198.51.100.2".into(),
            port: 80,
            country_code: None,
            subscription_id: None,
            latency_ms: None,
            details: ProtocolDetails::Shadowsocks(ShadowsocksDetails {
                method: "aes-256-gcm".into(),
                password: "pass".into(),
                uot: false,
                plugin: Some("v2ray-plugin".into()),
                plugin_opts: Some("tls".into()),
            }),
            created_at: "2026-11-25T00:00:00Z".into(),
            favorite: false,
            last_used_at: None,
            fingerprint_key: None,
            custom_name: None,
            overrides: None,
            original_source: None,
            config_revision: 0,
        };
        let report = analyze_server_profile(&profile, &AppSettings::default(), &base_diag());
        assert!(report
            .unsupported_fields
            .iter()
            .any(|f| f.contains("v2ray-plugin")));
    }
}
