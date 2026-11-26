use crate::config_gen::{
    build_primary_outbound_only, generate_wireproxy_awg_config_with_dns,
    generate_xray_config_with_options, resolve_effective_mtu, XrayGenOptions,
};
use crate::core_manager::validate_xray_config;
use crate::models::{
    AppSettings, ConfigDiffEntry, ConfigStudioView, ConfigValidationResult, ConnectionMode,
    CoreSelectionMode, ProfileEditRevisionMeta, ProtocolDetails, ServerProfile,
};
use crate::parser::raw_json::{is_allowed_proxy_protocol, sanitize_xray_outbound_v26};
use crate::routing_rules::RulepackData;
use crate::storage::{atomic_write_bytes, secure_delete_file, AppStorage};
use serde_json::{json, Value};
use std::path::Path;

fn redact_value_secrets(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                let low = k.to_ascii_lowercase();
                if matches!(
                    low.as_str(),
                    "id" | "password"
                        | "publickey"
                        | "shortid"
                        | "secretkey"
                        | "presharedkey"
                        | "seed"
                ) {
                    if let Some(s) = val.as_str() {
                        if !s.is_empty() && s != "auto" && s != "none" {
                            let prefix: String = s.chars().take(4).collect();
                            *val = Value::String(format!("{prefix}••••••"));
                            continue;
                        }
                    }
                }
                redact_value_secrets(val);
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_value_secrets(item);
            }
        }
        _ => {}
    }
}

fn collect_diffs(
    path: &str,
    layer: &str,
    before: &Value,
    after: &Value,
    reason: &str,
    out: &mut Vec<ConfigDiffEntry>,
) {
    if before == after || out.len() >= 120 {
        return;
    }
    match (before, after) {
        (Value::Object(bm), Value::Object(am)) => {
            for (k, bv) in bm {
                let p = if path.is_empty() {
                    format!("/{k}")
                } else {
                    format!("{path}/{k}")
                };
                match am.get(k) {
                    Some(av) => collect_diffs(&p, layer, bv, av, reason, out),
                    None => out.push(ConfigDiffEntry {
                        path: p,
                        layer: layer.to_string(),
                        change_type: "removed".into(),
                        before: Some(bv.to_string()),
                        after: None,
                        reason: reason.to_string(),
                    }),
                }
            }
            for (k, av) in am {
                if !bm.contains_key(k) {
                    let p = if path.is_empty() {
                        format!("/{k}")
                    } else {
                        format!("{path}/{k}")
                    };
                    out.push(ConfigDiffEntry {
                        path: p,
                        layer: layer.to_string(),
                        change_type: "added".into(),
                        before: None,
                        after: Some(av.to_string()),
                        reason: reason.to_string(),
                    });
                }
            }
        }
        _ => out.push(ConfigDiffEntry {
            path: if path.is_empty() {
                "/".into()
            } else {
                path.to_string()
            },
            layer: layer.to_string(),
            change_type: "modified".into(),
            before: Some(before.to_string()),
            after: Some(after.to_string()),
            reason: reason.to_string(),
        }),
    }
}

pub fn audit_untrusted_outbound(raw_ob: &Value) -> (Vec<ConfigDiffEntry>, Vec<String>) {
    let mut stripped = Vec::new();
    let mut errors = Vec::new();

    if !is_allowed_proxy_protocol(raw_ob) {
        let proto = raw_ob
            .as_object()
            .and_then(|m| m.iter().find(|(k, _)| k.eq_ignore_ascii_case("protocol")))
            .and_then(|(_, v)| v.as_str())
            .unwrap_or("unknown");
        errors.push(format!(
            "Протокол «{proto}» не разрешён в роли основного VPN outbound."
        ));
    }

    fn walk_unsafe(
        val: &Value,
        ptr: String,
        inside_freedom: bool,
        stripped: &mut Vec<ConfigDiffEntry>,
    ) {
        match val {
            Value::Object(map) => {
                let is_freedom = inside_freedom
                    || map.iter().any(|(k, v)| {
                        k.eq_ignore_ascii_case("protocol")
                            && v.as_str()
                                .is_some_and(|s| s.eq_ignore_ascii_case("freedom"))
                    });
                for (k, v) in map {
                    let k_lc = k.to_ascii_lowercase();
                    let next_ptr = format!("{ptr}/{k}");
                    let mut push_strip = |reason: &str| {
                        stripped.push(ConfigDiffEntry {
                            path: next_ptr.clone(),
                            layer: "security_guardrail".into(),
                            change_type: "stripped_unsafe".into(),
                            before: Some(v.to_string()),
                            after: None,
                            reason: reason.to_string(),
                        });
                    };

                    match k_lc.as_str() {
                        "allowinsecure" if v.as_bool() == Some(true) => {
                            push_strip("Проверка TLS-сертификатов не может быть ослаблена политикой безопасности AURA.");
                        }
                        "masterkeylog" => {
                            push_strip(
                                "Локальная запись TLS ключей в файл (masterKeyLog) запрещена.",
                            );
                        }
                        "certificates" | "certificatefile" | "keyfile" => {
                            push_strip("Загрузка произвольных клиентских/CA сертификатов из путей ОС запрещена.");
                        }
                        "interface" | "mark" | "tproxy" | "uds" => {
                            push_strip("Системный параметр сокета не должен переопределять маршрутизацию/права.");
                        }
                        "sendthrough" => {
                            push_strip("Принудительная привязка исходящего IP запрещена во избежание обхода туннеля.");
                        }
                        "proxysettings" => {
                            push_strip(
                                "Внешний chain proxySettings удаляется политикой изоляции AURA.",
                            );
                        }
                        "dialerproxy" => {
                            let clean = v.as_str().unwrap_or("").trim().to_ascii_lowercase();
                            if clean.is_empty()
                                || clean == "direct"
                                || clean == "block"
                                || clean == "dns-out"
                                || clean == "api"
                            {
                                push_strip(
                                    "Небезопасный dialerProxy на direct/block/dns-out запрещён.",
                                );
                            }
                        }
                        "redirect" | "userlevel" | "domainstrategy" if inside_freedom => {
                            push_strip("Переопределение redirect/strategy у freedom запрещено.");
                        }
                        _ => walk_unsafe(v, next_ptr, is_freedom && k_lc == "settings", stripped),
                    }
                }
            }
            Value::Array(arr) => {
                for (i, item) in arr.iter().enumerate() {
                    walk_unsafe(item, format!("{ptr}/{i}"), inside_freedom, stripped);
                }
            }
            _ => {}
        }
    }

    walk_unsafe(raw_ob, String::new(), false, &mut stripped);

    (stripped, errors)
}

#[allow(clippy::too_many_arguments)]
pub fn build_config_studio_view(
    profile: &ServerProfile,
    settings: &AppSettings,
    pack: &RulepackData,
    storage: &AppStorage,
    redact_secrets_flag: bool,
) -> ConfigStudioView {
    let mut base_no_overrides = profile.clone();
    base_no_overrides.overrides = None;

    let mut layer1_imported =
        build_primary_outbound_only(&base_no_overrides, settings.ipv6_enabled);
    let mut layer2_with_overrides = build_primary_outbound_only(profile, settings.ipv6_enabled);

    let effective_mode = profile
        .overrides
        .as_ref()
        .and_then(|o| o.preferred_mode)
        .unwrap_or(settings.connection_mode);
    let mode_source = if profile
        .overrides
        .as_ref()
        .and_then(|o| o.preferred_mode)
        .is_some()
    {
        "Индивидуально в профиле".into()
    } else {
        "Глобальные настройки".into()
    };

    let (effective_mtu, mtu_source) = resolve_effective_mtu(profile, settings);
    let (effective_dns, dns_source) = if let Some(cdns) = profile
        .overrides
        .as_ref()
        .and_then(|o| o.custom_dns.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        (cdns.to_string(), "Индивидуальный DNS профиля".into())
    } else if settings.dns.mode.eq_ignore_ascii_case("config") {
        let cfg_dns = match &profile.details {
            ProtocolDetails::Wireguard(w) => w.dns.first().cloned(),
            ProtocolDetails::AmneziaWg(a) => a.dns.first().cloned(),
            _ => None,
        };
        if let Some(d) = cfg_dns {
            (d, "Из конфигурации профиля".into())
        } else {
            (settings.dns.primary_dns.clone(), "Глобальный DNS".into())
        }
    } else {
        (
            settings.dns.primary_dns.clone(),
            "Глобальные настройки DNS".into(),
        )
    };

    let effective_core: String = match profile.protocol {
        crate::models::ProtocolType::AmneziaWg => "wireproxy-awg + Xray-core".into(),
        crate::models::ProtocolType::Wireguard => {
            let sel = profile
                .overrides
                .as_ref()
                .and_then(|o| o.preferred_core)
                .filter(|&c| c != CoreSelectionMode::Auto)
                .unwrap_or(settings.advanced.core_selection);
            if sel == CoreSelectionMode::WireproxyAwg {
                "wireproxy-awg (выбор профиля/настроек)".into()
            } else {
                "Xray-core (нативный WireGuard)".into()
            }
        }
        _ => "Xray-core".into(),
    };

    let mut layer4_final_sanitized = generate_xray_config_with_options(
        profile,
        effective_mode,
        settings.http_port,
        settings.socks_port,
        if effective_mode == ConnectionMode::Tun {
            Some(18085)
        } else {
            None
        },
        if matches!(profile.details, ProtocolDetails::AmneziaWg(_))
            || (matches!(profile.details, ProtocolDetails::Wireguard(_))
                && effective_core.starts_with("wireproxy-awg"))
        {
            Some(10899)
        } else {
            None
        },
        &settings.routing,
        settings.routing.bypass_lan,
        &settings.dns,
        settings.ipv6_enabled,
        &settings.log_level,
        pack,
        XrayGenOptions::from_settings(settings),
    );

    let awg_config_preview = match &profile.details {
        ProtocolDetails::AmneziaWg(d) => {
            let mut merged = d.clone();
            merged.mtu = Some(effective_mtu);
            generate_wireproxy_awg_config_with_dns(&merged, 10899, Some(&effective_dns)).ok()
        }
        _ => None,
    };

    let mut stripped_guardrails = Vec::new();
    if let ProtocolDetails::RawXray(ref rx) = profile.details {
        let (s, _) = audit_untrusted_outbound(&rx.outbound_json);
        stripped_guardrails = s;
    }

    let mut diffs = Vec::new();
    collect_diffs(
        "/outbound",
        "overrides",
        &layer1_imported,
        &layer2_with_overrides,
        "Применение индивидуальных overrides профиля и расширенных параметров",
        &mut diffs,
    );
    if let Some(first_ob) = layer4_final_sanitized
        .get("outbounds")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
    {
        collect_diffs(
            "/outbound",
            "sanitized",
            &layer2_with_overrides,
            first_ob,
            "Санитизация политики безопасности AURA и внедрение параметров сокета/Mux",
            &mut diffs,
        );
    }

    let layer3_injected_summary = vec![
        format!(
            "Inbound ({})",
            if effective_mode == ConnectionMode::Tun {
                format!("TUN «{}», MTU {effective_mtu}, DNS hijack :53", settings.tun.adapter_name)
            } else {
                format!(
                    "127.0.0.1 HTTP :{} / SOCKS5 :{} (localhost-only)",
                    settings.http_port, settings.socks_port
                )
            }
        ),
        format!(
            "DNS: режим «{}», сервер «{}» ({})",
            settings.dns.mode, effective_dns, dns_source
        ),
        format!(
            "Маршрутизация: профиль «{:?}», LAN direct={}, RU direct={}, IPv6={}",
            settings.routing.profile,
            settings.routing.bypass_lan,
            settings.routing.bypass_ru_domains,
            settings.ipv6_enabled
        ),
        "Outbounds безопасности: добавлены `direct` (freedom) и `block` (blackhole); Kill Switch не зависит от конфига узла.".into(),
    ];

    if redact_secrets_flag {
        redact_value_secrets(&mut layer1_imported);
        redact_value_secrets(&mut layer2_with_overrides);
        redact_value_secrets(&mut layer4_final_sanitized);
    }

    let revisions: Vec<ProfileEditRevisionMeta> = storage
        .load_profile_revisions(&profile.id)
        .into_iter()
        .map(|r| ProfileEditRevisionMeta {
            revision_id: r.revision_id,
            timestamp: r.timestamp,
            note: r.note,
            summary: r.summary,
        })
        .collect();

    ConfigStudioView {
        profile_id: profile.id.clone(),
        format: if awg_config_preview.is_some() {
            "awg_ini_plus_xray".into()
        } else {
            "xray_json".into()
        },
        effective_core,
        effective_mtu,
        mtu_source,
        effective_dns,
        dns_source,
        effective_mode,
        mode_source,
        layer1_imported,
        layer2_with_overrides,
        layer3_injected_summary,
        layer4_final_sanitized,
        awg_config_preview: awg_config_preview.map(|txt| {
            if redact_secrets_flag {
                txt.lines()
                    .map(|l| {
                        if l.starts_with("PrivateKey") || l.starts_with("PresharedKey") {
                            let k = l.split('=').next().unwrap_or(l).trim();
                            format!("{k} = ••••••••••••")
                        } else {
                            l.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                txt
            }
        }),
        stripped_guardrails,
        diffs,
        validation_ok: Some(true),
        validation_error: None,
        revisions,
    }
}

pub async fn validate_custom_outbound_json(
    edited_json: &str,
    xray_path: Option<&Path>,
    runtime_dir: &Path,
) -> Result<(Value, ConfigValidationResult), String> {
    if edited_json.len() > 512 * 1024 {
        return Err("Размер конфигурации превышает допустимый предел 512 КБ.".into());
    }
    let parsed: Value = serde_json::from_str(edited_json)
        .map_err(|e| format!("Синтаксическая ошибка JSON: {e}"))?;
    let mut ob = if parsed.get("outbounds").and_then(|v| v.as_array()).is_some() {
        parsed
            .get("outbounds")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .cloned()
            .ok_or_else(|| "Массив `outbounds` пуст.".to_string())?
    } else if parsed.get("protocol").is_some() {
        parsed.clone()
    } else {
        return Err(
            "Ожидается JSON объекта outbound (с полем `protocol`) или полный конфиг с `outbounds`."
                .into(),
        );
    };

    let (stripped, mut errors) = audit_untrusted_outbound(&ob);
    let stripped_fields: Vec<String> = stripped.iter().map(|s| s.path.clone()).collect();
    let mut warnings = Vec::new();
    if !stripped_fields.is_empty() {
        warnings.push(format!(
            "Небезопасные поля автоматически удалены политикой защиты: {}",
            stripped_fields.join(", ")
        ));
    }

    sanitize_xray_outbound_v26(&mut ob);

    let mut core_tested = false;
    if errors.is_empty() {
        if let Some(xp) = xray_path.filter(|p| p.exists()) {
            let test_cfg = json!({
                "log": { "loglevel": "none" },
                "inbounds": [{
                    "tag": "test-in",
                    "listen": "127.0.0.1",
                    "port": 10999,
                    "protocol": "socks",
                    "settings": { "auth": "noauth" }
                }],
                "outbounds": [
                    ob,
                    { "tag": "direct", "protocol": "freedom" },
                    { "tag": "block", "protocol": "blackhole" }
                ]
            });
            let temp_path = runtime_dir.join(format!("studio-test-{}.json", uuid::Uuid::new_v4()));
            if let Ok(text) = serde_json::to_string_pretty(&test_cfg) {
                if atomic_write_bytes(&temp_path, text.as_bytes()).is_ok() {
                    core_tested = true;
                    if let Err(err) = validate_xray_config(xp, &temp_path).await {
                        errors.push(err);
                    }
                    secure_delete_file(&temp_path);
                }
            }
        }
    }

    let ok = errors.is_empty();
    let res = ConfigValidationResult {
        ok,
        core_tested,
        errors,
        warnings,
        stripped_fields,
    };
    Ok((ob, res))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guardrails_detect_and_strip_unsafe_outbound_fields() {
        let evil = json!({
            "protocol": "vless",
            "sendThrough": "0.0.0.0",
            "proxySettings": { "tag": "direct" },
            "streamSettings": {
                "tlsSettings": {
                    "allowInsecure": true,
                    "masterKeyLog": "C:\\temp\\keys.log",
                    "certificates": [{ "certificateFile": "C:\\bad.pem" }]
                },
                "sockopt": { "interface": "eth0" }
            }
        });
        let (stripped, errors) = audit_untrusted_outbound(&evil);
        assert!(errors.is_empty());
        assert!(stripped.len() >= 5);
        assert!(stripped.iter().any(|d| d.path.contains("allowInsecure")));
        assert!(stripped.iter().any(|d| d.path.contains("masterKeyLog")));

        let evil_upper = json!({
            "protocol": "vless",
            "SENDTHROUGH": "0.0.0.0",
            "StreamSettings": {
                "tlsSettings": {
                    "MASTERKEYLOG": "C:\\temp\\keys.log"
                },
                "SockOpt": { "DIALERPROXY": "direct" }
            }
        });
        let (stripped_caps, errs_caps) = audit_untrusted_outbound(&evil_upper);
        assert!(errs_caps.is_empty());
        assert!(stripped_caps.len() >= 3);
    }
}
