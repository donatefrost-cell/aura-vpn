use crate::config_analyzer::analyze_server_profile;
use crate::core_manager::CoreManager;
use crate::dns_manager::test_dns_server_live;
use crate::elevation::is_elevated;
use crate::kill_switch::firewall_rule_exists_in_os;
use crate::models::{
    AppSettings, ConnectionMode, ConnectionSnapshot, ConnectionStatus, CoreDiagnostics,
    DoctorCheckResult, DoctorCheckSeverity, NetworkDoctorReport, ProfileCompatibilityStatus,
    ServerProfile,
};
use crate::tun_manager::collect_tun_snapshot;
use crate::windows_proxy::inspect_system_proxy;
use chrono::Utc;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn check_port_in_excluded_ranges(port: u16) -> Option<String> {
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let netsh = format!("{sys_root}\\System32\\netsh.exe");
    let out = Command::new(netsh)
        .args([
            "interface",
            "ipv4",
            "show",
            "excludedportrange",
            "protocol=tcp",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 2 {
            if let (Ok(start), Ok(end)) = (cols[0].parse::<u16>(), cols[1].parse::<u16>()) {
                if port >= start && port <= end {
                    return Some(format!("{start}–{end}"));
                }
            }
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub async fn run_network_doctor_suite(
    settings: &AppSettings,
    snap: &ConnectionSnapshot,
    diag: &CoreDiagnostics,
    active_profile: Option<&ServerProfile>,
    proxy_backup_exists: bool,
    ks_dirty_marker_exists: bool,
    include_external_probes: bool,
) -> NetworkDoctorReport {
    let mut checks = Vec::with_capacity(12);
    let is_conn = snap.status == ConnectionStatus::Connected;
    let effective_mode = active_profile
        .and_then(|p| p.overrides.as_ref())
        .and_then(|o| o.preferred_mode)
        .unwrap_or(if is_conn {
            snap.mode
        } else {
            settings.connection_mode
        });

    // 1. Binary integrity
    {
        let t0 = Instant::now();
        let ok = diag.core_available
            && diag.core_integrity_ok
            && diag.awg_integrity_ok
            && diag.wintun_integrity_ok;
        checks.push(DoctorCheckResult {
            id: "binary_integrity".into(),
            category: "Ядра и компоненты".into(),
            title: "Наличие и целостность компонентов (SHA-256)".into(),
            severity: if ok { DoctorCheckSeverity::Pass } else { DoctorCheckSeverity::Fail },
            summary: if ok {
                "Все встроенные ядра подтверждены SHA-256".into()
            } else {
                "Обнаружена проблема с целостностью ядра".into()
            },
            detail: diag
                .integrity_note
                .clone()
                .unwrap_or_else(|| format!("Xray: {}, AWG: {}, Wintun: {}", diag.core_available, diag.awg_available, diag.wintun_available)),
            recommended_action: (!ok).then(|| "Откройте Настройки → Сетевые ядра и проверьте целостность или переустановите AURA VPN.".into()),
            duration_ms: t0.elapsed().as_millis() as u64,
        });
    }

    // 2. Elevation status
    {
        let t0 = Instant::now();
        let elevated = is_elevated();
        let needs_admin = effective_mode == ConnectionMode::Tun
            || matches!(
                settings.kill_switch.mode,
                crate::models::KillSwitchMode::AlwaysOn
                    | crate::models::KillSwitchMode::RoutingAware
            );
        let sev = if !needs_admin || elevated {
            DoctorCheckSeverity::Pass
        } else {
            DoctorCheckSeverity::Warn
        };
        checks.push(DoctorCheckResult {
            id: "elevation_status".into(),
            category: "Разрешения Windows".into(),
            title: "Права администратора (UAC)".into(),
            severity: sev,
            summary: if elevated {
                "Повышенные права UAC активны".into()
            } else if needs_admin {
                "Для TUN / системного WFP требуются права администратора".into()
            } else {
                "Стандартные права (достаточно для Системного прокси)".into()
            },
            detail: "TUN через Wintun и системные фильтры WFP/netsh требуют UAC; режим Системного прокси работает без прав администратора.".into(),
            recommended_action: (sev == DoctorCheckSeverity::Warn)
                .then(|| "Перезапустите AURA VPN от имени администратора или переключитесь на Системный прокси.".into()),
            duration_ms: t0.elapsed().as_millis() as u64,
        });
    }

    // 3. Port conflicts & Windows excluded port ranges
    {
        let t0 = Instant::now();
        let http_p = if is_conn {
            snap.local_http_port.unwrap_or(settings.http_port)
        } else {
            settings.http_port
        };
        let socks_p = if is_conn {
            snap.local_socks_port.unwrap_or(settings.socks_port)
        } else {
            settings.socks_port
        };
        let excl_http = check_port_in_excluded_ranges(http_p);
        let excl_socks = check_port_in_excluded_ranges(socks_p);
        let mut warn_msg = Vec::new();
        if let Some(r) = excl_http {
            warn_msg.push(format!("HTTP-порт {http_p} попадает в зарезервированный Hyper-V/WSL диапазон Windows ({r})"));
        }
        if let Some(r) = excl_socks {
            warn_msg.push(format!(
                "SOCKS5-порт {socks_p} попадает в зарезервированный диапазон Windows ({r})"
            ));
        }
        if !is_conn {
            if std::net::TcpListener::bind(("127.0.0.1", http_p)).is_err() {
                warn_msg.push(format!("Порт {http_p} уже занят другим процессом"));
            }
            if std::net::TcpListener::bind(("127.0.0.1", socks_p)).is_err() {
                warn_msg.push(format!("Порт {socks_p} уже занят другим процессом"));
            }
        }
        let sev = if warn_msg.is_empty() {
            DoctorCheckSeverity::Pass
        } else {
            DoctorCheckSeverity::Fail
        };
        checks.push(DoctorCheckResult {
            id: "port_conflicts".into(),
            category: "Локальные порты".into(),
            title: "Проверка портов HTTP/SOCKS5 и диапазонов Hyper-V/WinNAT".into(),
            severity: sev,
            summary: if warn_msg.is_empty() {
                format!("Порты 127.0.0.1:{http_p} и :{socks_p} свободны")
            } else {
                "Обнаружен конфликт локальных портов".into()
            },
            detail: if warn_msg.is_empty() {
                "Конфликтов с занятыми портами или зарезервированными диапазонами WinNAT нет.".into()
            } else {
                warn_msg.join("; ")
            },
            recommended_action: (!warn_msg.is_empty())
                .then(|| "Измените локальные порты HTTP/SOCKS5 в Настройки → Подключение (например, 20808/20809).".into()),
            duration_ms: t0.elapsed().as_millis() as u64,
        });
    }

    // 4. Config compatibility
    {
        let t0 = Instant::now();
        if let Some(prof) = active_profile {
            let report = analyze_server_profile(prof, settings, diag);
            let sev = match report.status {
                ProfileCompatibilityStatus::Valid => DoctorCheckSeverity::Pass,
                ProfileCompatibilityStatus::ValidWithWarnings
                | ProfileCompatibilityStatus::NeedsAdaptation => DoctorCheckSeverity::Warn,
                ProfileCompatibilityStatus::Incompatible => DoctorCheckSeverity::Fail,
            };
            checks.push(DoctorCheckResult {
                id: "config_compatibility".into(),
                category: "Конфигурация".into(),
                title: "Совместимость активного серверного профиля".into(),
                severity: sev,
                summary: format!("Профиль «{}»: {:?}", prof.name, report.status),
                detail: if report.warnings.is_empty() {
                    format!(
                        "Протокол {} / {} полностью поддерживается ядром.",
                        report.capabilities.protocol, report.capabilities.transport
                    )
                } else {
                    report.warnings.join("; ")
                },
                recommended_action: (!report.warnings.is_empty()).then(|| {
                    "Откройте Config Studio (Инспектор узла) для просмотра рекомендаций.".into()
                }),
                duration_ms: t0.elapsed().as_millis() as u64,
            });
        } else {
            checks.push(DoctorCheckResult {
                id: "config_compatibility".into(),
                category: "Конфигурация".into(),
                title: "Совместимость активного серверного профиля".into(),
                severity: DoctorCheckSeverity::Skipped,
                summary: "Сервер не выбран".into(),
                detail: "Добавьте или выберите серверный профиль для анализа.".into(),
                recommended_action: None,
                duration_ms: t0.elapsed().as_millis() as u64,
            });
        }
    }

    // 5 & 6. TUN & Virtual adapter conflicts (read-only)
    {
        let t0 = Instant::now();
        let tun_snap = collect_tun_snapshot(&settings.tun, diag);
        let tun_ok = if effective_mode == ConnectionMode::Tun {
            tun_snap.adapter.wintun_present
                && tun_snap.adapter.wintun_integrity_ok
                && tun_snap.adapter.is_elevated
        } else {
            tun_snap.adapter.wintun_present && tun_snap.adapter.wintun_integrity_ok
        };
        checks.push(DoctorCheckResult {
            id: "tun_readiness".into(),
            category: "Виртуальный адаптер".into(),
            title: "Готовность TUN / Wintun".into(),
            severity: if tun_ok {
                DoctorCheckSeverity::Pass
            } else {
                DoctorCheckSeverity::Warn
            },
            summary: format!(
                "{} ({})",
                tun_snap.adapter.adapter_name, tun_snap.adapter.status
            ),
            detail: tun_snap.adapter.driver_status,
            recommended_action: (!tun_ok).then(|| {
                "Проверьте Настройки → TUN и адаптеры или запустите от имени администратора.".into()
            }),
            duration_ms: t0.elapsed().as_millis() as u64,
        });

        let warn_conflicts: Vec<_> = tun_snap
            .conflicts
            .iter()
            .filter(|c| c.severity == "warn")
            .collect();
        checks.push(DoctorCheckResult {
            id: "adapter_conflicts".into(),
            category: "Виртуальный адаптер".into(),
            title: "Конфликты виртуальных адаптеров и маршрутов".into(),
            severity: if warn_conflicts.is_empty() {
                DoctorCheckSeverity::Pass
            } else {
                DoctorCheckSeverity::Warn
            },
            summary: if warn_conflicts.is_empty() {
                format!(
                    "Активных конфликтов не найдено (обнаружено виртуальных интерфейсов: {})",
                    tun_snap.conflicts.len()
                )
            } else {
                format!(
                    "Обнаружено потенциально конфликтующих адаптеров: {}",
                    warn_conflicts.len()
                )
            },
            detail: if warn_conflicts.is_empty() {
                "Сторонние VPN/TAP/Wintun-адаптеры не мешают маршрутизации.".into()
            } else {
                warn_conflicts
                    .iter()
                    .map(|c| format!("{} ({})", c.adapter_name, c.category))
                    .collect::<Vec<_>>()
                    .join("; ")
            },
            recommended_action: (!warn_conflicts.is_empty())
                .then(|| "Перед использованием TUN отключите другие VPN-клиенты вручную.".into()),
            duration_ms: t0.elapsed().as_millis() as u64,
        });
    }

    // 7. System proxy consistency
    {
        let t0 = Instant::now();
        let (os_proxy_on, endpoint) = inspect_system_proxy();
        let expected_on =
            is_conn && snap.mode == ConnectionMode::SystemProxy && snap.system_proxy_enabled;
        let consistent = if is_conn {
            os_proxy_on == expected_on
        } else {
            !os_proxy_on || snap.kill_switch_engaged
        };
        checks.push(DoctorCheckResult {
            id: "system_proxy_consistency".into(),
            category: "Системный прокси".into(),
            title: "Согласованность прокси Windows".into(),
            severity: if consistent {
                DoctorCheckSeverity::Pass
            } else {
                DoctorCheckSeverity::Warn
            },
            summary: if os_proxy_on {
                format!("Включён ({})", endpoint.as_deref().unwrap_or("127.0.0.1"))
            } else {
                "Отключён".into()
            },
            detail: format!(
                "proxy_backup={proxy_backup_exists}, ожидаемое состояние={expected_on}"
            ),
            recommended_action: (!consistent).then(|| {
                "Если интернет не работает без VPN, нажмите «Экстренное восстановление сети»."
                    .into()
            }),
            duration_ms: t0.elapsed().as_millis() as u64,
        });
    }

    // 8. Kill Switch health
    {
        let t0 = Instant::now();
        let os_rule = firewall_rule_exists_in_os();
        let mut sev = DoctorCheckSeverity::Pass;
        let mut detail = format!(
            "Режим: {:?}, статус: {:?}, механизм: {:?}",
            snap.kill_switch.mode, snap.kill_switch.status, snap.kill_switch.enforcement
        );
        if ks_dirty_marker_exists && !snap.kill_switch.blocking_active {
            sev = DoctorCheckSeverity::Warn;
            detail.push_str(" • Обнаружен маркер от прошлой сессии.");
        }
        if matches!(
            snap.kill_switch.status,
            crate::models::KillSwitchStatus::Degraded
                | crate::models::KillSwitchStatus::RecoveryRequired
        ) {
            sev = DoctorCheckSeverity::Fail;
        }
        if let Some(exists) = os_rule {
            detail.push_str(&format!(" • Правило netsh в ОС: {exists}"));
        }
        checks.push(DoctorCheckResult {
            id: "kill_switch_health".into(),
            category: "Безопасность".into(),
            title: "Состояние Kill Switch 2.0 и брандмауэра".into(),
            severity: sev,
            summary: if snap.kill_switch.blocking_active {
                "Активна блокировка трафика".into()
            } else {
                format!("{:?}", snap.kill_switch.status)
            },
            detail,
            recommended_action: (sev != DoctorCheckSeverity::Pass)
                .then(|| "Откройте Центр защиты и выполните Экстренное восстановление сети (при необходимости с правами UAC).".into()),
            duration_ms: t0.elapsed().as_millis() as u64,
        });
    }

    // 9..12 Network probes (skipped cleanly when disabled or Kill Switch blocks)
    if !include_external_probes {
        for (id, title) in [
            (
                "internet_reachability",
                "Доступность базового интернета / выход через сеть",
            ),
            ("dns_probe", "Работа настроенного DNS-сервера"),
            ("server_reachability", "TCP-доступность выбранного VPN-узла"),
            (
                "active_tunnel_probe",
                "Подтверждение трафика через VPN-туннель (HTTPS 204)",
            ),
        ] {
            checks.push(DoctorCheckResult {
                id: id.into(),
                category: "Сетевые проверки".into(),
                title: title.into(),
                severity: DoctorCheckSeverity::Skipped,
                summary: "Пропущено (только по запросу)".into(),
                detail: "Включите сетевые проверки или запустите полную диагностику вручную."
                    .into(),
                recommended_action: None,
                duration_ms: 0,
            });
        }
    } else if snap.kill_switch.blocking_active || snap.kill_switch_engaged {
        for (id, title) in [
            ("internet_reachability", "Доступность базового интернета"),
            ("dns_probe", "Работа настроенного DNS-сервера"),
            ("server_reachability", "TCP-доступность выбранного VPN-узла"),
            (
                "active_tunnel_probe",
                "Подтверждение трафика через VPN-туннель",
            ),
        ] {
            checks.push(DoctorCheckResult {
                id: id.into(),
                category: "Сетевые проверки".into(),
                title: title.into(),
                severity: DoctorCheckSeverity::Info,
                summary: "Заблокировано Kill Switch".into(),
                detail: "Внешние проверки не выполнялись: Kill Switch активно удерживает блокировку утечек.".into(),
                recommended_action: Some("Подключитесь к серверу или снимите блокировку Kill Switch в Центре защиты.".into()),
                duration_ms: 0,
            });
        }
    } else {
        // DNS probe
        let t0 = Instant::now();
        let dns_res = test_dns_server_live(
            &settings.dns.primary_dns,
            Some("one.one.one.one"),
            snap,
            settings,
        )
        .await;
        checks.push(DoctorCheckResult {
            id: "dns_probe".into(),
            category: "Сетевые проверки".into(),
            title: "Работа настроенного DNS-сервера".into(),
            severity: if dns_res.reachable {
                DoctorCheckSeverity::Pass
            } else {
                DoctorCheckSeverity::Warn
            },
            summary: if dns_res.reachable {
                format!(
                    "{} ответил за {} мс",
                    dns_res.server,
                    dns_res.latency_ms.unwrap_or(0)
                )
            } else {
                format!("{} не ответил", dns_res.server)
            },
            detail: dns_res.error.unwrap_or_else(|| {
                format!(
                    "Протокол {}, ответы: {:?}",
                    dns_res.protocol, dns_res.resolved_ips
                )
            }),
            recommended_action: (!dns_res.reachable)
                .then(|| "Проверьте настройки в DNS-менеджере или выберите 1.1.1.1 / DoH.".into()),
            duration_ms: t0.elapsed().as_millis() as u64,
        });

        // Server reachability
        let t0 = Instant::now();
        if let Some(prof) = active_profile {
            let is_udp = matches!(
                prof.protocol,
                crate::models::ProtocolType::Hysteria2
                    | crate::models::ProtocolType::Wireguard
                    | crate::models::ProtocolType::AmneziaWg
            );
            if is_udp {
                checks.push(DoctorCheckResult {
                    id: "server_reachability".into(),
                    category: "Сетевые проверки".into(),
                    title: "Доступность выбранного VPN-узла".into(),
                    severity: DoctorCheckSeverity::Info,
                    summary: "UDP-протокол (TCP ping неприменим)".into(),
                    detail: format!("Узел {}:{} использует UDP-транспорт ({:?}); проверяется напрямую при подключении.", prof.address, prof.port, prof.protocol),
                    recommended_action: None,
                    duration_ms: t0.elapsed().as_millis() as u64,
                });
            } else {
                let lat = CoreManager::ping_profile_public(prof).await;
                checks.push(DoctorCheckResult {
                    id: "server_reachability".into(),
                    category: "Сетевые проверки".into(),
                    title: "TCP-доступность выбранного VPN-узла".into(),
                    severity: if lat.is_some() {
                        DoctorCheckSeverity::Pass
                    } else {
                        DoctorCheckSeverity::Fail
                    },
                    summary: lat
                        .map(|ms| format!("TCP-рукопожатие за {ms} мс"))
                        .unwrap_or_else(|| "Сервер недоступен по TCP".into()),
                    detail: format!("Узел {}:{} ({})", prof.address, prof.port, prof.name),
                    recommended_action: lat
                        .is_none()
                        .then(|| "Выберите другой узел или проверьте доступ к интернету.".into()),
                    duration_ms: t0.elapsed().as_millis() as u64,
                });
            }
        } else {
            checks.push(DoctorCheckResult {
                id: "server_reachability".into(),
                category: "Сетевые проверки".into(),
                title: "TCP-доступность выбранного VPN-узла".into(),
                severity: DoctorCheckSeverity::Skipped,
                summary: "Сервер не выбран".into(),
                detail: "Выберите активный узел.".into(),
                recommended_action: None,
                duration_ms: 0,
            });
        }

        // Active tunnel & base internet probe
        if is_conn {
            let t0 = Instant::now();
            let port = if snap.mode == ConnectionMode::SystemProxy {
                snap.local_http_port.or(Some(settings.http_port))
            } else {
                None
            };
            match CoreManager::probe_proxy_tunnel_public(port, Duration::from_secs(6)).await {
                Ok((rtt, url)) => {
                    checks.push(DoctorCheckResult {
                        id: "internet_reachability".into(),
                        category: "Сетевые проверки".into(),
                        title: "Доступность внешнего интернета".into(),
                        severity: DoctorCheckSeverity::Pass,
                        summary: "Интернет доступен через активное соединение".into(),
                        detail: format!("Подтверждён HTTPS 204 ответ ({url})"),
                        recommended_action: None,
                        duration_ms: rtt,
                    });
                    checks.push(DoctorCheckResult {
                        id: "active_tunnel_probe".into(),
                        category: "Сетевые проверки".into(),
                        title: "Подтверждение трафика через VPN-туннель".into(),
                        severity: DoctorCheckSeverity::Pass,
                        summary: format!("HTTPS RTT {rtt} мс"),
                        detail: format!("Трафик подтверждён через {url}."),
                        recommended_action: None,
                        duration_ms: t0.elapsed().as_millis() as u64,
                    });
                }
                Err(err) => {
                    checks.push(DoctorCheckResult {
                        id: "internet_reachability".into(),
                        category: "Сетевые проверки".into(),
                        title: "Доступность внешнего интернета".into(),
                        severity: DoctorCheckSeverity::Warn,
                        summary: "Через туннель нет ответа".into(),
                        detail: err.clone(),
                        recommended_action: None,
                        duration_ms: t0.elapsed().as_millis() as u64,
                    });
                    checks.push(DoctorCheckResult {
                        id: "active_tunnel_probe".into(),
                        category: "Сетевые проверки".into(),
                        title: "Подтверждение трафика через VPN-туннель".into(),
                        severity: DoctorCheckSeverity::Fail,
                        summary: "Не удалось подтвердить выход через туннель".into(),
                        detail: err,
                        recommended_action: Some(
                            "Откройте Инспектор подключения и Логи ядра или смените сервер.".into(),
                        ),
                        duration_ms: t0.elapsed().as_millis() as u64,
                    });
                }
            }
        } else {
            let t0 = Instant::now();
            match CoreManager::probe_proxy_tunnel_public(None, Duration::from_secs(5)).await {
                Ok((rtt, url)) => {
                    checks.push(DoctorCheckResult {
                        id: "internet_reachability".into(),
                        category: "Сетевые проверки".into(),
                        title: "Доступность базового интернета (без VPN)".into(),
                        severity: DoctorCheckSeverity::Pass,
                        summary: format!("Доступ подтверждён ({rtt} мс)"),
                        detail: format!("Прямой HTTPS 204 ({url}) успешен."),
                        recommended_action: None,
                        duration_ms: t0.elapsed().as_millis() as u64,
                    });
                }
                Err(err) => {
                    checks.push(DoctorCheckResult {
                        id: "internet_reachability".into(),
                        category: "Сетевые проверки".into(),
                        title: "Доступность базового интернета (без VPN)".into(),
                        severity: DoctorCheckSeverity::Fail,
                        summary: "Базовый интернет не отвечает".into(),
                        detail: err,
                        recommended_action: Some("Проверьте физическое подключение или выполните Экстренное восстановление сети.".into()),
                        duration_ms: t0.elapsed().as_millis() as u64,
                    });
                }
            }
            checks.push(DoctorCheckResult {
                id: "active_tunnel_probe".into(),
                category: "Сетевые проверки".into(),
                title: "Подтверждение трафика через VPN-туннель".into(),
                severity: DoctorCheckSeverity::Skipped,
                summary: "Туннель не запущен".into(),
                detail: "Подключитесь к серверу для проверки прохождения трафика через VPN.".into(),
                recommended_action: None,
                duration_ms: 0,
            });
        }
    }

    let pass_count = checks
        .iter()
        .filter(|c| c.severity == DoctorCheckSeverity::Pass)
        .count();
    let warn_count = checks
        .iter()
        .filter(|c| c.severity == DoctorCheckSeverity::Warn)
        .count();
    let fail_count = checks
        .iter()
        .filter(|c| c.severity == DoctorCheckSeverity::Fail)
        .count();
    let overall_status = if fail_count > 0 {
        DoctorCheckSeverity::Fail
    } else if warn_count > 0 {
        DoctorCheckSeverity::Warn
    } else {
        DoctorCheckSeverity::Pass
    };

    NetworkDoctorReport {
        checked_at: Utc::now().to_rfc3339(),
        overall_status,
        pass_count,
        warn_count,
        fail_count,
        checks,
    }
}
