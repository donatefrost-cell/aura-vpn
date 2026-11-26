use crate::ip_monitor::StoredIpMonitor;
use crate::models::{AppSettings, PrivacyInventory, PrivacyNetworkDisclosure, Subscription};
use crate::storage::AppStorage;

fn mask_hwid_value(raw: Option<&str>) -> Option<String> {
    let val = raw?.trim();
    if val.len() <= 8 {
        return Some("••••••••".into());
    }
    let start: String = val.chars().take(4).collect();
    let end: String = val
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    Some(format!("{start}••••{end}"))
}

pub fn build_privacy_inventory(
    storage: &AppStorage,
    settings: &AppSettings,
    subs: &[Subscription],
    ip_mon: &StoredIpMonitor,
    logs_count: usize,
) -> PrivacyInventory {
    let base = storage.base_dir();
    let mut dpapi_encrypted_files = Vec::new();
    let mut plaintext_files = Vec::new();

    for name in [
        "profiles.json",
        "subscriptions.json",
        "history.json",
        "ip-monitor.json",
    ] {
        if base.join(name).exists() {
            if storage.is_plaintext_legacy(name) {
                plaintext_files.push(format!(
                    "{name} (устаревший формат — мигрируется при сохранении)"
                ));
            } else {
                dpapi_encrypted_files.push(name.to_string());
            }
        }
    }
    for name in ["settings.json", "server-quality.json", "window-state.json"] {
        if base.join(name).exists() {
            plaintext_files.push(format!(
                "{name} (локальные UI/сетевые параметры без ключей)"
            ));
        }
    }
    plaintext_files.push(
        "WebView2 localStorage (уведомления, метаданные задержек и профили поведения без VPN-ключей; очищается в Центре приватности)"
            .to_string(),
    );

    let sub_backups_count = storage.count_subscription_backups();
    let sync_history_count: usize = subs.iter().map(|s| s.sync_history.len()).sum();
    let history_entries_count = storage.load_history().len();

    let external_network_features = vec![
        PrivacyNetworkDisclosure {
            id: "vpn_tunnel".into(),
            title: "VPN-туннель к выбранному серверу".into(),
            enabled: true,
            trigger: "Только при нажатии «Подключить» (или автоподключении)".into(),
            destination: "Адрес вашего активного VPN-узла".into(),
            data_sent: "Зашифрованный туннельный трафик".into(),
        },
        PrivacyNetworkDisclosure {
            id: "ip_monitor".into(),
            title: "Монитор внешнего IP (Мой IP 2.0)".into(),
            enabled: settings.auto_check_ip_interval_secs > 0,
            trigger: "По умолчанию только вручную (opt-in)".into(),
            destination: format!("{:?} / api.ipify.org", settings.preferred_ip_provider),
            data_sent: "Стандартный HTTPS-запрос (отправка/получение публичного IP без ключей)"
                .into(),
        },
        PrivacyNetworkDisclosure {
            id: "sub_hwid".into(),
            title: "Загрузка подписок и заголовок HWID".into(),
            enabled: settings.send_hwid,
            trigger: "При добавлении/обновлении подписки по HTTPS".into(),
            destination: "Домены добавленных вами подписок".into(),
            data_sent: if settings.send_hwid {
                "Заголовки x-hwid / x-device-os / x-device-model (только на исходный HTTPS-домен подписки)".into()
            } else {
                "Только HTTP User-Agent без идентификатора устройства".into()
            },
        },
        PrivacyNetworkDisclosure {
            id: "health_probe".into(),
            title: "Проверка жизнеспособности туннеля (HTTPS 204)".into(),
            enabled: settings.advanced.health_check_enabled,
            trigger: "При подключении и периодическом контроле стабильности".into(),
            destination: "cp.cloudflare.com / www.gstatic.com/generate_204 через VPN".into(),
            data_sent: "Минимальный запрос без cookies и пользовательских данных".into(),
        },
        PrivacyNetworkDisclosure {
            id: "updates".into(),
            title: "Проверка обновлений клиента / базы правил / ядра".into(),
            enabled: settings.auto_check_updates,
            trigger: "Вручную или при включённой автопроверке".into(),
            destination: "GitHub Releases API или настроенный HTTPS URL".into(),
            data_sent: "Только версия клиента без телеметрии".into(),
        },
    ];

    PrivacyInventory {
        config_dir: base.to_string_lossy().to_string(),
        dpapi_encrypted_files,
        plaintext_files,
        history_entries_count,
        saved_original_ip_present: ip_mon.original_ip.is_some(),
        saved_vpn_ip_present: ip_mon.vpn_ip.is_some(),
        logs_count,
        sub_backups_count,
        sync_history_count,
        send_hwid: settings.send_hwid,
        hwid_masked: mask_hwid_value(settings.device_hwid.as_deref()),
        external_network_features,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_hwid_preserving_only_ends() {
        assert_eq!(
            mask_hwid_value(Some("abcdef0123456789")),
            Some("abcd••••6789".to_string())
        );
        assert_eq!(mask_hwid_value(Some("short")), Some("••••••••".to_string()));
    }
}
