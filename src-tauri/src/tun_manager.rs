use crate::elevation::is_elevated;
use crate::models::{
    CoreDiagnostics, TunAdapterStatus, TunManagerSnapshot, TunSettings, VirtualAdapterConflict,
};
use chrono::Utc;
use serde::Deserialize;
use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PsNetAdapter {
    name: Option<String>,
    interface_description: Option<String>,
    status: Option<String>,
    interface_index: Option<u32>,
    nl_mtu: Option<u32>,
    ip_addresses: Option<Vec<String>>,
    dns_servers: Option<Vec<String>>,
}

fn powershell_exe_path() -> String {
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    format!("{sys_root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
}

/// Strictly read-only inspection of Windows virtual network adapters and TUN state.
/// Never creates, disables, or modifies any Windows network adapter or route.
fn inspect_windows_adapters_readonly(_tun_name: &str) -> Vec<PsNetAdapter> {
    let script = "$ProgressPreference='SilentlyContinue'; \
        $a = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | ForEach-Object { \
          $idx = $_.ifIndex; \
          $ips = @(Get-NetIPAddress -InterfaceIndex $idx -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress); \
          $dns = @(Get-DnsClientServerAddress -InterfaceIndex $idx -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses | Select-Object -Unique); \
          $mtu = (Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty NlMtuBytes); \
          [PSCustomObject]@{ Name=$_.Name; InterfaceDescription=$_.InterfaceDescription; Status=$_.Status.ToString(); InterfaceIndex=[int]$idx; NlMtu=[int]$mtu; IpAddresses=$ips; DnsServers=$dns } \
        }; \
        ConvertTo-Json -InputObject @($a) -Depth 3 -Compress";

    let out = Command::new(powershell_exe_path())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let Ok(out) = out else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        return Vec::new();
    }
    if let Ok(list) = serde_json::from_str::<Vec<PsNetAdapter>>(&text) {
        return list;
    }
    if let Ok(one) = serde_json::from_str::<PsNetAdapter>(&text) {
        return vec![one];
    }
    Vec::new()
}

pub fn classify_virtual_adapter(
    name: &str,
    desc: &str,
    own_tun_name: &str,
) -> Option<(&'static str, &'static str, &'static str)> {
    let n = name.to_ascii_lowercase();
    let d = desc.to_ascii_lowercase();
    if n == own_tun_name.to_ascii_lowercase() {
        return None;
    }
    if d.contains("wintun")
        || d.contains("wireguard")
        || n.contains("amnezia")
        || d.contains("amnezia")
    {
        Some((
            "WireGuard / Wintun",
            "warn",
            "Обнаружен другой Wintun/WireGuard-адаптер. Одновременная работа двух TUN-VPN может вызывать конфликт маршрута 0.0.0.0/0.",
        ))
    } else if d.contains("tap-windows") || d.contains("openvpn") || d.contains("wintap") {
        Some((
            "OpenVPN / TAP",
            "warn",
            "Обнаружен адаптер OpenVPN/TAP. Перед включением AURA TUN убедитесь, что сторонний VPN отключён.",
        ))
    } else if d.contains("hyper-v") || n.contains("vethernet") {
        Some((
            "Hyper-V",
            "info",
            "Виртуальный коммутатор Hyper-V: обычно не мешает TUN, но может резервировать диапазоны локальных портов.",
        ))
    } else if n.contains("wsl") || d.contains("wsl") {
        Some((
            "WSL",
            "info",
            "Адаптер WSL2 присутствует; при strictRoute DNS внутри WSL может требовать перезапуска WSL после запуска TUN.",
        ))
    } else if n.contains("docker") || d.contains("docker") {
        Some((
            "Docker",
            "info",
            "Виртуальный интерфейс Docker Desktop (подсети 172.17+ обычно не пересекаются с AURA TUN 10.24.0.0/24).",
        ))
    } else if d.contains("virtual")
        || d.contains("vmware")
        || d.contains("virtualbox")
        || d.contains("tailscale")
        || d.contains("zerotier")
        || d.contains("sing-box")
        || d.contains("clash")
        || d.contains("nekobox")
    {
        Some((
            "Сторонний виртуальный адаптер",
            "warn",
            "Виртуальный сетевой интерфейс активен или установлен в системе — при совпадении маршрутов возможен конфликт.",
        ))
    } else {
        None
    }
}

pub fn collect_tun_snapshot(
    tun_settings: &TunSettings,
    diag: &CoreDiagnostics,
) -> TunManagerSnapshot {
    let adapters = inspect_windows_adapters_readonly(&tun_settings.adapter_name);
    let own = adapters.iter().find(|a| {
        a.name
            .as_deref()
            .is_some_and(|n| n.eq_ignore_ascii_case(&tun_settings.adapter_name))
    });

    let elevated = is_elevated();
    let driver_status = if !diag.wintun_available {
        "wintun.dll не найден".into()
    } else if !diag.wintun_integrity_ok {
        "Ошибка проверки SHA-256 wintun.dll".into()
    } else if elevated {
        "Драйвер готов и проверен (права администратора активны)".into()
    } else {
        "Драйвер проверен SHA-256 (для запуска TUN нужны права администратора)".into()
    };

    let (
        adapter_present,
        interface_index,
        status,
        mtu,
        ipv4_addresses,
        ipv6_addresses,
        dns_servers,
    ) = if let Some(a) = own {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for ip in a.ip_addresses.clone().unwrap_or_default() {
            if ip.contains(':') {
                v6.push(ip);
            } else {
                v4.push(ip);
            }
        }
        (
            true,
            a.interface_index,
            a.status.clone().unwrap_or_else(|| "Unknown".into()),
            a.nl_mtu,
            v4,
            v6,
            a.dns_servers.clone().unwrap_or_default(),
        )
    } else {
        (
            false,
            None,
            "Ожидает запуска TUN".into(),
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    };

    let mut conflicts = Vec::new();
    for a in &adapters {
        let name = a.name.clone().unwrap_or_default();
        let desc = a.interface_description.clone().unwrap_or_default();
        let st = a.status.clone().unwrap_or_else(|| "Unknown".into());
        if let Some((category, base_sev, detail)) =
            classify_virtual_adapter(&name, &desc, &tun_settings.adapter_name)
        {
            let active = st.eq_ignore_ascii_case("Up");
            let severity = if active && base_sev == "warn" {
                "warn".to_string()
            } else {
                "info".to_string()
            };
            conflicts.push(VirtualAdapterConflict {
                adapter_name: name,
                interface_description: desc,
                category: category.to_string(),
                status: st,
                severity,
                detail: detail.to_string(),
            });
        }
    }

    TunManagerSnapshot {
        checked_at: Utc::now().to_rfc3339(),
        settings: tun_settings.clone(),
        adapter: TunAdapterStatus {
            adapter_present,
            adapter_name: tun_settings.adapter_name.clone(),
            interface_index,
            status,
            mtu,
            ipv4_addresses,
            ipv6_addresses,
            dns_servers,
            wintun_version: Some("0.14.1".into()),
            wintun_present: diag.wintun_available,
            wintun_integrity_ok: diag.wintun_integrity_ok,
            driver_status,
            is_elevated: elevated,
        },
        conflicts,
    }
}
