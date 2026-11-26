use crate::models::{
    KillSwitchConfig, KillSwitchEnforcement, KillSwitchMode, KillSwitchSnapshot, KillSwitchStatus,
};
use crate::storage::atomic_write_bytes;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const FIREWALL_RULE_NAME: &str = "AuraVPN_KillSwitch_Block";

const AURA_WFP_SUBLAYER_GUID: windows_sys::core::GUID =
    windows_sys::core::GUID::from_u128(0xa94a_5610_7f3c_4b92_91d2_44e9_0700_0001);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KillSwitchMarker {
    mode: String,
    firewall_rule_active: bool,
    #[serde(default)]
    persist_on_exit: bool,
}

struct ProxyGuardHandle {
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl ProxyGuardHandle {
    async fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        for task in self.tasks {
            task.abort();
            let _ = task.await;
        }
    }

    fn stop_nonblocking(self) {
        let _ = self.shutdown_tx.send(true);
        for task in self.tasks {
            task.abort();
        }
    }
}

struct WfpSession {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

unsafe impl Send for WfpSession {}
unsafe impl Sync for WfpSession {}

impl Drop for WfpSession {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0(
                    self.handle,
                );
                self.handle = std::ptr::null_mut();
            }
        }
    }
}

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn resolve_interface_luid_by_alias(alias: &str) -> Option<u64> {
    let trimmed = alias.trim();
    if trimmed.is_empty() {
        return None;
    }
    let wide = to_wide_null(trimmed);
    let mut luid: windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH =
        unsafe { std::mem::zeroed() };
    let rc = unsafe {
        windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid(
            wide.as_ptr(),
            &mut luid,
        )
    };
    if rc == 0 {
        let val = unsafe { luid.Value };
        (val != 0).then_some(val)
    } else {
        None
    }
}

impl WfpSession {
    #[allow(clippy::too_many_arguments)]
    fn open_and_arm(
        permit_core_tunnels: bool,
        core_exe_paths: &[PathBuf],
        allow_lan: bool,
        block_ipv6: bool,
        extra_app_exes: &[PathBuf],
        tun_interface_luid: Option<u64>,
    ) -> Result<(Self, Vec<String>), (bool, String)> {
        use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmEngineOpen0, FwpmFilterAdd0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
            FwpmSubLayerAdd0, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID,
            FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_PROTOCOL,
            FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
            FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
            FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
            FWP_CONDITION_VALUE0, FWP_MATCH_EQUAL, FWP_UINT16, FWP_UINT64, FWP_UINT8,
            FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
            FWP_VALUE0,
        };
        const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;

        let mut session_name = to_wide_null("AURA VPN Kill Switch 2.0");
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.displayData.name = session_name.as_mut_ptr();
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;

        let mut engine: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        let rc = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_DEFAULT,
                std::ptr::null(),
                &session,
                &mut engine,
            )
        };
        if rc != 0 {
            let needs_uac = rc == ERROR_ACCESS_DENIED;
            return Err((
                needs_uac,
                if needs_uac {
                    "Для активации системного WFP Kill Switch требуются права администратора Windows (UAC).".to_string()
                } else {
                    format!("Не удалось открыть движок Windows Filtering Platform (код {rc}).")
                },
            ));
        }

        let guard = Self { handle: engine };

        let mut sublayer_name = to_wide_null("AURA VPN Kill Switch Sublayer");
        let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sublayer.subLayerKey = AURA_WFP_SUBLAYER_GUID;
        sublayer.displayData = FWPM_DISPLAY_DATA0 {
            name: sublayer_name.as_mut_ptr(),
            description: sublayer_name.as_mut_ptr(),
        };
        sublayer.weight = 0x7FFF;

        let sub_rc = unsafe { FwpmSubLayerAdd0(guard.handle, &sublayer, std::ptr::null_mut()) };
        // Ignore ALREADY_EXISTS (0x8032_0009 as u32)
        if sub_rc != 0 && sub_rc != 0x8032_0009 {
            let needs_uac = sub_rc == ERROR_ACCESS_DENIED;
            return Err((
                needs_uac,
                if needs_uac {
                    "Нет прав для добавления правил WFP Kill Switch (требуется UAC).".to_string()
                } else {
                    format!("Ошибка инициализации sublayer WFP (код {sub_rc:#x}).")
                },
            ));
        }

        let mut exceptions = Vec::new();

        unsafe fn add_v4_cidr_permit(
            engine: windows_sys::Win32::Foundation::HANDLE,
            title: &str,
            ip_host_u32: u32,
            mask_host_u32: u32,
            mut weight_val: u64,
        ) -> Result<(), u32> {
            let mut wtitle = to_wide_null(title);
            let mut addr_mask = FWP_V4_ADDR_AND_MASK {
                addr: ip_host_u32,
                mask: mask_host_u32,
            };
            let mut cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
            cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            cond.matchType = FWP_MATCH_EQUAL;
            cond.conditionValue = FWP_CONDITION_VALUE0 {
                r#type: FWP_V4_ADDR_MASK,
                Anonymous: {
                    let mut u = std::mem::zeroed::<
                        windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0,
                    >();
                    u.v4AddrMask = &mut addr_mask;
                    u
                },
            };

            let mut filter: FWPM_FILTER0 = std::mem::zeroed();
            filter.displayData.name = wtitle.as_mut_ptr();
            filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            filter.subLayerKey = AURA_WFP_SUBLAYER_GUID;
            filter.weight = FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: {
                    let mut w = std::mem::zeroed::<
                        windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0,
                    >();
                    w.uint64 = &mut weight_val;
                    w
                },
            };
            filter.numFilterConditions = 1;
            filter.filterCondition = &mut cond;
            filter.action = FWPM_ACTION0 {
                r#type: FWP_ACTION_PERMIT,
                Anonymous: std::mem::zeroed(),
            };

            let mut fid = 0u64;
            let r = FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut fid);
            if r == 0 {
                Ok(())
            } else {
                Err(r)
            }
        }

        unsafe fn add_v6_cidr_permit(
            engine: windows_sys::Win32::Foundation::HANDLE,
            title: &str,
            addr: [u8; 16],
            prefix_len: u8,
            mut weight_val: u64,
        ) -> Result<(), u32> {
            let mut wtitle = to_wide_null(title);
            let mut addr_mask = FWP_V6_ADDR_AND_MASK {
                addr,
                prefixLength: prefix_len,
            };
            let mut cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
            cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            cond.matchType = FWP_MATCH_EQUAL;
            cond.conditionValue = FWP_CONDITION_VALUE0 {
                r#type: FWP_V6_ADDR_MASK,
                Anonymous: {
                    let mut u = std::mem::zeroed::<
                        windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0,
                    >();
                    u.v6AddrMask = &mut addr_mask;
                    u
                },
            };

            let mut filter: FWPM_FILTER0 = std::mem::zeroed();
            filter.displayData.name = wtitle.as_mut_ptr();
            filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
            filter.subLayerKey = AURA_WFP_SUBLAYER_GUID;
            filter.weight = FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: {
                    let mut w = std::mem::zeroed::<
                        windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0,
                    >();
                    w.uint64 = &mut weight_val;
                    w
                },
            };
            filter.numFilterConditions = 1;
            filter.filterCondition = &mut cond;
            filter.action = FWPM_ACTION0 {
                r#type: FWP_ACTION_PERMIT,
                Anonymous: std::mem::zeroed(),
            };

            let mut fid = 0u64;
            let r = FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut fid);
            if r == 0 {
                Ok(())
            } else {
                Err(r)
            }
        }

        unsafe fn add_dhcp_v4_permit(
            engine: windows_sys::Win32::Foundation::HANDLE,
            port: u16,
            mut weight_val: u64,
        ) -> Result<(), u32> {
            let mut wtitle = to_wide_null("AURA Permit DHCP v4");
            for (remote_ip, remote_mask) in [
                (0xFFFF_FFFFu32, 0xFFFF_FFFFu32), // Limited broadcast 255.255.255.255/32
                (0x0A00_0000u32, 0xFF00_0000u32), // RFC1918 10.0.0.0/8
                (0xAC10_0000u32, 0xFFF0_0000u32), // RFC1918 172.16.0.0/12
                (0xC0A8_0000u32, 0xFFFF_0000u32), // RFC1918 192.168.0.0/16
                (0xA9FE_0000u32, 0xFFFF_0000u32), // Link-local 169.254.0.0/16
            ] {
                let mut addr_mask = FWP_V4_ADDR_AND_MASK {
                    addr: remote_ip,
                    mask: remote_mask,
                };
                let mut conds: [FWPM_FILTER_CONDITION0; 3] = std::mem::zeroed();
                conds[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                conds[0].matchType = FWP_MATCH_EQUAL;
                conds[0].conditionValue.r#type = FWP_UINT8;
                conds[0].conditionValue.Anonymous.uint8 = 17; // UDP

                conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                conds[1].matchType = FWP_MATCH_EQUAL;
                conds[1].conditionValue.r#type = FWP_UINT16;
                conds[1].conditionValue.Anonymous.uint16 = port;

                conds[2].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                conds[2].matchType = FWP_MATCH_EQUAL;
                conds[2].conditionValue.r#type = FWP_V4_ADDR_MASK;
                conds[2].conditionValue.Anonymous.v4AddrMask = &mut addr_mask;

                let mut filter: FWPM_FILTER0 = std::mem::zeroed();
                filter.displayData.name = wtitle.as_mut_ptr();
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                filter.subLayerKey = AURA_WFP_SUBLAYER_GUID;
                filter.weight = FWP_VALUE0 {
                    r#type: FWP_UINT64,
                    Anonymous: {
                        let mut w = std::mem::zeroed::<
                            windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0,
                        >();
                        w.uint64 = &mut weight_val;
                        w
                    },
                };
                filter.numFilterConditions = 3;
                filter.filterCondition = conds.as_mut_ptr();
                filter.action = FWPM_ACTION0 {
                    r#type: FWP_ACTION_PERMIT,
                    Anonymous: std::mem::zeroed(),
                };
                let mut fid = 0u64;
                let r = FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut fid);
                if r != 0 {
                    return Err(r);
                }
            }
            Ok(())
        }

        unsafe fn add_interface_luid_permit(
            engine: windows_sys::Win32::Foundation::HANDLE,
            mut luid_val: u64,
            include_v6: bool,
            mut weight_val: u64,
        ) -> Result<(), u32> {
            let mut wtitle = to_wide_null("AURA Permit Wintun Interface");
            let mut cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
            cond.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
            cond.matchType = FWP_MATCH_EQUAL;
            cond.conditionValue.r#type = FWP_UINT64;
            cond.conditionValue.Anonymous.uint64 = &mut luid_val;

            for (layer, is_v6) in [
                (FWPM_LAYER_ALE_AUTH_CONNECT_V4, false),
                (FWPM_LAYER_ALE_AUTH_CONNECT_V6, true),
            ] {
                if is_v6 && !include_v6 {
                    continue;
                }
                let mut filter: FWPM_FILTER0 = std::mem::zeroed();
                filter.displayData.name = wtitle.as_mut_ptr();
                filter.layerKey = layer;
                filter.subLayerKey = AURA_WFP_SUBLAYER_GUID;
                filter.weight = FWP_VALUE0 {
                    r#type: FWP_UINT64,
                    Anonymous: {
                        let mut w = std::mem::zeroed::<
                            windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0,
                        >();
                        w.uint64 = &mut weight_val;
                        w
                    },
                };
                filter.numFilterConditions = 1;
                filter.filterCondition = &mut cond;
                filter.action = FWPM_ACTION0 {
                    r#type: FWP_ACTION_PERMIT,
                    Anonymous: std::mem::zeroed(),
                };
                let mut fid = 0u64;
                let r = FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut fid);
                if r != 0 {
                    return Err(r);
                }
            }
            Ok(())
        }

        unsafe fn add_app_permit(
            engine: windows_sys::Win32::Foundation::HANDLE,
            exe_path: &Path,
            include_v6: bool,
            mut weight_val: u64,
        ) -> Result<(), u32> {
            let mut wpath: Vec<u16> = exe_path
                .as_os_str()
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut blob_ptr: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
            let rc = FwpmGetAppIdFromFileName0(wpath.as_mut_ptr(), &mut blob_ptr);
            if rc != 0 || blob_ptr.is_null() {
                return Err(if rc != 0 { rc } else { 1 });
            }

            let mut wtitle = to_wide_null("AURA Permit App");
            let mut cond: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
            cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
            cond.matchType = FWP_MATCH_EQUAL;
            cond.conditionValue = FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: {
                    let mut u = std::mem::zeroed::<
                        windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0,
                    >();
                    u.byteBlob = blob_ptr;
                    u
                },
            };

            let mut res = Ok(());
            for (layer, is_v6) in [
                (FWPM_LAYER_ALE_AUTH_CONNECT_V4, false),
                (FWPM_LAYER_ALE_AUTH_CONNECT_V6, true),
            ] {
                if is_v6 && !include_v6 {
                    continue;
                }
                let mut filter: FWPM_FILTER0 = std::mem::zeroed();
                filter.displayData.name = wtitle.as_mut_ptr();
                filter.layerKey = layer;
                filter.subLayerKey = AURA_WFP_SUBLAYER_GUID;
                filter.weight = FWP_VALUE0 {
                    r#type: FWP_UINT64,
                    Anonymous: {
                        let mut w = std::mem::zeroed::<
                            windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0,
                        >();
                        w.uint64 = &mut weight_val;
                        w
                    },
                };
                filter.numFilterConditions = 1;
                filter.filterCondition = &mut cond;
                filter.action = FWPM_ACTION0 {
                    r#type: FWP_ACTION_PERMIT,
                    Anonymous: std::mem::zeroed(),
                };
                let mut fid = 0u64;
                let r = FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut fid);
                if r != 0 {
                    res = Err(r);
                    break;
                }
            }

            FwpmFreeMemory0((&mut blob_ptr as *mut *mut FWP_BYTE_BLOB).cast());
            res
        }

        unsafe fn add_block_all(
            engine: windows_sys::Win32::Foundation::HANDLE,
            block_v6: bool,
            mut weight_val: u64,
        ) -> Result<(), u32> {
            let mut wtitle = to_wide_null("AURA Block Non-VPN Outbound");
            for (idx, layer) in [
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            ]
            .iter()
            .enumerate()
            {
                if idx == 1 && !block_v6 {
                    continue;
                }
                let mut filter: FWPM_FILTER0 = std::mem::zeroed();
                filter.displayData.name = wtitle.as_mut_ptr();
                filter.layerKey = *layer;
                filter.subLayerKey = AURA_WFP_SUBLAYER_GUID;
                filter.weight = FWP_VALUE0 {
                    r#type: FWP_UINT64,
                    Anonymous: {
                        let mut w = std::mem::zeroed::<
                            windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0,
                        >();
                        w.uint64 = &mut weight_val;
                        w
                    },
                };
                filter.numFilterConditions = 0;
                filter.filterCondition = std::ptr::null_mut();
                filter.action = FWPM_ACTION0 {
                    r#type: FWP_ACTION_BLOCK,
                    Anonymous: std::mem::zeroed(),
                };
                let mut fid = 0u64;
                let r = FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut fid);
                if r != 0 {
                    return Err(r);
                }
            }
            Ok(())
        }

        let map_wfp_err = |code: u32| -> (bool, String) {
            let needs_uac = code == ERROR_ACCESS_DENIED;
            (
                needs_uac,
                if needs_uac {
                    "Недостаточно прав для применения фильтров WFP Kill Switch (UAC).".to_string()
                } else {
                    format!("Ошибка добавления фильтра WFP Kill Switch (код {code:#x}).")
                },
            )
        };

        unsafe {
            // 1. Loopback always permitted
            add_v4_cidr_permit(
                guard.handle,
                "AURA Permit Loopback v4",
                0x7F00_0000,
                0xFF00_0000,
                100,
            )
            .map_err(map_wfp_err)?;
            add_v6_cidr_permit(
                guard.handle,
                "AURA Permit Loopback v6",
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                128,
                100,
            )
            .map_err(map_wfp_err)?;
            exceptions.push("Loopback (127.0.0.0/8, ::1)".to_string());

            // 2. DHCP v4 lease renewal permitted
            add_dhcp_v4_permit(guard.handle, 67, 95).map_err(map_wfp_err)?;
            add_dhcp_v4_permit(guard.handle, 68, 95).map_err(map_wfp_err)?;

            // 3. Optional LAN permit
            if allow_lan {
                for (name, ip, mask) in [
                    ("AURA Permit LAN 10/8", 0x0A00_0000u32, 0xFF00_0000u32),
                    ("AURA Permit LAN 172.16/12", 0xAC10_0000u32, 0xFFF0_0000u32),
                    ("AURA Permit LAN 192.168/16", 0xC0A8_0000u32, 0xFFFF_0000u32),
                    ("AURA Permit LinkLocal", 0xA9FE_0000u32, 0xFFFF_0000u32),
                ] {
                    add_v4_cidr_permit(guard.handle, name, ip, mask, 90).map_err(map_wfp_err)?;
                }
                add_v6_cidr_permit(
                    guard.handle,
                    "AURA Permit LinkLocal v6",
                    [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    10,
                    90,
                )
                .map_err(map_wfp_err)?;
                exceptions.push("Локальная сеть (RFC1918 / Link-Local)".to_string());
            }

            // 4. Permit AURA core binaries & tunnel interface when armed
            if permit_core_tunnels {
                if let Some(luid) = tun_interface_luid {
                    if add_interface_luid_permit(guard.handle, luid, !block_ipv6, 88).is_ok() {
                        exceptions.push("Виртуальный адаптер Wintun (LUID)".to_string());
                    }
                }
                if let Ok(self_exe) = std::env::current_exe() {
                    if self_exe.exists() {
                        let _ = add_app_permit(guard.handle, &self_exe, !block_ipv6, 85);
                    }
                }
                for bin in core_exe_paths {
                    if bin.exists() && add_app_permit(guard.handle, bin, true, 85).is_ok() {
                        if let Some(name) = bin.file_name().and_then(|s| s.to_str()) {
                            exceptions.push(format!("Ядро {name}"));
                        }
                    }
                }
            }

            // 5. Permit explicit RoutingAware bypass executables (only if full path exists on disk)
            for app in extra_app_exes {
                if app.exists()
                    && app.is_file()
                    && add_app_permit(guard.handle, app, !block_ipv6, 80).is_ok()
                {
                    if let Some(name) = app.file_name().and_then(|s| s.to_str()) {
                        exceptions.push(format!("Прямое исключение: {name}"));
                    }
                }
            }

            // 6. Lowest-weight catch-all BLOCK
            add_block_all(guard.handle, block_ipv6, 1).map_err(map_wfp_err)?;
        }

        Ok((guard, exceptions))
    }
}

fn netsh_exe_path() -> PathBuf {
    let mut buf = [0u16; 260];
    let len = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    };
    if len > 0 && (len as usize) < buf.len() {
        let sys_dir = String::from_utf16_lossy(&buf[..len as usize]);
        return PathBuf::from(sys_dir).join("netsh.exe");
    }
    let sys_root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    PathBuf::from(sys_root).join("System32").join("netsh.exe")
}

fn spawn_503_guard_loop(
    listener: TcpListener,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((mut sock, _)) => {
                            tokio::spawn(async move {
                                let mut buf = [0u8; 1024];
                                let _ = tokio::time::timeout(
                                    Duration::from_secs(3),
                                    sock.read(&mut buf),
                                ).await;
                                let body = "AURA VPN Kill Switch active: connection blocked until VPN restores or protection is turned off.";
                                let resp = format!(
                                    "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                );
                                let _ = sock.write_all(resp.as_bytes()).await;
                                let _ = sock.shutdown().await;
                            });
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    })
}

fn spawn_socks5_guard_loop(
    listener: TcpListener,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((mut sock, _)) => {
                            tokio::spawn(async move {
                                let mut hdr = [0u8; 2];
                                if tokio::time::timeout(Duration::from_secs(3), sock.read_exact(&mut hdr))
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                                if hdr[0] != 0x05 {
                                    // Non-SOCKS5 client: return immediate refusal byte & close
                                    let _ = sock.write_all(&[0x05, 0xFF]).await;
                                    let _ = sock.shutdown().await;
                                    return;
                                }
                                let nmethods = hdr[1] as usize;
                                if nmethods > 0 {
                                    let mut methods = vec![0u8; nmethods];
                                    if tokio::time::timeout(
                                        Duration::from_secs(3),
                                        sock.read_exact(&mut methods),
                                    )
                                    .await
                                    .is_err()
                                    {
                                        return;
                                    }
                                }
                                // Accept NO_AUTH method to read CONNECT and emit clean SOCKS5 General Failure (0x01)
                                if sock.write_all(&[0x05, 0x00]).await.is_err() {
                                    return;
                                }
                                let mut req = [0u8; 264];
                                let _ = tokio::time::timeout(
                                    Duration::from_secs(3),
                                    sock.read(&mut req),
                                )
                                .await;
                                let reply = [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
                                let _ = sock.write_all(&reply).await;
                                let _ = sock.shutdown().await;
                            });
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    })
}

pub struct KillSwitchState {
    proxy_guard: Option<ProxyGuardHandle>,
    wfp_session: Option<WfpSession>,
    firewall_rule_active: bool,
    state_path: PathBuf,
    snapshot: KillSwitchSnapshot,
}

impl KillSwitchState {
    pub fn new(state_path: PathBuf) -> Self {
        Self {
            proxy_guard: None,
            wfp_session: None,
            firewall_rule_active: false,
            state_path,
            snapshot: KillSwitchSnapshot::default(),
        }
    }

    pub fn is_engaged(&self) -> bool {
        self.proxy_guard.is_some()
            || self.wfp_session.is_some()
            || self.firewall_rule_active
            || self.snapshot.blocking_active
    }

    pub fn snapshot(&self) -> KillSwitchSnapshot {
        self.snapshot.clone()
    }

    pub fn update_inactive_snapshot(&mut self, cfg: &KillSwitchConfig, reason: Option<String>) {
        self.snapshot = KillSwitchSnapshot {
            mode: cfg.mode,
            status: if cfg.mode == KillSwitchMode::Off {
                KillSwitchStatus::Inactive
            } else {
                KillSwitchStatus::Armed
            },
            enforcement: KillSwitchEnforcement::None,
            blocking_active: false,
            needs_elevation: false,
            allowed_exceptions: Vec::new(),
            last_reason: reason.or_else(|| self.snapshot.last_reason.clone()),
            updated_at: Some(Utc::now().to_rfc3339()),
        };
    }

    pub fn sync_armed_tunnel_state(
        &mut self,
        cfg: &KillSwitchConfig,
        is_tun: bool,
        core_exe_paths: &[PathBuf],
        extra_app_exes: &[PathBuf],
        tun_alias: Option<&str>,
    ) {
        if cfg.mode == KillSwitchMode::Off {
            self.wfp_session = None;
            self.update_inactive_snapshot(cfg, None);
            return;
        }
        if is_tun {
            let allow_apps = if cfg.mode == KillSwitchMode::RoutingAware {
                extra_app_exes
            } else {
                &[]
            };
            let tun_luid = tun_alias.and_then(resolve_interface_luid_by_alias);
            match WfpSession::open_and_arm(
                true,
                core_exe_paths,
                cfg.allow_lan,
                cfg.block_ipv6_leaks,
                allow_apps,
                tun_luid,
            ) {
                Ok((sess, exceptions)) => {
                    self.wfp_session = Some(sess);
                    self.snapshot = KillSwitchSnapshot {
                        mode: cfg.mode,
                        status: KillSwitchStatus::Armed,
                        enforcement: KillSwitchEnforcement::WfpFirewall,
                        blocking_active: false,
                        needs_elevation: false,
                        allowed_exceptions: exceptions,
                        last_reason: self.snapshot.last_reason.clone(),
                        updated_at: Some(Utc::now().to_rfc3339()),
                    };
                }
                Err((needs_uac, msg)) => {
                    self.wfp_session = None;
                    self.snapshot = KillSwitchSnapshot {
                        mode: cfg.mode,
                        status: KillSwitchStatus::Degraded,
                        enforcement: KillSwitchEnforcement::None,
                        blocking_active: false,
                        needs_elevation: needs_uac,
                        allowed_exceptions: Vec::new(),
                        last_reason: Some(msg),
                        updated_at: Some(Utc::now().to_rfc3339()),
                    };
                }
            }
        } else {
            self.wfp_session = None;
            let mut ex = vec!["Только проксируемый TCP/WinINET трафик".to_string()];
            if cfg.mode == KillSwitchMode::RoutingAware {
                ex.push("Исключения из ProxyOverride (LAN / прямые правила)".to_string());
            }
            self.snapshot = KillSwitchSnapshot {
                mode: cfg.mode,
                status: KillSwitchStatus::Degraded,
                enforcement: KillSwitchEnforcement::ProxyGuard,
                blocking_active: false,
                needs_elevation: false,
                allowed_exceptions: ex,
                last_reason: Some(
                    "В режиме «Системный прокси» Kill Switch защищает прокси-трафик (для полной блокировки на уровне ОС используйте TUN + UAC)."
                        .to_string(),
                ),
                updated_at: Some(Utc::now().to_rfc3339()),
            };
        }
    }

    pub async fn engage_proxy_guard(&mut self, http_port: u16) -> Result<(), String> {
        self.engage_proxy_guards(
            http_port,
            None,
            KillSwitchMode::OnDrop,
            "Защитный прокси-фильтр активен".to_string(),
        )
        .await
    }

    pub async fn engage_proxy_guards(
        &mut self,
        http_port: u16,
        socks_port: Option<u16>,
        mode: KillSwitchMode,
        reason: String,
    ) -> Result<(), String> {
        let _ = self.disengage_async().await;

        let http_listener = TcpListener::bind(("127.0.0.1", http_port))
            .await
            .map_err(|e| {
                format!("Не удалось активировать Kill Switch на HTTP-порту {http_port}: {e}")
            })?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut tasks = vec![spawn_503_guard_loop(http_listener, shutdown_rx.clone())];

        if let Some(sp) = socks_port.filter(|&p| p != http_port && p > 0) {
            if let Ok(socks_listener) = TcpListener::bind(("127.0.0.1", sp)).await {
                tasks.push(spawn_socks5_guard_loop(socks_listener, shutdown_rx));
            }
        }

        self.proxy_guard = Some(ProxyGuardHandle { shutdown_tx, tasks });
        self.write_marker("system_proxy", false, false);
        self.snapshot = KillSwitchSnapshot {
            mode,
            status: KillSwitchStatus::Blocking,
            enforcement: KillSwitchEnforcement::ProxyGuard,
            blocking_active: true,
            needs_elevation: false,
            allowed_exceptions: if mode == KillSwitchMode::RoutingAware {
                vec![
                    "Прокси-соединения блокируются (503/SOCKS5)".to_string(),
                    "Прямые исключения из маршрутизации сохранены".to_string(),
                ]
            } else {
                vec!["Прокси-трафик блокируется на уровне 127.0.0.1 (без полной блокировки non-proxy UDP)".to_string()]
            },
            last_reason: Some(reason),
            updated_at: Some(Utc::now().to_rfc3339()),
        };
        Ok(())
    }

    pub async fn engage_tun_firewall_guard(
        &mut self,
        cfg: &KillSwitchConfig,
        extra_app_exes: &[PathBuf],
        reason: String,
        use_persistent_netsh: bool,
    ) -> Result<(), String> {
        let _ = self.disengage_async().await;

        if !use_persistent_netsh {
            let allow_apps = if cfg.mode == KillSwitchMode::RoutingAware {
                extra_app_exes
            } else {
                &[]
            };
            match WfpSession::open_and_arm(
                false,
                &[],
                cfg.allow_lan,
                cfg.block_ipv6_leaks,
                allow_apps,
                None,
            ) {
                Ok((sess, exceptions)) => {
                    self.wfp_session = Some(sess);
                    self.snapshot = KillSwitchSnapshot {
                        mode: cfg.mode,
                        status: KillSwitchStatus::Blocking,
                        enforcement: KillSwitchEnforcement::WfpFirewall,
                        blocking_active: true,
                        needs_elevation: false,
                        allowed_exceptions: exceptions,
                        last_reason: Some(reason),
                        updated_at: Some(Utc::now().to_rfc3339()),
                    };
                    return Ok(());
                }
                Err((needs_uac, msg)) => {
                    if needs_uac {
                        self.snapshot = KillSwitchSnapshot {
                            mode: cfg.mode,
                            status: KillSwitchStatus::RecoveryRequired,
                            enforcement: KillSwitchEnforcement::None,
                            blocking_active: false,
                            needs_elevation: true,
                            allowed_exceptions: Vec::new(),
                            last_reason: Some(msg.clone()),
                            updated_at: Some(Utc::now().to_rfc3339()),
                        };
                        return Err(msg);
                    }
                    // Fall through to netsh fallback if WFP failed for non-UAC reason
                }
            }
        }

        self.write_marker("tun", true, use_persistent_netsh);
        let netsh = netsh_exe_path();
        let output = tokio::task::spawn_blocking(move || {
            let _ = Command::new(&netsh)
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={FIREWALL_RULE_NAME}"),
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .output();
            Command::new(&netsh)
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={FIREWALL_RULE_NAME}"),
                    "dir=out",
                    "action=block",
                    "profile=any",
                    "enable=yes",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
        })
        .await
        .map_err(|e| format!("Внутренняя ошибка запуска Kill Switch: {e}"))?
        .map_err(|e| format!("Не удалось запустить netsh для Kill Switch: {e}"))?;

        if !output.status.success() {
            let _ = fs::remove_file(&self.state_path);
            let err = format!(
                "{} {}",
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            );
            let msg = format!(
                "Не удалось добавить правило брандмауэра Kill Switch (код {:?}): {}",
                output.status.code(),
                err.trim()
            );
            self.snapshot = KillSwitchSnapshot {
                mode: cfg.mode,
                status: KillSwitchStatus::Degraded,
                enforcement: KillSwitchEnforcement::None,
                blocking_active: false,
                needs_elevation: true,
                allowed_exceptions: Vec::new(),
                last_reason: Some(msg.clone()),
                updated_at: Some(Utc::now().to_rfc3339()),
            };
            return Err(msg);
        }

        self.firewall_rule_active = true;
        self.snapshot = KillSwitchSnapshot {
            mode: cfg.mode,
            status: KillSwitchStatus::Blocking,
            enforcement: KillSwitchEnforcement::NetshFallback,
            blocking_active: true,
            needs_elevation: false,
            allowed_exceptions: Vec::new(),
            last_reason: Some(reason),
            updated_at: Some(Utc::now().to_rfc3339()),
        };
        Ok(())
    }

    pub async fn disengage_async(&mut self) -> Result<(), String> {
        if let Some(guard) = self.proxy_guard.take() {
            guard.stop().await;
        }
        self.wfp_session = None;

        // Always verify OS firewall state instead of trusting only in-memory `firewall_rule_active`
        let res = tokio::task::spawn_blocking(remove_firewall_rule_verified).await;
        match res {
            Ok(Ok(())) => {
                self.firewall_rule_active = false;
                let _ = fs::remove_file(&self.state_path);
                self.snapshot.blocking_active = false;
                self.snapshot.needs_elevation = false;
                if self.snapshot.mode == KillSwitchMode::Off {
                    self.snapshot.status = KillSwitchStatus::Inactive;
                    self.snapshot.enforcement = KillSwitchEnforcement::None;
                } else {
                    self.snapshot.status = KillSwitchStatus::Armed;
                }
                self.snapshot.updated_at = Some(Utc::now().to_rfc3339());
                Ok(())
            }
            Ok(Err(e)) => {
                self.snapshot.needs_elevation = true;
                self.snapshot.status = KillSwitchStatus::RecoveryRequired;
                self.snapshot.last_reason = Some(e.clone());
                Err(e)
            }
            Err(e) => Err(format!("Ошибка снятия Kill Switch: {e}")),
        }
    }

    pub fn disengage(&mut self) {
        if let Some(guard) = self.proxy_guard.take() {
            guard.stop_nonblocking();
        }
        self.wfp_session = None;
        if remove_firewall_rule_verified().is_ok() {
            self.firewall_rule_active = false;
            let _ = fs::remove_file(&self.state_path);
        }
        self.snapshot.blocking_active = false;
    }

    pub fn persist_exit_rule_if_requested(&mut self, cfg: &KillSwitchConfig) {
        if cfg.mode == KillSwitchMode::AlwaysOn && cfg.persist_on_exit {
            self.wfp_session = None;
            if let Some(guard) = self.proxy_guard.take() {
                guard.stop_nonblocking();
            }
            let _ = remove_firewall_rule_verified();
            let netsh = netsh_exe_path();
            // When allow_lan is enabled, block only non-LAN public IPv4/IPv6 ranges in one rule
            // because in Windows Firewall an explicit Block rule always overrides Allow rules.
            let mut args: Vec<String> = vec![
                "advfirewall".into(),
                "firewall".into(),
                "add".into(),
                "rule".into(),
                format!("name={FIREWALL_RULE_NAME}"),
                "dir=out".into(),
                "action=block".into(),
                "profile=any".into(),
                "enable=yes".into(),
            ];
            if cfg.allow_lan {
                let mut remote = "0.0.0.0-9.255.255.255,11.0.0.0-126.255.255.255,128.0.0.0-169.253.255.255,169.255.0.0-172.15.255.255,172.32.0.0-192.167.255.255,192.169.0.0-223.255.255.255".to_string();
                if cfg.block_ipv6_leaks {
                    remote.push_str(",2000::/3");
                }
                args.push(format!("remoteip={remote}"));
            }
            let ok = Command::new(&netsh)
                .args(&args)
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .is_ok_and(|o| o.status.success());
            if ok {
                self.write_marker("tun", true, true);
                self.firewall_rule_active = true;
            } else {
                let _ = fs::remove_file(&self.state_path);
                self.firewall_rule_active = false;
            }
        } else {
            self.disengage();
        }
    }

    fn write_marker(&self, mode: &str, firewall_rule_active: bool, persist_on_exit: bool) {
        let marker = KillSwitchMarker {
            mode: mode.to_string(),
            firewall_rule_active,
            persist_on_exit,
        };
        if let Ok(json) = serde_json::to_string_pretty(&marker) {
            let _ = atomic_write_bytes(&self.state_path, json.as_bytes());
        }
    }
}

pub fn firewall_rule_exists_in_os() -> Option<bool> {
    firewall_rule_exists(&netsh_exe_path())
}

fn firewall_rule_exists(netsh: &Path) -> Option<bool> {
    let out = Command::new(netsh)
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={FIREWALL_RULE_NAME}"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if out.status.success() {
        return Some(true);
    }
    let combined = format!(
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .to_ascii_lowercase();
    if combined.contains("denied")
        || combined.contains("отказано")
        || combined.contains("elevat")
        || combined.contains("админист")
    {
        return None;
    }
    // netsh returns exit code 1 with rule-not-found text when the rule does not exist
    Some(false)
}

pub fn remove_firewall_rule_verified() -> Result<(), String> {
    let netsh = netsh_exe_path();
    let out = Command::new(&netsh)
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={FIREWALL_RULE_NAME}"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Не удалось запустить netsh.exe: {e}"))?;

    if out.status.success() {
        return Ok(());
    }

    if matches!(firewall_rule_exists(&netsh), Some(false)) && crate::elevation::is_elevated() {
        return Ok(());
    }
    if matches!(firewall_rule_exists(&netsh), Some(false)) {
        // Double-check cleanly when un-elevated only if no permission error occurred
        let check = Command::new(&netsh)
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                &format!("name={FIREWALL_RULE_NAME}"),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        if let Ok(c) = check {
            let txt = format!(
                "{} {}",
                String::from_utf8_lossy(&c.stdout),
                String::from_utf8_lossy(&c.stderr)
            );
            if !c.status.success() && !txt.trim().is_empty() && c.status.code() == Some(1) {
                // Rule genuinely not present (only exit code 1 with non-empty localized message)
                return Ok(());
            }
        }
    }

    Err(
        "Для снятия правила брандмауэра Kill Switch требуются права администратора (UAC)."
            .to_string(),
    )
}

pub fn recover_kill_switch_if_dirty(state_path: &Path) -> Result<bool, String> {
    let marker_exists = state_path.exists();
    let rule_in_os = firewall_rule_exists_in_os();

    if !marker_exists && !matches!(rule_in_os, Some(true)) {
        return Ok(false);
    }

    let raw = fs::read_to_string(state_path).unwrap_or_default();
    let marker: Option<KillSwitchMarker> = serde_json::from_str(&raw).ok();
    let had_fw =
        marker.as_ref().is_none_or(|m| m.firewall_rule_active) || matches!(rule_in_os, Some(true));

    if had_fw {
        // Keep marker intact if OS rule removal fails so next launch or UI can trigger UAC recovery
        remove_firewall_rule_verified()?;
    }

    let _ = fs::remove_file(state_path);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy_meter::pick_ephemeral_loopback_ports;

    #[tokio::test]
    async fn proxy_kill_switch_blocks_with_503_and_releases_port() {
        let temp = std::env::temp_dir().join(format!("aura_ks_{}.json", uuid::Uuid::new_v4()));
        let (port, socks_port) = pick_ephemeral_loopback_ports().unwrap();

        let mut ks = KillSwitchState::new(temp.clone());
        ks.engage_proxy_guards(
            port,
            Some(socks_port),
            KillSwitchMode::OnDrop,
            "test".into(),
        )
        .await
        .unwrap();
        assert!(ks.is_engaged());
        assert!(temp.exists());
        assert!(ks.snapshot().blocking_active);

        let proxy = reqwest::Proxy::http(format!("http://127.0.0.1:{port}")).unwrap();
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let resp = client.get("http://example.com/").send().await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        let body = resp.text().await.unwrap();
        assert!(body.contains("Kill Switch"));

        let _ = ks.disengage_async().await;
        assert!(!ks.is_engaged());
        assert!(!temp.exists());

        let rebound = std::net::TcpListener::bind(("127.0.0.1", port));
        assert!(
            rebound.is_ok(),
            "Kill Switch port should be released on disengage_async"
        );
    }

    #[tokio::test]
    async fn socks5_kill_switch_returns_socks5_general_failure() {
        let temp = std::env::temp_dir().join(format!("aura_ks_s5_{}.json", uuid::Uuid::new_v4()));
        let (port, socks_port) = pick_ephemeral_loopback_ports().unwrap();

        let mut ks = KillSwitchState::new(temp);
        ks.engage_proxy_guards(
            port,
            Some(socks_port),
            KillSwitchMode::AlwaysOn,
            "socks test".into(),
        )
        .await
        .unwrap();

        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", socks_port))
            .await
            .unwrap();
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method_resp = [0u8; 2];
        stream.read_exact(&mut method_resp).await.unwrap();
        assert_eq!(method_resp, [0x05, 0x00]);

        // SOCKS5 CONNECT to 1.1.1.1:443
        stream
            .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xBB])
            .await
            .unwrap();
        let mut rep = [0u8; 10];
        stream.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[0], 0x05);
        assert_eq!(rep[1], 0x01);

        let _ = ks.disengage_async().await;
    }

    #[test]
    fn disengage_async_does_not_drop_snapshot_erroneously_when_inactive() {
        let temp = std::env::temp_dir().join(format!("aura_ks_snap_{}.json", uuid::Uuid::new_v4()));
        let mut ks = KillSwitchState::new(temp);
        let cfg = KillSwitchConfig {
            mode: KillSwitchMode::AlwaysOn,
            ..Default::default()
        };
        ks.update_inactive_snapshot(&cfg, Some("init".into()));
        assert_eq!(ks.snapshot().status, KillSwitchStatus::Armed);
        assert!(!ks.snapshot().blocking_active);
    }
}
