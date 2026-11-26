use std::os::windows::process::CommandExt;
use std::process::Command;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
use winreg::RegKey;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const ENTRY_NAME: &str = "AuraVPN";
const TASK_NAME: &str = "AURA VPN";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn schtasks_exe_path() -> std::path::PathBuf {
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    std::path::PathBuf::from(sys_root)
        .join("System32")
        .join("schtasks.exe")
}

pub fn sync_autostart(enabled: bool, start_minimized: bool) -> Result<(), String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey_with_flags(RUN_KEY, KEY_READ | KEY_WRITE)
        .map_err(|e| format!("Не удалось открыть реестр автозапуска Windows: {e}"))?;

    if !enabled {
        let _ = key.delete_value(ENTRY_NAME);
        let _ = Command::new(schtasks_exe_path())
            .args(["/Delete", "/TN", TASK_NAME, "/F"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        return Ok(());
    }

    let exe = std::env::current_exe()
        .map_err(|e| format!("Не удалось определить путь к приложению: {e}"))?;
    let exe_str = exe.to_string_lossy();
    let cmd = if start_minimized {
        format!("\"{exe_str}\" --minimized")
    } else {
        format!("\"{exe_str}\"")
    };

    if crate::elevation::is_always_admin_enabled() && crate::elevation::is_elevated() {
        let out = Command::new(schtasks_exe_path())
            .args([
                "/Create", "/TN", TASK_NAME, "/TR", &cmd, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        if out.as_ref().is_ok_and(|o| o.status.success()) {
            let _ = key.delete_value(ENTRY_NAME);
            return Ok(());
        }
    } else {
        let _ = Command::new(schtasks_exe_path())
            .args(["/Delete", "/TN", TASK_NAME, "/F"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }

    key.set_value(ENTRY_NAME, &cmd)
        .map_err(|e| format!("Не удалось записать автозапуск Windows: {e}"))?;
    Ok(())
}
