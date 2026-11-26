use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
use winreg::RegKey;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const ENTRY_NAME: &str = "AuraVPN";

pub fn sync_autostart(enabled: bool, start_minimized: bool) -> Result<(), String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey_with_flags(RUN_KEY, KEY_READ | KEY_WRITE)
        .map_err(|e| format!("Не удалось открыть реестр автозапуска Windows: {e}"))?;

    if !enabled {
        let _ = key.delete_value(ENTRY_NAME);
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

    key.set_value(ENTRY_NAME, &cmd)
        .map_err(|e| format!("Не удалось записать автозапуск Windows: {e}"))?;
    Ok(())
}
