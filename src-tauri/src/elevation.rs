use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

const LAYERS_SUBKEY: &str = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";

pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

pub fn has_runasadmin_flag(value: &str) -> bool {
    value
        .split_whitespace()
        .any(|tok| tok.eq_ignore_ascii_case("RUNASADMIN"))
}

pub fn is_always_admin_enabled() -> bool {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
        use winreg::RegKey;

        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        let exe_key = exe.to_string_lossy().to_string();
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(key) = hkcu.open_subkey_with_flags(LAYERS_SUBKEY, KEY_READ) {
            if let Ok(val) = key.get_value::<String, _>(&exe_key) {
                return has_runasadmin_flag(&val);
            }
        }
        false
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn set_always_admin(enabled: bool) -> Result<bool, String> {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
        use winreg::RegKey;

        let exe = std::env::current_exe()
            .map_err(|e| format!("Не удалось определить путь к приложению: {e}"))?;
        let exe_key = exe.to_string_lossy().to_string();
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey_with_flags(LAYERS_SUBKEY, KEY_READ | KEY_WRITE)
            .map_err(|e| format!("Не удалось открыть AppCompatFlags\\Layers: {e}"))?;

        let existing: String = key.get_value(&exe_key).unwrap_or_default();
        let mut tokens: Vec<String> = existing
            .split_whitespace()
            .filter(|t| !t.eq_ignore_ascii_case("RUNASADMIN") && *t != "~")
            .map(|t| t.to_string())
            .collect();

        if enabled {
            tokens.push("RUNASADMIN".to_string());
            let new_val = format!("~ {}", tokens.join(" "));
            key.set_value(&exe_key, &new_val)
                .map_err(|e| format!("Не удалось сохранить флаг RUNASADMIN: {e}"))?;
            Ok(true)
        } else {
            if tokens.is_empty() {
                let _ = key.delete_value(&exe_key);
            } else {
                let new_val = format!("~ {}", tokens.join(" "));
                key.set_value(&exe_key, &new_val)
                    .map_err(|e| format!("Не удалось обновить AppCompatFlags\\Layers: {e}"))?;
            }
            Ok(false)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = enabled;
        Ok(false)
    }
}

fn to_wide_null(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

pub fn relaunch_as_admin() -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("Не удалось определить путь к приложению: {e}"))?;
    let verb = to_wide_null(OsStr::new("runas"));
    let file = to_wide_null(exe.as_os_str());
    let params = to_wide_null(OsStr::new("--tun-ready"));

    let res = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };

    if (res as isize) <= 32 {
        return Err("Запрос прав администратора отклонён или отменён пользователем".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_runasadmin_compat_token_case_insensitively() {
        assert!(has_runasadmin_flag("~ RUNASADMIN"));
        assert!(has_runasadmin_flag("~ HIGHDPIAWARE runasadmin"));
        assert!(!has_runasadmin_flag("~ HIGHDPIAWARE"));
        assert!(!has_runasadmin_flag(""));
    }
}
