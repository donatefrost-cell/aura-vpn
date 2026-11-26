use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub hwid: String,
    pub device_os: String,
    pub ver_os: String,
    pub device_model: String,
}

/// SHA-256 digest backed by RustCrypto `sha2` to derive a deterministic,
/// non-reversible HWID from the Windows MachineGuid.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Derives a deterministic UUIDv4-formatted HWID (36 chars, `/^[a-zA-Z0-9=-]{10,64}$/`).
pub fn derive_hwid_from_seed(seed: &str) -> String {
    let mut input = Vec::with_capacity(17 + seed.len());
    input.extend_from_slice(b"aura-vpn-hwid-v1:");
    input.extend_from_slice(seed.as_bytes());
    let digest = sha256(&input);
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3],
        b[4], b[5],
        b[6], b[7],
        b[8], b[9],
        b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Validates Remnawave / Happ HWID constraints (`/^[a-zA-Z0-9=-]{10,64}$/`).
pub fn validate_hwid(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if !(10..=64).contains(&trimmed.len()) {
        return Err(
            "HWID должен содержать от 10 до 64 символов (латинские буквы, цифры, '-' или '=')"
                .to_string(),
        );
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '=')
    {
        return Err(
            "HWID содержит недопустимые символы — разрешены только латинские буквы, цифры, '-' и '='"
                .to_string(),
        );
    }
    Ok(trimmed.to_string())
}

pub fn generate_default_hwid() -> String {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let key = hklm
            .open_subkey_with_flags(
                "SOFTWARE\\Microsoft\\Cryptography",
                KEY_READ | KEY_WOW64_64KEY,
            )
            .or_else(|_| hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography"));
        if let Ok(subkey) = key {
            if let Ok(guid) = subkey.get_value::<String, _>("MachineGuid") {
                let clean = guid.trim();
                if !clean.is_empty() {
                    return derive_hwid_from_seed(clean);
                }
            }
        }
    }

    uuid::Uuid::new_v4().to_string()
}

fn sanitize_header_ascii(raw: &str, max_len: usize) -> String {
    let ascii_only: String = raw
        .chars()
        .filter(|&c| ('\x20'..='\x7e').contains(&c))
        .collect();
    let collapsed = ascii_only.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed.trim();
    if trimmed.len() <= max_len {
        trimmed.to_string()
    } else {
        trimmed
            .chars()
            .take(max_len)
            .collect::<String>()
            .trim_end()
            .to_string()
    }
}

fn read_windows_os_version() -> String {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let key = hklm
            .open_subkey_with_flags(
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                KEY_READ | KEY_WOW64_64KEY,
            )
            .or_else(|_| hklm.open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"));

        if let Ok(subkey) = key {
            let major = subkey.get_value::<u32, _>("CurrentMajorVersionNumber").ok();
            let minor = subkey.get_value::<u32, _>("CurrentMinorVersionNumber").ok();
            let build = subkey
                .get_value::<String, _>("CurrentBuildNumber")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            if let (Some(maj), Some(min)) = (major, minor) {
                let ver = match build {
                    Some(b) => format!("{maj}.{min}.{b}"),
                    None => format!("{maj}.{min}"),
                };
                let clean = sanitize_header_ascii(&ver, 32);
                if !clean.is_empty() {
                    return clean;
                }
            }
        }
    }

    "10.0".to_string()
}

fn is_generic_oem_placeholder(val: &str) -> bool {
    let lower = val.trim().to_ascii_lowercase();
    lower.is_empty()
        || matches!(
            lower.as_str(),
            "to be filled by o.e.m."
                | "system product name"
                | "system manufacturer"
                | "default string"
                | "none"
                | "not specified"
                | "o.e.m."
        )
}

fn read_windows_device_model() -> String {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let key = hklm
            .open_subkey_with_flags(
                "HARDWARE\\DESCRIPTION\\System\\BIOS",
                KEY_READ | KEY_WOW64_64KEY,
            )
            .or_else(|_| hklm.open_subkey("HARDWARE\\DESCRIPTION\\System\\BIOS"));

        if let Ok(subkey) = key {
            let manufacturer = subkey
                .get_value::<String, _>("SystemManufacturer")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !is_generic_oem_placeholder(s));
            let product = subkey
                .get_value::<String, _>("SystemProductName")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !is_generic_oem_placeholder(s));

            let combined = match (manufacturer, product) {
                (Some(mfg), Some(prod)) => {
                    if prod
                        .to_ascii_lowercase()
                        .starts_with(&mfg.to_ascii_lowercase())
                    {
                        prod
                    } else {
                        format!("{mfg} {prod}")
                    }
                }
                (Some(mfg), None) => mfg,
                (None, Some(prod)) => prod,
                (None, None) => String::new(),
            };

            let clean = sanitize_header_ascii(&combined, 64);
            if !clean.is_empty() {
                return clean;
            }
        }
    }

    // Do not expose local host COMPUTERNAME to remote subscription panels
    "Windows PC".to_string()
}

pub fn resolve_device_identity(custom_hwid: Option<&str>) -> DeviceIdentity {
    let hwid = custom_hwid
        .and_then(|s| validate_hwid(s).ok())
        .unwrap_or_else(generate_default_hwid);

    DeviceIdentity {
        hwid,
        device_os: "Windows".to_string(),
        ver_os: read_windows_os_version(),
        device_model: read_windows_device_model(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    #[test]
    fn sha256_matches_nist_test_vector() {
        let digest = sha256(b"abc");
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn default_hwid_matches_remnawave_regex_and_is_deterministic() {
        let a = derive_hwid_from_seed("12345678-aaaa-bbbb-cccc-001122334455");
        let b = derive_hwid_from_seed("12345678-aaaa-bbbb-cccc-001122334455");
        assert_eq!(a, b);
        assert!(validate_hwid(&a).is_ok());

        let generated = generate_default_hwid();
        assert!((10..=64).contains(&generated.len()));
        assert!(validate_hwid(&generated).is_ok());
    }

    #[test]
    fn validate_hwid_accepts_valid_and_rejects_invalid() {
        assert!(validate_hwid("UE42LJXu4DbiCaBv==").is_ok());
        assert!(validate_hwid("a1b2c3d4-e5f6-4789-8abc-0123456789ef").is_ok());
        assert!(validate_hwid("short").is_err());
        assert!(validate_hwid(&"a".repeat(65)).is_err());
        assert!(validate_hwid("bad_underscore_id").is_err());
        assert!(validate_hwid("has space 1234").is_err());
    }

    #[test]
    fn device_identity_headers_are_valid_http_header_values() {
        let id = resolve_device_identity(None);
        assert_eq!(id.device_os, "Windows");
        assert!(!id.ver_os.is_empty());
        assert!(!id.device_model.is_empty());
        assert!(HeaderValue::from_str(&id.hwid).is_ok());
        assert!(HeaderValue::from_str(&id.device_os).is_ok());
        assert!(HeaderValue::from_str(&id.ver_os).is_ok());
        assert!(HeaderValue::from_str(&id.device_model).is_ok());
    }
}
