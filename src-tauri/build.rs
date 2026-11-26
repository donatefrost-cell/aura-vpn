use std::fs;
use std::path::Path;

fn extract_sha256(manifest_path: &Path, key: &str) -> String {
    let Ok(raw) = fs::read_to_string(manifest_path) else {
        return String::new();
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return String::new();
    };
    val.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or_default()
}

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let core_dir = Path::new(&manifest_dir).join("resources").join("core");

    let specs = [
        ("core-manifest.json", "exeSha256", "AURA_XRAY_SHA256"),
        ("awg-manifest.json", "exeSha256", "AURA_AWG_SHA256"),
        ("wintun-manifest.json", "dllSha256", "AURA_WINTUN_SHA256"),
    ];

    let is_release = std::env::var("PROFILE").as_deref() == Ok("release");
    for (file, json_key, env_name) in specs {
        let path = core_dir.join(file);
        println!("cargo:rerun-if-changed={}", path.display());
        let hash = extract_sha256(&path, json_key);
        if is_release && hash.is_empty() {
            panic!(
                "Release build requires valid 64-hex SHA-256 ({json_key}) in {}",
                path.display()
            );
        }
        println!("cargo:rustc-env={env_name}={hash}");
    }

    tauri_build::build();
}
