# Privacy Policy & Local Data Handling — AURA VPN

AURA VPN is open-source desktop software. We **do not collect, transmit, sell, log remotely, or analyze** your personal data, browsing activity, VPN keys, or IP addresses on any developer-controlled server.

---

## 1. Local Data Stored on Your PC

All runtime data remains strictly on your Windows machine:

| Data Category | Location | Protection | Retention |
| --- | --- | --- | --- |
| **Server profiles, Raw JSON, Subscription URLs, Settings, Routing, Connection History** | `%APPDATA%\app.auravpn.desktop\` | **Windows DPAPI (`CryptProtectData`)** encrypted per current Windows user | Until deleted or cleared in *Privacy Center* |
| **Application Diagnostics Log** | In-memory ring buffer (`VecDeque`, max 300 entries) | Redacted in memory via `redact_secrets()` (UUIDs, WG Base64 keys, passwords, tokens stripped); **no log files are written to disk automatically** unless you explicitly click *Export Diagnostics Bundle* | Cleared on exit or in *Privacy Center* |
| **Generated Runtime Configs (`xray.json` / `awg.conf`)** | `%LOCALAPPDATA%\Temp\aura-vpn\` or `%APPDATA%\app.auravpn.desktop\runtime\` | Created only during active core run | Cleaned up on disconnect / exit |
| **Minor UI Flags (dismissed alerts, cosmetic UI state)** | WebView2 `localStorage` | Plaintext browser storage inside `%LOCALAPPDATA%\app.auravpn.desktop\EBWebView\` | Cleared via *Privacy Center -> Purge All Data* |

---

## 2. Hardware ID (HWID) & Device Headers on Subscription Refresh

Some subscription providers (such as Remnawave / Happ-compatible panels) enforce per-device slot limits using request headers (`x-hwid`, `x-device-os`, `x-ver-os`, `x-device-model`). In AURA VPN `v1.0.0-rc.1`:
- **`sendHwid` defaults to `true`** (`src-tauri/src/models.rs` & `src/config/defaultSettings.ts`) so existing subscription device bindings work out of the box. You can **disable it at any time** in **Settings -> Privacy Center** (and optionally strip OS/device headers).
- When `deviceHwid` is empty (`None`), `hwid.rs` derives a deterministic SHA-256 hash seeded from `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` (never reading motherboard/disk serials directly), and reads OS build and SMBIOS `SystemManufacturer`/`SystemProductName` strings for HTTPS subscription requests when enabled.
- Clicking **Rotate HWID** generates a cryptographically random `Uuid::new_v4()` stored in DPAPI settings, immediately replacing the derived identifier.

---

## 3. Diagnostics Exports

When using **Export Diagnostics Bundle**, AURA VPN writes a local troubleshooting JSON report containing sanitized snapshot metadata and up to 300 redacted in-memory log entries. Sensitive tokens, UUIDs, PrivateKeys, credentials, integrity notes, and error strings pass through `redact_secrets()` before writing. Always review any exported file before sharing it publicly on GitHub.
