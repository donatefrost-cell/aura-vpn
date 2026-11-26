# Security Policy — AURA VPN

## Supported Versions

| Version | Status | Security Fixes |
| --- | --- | --- |
| `1.0.0-rc.1` (Release Candidate) | Active Pre-Release | Supported |
| `< 1.0.0-rc.1` (`0.x`) | End of Life | Upgrade to `1.0.0-rc.1` |

---

## Reporting a Vulnerability

Please **do not** disclose security vulnerabilities in public GitHub issues before coordinated triage.

1. Use **GitHub Security Advisories** ("Report a vulnerability" on the repository Security tab: <https://github.com/donatefrost-cell/aura-vpn/security/advisories/new>).
2. Include in your report:
   - AURA VPN version and Windows version (`winver`).
   - Affected subsystem (e.g., Kill Switch WFP engine, URI/YAML/JSON parser, Tauri IPC command, updater, bundled core verification).
   - Minimal reproducible steps or redacted Proof of Concept (**never send real VPN keys, UUIDs, PrivateKeys, or personal IPs**).
   - Impact assessment (e.g., IP/DNS leak condition, arbitrary Xray config injection, local privilege escalation).

Expected acknowledgment: best-effort response within **72 hours** for confirmed security issues.

---

## Security Architecture Highlights

- **Encrypted Local Secrets**: Server profiles, raw JSON, subscription URLs, and settings are stored with **Windows DPAPI (`CryptProtectData`)** bound to the current Windows user account and entropy domain (`%APPDATA%\app.auravpn.desktop\`).
- **Mandatory Binary Integrity Verification**: Before starting any tunnel session or Config Studio validation, AURA VPN verifies the pinned lowercase SHA-256 digests of `xray.exe`, `wireproxy-awg.exe`, and `wintun.dll` in `src-tauri/resources/core/`.
- **System-Level Kill Switch (`Windows Filtering Platform`)**: In `on_drop`, `always_on`, and `routing_aware` modes (with Administrator privileges), WFP permits loopback, strictly scoped RFC1918/link-local DHCPv4, the active TUN interface LUID (when in TUN mode, resolved via `ConvertInterfaceAliasToLuid`), explicit `RoutingAware` bypass executables, and `aura-vpn.exe` / the pinned tunnel core executables (`xray.exe`, `wireproxy-awg.exe` via `FWPM_CONDITION_ALE_APP_ID` so the core can establish and maintain tunnel sockets), while blocking general OS IPv4/IPv6 egress outside the tunnel. Traffic separation inside `xray.exe` is additionally enforced by sanitized config/balancer guardrails (`config_gen.rs`). In standard-user Proxy Guard fallback mode, Windows HTTP Proxy is restricted without kernel WFP blocking.
- **Anti-SSRF & Parser Guardrails**: Subscriptions and IP probes block private/loopback/link-local/CGNAT IPs (with DNS resolution pinning against DNS rebinding). Untrusted Raw Xray JSON, Clash YAML, and WireGuard INI imports undergo strict schema validation and dangerous-directive stripping (`api`, `freedom` sockopt/fragment outside allowed outbounds, `fs` reads, arbitrary scripts).
- **Redacted Logging & Export**: In-app logs and diagnostics exports pass through central redaction rules masking UUIDs, private keys, tokens, passwords, and non-exempt host details.

---

## Known Security & Release Limitations (`v1.0.0-rc.1`)

- **No Authenticode Certificate**: `v1.0.0-rc.1` installers and `aura-vpn.exe` are currently **unsigned** (no commercial EV/OV code signing certificate). Windows SmartScreen will display an "Unknown publisher" warning on first download. Always verify SHA-256 checksums against `SHA256SUMS.txt` and inspect the CycloneDX 1.5 `SBOM.json`.
- **Single-User DPAPI Scope**: DPAPI (`CryptProtectData`) protects secrets at rest from other OS users and offline disk extraction; any process running under the same Windows user session can decrypt DPAPI blobs via Win32 APIs.
- **Tauri State in WebView2**: Read-only visual UI preferences (such as notification center dismissal timestamps or minor non-secret UI flags) may use WebView2 `localStorage` (`PrivacyCenter` explicitly accounts for this under `plaintext_files`), while all credentials stay exclusively in the Rust backend.
- **Zero Clean-VM Matrix Test Yet**: Pre-release RC testing was verified on the primary Windows 11 developer environment; independent clean-VM testing across Windows 10/11 SKUs is still in progress prior to `v1.0.0` GA.
