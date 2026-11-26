# Security Audit Report — AURA VPN `v1.0.0-rc.1`

This document summarizes the internal multi-domain pre-release security, privacy, malware-free, and supply-chain audit conducted ahead of **AURA VPN `v1.0.0-rc.1`**.

> Note: This is an internal pre-release audit performed alongside automated tooling (`clippy`, `vitest`, `tsc`, `npm audit`). It is **not** a third-party external penetration test or formal certification.

---

## 1. Malware-Free & Behavioral Cleanliness Verdict

**Verdict: Clean — Zero malicious, hidden, or deceptive behavior.**

Inspected all Rust backend modules (`src-tauri/src/`) and TypeScript/React modules (`src/`):
- **Zero hidden telemetry or analytics SDKs**: No crash/usage beacons, ad IDs, or remote font requests.
- **Zero credential harvesting or keylogging**: No keyboard hooks, screen capture, browser cookie/token reading, or undocumented filesystem scanning.
- **Every OS interaction & network request maps directly to user-visible VPN functionality**: DPAPI user storage, WFP/Firewall Kill Switch rules, HKCU System Proxy toggle, Wintun L3 TUN adapter setup, explicit update/IP/DNS diagnostic buttons, and `.wake` recovery marker.
- **Zero code obfuscation / packers**: Clean PE/Tauri binary structure without runtime code injection or dynamic download-and-execute paths.

---

## 2. Key Hardening Measures Implemented for `v1.0.0-rc.1`

### Backend & Network Security (Rust)
- **WFP Kill Switch (`kill_switch.rs`)**: Scoped UDP 67/68 DHCP IPv4 permits strictly to broadcast/RFC1918/link-local remote addresses; bound TUN adapter permit via `ConvertInterfaceAliasToLuid`; excluded non-LAN CIDRs correctly in persisted firewall rules; locale-independent rule cleanup and crash-safe recovery.
- **Bypass Closure While Kill Switch Active (`core_manager.rs`, `commands.rs`)**: Direct pre-connect latency probes, `ping_server`, `run_ping_all`, `update_rulepack`, `dns_lookup_route`, `check_for_updates`, and `check_core_updates` refuse direct outbound execution when Kill Switch is engaged.
- **Pre-Launch Core Integrity (`core_manager.rs`, `commands.rs`)**: Wired `verify_xray_integrity` across Config Studio `xray` execution paths as well as VPN tunnel startup.
- **DNS / DoH & Subscription Anti-SSRF (`dns_manager.rs`, `net_fetch.rs`)**: Enforced HTTPS/public-IP checks and DNS lookup pinning on DoH/DoT/UDP targets, domain character allowlisting, bounded streaming response reads, and pinned GitHub release URLs (`donatefrost-cell/aura-vpn` and `xtls/xray-core`).
- **Untrusted Config Parser Hardening (`parser/`, `config_gen.rs`, `config_studio.rs`)**: Case-insensitive JSON outbound/directive sanitization, short-prefix blocking of reserved outbounds (`direct`, `block`, `dns-out`, `api`) in balancers/observatory, UTF-8 multi-byte boundary safety, YAML recursion depth limit & backslash-parity quote parsing, and safe WireGuard IPv6 bracket handling.
- **Privacy & Secret Redaction (`logger.rs`, `commands.rs`, `privacy.rs`)**: Expanded Base64 key regex masking without word-boundary bypass, redacted `integrity_note` / `last_reason` / `health.reason` in diagnostics exports, switched HWID rotation to `Uuid::new_v4()`, and transparently disclosed WebView2 `localStorage` under `PrivacyCenter`.

### Frontend, IPC & Supply Chain
- **WebView Hardening (`tauri.conf.json`, `capabilities/default.json`, `api.ts`)**: Enabled `freezePrototype: true`, tightened CSP (`frame-src 'none'; worker-src 'none'`), removed unused clipboard write permission, isolated `previewApi` strictly behind `IS_PREVIEW_BUILD` (`0` mock chunks in production `dist/`), and removed unused `ServerInspectorModal`.
- **CycloneDX 1.5 SBOM & Legal Packaging**: Standardized `SBOM.json` (`specVersion: 1.5`), expanded `THIRD_PARTY_NOTICES.md` (`Apache-2.0`, `MPL-2.0`, `ISC`, `Wintun Prebuilt Binaries License`, `SIL OFL 1.1`), pinned extracted core binary SHA-256 + WireGuard Authenticode checks in `scripts/download-*.mjs`, and pinned GitHub Actions to 40-char commit SHAs.

---

## 3. Known Limitations Before `v1.0.0` GA

1. **Unsigned Windows Binaries**: No EV/OV Authenticode certificate yet; Microsoft SmartScreen prompt is expected on fresh installs.
2. **Clean VM Matrix Pending**: Full fresh-OS matrix testing across clean Windows 10/11 VMs (non-dev machines without cached WebView2/SDK runtimes) has not yet been performed.
3. **CI Dynamic Checks Require GitHub Hosting**: Gitleaks, `rustsec/audit-check`, and CodeQL execute automatically once pushed to GitHub.
