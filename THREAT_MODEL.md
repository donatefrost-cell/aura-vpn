# Threat Model — AURA VPN

This document defines the trust boundaries, assets protected, attacker capabilities, and mitigations implemented in **AURA VPN `v1.0.0-rc.1`**.

---

## 1. Protected Assets

1. **User VPN Credentials**: UUIDs, Trojan passwords, Shadowsocks keys, Hysteria2 auth strings, WireGuard/AmneziaWG PrivateKeys, subscription URLs (often containing bearer tokens).
2. **Real Public IP & DNS Queries**: Preventing silent fallback to unencrypted ISP egress on tunnel drop or misconfiguration.
3. **Endpoint & OS Integrity**: Preventing untrusted imported configs, subscription responses, or compromised core binaries from executing arbitrary commands, reading local files, or persisting hidden firewall backdoors.

---

## 2. Trust Boundaries

| Boundary | Trusted Side | Untrusted / Semi-Trusted Side | Controls |
| --- | --- | --- | --- |
| **Profile / Subscription Import** | Rust `parser/` & `config_studio.rs` | Share links, Clash YAML, Raw Xray JSON, remote HTTP subscriptions | SSRF IP/CIDR blocklist, DNS pinning, response size caps, YAML depth limits, Xray outbound/tag allowlists |
| **IPC (WebView <-> Rust)** | Rust `commands.rs` | React WebView2 renderer | Restricted Tauri capabilities (`default.json`), `freezePrototype: true`, strict CSP (`frame-src 'none'; worker-src 'none'`), no `eval`, backend enforces security invariants |
| **Core Process Execution** | Rust `core_manager.rs` | On-disk `xray.exe`, `wireproxy-awg.exe`, `wintun.dll` | Compile-time pinned SHA-256 verification before tunnel start & Config Studio run; `CREATE_NO_WINDOW` |
| **Network Egress** | Active tunnel core + TUN LUID | Arbitrary OS applications attempting non-tunnel egress | WFP Kill Switch filters (`on_drop` / `always_on` / `routing_aware`) permitting loopback, scoped DHCP, TUN LUID, and verified core executables via `ALE_APP_ID` + config balancer guardrails; direct Rust probe/update commands blocked while KS active |
| **Local Storage** | DPAPI Vault (`%APPDATA%\app.auravpn.desktop`) | Other OS users, offline disk access | Windows `CryptProtectData` per-user encryption + memory zeroization on sensitive structs (`zeroize`) |

---

## 3. Threats & Mitigations

### T1 — IP / DNS Leak on Tunnel Drop or Crash
- **Mitigation**: In elevated mode, `WfpSession` installs high-priority block filters on IPv4/IPv6 outbound layers with explicit permits for loopback, scoped DHCP, the verified TUN interface LUID (`ConvertInterfaceAliasToLuid`), explicit `RoutingAware` bypass executables, and `aura-vpn.exe` / active core paths (`ALE_APP_ID`). Balancer and `freedom` prefix guardrails in `config_gen.rs` prevent untrusted profiles from routing user traffic directly through helper outbounds. On unexpected abort during TUN startup, WFP stays armed (when `always_on`/`on_drop` semantics apply) or rolls back cleanly alongside proxy guard restoration.

### T2 — Malicious Imported Xray JSON / Clash YAML Configs
- **Mitigation**: Untrusted `api` services, `freedom` bypasses targeting local sockets, reserved outbound tag hijacks (exact or prefix match against `direct`, `block`, `dns-out`, `api` in balancers/observatory), arbitrary filesystem directives, and deep recursive YAML structures are rejected or stripped before config generation.

### T3 — Server-Side Request Forgery (SSRF) via Subscriptions or DoH
- **Mitigation**: `net_fetch.rs` and `dns_manager.rs` enforce HTTPS (for DoH/updates) and validate resolved IPs against RFC1918, loopback, link-local (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), multicast, and IPv6 ULA/link-local ranges with DNS pinning prior to connection, plus bounded streaming reads.

### T4 — Binary Tampering / DLL Hijacking in `resources/core/`
- **Mitigation**: Before starting `xray.exe` or `wireproxy-awg.exe` (both for active tunnels and Config Studio `xray test` checks), `core_manager.rs` checks exact lowercase SHA-256 checksums matching `core-manifest.json` and `awg-manifest.json` (`wintun.dll` is signed by `WireGuard LLC` and pinned via `wintun-manifest.json`).

### T5 — Secret Leakage in Logs & Diagnostics Exports
- **Mitigation**: All log writes and diagnostics bundle exports pass through `redact_secrets()` (masking UUIDs, Base64 WireGuard keys, Bearer/query tokens, passwords, and non-exempt error messages/reasons including integrity and health failure strings).

---

## 4. Explicit Non-Goals / Accepted Residual Risks

- **Same-User Malware**: Any malicious binary already executing as the same logged-in Windows user has OS permission to invoke DPAPI or inspect process memory.
- **Kernel Drivers**: AURA VPN does not ship custom kernel drivers; it uses WireGuard's signed `wintun.dll` and user-mode Win32 WFP APIs.
- **Network-Level Nation-State Traffic Analysis**: Transport obfuscation depends on the underlying user-supplied protocol configuration (VLESS Reality, AmneziaWG junk packets, TLS/Hysteria2, etc.).
