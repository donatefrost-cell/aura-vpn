# Architecture — AURA VPN

**AURA VPN** (`v1.0.0-rc.1`) is a Windows desktop VPN client built on **Tauri 2**, pairing a **React 19 / TypeScript** Material 3 UI with a privileged-capable **Rust** networking and security core.

---

## 1. High-Level Component Architecture

```text
+-------------------------------------------------------------------+
|                     React 19 + TypeScript UI                      |
|   Home · Servers · Subscriptions · Routing · Settings · Studio    |
|   Strict CSP · freezePrototype · No remote fonts · No telemetry   |
+---------------------------------+---------------------------------+
                                  | Tauri v2 IPC (src-tauri/capabilities/default.json)
                                  v
+-------------------------------------------------------------------+
|                        Rust Backend Core                          |
|  - commands.rs: IPC handlers, validation, KS direct-net guards    |
|  - core_manager.rs: Process supervisor, SHA-256 verification      |
|  - config_gen.rs / config_studio.rs: 4-layer config + Guardrails  |
|  - kill_switch.rs: Windows Filtering Platform (WFP) + Proxy Guard |
|  - dns_manager.rs / ip_monitor.rs / tun_manager.rs                |
|  - storage.rs: Windows DPAPI (CryptProtectData) encrypted vault   |
|  - parser/: VLESS, VMess, Trojan, SS, Hysteria2, WG, AWG, Clash   |
|  - logger.rs: Rotating redacted diagnostics & zero-key policy     |
+--------+-------------------------+------------------------+-------+
         |                         |                        |
         v                         v                        v
+-----------------+      +-------------------+     +----------------+
|   xray.exe      |      | wireproxy-awg.exe |     |   wintun.dll   |
|   (v26.11.9)    |      |     (v1.0.18)     |     |    (0.14.1)    |
| Mixed/TUN Core  |      |   AmneziaWG/WG    |     |  L3 TUN Driver |
+-----------------+      +-------------------+     +----------------+
```

---

## 2. Core Data Flows

1. **Profile Import & Parsing (`src-tauri/src/parser/`)**:
   - Accepts share URIs (`vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`, `hy2://`, `wireguard://`), WireGuard/AmneziaWG `.conf` INI files, Clash/Mihomo YAML (with depth limits and backslash-parity parsing), or Raw Xray JSON.
   - Untrusted Raw Xray JSON and Config Studio overrides pass through schema sanitization blocking unsafe outbounds/directives (`api`, `fs` reads, loopback/private freedom abuse, short prefixes of reserved outbound tags `direct`/`block`/`dns-out`/`api`).
2. **Encrypted Persistence (`storage.rs`)**:
   - Profiles, subscriptions, routing configuration, connection history, and settings are serialized to JSON and sealed via Windows DPAPI (`CryptProtectData` with AURA entropy) in `%APPDATA%\app.auravpn.desktop\`.
   - WebView2 stores only minor non-secret UI state in `localStorage`.
3. **4-Layer Config Synthesis (`config_gen.rs` & `config_studio.rs`)**:
   - Layer 1: Raw server/profile base parameters.
   - Layer 2: Global application routing, DNS, TUN, and advanced settings.
   - Layer 3: Smart Config Engine auto-adaptation (when enabled) & per-profile overrides.
   - Layer 4: User Custom Patch / Xray JSON overlay validated by Config Studio guardrails.
4. **Tunnel Execution & Kill Switch (`core_manager.rs` & `kill_switch.rs`)**:
   - Verifies lowercase SHA-256 digests of `xray.exe` and `wireproxy-awg.exe` (and Wintun presence) against compile-time pinned manifests before spawning.
   - Connects via **System Proxy** (Windows `Internet Settings` registry HKCU) or **TUN** (`wintun.dll` L3 interface, requiring Administrator privileges).
   - **WFP Kill Switch**: Opens a BFE/WFP session blocking general OS IPv4/IPv6 egress outside: loopback, strictly scoped RFC1918/link-local DHCPv4, the active TUN interface LUID (`ConvertInterfaceAliasToLuid`), explicit `RoutingAware` bypass apps, and the verified `aura-vpn.exe` / active tunnel core executables (`ALE_APP_ID`) while routing inside `xray.exe` is restricted by config/balancer guardrails.
   - Clean teardown or crash recovery restores Windows proxy state, removes persistent/transient firewall filters cleanly across OS locales, and writes a `.wake` state marker safely.
