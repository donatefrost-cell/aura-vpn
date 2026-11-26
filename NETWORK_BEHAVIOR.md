# Network Behavior Specification — AURA VPN

This document enumerates **every** network connection AURA VPN (`v1.0.0-rc.1`) can initiate, under what condition, and how user consent applies.

---

## 1. Zero Background Telemetry Guarantee

AURA VPN contains **no** analytics SDKs, crash reporting beacons, advertisement identifiers, remote font CDNs, or background heartbeat pings. When idle and disconnected (with optional automatic checks turned off), AURA VPN performs **zero** outbound network requests.

---

## 2. Complete Network Connection Inventory

| Feature | Trigger | Destination | Data Sent | Bypassed when Kill Switch Active? |
| --- | --- | --- | --- | --- |
| **VPN Tunnel Traffic** | User clicks Connect / Reconnect | User-configured VPN server IP:Port | Encrypted VPN protocol payload (`xray.exe` / `wireproxy-awg.exe`) | Explicit WFP permit for server endpoint + TUN LUID |
| **Subscription Refresh** | Manual refresh or user-enabled auto-interval | User-configured subscription HTTPS/HTTP URL | Standard HTTP `GET` + optional `hwid` / User-Agent headers only if configured by user profile/settings | No (blocked if direct / not permitted outside tunnel) |
| **Latency Ping / Proxy Probe** | Manual ping / Auto-Select / Connect verify | Connected local proxy (`127.0.0.1`) or target server port TCP/HTTP | TCP connect or HTTP `HEAD`/`GET` to `generate_204` probe target | Direct `ping_server` & `run_ping_all` are **blocked** when KS is engaged |
| **IP & Geo Monitor ("My IP")** | Manual "Check IP" click or optional `autoCheckIpIntervalSecs` (`>= 60s`) | Selected provider (`api.ipify.org`, `ipwho.is`, `ipinfo.io`, `ifconfig.me`, etc.) | HTTP `GET` (through tunnel if connected; direct only if disconnected & KS inactive) | Skipped / guarded when KS is blocking |
| **DNS Leak / Route Test** | Manual test in DNS Manager / Network Doctor | User-selected DNS endpoint (UDP/DoT/DoH) | DNS query for user/diagnostic domain | Direct DoT/UDP/lookup **blocked** while KS active; SSRF-checked |
| **App Update Check** | Manual "Check Updates" or optional `autoCheckUpdates` toggle | `https://api.github.com/repos/donatefrost-cell/aura-vpn/releases` (channel-filtered) | Standard GitHub API `GET` | **Blocked** when KS active; URL strict-pinned to `donatefrost-cell/aura-vpn` |
| **Core Update Check** | Manual check in Core Manager | `https://api.github.com/repos/XTLS/Xray-core/releases` (and upstream release tags) | Standard GitHub API `GET` | **Blocked** when KS active |
| **GeoIP / Rulepack Update** | Manual rulepack update action | Pinned / user-configured HTTPS geosite/geoip release URL | HTTPS `GET` | **Blocked** when KS active |

---

## 3. Build-Time Only Connections

Running `npm run download-core` (for developers or CI) downloads pinned releases over HTTPS and verifies SHA-256 checksums + Authenticode:
- `github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-windows-64.zip`
- `www.wintun.net/builds/wintun-0.14.1.zip`
- `github.com/artem-russkikh/wireproxy-awg/releases/download/v1.0.18/wireproxy_windows_amd64.tar.gz`

End users installing AURA VPN via `AURA VPN_1.0.0-rc.1_x64-setup.exe` already receive verified binaries bundled offline inside the installer.
