# Changelog — AURA VPN

All notable changes to AURA VPN are documented in this file.

## [1.0.0-rc.2] — 2026-11-26 (Release Candidate 2)

### Added
- **Защита Claude и Anthropic (Always-VPN + Anti-RU-Leak)**: Приоритизированная маршрутизация трафика и DNS (`claude.ai`, `*.anthropic.com`, `claude.com`, `*.claude.ai`, обнаруженных `Claude.exe` из WindowsApps/AppData и пользовательских процессов) всегда через VPN поверх режимов `РФ напрямую` и `Только выбранные приложения`. При отключении или неожиданном обрыве VPN до автопереподключения автоматически включается отдельный sublayer WFP (`AURA_CLAUDE_WFP_SUBLAYER_GUID`), блокирующий трафик приложений и IP Claude/Anthropic для защиты от утечек реального/РФ IP (без редактирования системного файла `hosts`).
- **Постоянные «Права администратора навсегда»**: Переключатель в Настройках, Панели TUN и карточке защиты Claude (флаг совместимости Windows `HKCU\...\AppCompatFlags\Layers` `~ RUNASADMIN` + задача Планировщика с `RL HIGHEST` при автозапуске).

### Security & Stability Fixes
- **Надёжность TUN и AmneziaWG (`wireproxy-awg`)**: Переработан подбор физического исходящего интерфейса Windows через нативный kernel API `GetIfTable2` (UTF-16, корректная работа с кириллическими именами вроде «Беспроводная сеть» и обход конкурирующих VPN-адаптеров); для `wireproxy-awg` в TUN отключён `autoOutboundsInterface` на `tun-in` (восстановлен локальный SOCKS5-мост `127.0.0.1`), добавлены безусловные direct-правила loopback/endpoint UDP и пропущен лишний `::/0` маршрут для IPv4-only конфигов.
- **AmneziaWG / WireGuard Парсер**: Сохраняются все CPS-теги `I1..I5` с точкой с запятой (`;`), исправлена фильтрация невалидных/пустых `dns1`/`dns2` в Amnezia-обёртках.
- **Проверка туннеля и старт TUN**: Пре-коннект TCP-пинг сделан рекомендательным для стабильной работы за фильтрами/CDN; ожидание старта TUN теперь контролирует реальную готовность LUID интерфейса Wintun; HTTPS 204-зонд выполняется параллельно (`JoinSet`) с ретраем в TUN и подсказкой при конфликте со сторонними VPN-адаптерами.

## [1.0.0-rc.1] — 2026-11-26 (Release Candidate 1)

### Added
- **Apache-2.0 Open-Source Licensing & Legal Bundle**: Added root [`LICENSE`](LICENSE), expanded [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) with full SIL OFL 1.1, ISC, MPL-2.0, Lucide/Feather, and Wintun notices, and bundled `resources/legal/` inside the NSIS installer.
- **CycloneDX 1.5 SBOM**: Replaced custom BOM schema with standard CycloneDX 1.5 (`npm run sbom`) covering npm (`prod` + `devOptional`), Cargo crates (with SHA-256 checksums and SPDX licenses), and pinned native binaries.
- **Hardened Supply Chain & CI/CD**: Pinned GitHub Actions to 40-char commit SHAs, added Gitleaks secret scanning, `rustsec/audit-check`, CodeQL (`javascript-typescript` & `rust`), Dependabot, build provenance attestation (`actions/attest-build-provenance`), and binary SHA-256 + WireGuard Authenticode verification in `scripts/download-*.mjs`.
- **Release & Security Documentation**: Added [`SECURITY.md`](SECURITY.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), [`THREAT_MODEL.md`](THREAT_MODEL.md), [`NETWORK_BEHAVIOR.md`](NETWORK_BEHAVIOR.md), [`PRIVACY.md`](PRIVACY.md), [`RELEASE_SECURITY.md`](RELEASE_SECURITY.md), [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), and RU/EN `README`.

### Security & Stability Fixes
- **Windows Filtering Platform (WFP) Kill Switch Hardening**: Tightened DHCP IPv4 permit rules to broadcast/RFC1918/link-local destinations; bound TUN interface permit via `ConvertInterfaceAliasToLuid`; excluded non-LAN CIDRs cleanly on persisted exit firewall rules; reconciled/disengaged WFP and proxy guard consistently upon abort.
- **Pre-Launch Core Integrity Enforcement**: Wired `verify_xray_integrity` into Config Studio validation/execution alongside session launch.
- **Network & Anti-SSRF Hardening**: Blocked DoH non-HTTPS / private-IP SSRF and bounded response sizes; restricted direct `ping_server`, `run_ping_all`, `update_rulepack`, `dns_lookup_route`, and update checks while Kill Switch is engaged; pinned GitHub release update URLs to `donatefrost-cell/aura-vpn` and `xtls/xray-core` with semver validation.
- **Parser & Config Guardrails**: Made Raw Xray JSON and Config Studio directive checks case-insensitive, blocked balancer short-prefix bypasses against built-in outbounds (`direct`, `block`, `dns-out`, `api`), fixed UTF-8 multi-byte slicing panic, added Clash YAML recursion depth limits and backslash-parity quote parsing, and allowed bracketed IPv6 tokens safely in WireGuard INI endpoints.
- **Privacy & Redaction**: Improved regex redaction for WireGuard Base64 keys, passed `integrity_note` / `last_reason` / `health.reason` through `redact_secrets()`, randomized device HWID rotation via UUIDv4, isolated `previewApi` completely from production bundles, enabled `freezePrototype: true` and strict CSP (`frame-src 'none'; worker-src 'none'`), and removed unused clipboard write capability.
- **UI/UX & Accessibility Polish**: Fixed draft-commit state across 12 Settings/TUN/DNS sliders and inputs (preventing slider snap-back during drag), eliminated unused `ServerInspectorModal` bloat, aligned `TunnelHealthState` & `DnsMode` types with backend contracts, added dialog ARIA semantics and keyboard activation on server cards, and resolved settings state rollback on IPC error.

## [0.8.0] — Previous Development Milestone
- Added Config Studio (4-layer inspection, Diff, Xray JSON editor), Core Manager, Network Doctor, My IP & Leak Center, Connection Inspector Drawer, TUN Manager, DNS Manager, Privacy & Telemetry Center, and Material 3 Expressive Settings Master-Detail layout.

## [0.7.0] — Security & Smart Config Milestone
- Introduced multi-mode Kill Switch (WFP + Proxy Guard), IP Monitor, Smart Config Engine compatibility checks, RU-bypass quick profile, and Windows Defender `.wake` crash/quarantine hardening.
