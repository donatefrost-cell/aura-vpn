# Руководство разработчика и сборка (DEVELOPMENT)

## Требования к окружению
- Node.js 20+ (`npm.cmd`, `npx.cmd` в Windows PowerShell).
- Rust toolchain (stable MSVC `x86_64-pc-windows-msvc`) + Cargo.
- Visual Studio C++ Build Tools & Windows SDK.
- Tauri CLI (`@tauri-apps/cli`).

## Подготовка встроенных ядер и иконок
```powershell
npm.cmd install
npm.cmd run download-core
npm.cmd run generate-icons
node scripts/generate-sbom.mjs
```

## Проверки и тестирование
- **TypeScript + сборка фронтенда**:
  ```powershell
  npx.cmd tsc --noEmit
  npm.cmd run build
  ```
- **Frontend unit-тесты (Vitest)**:
  ```powershell
  npm.cmd run test
  ```
- **Rust Clippy и unit-тесты**:
  ```powershell
  cargo clippy --manifest-path src-tauri/Cargo.toml --lib -- -W clippy::all -D warnings
  ```
  Примечание: для запуска тестового бинарника Rust с манифестом Windows используйте `cargo rustc --lib --profile test` со встраиванием `src-tauri/tests.manifest`.

## Сборка релизного установщика NSIS
```powershell
npm.cmd run tauri build
```
Готовый установщик создаётся в `src-tauri\target\release\bundle\nsis\AURA VPN_0.8.0_x64-setup.exe`.

## Ключевые модули v0.8.0
- **Backend (Rust, `src-tauri/src/`)**: `core_registry.rs`, `dns_manager.rs`, `tun_manager.rs`, `connection_inspector.rs`, `config_studio.rs`, `network_doctor.rs`, `privacy.rs`, `kill_switch.rs`, `ip_monitor.rs`, `config_analyzer.rs`, `subscription.rs`, `window_state.rs`, `parser/*` & `config_gen.rs`.
- **Frontend (React + TS, `src/`)**: `config/settingsRegistry.ts`, `components/settings/{CoreManagerPanel,AdvancedVpnPanel,DnsManagerPanel,TunManagerPanel,MyIpPanel,NetworkDoctorPanel,PrivacyCenterPanel,SettingMetaRow}.tsx`, `components/{ConfigStudioModal,ConnectionInspectorDrawer,ProtectionCenterModal,TrafficGraph}.tsx`, `views/{HomeView,ServersView,SubscriptionsView,RoutingView,SettingsView}.tsx`.
