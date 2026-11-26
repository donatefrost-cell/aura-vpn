# Contributing to AURA VPN

Thank you for helping improve **AURA VPN**!

## Code of Conduct

All contributors and maintainers agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Development Prerequisites (Windows 10/11 x64)

- **Node.js** 22 LTS + `npm`
- **Rust** stable toolchain (`x86_64-pc-windows-msvc`) with `rustfmt` and `clippy`
- **Visual Studio Build Tools 2022** (C++ Desktop workload + Windows 10/11 SDK for `mt.exe` and linker)
- **WebView2 Runtime** (preinstalled on Windows 11 and modern Windows 10)

## Local Setup & Verification

```powershell
# 1. Install frontend dependencies
npm ci

# 2. Download & verify pinned native core binaries (Xray-core, wireproxy-awg, Wintun)
npm run download-core

# 3. Frontend quality gates
npm run test
npx tsc --noEmit
npm run build

# 4. Rust formatting, strict Clippy & UAC-manifested tests
cd src-tauri
cargo fmt --check
cargo clippy --all-targets -- -W clippy::all -D warnings
cargo test --lib --locked
```

> **Note on Rust unit tests**: WFP / Windows Firewall Kill Switch tests require elevation if testing elevated paths; `src-tauri/tests.manifest` embeds `<requestedExecutionLevel level="highestAvailable"/>` when merged via `mt.exe`.

## Pull Request & Security Rules

1. **Never commit secrets, personal IPs, real subscription links, or mock-enabled builds**.
2. Keep frontend UI pure of telemetry, remote fonts, or unvalidated `dangerouslySetInnerHTML`.
3. Any change to network parsers (`src-tauri/src/parser/`), Kill Switch (`kill_switch.rs`), Config Engine (`config_gen.rs`, `config_studio.rs`), or IPC (`commands.rs`) must include unit tests covering invalid/malicious inputs.
4. Do not modify or bypass SHA-256 verification pins in `scripts/download-*.mjs` or pre-launch checks in `src-tauri/src/core_manager.rs` without updating upstream manifests and `THIRD_PARTY_NOTICES.md` + `SBOM.json`.
5. Run `npm run sbom` whenever dependencies or bundled core versions change.
