# Release Security & Verification — AURA VPN

This document explains how **AURA VPN** binaries and installers are built, verified, and published on GitHub.

---

## 1. Supply Chain & Build Reproducibility

Every release build executes via GitHub Actions (`.github/workflows/ci-release.yml`) on `windows-latest` with:
- **SHA-pinned GitHub Actions** (every third-party `uses:` references a 40-character immutable commit SHA).
- **Minimal `GITHUB_TOKEN` permissions** (`contents: read` for verification; `contents: write`, `id-token: write`, `attestations: write` isolated solely to `release-build` on tag pushes).
- **Pinned Native Core Provisioning (`npm run download-core`)**:
  - `xray.exe` (`v26.11.9`): verifies downloaded ZIP SHA-256 (`1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d`) AND extracted binary SHA-256 (`1ca7a2cf61ba2c5d20b21a80d405b57933939751081cb289f07bd8ddf7cc3185`).
  - `wireproxy-awg.exe` (`v1.0.18`): verifies `.tar.gz` SHA-256 (`0b7c5e72930196b2b3e0c1d79068fad706148e4b5bbe44c8ee6374caf2c3b8b7`) AND extracted binary SHA-256 (`3e59b2c518cf2402f8d858caf977205dfa9277703eddb266a34395c93674bbec`).
  - `wintun.dll` (`0.14.1`): verifies ZIP SHA-256 (`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`), extracted DLL SHA-256 (`e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`), AND Windows Authenticode signature (`Status == Valid`, `CN=WireGuard LLC`).
- **Pre-Release Automated Gates**:
  - `vitest run`, `tsc --noEmit`, `vite build` (asserting 0 `previewApi*` mock chunks in production `dist/assets`).
  - `cargo fmt --check`, `cargo clippy --all-targets -- -W clippy::all -D warnings`, `cargo test --lib --locked` (with `tests.manifest`).
  - `npm audit --audit-level=high`, `rustsec/audit-check`, `gitleaks`, and CodeQL (`javascript-typescript` & `rust`).
- **CycloneDX 1.5 SBOM (`SBOM.json`)** + **`SHA256SUMS.txt`** + **GitHub Build Provenance Attestation** (`actions/attest-build-provenance`).

---

## 2. How Users Verify a Downloaded Release (`PowerShell`)

After downloading `AURA VPN_1.0.0-rc.1_x64-setup.exe`, `SHA256SUMS.txt`, and `SBOM.json` from [GitHub Releases](https://github.com/donatefrost-cell/aura-vpn/releases):

```powershell
# Compute actual SHA-256 of the downloaded installer
Get-FileHash ".\AURA VPN_1.0.0-rc.1_x64-setup.exe" -Algorithm SHA256 | Format-List

# Compare against the official checksum published in SHA256SUMS.txt
Get-Content ".\SHA256SUMS.txt"
```

If GitHub CLI (`gh`) is installed, you can also verify CI-built provenance attestations:

```powershell
gh attestation verify ".\AURA VPN_1.0.0-rc.1_x64-setup.exe" --repo donatefrost-cell/aura-vpn
```

---

## 3. Windows SmartScreen & Unsigned Binary Notice (`v1.0.0-rc.1`)

- `AURA VPN v1.0.0-rc.1` is published **without a commercial EV/OV Authenticode code-signing certificate**.
- Because `aura-vpn.exe` and the NSIS installer are unsigned, **Microsoft Defender SmartScreen** may show *"Windows protected your PC / Unknown publisher"* on newly published releases until file reputation builds or an Authenticode certificate is added via repository secrets (`WINDOWS_SIGN_CERT_BASE64`).
- `wintun.dll` (`0.14.1`) retains its original upstream Authenticode signature from **WireGuard LLC**.
- We intentionally keep `[profile.release]` (`opt-level = 3`, `lto = "thin"`, `strip = false`) without obfuscation or packers (never use UPX) to preserve clean PE structure and minimize heuristic false positives.
