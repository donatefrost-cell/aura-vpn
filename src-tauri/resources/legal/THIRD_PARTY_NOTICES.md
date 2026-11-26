# Third-Party Software Notices (THIRD_PARTY_NOTICES)

**AURA VPN** is licensed under the **Apache License, Version 2.0** (see [`LICENSE`](LICENSE)).
This product includes unmodified third-party native binaries, Rust crates, npm packages, icons, and web fonts. Their licenses and source-availability notices are listed below.

---

## 1. Bundled Native Components (`src-tauri/resources/core/`)

| Component | Version | Architecture | License | Source Code / License File |
| --- | --- | --- | --- | --- |
| **Xray-core** | `v26.11.9` | `windows-amd64` | `MPL-2.0` | Source: <https://github.com/XTLS/Xray-core> · Notice: [XRAY-LICENSE.txt](src-tauri/resources/core/XRAY-LICENSE.txt) |
| **wireproxy-awg** | `v1.0.18` | `windows-amd64` | `ISC` | Source: <https://github.com/artem-russkikh/wireproxy-awg> · Notice: [WIREPROXY-AWG-LICENSE.txt](src-tauri/resources/core/WIREPROXY-AWG-LICENSE.txt) |
| **Wintun** | `0.14.1` | `amd64` | Wintun Prebuilt Binaries License (WireGuard LLC, Authenticode-signed) | Home: <https://www.wintun.net/> · Notice: [WINTUN-LICENSE.txt](src-tauri/resources/core/WINTUN-LICENSE.txt) |

**Pinned SHA-256 digests (`windows-amd64`)**:
- `xray.exe` (`v26.11.9`): `1ca7a2cf61ba2c5d20b21a80d405b57933939751081cb289f07bd8ddf7cc3185` (archive `1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d`)
- `wireproxy-awg.exe` (`v1.0.18`): `3e59b2c518cf2402f8d858caf977205dfa9277703eddb266a34395c93674bbec` (archive `0b7c5e72930196b2b3e0c1d79068fad706148e4b5bbe44c8ee6374caf2c3b8b7`)
- `wintun.dll` (`0.14.1`): `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` (archive `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`, signed by `WireGuard LLC`)

Unmodified MPL-2.0 source code for Xray-core (`v26.11.9`) is available in Executable Form's upstream repository <https://github.com/XTLS/Xray-core/releases/tag/v26.11.9>. Pre-launch SHA-256 verification enforces exact integrity of `xray.exe`, `wireproxy-awg.exe`, and `wintun.dll` before starting a tunnel session.

---

## 2. Frontend Packages & Icons (npm)

- **React / ReactDOM** (`19.3.1`) — `MIT`
- **@tauri-apps/api**, **@tauri-apps/plugin-clipboard-manager**, **@tauri-apps/plugin-single-instance** — `MIT OR Apache-2.0`
- **motion** (`12.x`) — `MIT`
- **Tailwind CSS** (`4.3.5`) — `MIT`
- **Lucide Icons** (`lucide-react` `1.47.0`) — `ISC` (`Copyright (c) 2026 Lucide Icons and Contributors`), with certain icons derived from **Feather** (`Copyright (c) 2013-present Cole Bemis`) under the `MIT` License:

```text
ISC License — Copyright (c) 2026 Lucide Icons and Contributors
Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

MIT License (Feather-derived icons) — Copyright (c) 2013-present Cole Bemis
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

---

## 3. Embedded Fonts (SIL Open Font License 1.1)

The web UI bundles self-hosted fonts via `@fontsource-variable/*` (no external Google Fonts CDN requests):
- **Inter Variable**: `Copyright 2016 The Inter Project Authors (https://github.com/rsms/inter)`
- **Manrope Variable**: `Copyright 2019 The Manrope Project Authors (https://github.com/sharanda/manrope)`
- **JetBrains Mono Variable**: `Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono)`

Full license text required by SIL OFL 1.1 Condition 2:

```text
SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font creation
efforts of academic and linguistic communities, and to provide a free and
open framework in which fonts may be shared and improved in partnership
with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded,
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply
to any document created using the fonts or their derivatives.

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such. This may
include source files, build scripts and documentation.
"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).
"Original Version" refers to the collection of Font Software components as
distributed by the Copyright Holder(s).
"Modified Version" refers to any derivative made by adding to, deleting,
or substituting -- in part or in whole -- any of the components of the
Original Version, by changing formats or by porting the Font Software to a
new environment.
"Author" refers to any designer, engineer, programmer, technical
writer or other person who contributed to the Font Software.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining
a copy of the Font Software, to use, study, copy, merge, embed, modify,
redistributed and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components,
in Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or
in the appropriate machine-readable metadata fields within text or
binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the corresponding
Copyright Holder. This restriction only applies to the primary font name as
presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any
Modified Version, except to acknowledge the contribution(s) of the
Copyright Holder(s) and the Author(s) or with their explicit written
permission.

5) The Font Software, modified or unmodified, in part or in whole,
must be distributed entirely under this license, and must not be
distributed under any other license. The requirement for fonts to remain
under this license does not apply to any document created using the Font
Software.

TERMINATION
This license becomes null and void if any of the above conditions are
not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

---

## 4. Key Rust Crates (Cargo)

- **tauri** (`2.12.x`) — `Apache-2.0 OR MIT`
- **tokio**, **reqwest**, **serde**, **serde_json**, **thiserror**, **sha2**, **zeroize** — `MIT OR Apache-2.0`
- **yaml-rust2** (`0.10.4`, strict YAML parser for Clash profiles) — `MIT OR Apache-2.0`
- **option-ext** (`0.2.0`, transitive dependency of `dirs-sys`) — `MPL-2.0` (<https://crates.io/crates/option-ext>)
- **windows-sys** (`0.61.2`, Windows API & WFP/DPAPI bindings) — `MIT OR Apache-2.0`

A complete machine-readable **CycloneDX 1.5** Software Bill of Materials (`SBOM.json`) covering all locked npm packages, Cargo crates, and bundled native binaries is generated by `npm run sbom` (`node scripts/generate-sbom.mjs`).
