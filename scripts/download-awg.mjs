import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const AWG_VERSION = 'v1.0.18';
const AWG_URL = `https://github.com/artem-russkikh/wireproxy-awg/releases/download/${AWG_VERSION}/wireproxy_windows_amd64.tar.gz`;
const EXPECTED_TAR_SHA256 = '0b7c5e72930196b2b3e0c1d79068fad706148e4b5bbe44c8ee6374caf2c3b8b7';
const EXPECTED_EXE_SHA256 = '3e59b2c518cf2402f8d858caf977205dfa9277703eddb266a34395c93674bbec';

const FULL_ISC_LICENSE = `ISC License

Copyright (c) 2026 Tsz Fung Wong <im@windtfw.com>
AmneziaWG fork: https://github.com/artem-russkikh/wireproxy-awg

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
`;

const ROOT = path.resolve(import.meta.dirname, '..');
const CORE_DIR = path.join(ROOT, 'src-tauri', 'resources', 'core');
const AWG_EXE = path.join(CORE_DIR, 'wireproxy-awg.exe');
const AWG_LICENSE = path.join(CORE_DIR, 'WIREPROXY-AWG-LICENSE.txt');
const META_FILE = path.join(CORE_DIR, 'awg-manifest.json');

fs.mkdirSync(CORE_DIR, { recursive: true });

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

if (fs.existsSync(AWG_EXE) && fs.existsSync(AWG_LICENSE) && fs.existsSync(META_FILE)) {
  try {
    const meta = JSON.parse(fs.readFileSync(META_FILE, 'utf8'));
    if (
      meta.version === AWG_VERSION &&
      meta.tarSha256 === EXPECTED_TAR_SHA256 &&
      meta.exeSha256 === EXPECTED_EXE_SHA256 &&
      sha256File(AWG_EXE) === EXPECTED_EXE_SHA256
    ) {
      console.log(`wireproxy-awg ${AWG_VERSION} already provisioned and verified.`);
      process.exit(0);
    }
  } catch {
    // Re-download if manifest is invalid
  }
}

const tmpDir = path.join(ROOT, '.tmp-awg');
fs.rmSync(tmpDir, { recursive: true, force: true });
fs.mkdirSync(tmpDir, { recursive: true });

const tarPath = path.join(tmpDir, 'wireproxy_windows_amd64.tar.gz');
console.log(`Downloading wireproxy-awg ${AWG_VERSION} from ${AWG_URL}...`);

const res = await fetch(AWG_URL, {
  headers: { 'User-Agent': 'aura-vpn-build/0.3.0' },
  redirect: 'follow',
});
if (!res.ok) {
  throw new Error(`Failed to download wireproxy-awg: HTTP ${res.status} ${res.statusText}`);
}

const buf = Buffer.from(await res.arrayBuffer());
const actualSha = crypto.createHash('sha256').update(buf).digest('hex');
if (actualSha !== EXPECTED_TAR_SHA256) {
  throw new Error(
    `wireproxy-awg SHA-256 verification failed!\nExpected: ${EXPECTED_TAR_SHA256}\nActual:   ${actualSha}`,
  );
}
console.log(`Verified tar.gz SHA-256: ${actualSha}`);
fs.writeFileSync(tarPath, buf);

const extractDir = path.join(tmpDir, 'extracted');
fs.mkdirSync(extractDir, { recursive: true });

const systemTar = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe');
const tarCmd = fs.existsSync(systemTar) ? systemTar : 'tar.exe';
execFileSync(tarCmd, ['-xzf', tarPath, '-C', extractDir], { stdio: 'inherit' });

// Locate wireproxy.exe inside extracted directory (root or nested folder)
function findFile(dir, targetName) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const found = findFile(full, targetName);
      if (found) return found;
    } else if (entry.name.toLowerCase() === targetName) {
      return full;
    }
  }
  return null;
}

const extractedExe = findFile(extractDir, 'wireproxy.exe');
if (!extractedExe) {
  throw new Error('wireproxy.exe missing from archive');
}
const extractedLic = findFile(extractDir, 'license') || findFile(extractDir, 'license.txt');

fs.copyFileSync(extractedExe, AWG_EXE);
if (extractedLic) {
  fs.copyFileSync(extractedLic, AWG_LICENSE);
} else {
  fs.writeFileSync(AWG_LICENSE, FULL_ISC_LICENSE, 'utf8');
}

const exeSha256 = sha256File(AWG_EXE);
if (exeSha256 !== EXPECTED_EXE_SHA256) {
  fs.rmSync(AWG_EXE, { force: true });
  throw new Error(
    `wireproxy-awg.exe SHA-256 verification failed!\nExpected: ${EXPECTED_EXE_SHA256}\nActual:   ${exeSha256}`,
  );
}
fs.writeFileSync(
  META_FILE,
  JSON.stringify(
    {
      component: 'wireproxy-awg',
      version: AWG_VERSION,
      license: 'ISC',
      sourceUrl: 'https://github.com/artem-russkikh/wireproxy-awg',
      tarSha256: EXPECTED_TAR_SHA256,
      exeSha256,
      provisionedAt: new Date().toISOString(),
    },
    null,
    2,
  ),
);

fs.rmSync(tmpDir, { recursive: true, force: true });
console.log(`Provisioned wireproxy-awg ${AWG_VERSION} (exe SHA-256: ${exeSha256})`);
