import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const XRAY_VERSION = 'v26.11.9';
const XRAY_URL = `https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-windows-64.zip`;
const EXPECTED_ZIP_SHA256 = '1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d';
const EXPECTED_EXE_SHA256 = '1ca7a2cf61ba2c5d20b21a80d405b57933939751081cb289f07bd8ddf7cc3185';

const ROOT = path.resolve(import.meta.dirname, '..');
const CORE_DIR = path.join(ROOT, 'src-tauri', 'resources', 'core');
const XRAY_EXE = path.join(CORE_DIR, 'xray.exe');
const XRAY_LICENSE = path.join(CORE_DIR, 'XRAY-LICENSE.txt');
const META_FILE = path.join(CORE_DIR, 'core-manifest.json');

fs.mkdirSync(CORE_DIR, { recursive: true });

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

if (fs.existsSync(XRAY_EXE) && fs.existsSync(XRAY_LICENSE) && fs.existsSync(META_FILE)) {
  try {
    const meta = JSON.parse(fs.readFileSync(META_FILE, 'utf8'));
    if (
      meta.version === XRAY_VERSION &&
      meta.zipSha256 === EXPECTED_ZIP_SHA256 &&
      meta.exeSha256 === EXPECTED_EXE_SHA256 &&
      sha256File(XRAY_EXE) === EXPECTED_EXE_SHA256
    ) {
      console.log(`Xray-core ${XRAY_VERSION} already provisioned and verified.`);
      process.exit(0);
    }
  } catch {
    // Re-download if manifest is corrupted
  }
}

const tmpDir = path.join(ROOT, '.tmp-xray');
fs.rmSync(tmpDir, { recursive: true, force: true });
fs.mkdirSync(tmpDir, { recursive: true });

const zipPath = path.join(tmpDir, 'Xray-windows-64.zip');
console.log(`Downloading Xray-core ${XRAY_VERSION} from ${XRAY_URL}...`);

const res = await fetch(XRAY_URL, {
  headers: { 'User-Agent': 'aura-vpn-build/0.1.0' },
  redirect: 'follow',
});
if (!res.ok) {
  throw new Error(`Failed to download Xray-core: HTTP ${res.status} ${res.statusText}`);
}

const arrayBuf = await res.arrayBuffer();
const buf = Buffer.from(arrayBuf);
const actualSha = crypto.createHash('sha256').update(buf).digest('hex');
if (actualSha !== EXPECTED_ZIP_SHA256) {
  throw new Error(
    `SHA-256 verification failed!\nExpected: ${EXPECTED_ZIP_SHA256}\nActual:   ${actualSha}`,
  );
}
console.log(`Verified ZIP SHA-256: ${actualSha}`);
fs.writeFileSync(zipPath, buf);

const extractDir = path.join(tmpDir, 'extracted');
fs.mkdirSync(extractDir, { recursive: true });

const systemTar = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe');
const tarCmd = fs.existsSync(systemTar) ? systemTar : 'tar.exe';
execFileSync(tarCmd, ['-xf', zipPath, '-C', extractDir], { stdio: 'inherit' });

const extractedExe = path.join(extractDir, 'xray.exe');
const extractedLic = path.join(extractDir, 'LICENSE');
if (!fs.existsSync(extractedExe)) {
  throw new Error('xray.exe missing from archive');
}

fs.copyFileSync(extractedExe, XRAY_EXE);
if (fs.existsSync(extractedLic)) {
  fs.copyFileSync(extractedLic, XRAY_LICENSE);
} else {
  fs.writeFileSync(XRAY_LICENSE, 'Xray-core is licensed under MPL-2.0: https://github.com/XTLS/Xray-core/blob/main/LICENSE\n');
}

const exeSha256 = sha256File(XRAY_EXE);
if (exeSha256 !== EXPECTED_EXE_SHA256) {
  fs.rmSync(XRAY_EXE, { force: true });
  throw new Error(
    `xray.exe SHA-256 verification failed!\nExpected: ${EXPECTED_EXE_SHA256}\nActual:   ${exeSha256}`,
  );
}
fs.writeFileSync(
  META_FILE,
  JSON.stringify(
    {
      core: 'xray-core',
      version: XRAY_VERSION,
      license: 'MPL-2.0',
      sourceUrl: 'https://github.com/XTLS/Xray-core',
      zipSha256: EXPECTED_ZIP_SHA256,
      exeSha256,
      provisionedAt: new Date().toISOString(),
    },
    null,
    2,
  ),
);

fs.rmSync(tmpDir, { recursive: true, force: true });
console.log(`Provisioned Xray-core ${XRAY_VERSION} (exe SHA-256: ${exeSha256})`);
