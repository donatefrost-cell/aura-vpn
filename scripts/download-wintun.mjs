import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const WINTUN_VERSION = '0.14.1';
const WINTUN_URL = `https://www.wintun.net/builds/wintun-${WINTUN_VERSION}.zip`;
const EXPECTED_ZIP_SHA256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51';
const EXPECTED_DLL_SHA256 = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce';

const ROOT = path.resolve(import.meta.dirname, '..');
const CORE_DIR = path.join(ROOT, 'src-tauri', 'resources', 'core');
const WINTUN_DLL = path.join(CORE_DIR, 'wintun.dll');
const WINTUN_LICENSE = path.join(CORE_DIR, 'WINTUN-LICENSE.txt');
const META_FILE = path.join(CORE_DIR, 'wintun-manifest.json');

fs.mkdirSync(CORE_DIR, { recursive: true });

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

function verifyAuthenticode(dllPath) {
  const escaped = dllPath.replace(/'/g, "''");
  const out = execFileSync(
    'powershell.exe',
    [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      `$sig = Get-AuthenticodeSignature -LiteralPath '${escaped}'; if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard LLC') { throw ('Invalid Wintun signature: ' + $sig.Status + ' ' + $sig.SignerCertificate.Subject) }; Write-Output ($sig.Status.ToString() + '|' + $sig.SignerCertificate.Subject)`,
    ],
    { encoding: 'utf8' },
  ).trim();
  console.log(`Verified Wintun Authenticode signature: ${out}`);
}

if (fs.existsSync(WINTUN_DLL) && fs.existsSync(WINTUN_LICENSE) && fs.existsSync(META_FILE)) {
  try {
    const meta = JSON.parse(fs.readFileSync(META_FILE, 'utf8'));
    if (
      meta.version === WINTUN_VERSION &&
      meta.zipSha256 === EXPECTED_ZIP_SHA256 &&
      meta.dllSha256 === EXPECTED_DLL_SHA256 &&
      sha256File(WINTUN_DLL) === EXPECTED_DLL_SHA256
    ) {
      verifyAuthenticode(WINTUN_DLL);
      console.log(`Wintun ${WINTUN_VERSION} already provisioned and verified.`);
      process.exit(0);
    }
  } catch {
    // Re-download if manifest invalid
  }
}

const tmpDir = path.join(ROOT, '.tmp-wintun');
fs.rmSync(tmpDir, { recursive: true, force: true });
fs.mkdirSync(tmpDir, { recursive: true });

const zipPath = path.join(tmpDir, `wintun-${WINTUN_VERSION}.zip`);
console.log(`Downloading Wintun ${WINTUN_VERSION} from ${WINTUN_URL}...`);

const res = await fetch(WINTUN_URL, {
  headers: { 'User-Agent': 'aura-vpn-build/0.2.0' },
  redirect: 'follow',
});
if (!res.ok) {
  throw new Error(`Failed to download Wintun: HTTP ${res.status} ${res.statusText}`);
}

const buf = Buffer.from(await res.arrayBuffer());
const actualSha = crypto.createHash('sha256').update(buf).digest('hex');
if (actualSha !== EXPECTED_ZIP_SHA256) {
  throw new Error(
    `Wintun SHA-256 verification failed!\nExpected: ${EXPECTED_ZIP_SHA256}\nActual:   ${actualSha}`,
  );
}
console.log(`Verified Wintun ZIP SHA-256: ${actualSha}`);
fs.writeFileSync(zipPath, buf);

const extractDir = path.join(tmpDir, 'extracted');
fs.mkdirSync(extractDir, { recursive: true });

execFileSync(
  'powershell.exe',
  [
    '-NoProfile',
    '-NonInteractive',
    '-Command',
    `Expand-Archive -LiteralPath '${zipPath.replace(/'/g, "''")}' -DestinationPath '${extractDir.replace(/'/g, "''")}' -Force`,
  ],
  { stdio: 'inherit' },
);

const extractedDll = path.join(extractDir, 'wintun', 'bin', 'amd64', 'wintun.dll');
const extractedLic = path.join(extractDir, 'wintun', 'LICENSE.txt');
if (!fs.existsSync(extractedDll)) {
  throw new Error('wintun/bin/amd64/wintun.dll missing from archive');
}

fs.copyFileSync(extractedDll, WINTUN_DLL);
if (fs.existsSync(extractedLic)) {
  fs.copyFileSync(extractedLic, WINTUN_LICENSE);
}

const dllSha256 = sha256File(WINTUN_DLL);
if (dllSha256 !== EXPECTED_DLL_SHA256) {
  fs.rmSync(WINTUN_DLL, { force: true });
  throw new Error(
    `wintun.dll SHA-256 verification failed!\nExpected: ${EXPECTED_DLL_SHA256}\nActual:   ${dllSha256}`,
  );
}
verifyAuthenticode(WINTUN_DLL);
fs.writeFileSync(
  META_FILE,
  JSON.stringify(
    {
      component: 'wintun',
      version: WINTUN_VERSION,
      arch: 'amd64',
      license: 'Wintun Prebuilt Binaries License (WireGuard LLC)',
      sourceUrl: 'https://www.wintun.net/',
      zipSha256: EXPECTED_ZIP_SHA256,
      dllSha256,
      provisionedAt: new Date().toISOString(),
    },
    null,
    2,
  ),
);

fs.rmSync(tmpDir, { recursive: true, force: true });
console.log(`Provisioned Wintun ${WINTUN_VERSION} (dll SHA-256: ${dllSha256})`);
