import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

function readJson(relPath) {
  return JSON.parse(fs.readFileSync(path.join(rootDir, relPath), 'utf8'));
}

function parseCargoLock(lockText) {
  const packages = [];
  const blocks = lockText.split(/\r?\n\[\[package\]\]\r?\n/).slice(1);
  for (const block of blocks) {
    const nameMatch = block.match(/^name = "([^"]+)"/m);
    const versionMatch = block.match(/^version = "([^"]+)"/m);
    const sourceMatch = block.match(/^source = "([^"]+)"/m);
    const checksumMatch = block.match(/^checksum = "([^"]+)"/m);
    if (!nameMatch || !versionMatch) continue;
    packages.push({
      name: nameMatch[1],
      version: versionMatch[1],
      source: sourceMatch ? sourceMatch[1] : null,
      checksum: checksumMatch ? checksumMatch[1] : null,
    });
  }
  return packages;
}

function formatCdxLicense(rawLicense) {
  if (!rawLicense || typeof rawLicense !== 'string') return undefined;
  const trimmed = rawLicense.trim();
  if (!trimmed || trimmed === 'UNKNOWN') return undefined;
  const normalized = trimmed.replaceAll('/', ' OR ');
  if (/[()\s]/.test(normalized)) {
    return [{ expression: normalized }];
  }
  return [{ license: { id: normalized } }];
}

function parseSriHash(integrity) {
  if (!integrity || typeof integrity !== 'string') return undefined;
  const match = integrity.match(/^(sha512|sha384|sha256)-([A-Za-z0-9+/=]+)$/);
  if (!match) return undefined;
  const algMap = { sha512: 'SHA-512', sha384: 'SHA-384', sha256: 'SHA-256' };
  const hex = Buffer.from(match[2], 'base64').toString('hex');
  return [{ alg: algMap[match[1]], content: hex }];
}

function loadCargoMetadata() {
  try {
    const raw = execFileSync(
      'cargo',
      [
        'metadata',
        '--manifest-path',
        path.join(rootDir, 'src-tauri', 'Cargo.toml'),
        '--locked',
        '--format-version',
        '1',
        '--filter-platform',
        'x86_64-pc-windows-msvc',
      ],
      { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
    );
    const parsed = JSON.parse(raw);
    const map = new Map();
    for (const p of parsed.packages ?? []) {
      map.set(`${p.name}@${p.version}`, {
        license: p.license ?? null,
        repository: p.repository ?? p.homepage ?? null,
        source: p.source ?? null,
      });
    }
    return map;
  } catch (err) {
    console.warn(`cargo metadata unavailable (${err.message}); falling back to Cargo.lock only`);
    return null;
  }
}

const pkg = readJson('package.json');
const pkgLock = readJson('package-lock.json');
const cargoLockText = fs.readFileSync(path.join(rootDir, 'src-tauri', 'Cargo.lock'), 'utf8');
const coreManifest = readJson('src-tauri/resources/core/core-manifest.json');
const awgManifest = readJson('src-tauri/resources/core/awg-manifest.json');
const wintunManifest = readJson('src-tauri/resources/core/wintun-manifest.json');

const components = [];
const dependencies = [];
const rootRef = `pkg:generic/aura-vpn@${pkg.version}`;
const rootDependsOn = [];

// 1. Embedded native binaries
const embeddedBinaries = [
  {
    name: coreManifest.core || 'xray-core',
    version: coreManifest.version,
    license: coreManifest.license || 'MPL-2.0',
    sha256: coreManifest.exeSha256,
    archiveSha256: coreManifest.zipSha256,
    file: 'src-tauri/resources/core/xray.exe',
    url: 'https://github.com/XTLS/Xray-core',
  },
  {
    name: awgManifest.component || 'wireproxy-awg',
    version: awgManifest.version,
    license: awgManifest.license || 'ISC',
    sha256: awgManifest.exeSha256,
    archiveSha256: awgManifest.tarSha256,
    file: 'src-tauri/resources/core/wireproxy-awg.exe',
    url: 'https://github.com/artem-russkikh/wireproxy-awg',
  },
  {
    name: wintunManifest.component || 'wintun',
    version: wintunManifest.version,
    license: null,
    licenseName: 'Wintun Prebuilt Binaries License (WireGuard LLC)',
    sha256: wintunManifest.dllSha256,
    archiveSha256: wintunManifest.zipSha256,
    file: 'src-tauri/resources/core/wintun.dll',
    url: 'https://www.wintun.net/',
  },
];

for (const bin of embeddedBinaries) {
  const bomRef = `pkg:generic/${bin.name}@${bin.version}?arch=x86_64&os=windows`;
  const licenses = bin.license
    ? formatCdxLicense(bin.license)
    : [{ license: { name: bin.licenseName } }];
  components.push({
    'bom-ref': bomRef,
    type: 'library',
    name: bin.name,
    version: bin.version,
    scope: 'required',
    purl: bomRef,
    licenses,
    hashes: bin.sha256 ? [{ alg: 'SHA-256', content: bin.sha256 }] : undefined,
    externalReferences: [{ type: 'website', url: bin.url }],
    properties: [
      { name: 'aura:ecosystem', value: 'native-binary' },
      { name: 'aura:resourcePath', value: bin.file },
      ...(bin.archiveSha256 ? [{ name: 'aura:archiveSha256', value: bin.archiveSha256 }] : []),
    ],
  });
  rootDependsOn.push(bomRef);
}

// 2. npm locked packages
let npmProdCount = 0;
let npmDevCount = 0;
const seenNpmRefs = new Set();
for (const [pkgPath, meta] of Object.entries(pkgLock.packages ?? {})) {
  if (!pkgPath || !meta.version) continue;
  const cleanName = pkgPath.replace(/^node_modules\//, '').split('node_modules/').pop();
  if (!cleanName || cleanName === pkg.name) continue;
  const purlName = cleanName.startsWith('@') ? `%40${cleanName.slice(1)}` : cleanName;
  const purl = `pkg:npm/${purlName}@${meta.version}`;
  if (seenNpmRefs.has(purl)) continue;
  seenNpmRefs.add(purl);

  const isDev = Boolean(meta.dev);
  if (isDev) npmDevCount += 1;
  else npmProdCount += 1;

  const comp = {
    'bom-ref': purl,
    type: 'library',
    name: cleanName,
    version: meta.version,
    scope: isDev ? 'optional' : 'required',
    purl,
    properties: [{ name: 'aura:ecosystem', value: 'npm' }],
  };
  const licenses = formatCdxLicense(meta.license);
  if (licenses) comp.licenses = licenses;
  const hashes = parseSriHash(meta.integrity);
  if (hashes) comp.hashes = hashes;
  components.push(comp);
  if (!isDev) rootDependsOn.push(purl);
}

// 3. Cargo crates (excluding root aura-vpn crate)
const cargoLockPkgs = parseCargoLock(cargoLockText);
const cargoMeta = loadCargoMetadata();
let cargoCount = 0;
const seenCargoRefs = new Set();

for (const crate of cargoLockPkgs) {
  if (crate.name === 'aura-vpn' && crate.source === null) continue;
  const key = `${crate.name}@${crate.version}`;
  const meta = cargoMeta?.get(key);
  if (cargoMeta && !meta) continue;
  const purl = `pkg:cargo/${crate.name}@${crate.version}`;
  if (seenCargoRefs.has(purl)) continue;
  seenCargoRefs.add(purl);
  cargoCount += 1;

  const comp = {
    'bom-ref': purl,
    type: 'library',
    name: crate.name,
    version: crate.version,
    scope: 'required',
    purl,
    properties: [{ name: 'aura:ecosystem', value: 'cargo' }],
  };
  const licenses = formatCdxLicense(meta?.license);
  if (licenses) comp.licenses = licenses;
  if (crate.checksum) {
    comp.hashes = [{ alg: 'SHA-256', content: crate.checksum }];
  }
  if (meta?.repository) {
    comp.externalReferences = [{ type: 'vcs', url: meta.repository }];
  }
  components.push(comp);
  rootDependsOn.push(purl);
}

dependencies.push({
  ref: rootRef,
  dependsOn: Array.from(new Set(rootDependsOn)),
});

const sbom = {
  $schema: 'http://cyclonedx.org/schema/bom-1.5.schema.json',
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${crypto.randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: {
      components: [
        {
          type: 'application',
          name: 'aura-sbom-generator',
          version: pkg.version,
        },
      ],
    },
    component: {
      'bom-ref': rootRef,
      type: 'application',
      name: 'AURA VPN',
      version: pkg.version,
      licenses: [{ license: { id: 'Apache-2.0' } }],
      purl: rootRef,
      properties: [
        { name: 'aura:identifier', value: 'app.auravpn.desktop' },
        { name: 'aura:platform', value: 'windows-x86_64' },
      ],
    },
  },
  components,
  dependencies,
};

const outPath = path.join(rootDir, 'SBOM.json');
fs.writeFileSync(outPath, `${JSON.stringify(sbom, null, 2)}\n`, 'utf8');
console.log(
  `CycloneDX 1.5 SBOM generated: ${components.length} components (npm=${npmProdCount} prod + ${npmDevCount} devOptional, cargo=${cargoCount}, native=${embeddedBinaries.length}) -> ${outPath}`,
);
