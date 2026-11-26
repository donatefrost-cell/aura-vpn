import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

const ROOT = path.resolve(import.meta.dirname, '..');
const ICONS_DIR = path.join(ROOT, 'src-tauri', 'icons');
fs.mkdirSync(ICONS_DIR, { recursive: true });

// CRC32 table for valid PNG chunks
const crcTable = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) {
    c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  crcTable[i] = c >>> 0;
}

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function makeChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crcBuf = Buffer.alloc(4);
  const combined = Buffer.concat([typeBuf, data]);
  crcBuf.writeUInt32BE(crc32(combined), 0);
  return Buffer.concat([len, combined, crcBuf]);
}

function encodePng(width, height, rgba) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const stride = width * 4 + 1;
  const raw = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y++) {
    raw[y * stride] = 0; // filter None
    rgba.copy(raw, y * stride + 1, y * width * 4, (y + 1) * width * 4);
  }
  const idat = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([
    signature,
    makeChunk('IHDR', ihdr),
    makeChunk('IDAT', idat),
    makeChunk('IEND', Buffer.alloc(0)),
  ]);
}

function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}

function smoothstep(edge0, edge1, x) {
  const t = clamp((x - edge0) / (edge1 - edge0), 0, 1);
  return t * t * (3 - 2 * t);
}

function mix(a, b, t) {
  return a + (b - a) * t;
}

function blendPixel(buf, idx, r, g, b, a) {
  if (a <= 0) return;
  const sa = clamp(a, 0, 1);
  const da = buf[idx + 3] / 255;
  const outA = sa + da * (1 - sa);
  if (outA <= 0) return;
  buf[idx] = Math.round((r * sa + buf[idx] * da * (1 - sa)) / outA);
  buf[idx + 1] = Math.round((g * sa + buf[idx + 1] * da * (1 - sa)) / outA);
  buf[idx + 2] = Math.round((b * sa + buf[idx + 2] * da * (1 - sa)) / outA);
  buf[idx + 3] = Math.round(outA * 255);
}

// Signed distance to rounded rectangle centered at (0,0)
function sdRoundedBox(px, py, bx, by, r) {
  const qx = Math.abs(px) - bx + r;
  const qy = Math.abs(py) - by + r;
  const out = Math.hypot(Math.max(qx, 0), Math.max(qy, 0));
  const inside = Math.min(Math.max(qx, qy), 0);
  return out + inside - r;
}

// Distance to segment AB
function distToSegment(px, py, ax, ay, bx, by) {
  const pax = px - ax;
  const pay = py - ay;
  const bax = bx - ax;
  const bay = by - ay;
  const h = clamp((pax * bax + pay * bay) / (bax * bax + bay * bay), 0, 1);
  return Math.hypot(pax - bax * h, pay - bay * h);
}

// Distance to orbital open arc centered at (cx, cy) with gap symmetric at bottom (PI/2)
function distToOrbitalArc(px, py, cx, cy, radius, halfGapRad) {
  const dx = px - cx;
  const dy = py - cy;
  let delta = Math.atan2(dy, dx) - Math.PI / 2;
  while (delta > Math.PI) delta -= Math.PI * 2;
  while (delta < -Math.PI) delta += Math.PI * 2;
  if (Math.abs(delta) >= halfGapRad) {
    return Math.abs(Math.hypot(dx, dy) - radius);
  }
  const ep1x = cx + radius * Math.cos(Math.PI / 2 + halfGapRad);
  const ep1y = cy + radius * Math.sin(Math.PI / 2 + halfGapRad);
  const ep2x = cx + radius * Math.cos(Math.PI / 2 - halfGapRad);
  const ep2y = cy + radius * Math.sin(Math.PI / 2 - halfGapRad);
  return Math.min(
    Math.hypot(px - ep1x, py - ep1y),
    Math.hypot(px - ep2x, py - ep2y),
  );
}

function renderAppIcon(size) {
  const buf = Buffer.alloc(size * size * 4);
  const aa = 1.25 / size;
  const half = 0.445;
  const corner = 0.215;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const nx = (x + 0.5) / size - 0.5;
      const ny = (y + 0.5) / size - 0.5;
      const idx = (y * size + x) * 4;

      // Squircle container
      const boxDist = sdRoundedBox(nx, ny, half, half, corner);
      const boxAlpha = 1 - smoothstep(-aa, aa, boxDist);
      if (boxAlpha <= 0) continue;

      // Diagonal rich Material You indigo-to-cyan gradient background
      const diag = clamp((nx + ny + 0.78) / 1.56, 0, 1);
      const topGlow = Math.exp(-((nx + 0.14) ** 2 + (ny + 0.20) ** 2) * 5.2);
      const bgR = mix(30, 14, diag) + topGlow * 28;
      const bgG = mix(27, 116, diag) + topGlow * 22;
      const bgB = mix(75, 144, diag) + topGlow * 62;
      blendPixel(buf, idx, clamp(bgR, 0, 255), clamp(bgG, 0, 255), clamp(bgB, 0, 255), boxAlpha);

      // Subtle inner specular hairline border
      const innerBorder = Math.abs(boxDist + 0.012) - 0.004;
      const borderAlpha = (1 - smoothstep(-aa, aa, innerBorder)) * boxAlpha * 0.22;
      blendPixel(buf, idx, 255, 255, 255, borderAlpha);

      // Orbital halo arc (top sweep with clean negative-space gap around apex)
      const arcDist = distToOrbitalArc(nx, ny, 0.0, 0.015, 0.325, 0.85) - 0.0235;
      const arcAlpha = (1 - smoothstep(-aa, aa, arcDist)) * boxAlpha;
      const tGrad = clamp((nx + ny + 0.55) / 1.1, 0, 1);
      const arcR = mix(199, 103, tGrad);
      const arcG = mix(210, 232, tGrad);
      const arcB = mix(254, 249, tGrad);
      blendPixel(buf, idx, arcR, arcG, arcB, arcAlpha * 0.96);

      // Crisp geometric "A" chevron legs cleanly nested inside halo
      const leftLeg = distToSegment(nx, ny, 0.0, -0.175, -0.165, 0.205) - 0.036;
      const rightLeg = distToSegment(nx, ny, 0.0, -0.175, 0.165, 0.205) - 0.036;
      const chevronDist = Math.min(leftLeg, rightLeg);
      const chevronAlpha = (1 - smoothstep(-aa, aa, chevronDist)) * boxAlpha;
      blendPixel(buf, idx, 255, 255, 255, chevronAlpha);

      // Luminous cyan core node inside A-aperture
      const dotDist = Math.hypot(nx, ny - 0.105) - 0.047;
      const dotAlpha = (1 - smoothstep(-aa, aa, dotDist)) * boxAlpha;
      const coreGrad = clamp((nx + ny + 0.1) / 0.25, 0, 1);
      blendPixel(
        buf,
        idx,
        mix(165, 34, coreGrad),
        mix(243, 211, coreGrad),
        mix(252, 238, coreGrad),
        dotAlpha,
      );
    }
  }
  return encodePng(size, size, buf);
}

const TRAY_STATES = {
  disconnected: {
    bg: [22, 27, 38],
    rim: [100, 116, 139],
    arc: [148, 163, 184],
    chevron: [226, 232, 240],
    core: [148, 163, 184],
    badge: null,
  },
  connecting: {
    bg: [24, 28, 54],
    rim: [129, 140, 248],
    arc: [125, 211, 252],
    chevron: [255, 255, 255],
    core: [56, 189, 248],
    badge: [56, 189, 248],
  },
  connected: {
    bg: [12, 46, 38],
    rim: [52, 211, 153],
    arc: [110, 231, 183],
    chevron: [255, 255, 255],
    core: [52, 211, 153],
    badge: [16, 185, 129],
  },
  reconnecting: {
    bg: [48, 34, 12],
    rim: [251, 191, 36],
    arc: [253, 224, 71],
    chevron: [255, 255, 255],
    core: [251, 191, 36],
    badge: [245, 158, 11],
  },
  error: {
    bg: [56, 18, 24],
    rim: [248, 113, 113],
    arc: [252, 165, 165],
    chevron: [255, 255, 255],
    core: [248, 113, 113],
    badge: [239, 68, 68],
  },
  killswitch: {
    bg: [62, 14, 28],
    rim: [251, 146, 60],
    arc: [253, 164, 175],
    chevron: [255, 255, 255],
    core: [251, 146, 60],
    badge: [244, 63, 94],
  },
};

function renderTrayIcon(size, palette) {
  const buf = Buffer.alloc(size * size * 4);
  const aa = 1.4 / size;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const nx = (x + 0.5) / size - 0.5;
      const ny = (y + 0.5) / size - 0.5;
      const idx = (y * size + x) * 4;

      const r = Math.hypot(nx, ny);
      const circleAlpha = 1 - smoothstep(-aa, aa, r - 0.455);
      if (circleAlpha > 0) {
        blendPixel(buf, idx, palette.bg[0], palette.bg[1], palette.bg[2], circleAlpha);

        const rimDist = Math.abs(r - 0.425) - 0.032;
        const rimAlpha = (1 - smoothstep(-aa, aa, rimDist)) * circleAlpha;
        blendPixel(buf, idx, palette.rim[0], palette.rim[1], palette.rim[2], rimAlpha * 0.85);

        // Bold orbital arc cleanly separated from inner chevron at 16px tray
        const arcDist = distToOrbitalArc(nx, ny, 0.0, 0.015, 0.305, 0.85) - 0.028;
        const arcAlpha = (1 - smoothstep(-aa, aa, arcDist)) * circleAlpha;
        blendPixel(buf, idx, palette.arc[0], palette.arc[1], palette.arc[2], arcAlpha * 0.92);

        // High-contrast 'A' chevron
        const leftLeg = distToSegment(nx, ny, 0.0, -0.165, -0.155, 0.19) - 0.043;
        const rightLeg = distToSegment(nx, ny, 0.0, -0.165, 0.155, 0.19) - 0.043;
        const chevronAlpha = (1 - smoothstep(-aa, aa, Math.min(leftLeg, rightLeg))) * circleAlpha;
        blendPixel(
          buf,
          idx,
          palette.chevron[0],
          palette.chevron[1],
          palette.chevron[2],
          chevronAlpha,
        );

        // Inner core beacon dot
        const dotDist = Math.hypot(nx, ny - 0.10) - 0.056;
        const dotAlpha = (1 - smoothstep(-aa, aa, dotDist)) * circleAlpha;
        blendPixel(buf, idx, palette.core[0], palette.core[1], palette.core[2], dotAlpha);
      }

      // Crisp corner state badge dot (bottom-right) for rapid recognition at 16px
      if (palette.badge) {
        const bx = nx - 0.30;
        const by = ny - 0.30;
        const br = Math.hypot(bx, by);
        const haloAlpha = 1 - smoothstep(-aa, aa, br - 0.165);
        blendPixel(buf, idx, 10, 12, 18, haloAlpha);
        const dotAlpha = 1 - smoothstep(-aa, aa, br - 0.118);
        blendPixel(buf, idx, palette.badge[0], palette.badge[1], palette.badge[2], dotAlpha);
      }
    }
  }
  return encodePng(size, size, buf);
}

function buildIco(entries) {
  // ICONDIR (6 bytes) + N * ICONDIRENTRY (16 bytes) + PNG payloads
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(entries.length, 4);

  let offset = 6 + entries.length * 16;
  const dirEntries = [];
  for (const { size, png } of entries) {
    const entry = Buffer.alloc(16);
    entry[0] = size >= 256 ? 0 : size;
    entry[1] = size >= 256 ? 0 : size;
    entry[2] = 0;
    entry[3] = 0;
    entry.writeUInt16LE(1, 4);
    entry.writeUInt16LE(32, 6);
    entry.writeUInt32LE(png.length, 8);
    entry.writeUInt32LE(offset, 12);
    dirEntries.push(entry);
    offset += png.length;
  }

  return Buffer.concat([header, ...dirEntries, ...entries.map((e) => e.png)]);
}

const p16 = renderAppIcon(16);
const p24 = renderAppIcon(24);
const p32 = renderAppIcon(32);
const p48 = renderAppIcon(48);
const p64 = renderAppIcon(64);
const p128 = renderAppIcon(128);
const p256 = renderAppIcon(256);
const p512 = renderAppIcon(512);

fs.writeFileSync(path.join(ICONS_DIR, '32x32.png'), p32);
fs.writeFileSync(path.join(ICONS_DIR, '128x128.png'), p128);
fs.writeFileSync(path.join(ICONS_DIR, '128x128@2x.png'), p256);
fs.writeFileSync(path.join(ICONS_DIR, 'icon.png'), p512);
fs.writeFileSync(
  path.join(ICONS_DIR, 'icon.ico'),
  buildIco([
    { size: 16, png: p16 },
    { size: 24, png: p24 },
    { size: 32, png: p32 },
    { size: 48, png: p48 },
    { size: 64, png: p64 },
    { size: 128, png: p128 },
    { size: 256, png: p256 },
  ]),
);

for (const [name, palette] of Object.entries(TRAY_STATES)) {
  fs.writeFileSync(path.join(ICONS_DIR, `tray-${name}.png`), renderTrayIcon(32, palette));
}

console.log('Generated AURA VPN v0.5.0 icons & 6 tray icons in', ICONS_DIR);
