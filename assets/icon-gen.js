const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const ROOT = path.resolve(__dirname, '..');

const BG = [0x40, 0x54, 0xC8];

function inRoundRect(x, y, x0, y0, x1, y1, r) {
  const cx = Math.min(Math.max(x, x0 + r), x1 - r);
  const cy = Math.min(Math.max(y, y0 + r), y1 - r);
  const dx = x - cx;
  const dy = y - cy;
  return dx * dx + dy * dy <= r * r;
}

function sampleFlat(u, v, rounded) {
  const inBg = rounded
    ? inRoundRect(u, v, 0.03, 0.03, 0.97, 0.97, 0.19)
    : true;
  if (!inBg) return [0, 0, 0, 0];
  const cx = 0.5, cy = 0.445, ro = 0.150, ri = 0.102;
  const dxc = u - cx, dyc = v - cy;
  const d = Math.sqrt(dxc * dxc + dyc * dyc);
  const inRing = d <= ro && d >= ri && v <= cy;
  const inLegL = u >= 0.350 && u <= 0.398 && v >= cy - 0.004 && v <= 0.530;
  const inLegR = u >= 0.602 && u <= 0.650 && v >= cy - 0.004 && v <= 0.530;
  const inBody = inRoundRect(u, v, 0.300, 0.500, 0.700, 0.790, 0.055);
  if (inRing || inLegL || inLegR || inBody) {
    const kx = u - 0.5, ky = v - 0.605;
    const inKey = (kx * kx + ky * ky <= 0.047 * 0.047) ||
      (u >= 0.4885 && u <= 0.5115 && v >= 0.605 && v <= 0.690);
    if (inKey) return [BG[0], BG[1], BG[2], 255];
    return [255, 255, 255, 255];
  }
  return [BG[0], BG[1], BG[2], 255];
}

function renderRGBA(size, rounded) {
  const ss = 4;
  const out = Buffer.alloc(size * size * 4);
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const u = (px + (sx + 0.5) / ss) / size;
          const v = (py + (sy + 0.5) / ss) / size;
          const c = sampleFlat(u, v, rounded);
          r += c[0]; g += c[1]; b += c[2]; a += c[3];
        }
      }
      const n = ss * ss;
      const o = (py * size + px) * 4;
      out[o] = Math.round(r / n);
      out[o + 1] = Math.round(g / n);
      out[o + 2] = Math.round(b / n);
      out[o + 3] = Math.round(a / n);
    }
  }
  return out;
}

const PX = {
  BK: [0, 0, 0, 255],
  WH: [255, 255, 255, 255],
  FACE: [192, 192, 192, 255],
  HI: [255, 255, 255, 255],
  LO: [128, 128, 128, 255],
  DK: [64, 64, 64, 255],
  NAVY: [0, 0, 128, 255],
  NONE: [0, 0, 0, 0]
};

function pixelArt32() {
  const N = 32;
  const out = Buffer.alloc(N * N * 4);
  for (let py = 0; py < N; py++) {
    for (let px = 0; px < N; px++) {
      const fx = px + 0.5, fy = py + 0.5;
      let c = PX.NONE;
      if (px >= 1 && px <= 30 && py >= 1 && py <= 30) {
        c = PX.FACE;
        if (px <= 2 || py <= 2) c = PX.HI;
        if (px >= 29 || py >= 29) c = PX.DK;
        if (px === 1 || py === 1 || px === 30 || py === 30) c = PX.BK;
        if (px === 2 && py === 2) c = PX.HI;
      }
      const dx = fx - 16.0, dy = fy - 14.0;
      const d = Math.sqrt(dx * dx + dy * dy);
      if (fy <= 14.5 && d <= 6.8 && d >= 3.8) {
        c = PX.LO;
        if (d >= 6.1 || d <= 4.5) c = PX.BK;
        else if (fx < 15.0 && d > 4.5 && d < 5.4) c = PX.WH;
      }
      if (px >= 7 && px <= 25 && py >= 15 && py <= 27) {
        if (px === 7 || px === 25 || py === 15 || py === 27) c = PX.BK;
        else if (px === 8 || py === 16) c = PX.HI;
        else if (px === 24 || py === 26) c = PX.LO;
        else c = PX.FACE;
      }
      const kx = fx - 16.0, ky = fy - 20.0;
      const inKey = (kx * kx + ky * ky <= 2.6 * 2.6) ||
        (px >= 15 && px <= 16 && py >= 20 && py <= 24);
      if (inKey && px > 7 && px < 25 && py > 15 && py < 27) c = PX.NAVY;
      const o = (py * N + px) * 4;
      out[o] = c[0]; out[o + 1] = c[1]; out[o + 2] = c[2]; out[o + 3] = c[3];
    }
  }
  return out;
}

function renderPixelArt(size) {
  const base = pixelArt32();
  const out = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const sx = Math.min(31, Math.floor(x * 32 / size));
      const sy = Math.min(31, Math.floor(y * 32 / size));
      const si = (sy * 32 + sx) * 4;
      const di = (y * size + x) * 4;
      out[di] = base[si];
      out[di + 1] = base[si + 1];
      out[di + 2] = base[si + 2];
      out[di + 3] = base[si + 3];
    }
  }
  return out;
}

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

function pngEncode(rgba, w, h) {
  const stride = w * 4 + 1;
  const raw = Buffer.alloc(stride * h);
  for (let y = 0; y < h; y++) {
    raw[y * stride] = 0;
    rgba.copy(raw, y * stride + 1, y * w * 4, (y + 1) * w * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0))
  ]);
}

function bmpEntry(rgba, size) {
  const xor = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const src = ((size - 1 - y) * size + x) * 4;
      const dst = (y * size + x) * 4;
      xor[dst] = rgba[src + 2];
      xor[dst + 1] = rgba[src + 1];
      xor[dst + 2] = rgba[src];
      xor[dst + 3] = rgba[src + 3];
    }
  }
  const maskRow = Math.ceil(size / 32) * 4;
  const mask = Buffer.alloc(maskRow * size);
  const header = Buffer.alloc(40);
  header.writeUInt32LE(40, 0);
  header.writeInt32LE(size, 4);
  header.writeInt32LE(size * 2, 8);
  header.writeUInt16LE(1, 12);
  header.writeUInt16LE(32, 14);
  return Buffer.concat([header, xor, mask]);
}

function buildIco() {
  const entries = [];
  for (const size of [16, 32, 48]) {
    entries.push({ size, data: bmpEntry(renderPixelArt(size), size) });
  }
  for (const size of [64, 128, 256]) {
    entries.push({ size, data: pngEncode(renderPixelArt(size), size, size) });
  }
  const header = Buffer.alloc(6 + entries.length * 16);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(entries.length, 4);
  let offset = header.length;
  entries.forEach((e, i) => {
    const o = 6 + i * 16;
    header[o] = e.size === 256 ? 0 : e.size;
    header[o + 1] = e.size === 256 ? 0 : e.size;
    header[o + 2] = 0;
    header[o + 3] = 0;
    header.writeUInt16LE(1, o + 4);
    header.writeUInt16LE(32, o + 6);
    header.writeUInt32LE(e.data.length, o + 8);
    header.writeUInt32LE(offset, o + 12);
    offset += e.data.length;
  });
  return Buffer.concat([header].concat(entries.map(e => e.data)));
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

ensureDir(path.join(ROOT, 'win32'));
fs.writeFileSync(path.join(ROOT, 'win32', 'app.ico'), buildIco());

const androidPng = [[48, 'mdpi'], [72, 'hdpi'], [96, 'xhdpi'], [144, 'xxhdpi'], [192, 'xxxhdpi']];
for (const [size, density] of androidPng) {
  const dir = path.join(ROOT, 'android', 'res', 'mipmap-' + density);
  ensureDir(dir);
  fs.writeFileSync(path.join(dir, 'ic_launcher.png'), pngEncode(renderRGBA(size, false), size, size));
}

fs.writeFileSync(path.join(ROOT, 'assets', 'preview.png'), pngEncode(renderRGBA(256, true), 256, 256));

const icoSize = fs.statSync(path.join(ROOT, 'win32', 'app.ico')).size;
console.log('app.ico: ' + icoSize + ' bytes');
console.log('android mipmaps: ' + androidPng.map(p => p[1]).join(', '));
console.log('preview: assets/preview.png');
