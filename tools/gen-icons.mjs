// Generates the PWA icon set. Pure Node (zlib only), so the repo needs no
// image toolchain to rebuild them:  node tools/gen-icons.mjs
//
// Output: rounded-square "any" icons plus a full-bleed maskable icon for
// Android adaptive icons.

import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'web', 'assets');

const ACCENT = [37, 99, 235, 255];   // #2563eb
const WHITE = [255, 255, 255, 255];

// ---------------------------------------------------------------- png ------

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

function encodePNG(width, height, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;   // bit depth
  ihdr[9] = 6;   // RGBA
  ihdr[10] = 0;  // deflate
  ihdr[11] = 0;  // adaptive filtering
  ihdr[12] = 0;  // no interlace

  // Prefix every scanline with filter type 0 (None).
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0;
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// ------------------------------------------------------------ raster ------

/** Signed distance to a rounded rectangle centred at (cx, cy). */function sdRoundRect(px, py, cx, cy, halfW, halfH, r) {
  const qx = Math.abs(px - cx) - (halfW - r);
  const qy = Math.abs(py - cy) - (halfH - r);
  const ax = Math.max(qx, 0);
  const ay = Math.max(qy, 0);
  return Math.hypot(ax, ay) + Math.min(Math.max(qx, qy), 0) - r;
}

/**
 * Draw one icon. `full` fills the whole canvas (maskable); otherwise the
 * background is a rounded square inset by 8%.
 */
function drawIcon(size, { full = false } = {}) {
  const buf = Buffer.alloc(size * size * 4);
  const SS = 3; // supersampling factor, for smooth edges
  const cx = size / 2;

  // Folder geometry, sized relative to the canvas.
  const fw = size * 0.50;
  const fh = size * 0.36;
  const tabW = fw * 0.46;
  const tabH = fh * 0.30;
  const r = size * 0.055;

  const put = (x, y, rgb) => {
    const i = (y * size + x) * 4;
    buf[i] = rgb[0]; buf[i + 1] = rgb[1]; buf[i + 2] = rgb[2]; buf[i + 3] = rgb[3];
  };

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let bgCover = 0;
      let fgCover = 0;

      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const px = x + (sx + 0.5) / SS;
          const py = y + (sy + 0.5) / SS;

          // Background: full bleed or a rounded square.
          const dBg = full
            ? -1
            : sdRoundRect(px, py, cx, cx, size * 0.46, size * 0.46, size * 0.22);
          if (dBg <= 0) bgCover++;

          // Folder: a body plus a raised tab on the top-left, unioned.
          const bodyTop = cx + fh * 0.10;
          const inBody = sdRoundRect(px, py, cx, bodyTop + (fh - tabH) / 2, fw / 2, (fh - tabH) / 2, r) <= 0;
          const inTab = sdRoundRect(px, py, cx - fw / 2 + tabW / 2, bodyTop - tabH / 2 + 1, tabW / 2, tabH / 2, r * 0.7) <= 0;
          if (inBody || inTab) fgCover++;
        }
      }

      const n = SS * SS;
      const bgA = bgCover / n;
      const fgA = fgCover / n;

      let colour;
      if (fgA > 0 && bgA > 0) {
        // Composite the white folder over the accent background.
        colour = [
          Math.round(ACCENT[0] * (1 - fgA) + WHITE[0] * fgA),
          Math.round(ACCENT[1] * (1 - fgA) + WHITE[1] * fgA),
          Math.round(ACCENT[2] * (1 - fgA) + WHITE[2] * fgA),
          255,
        ];
      } else if (fgA > 0) {
        colour = [...WHITE];
      } else if (bgA > 0) {
        colour = [...ACCENT];
      } else {
        colour = [0, 0, 0, 0];
      }

      put(x, y, colour);
    }
  }
  return encodePNG(size, size, buf);
}

// ------------------------------------------------------------- output -----

mkdirSync(OUT, { recursive: true });

const targets = [
  ['icon-192.png', 192, {}],
  ['icon-512.png', 512, {}],
  ['icon-180.png', 180, {}],           // iOS home screen
  ['icon-maskable-512.png', 512, { full: true }],
];

for (const [name, size, opts] of targets) {
  writeFileSync(join(OUT, name), drawIcon(size, opts));
  console.log('wrote', name, `${size}x${size}`);
}
