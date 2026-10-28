'use strict';

// Bilinen kriptografik sabitleri bayt düzeyinde arar. Varlıkları, o algoritmanın
// kullanıldığına dair güçlü bir ipucudur (CTF/crackme'de çok işe yarar).

const SIGS = [
  {
    name: 'AES S-box', algo: 'AES',
    bytes: [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]
  },
  {
    name: 'AES inv S-box', algo: 'AES',
    bytes: [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb]
  },
  {
    name: 'SHA-256 init (H0)', algo: 'SHA-256',
    bytes: [0x67, 0xe6, 0x09, 0x6a] // 0x6a09e667 little-endian
  },
  {
    name: 'MD5/SHA-1 init (A)', algo: 'MD5 / SHA-1',
    bytes: [0x01, 0x23, 0x45, 0x67] // 0x67452301 little-endian
  },
  {
    name: 'CRC32 table', algo: 'CRC32',
    bytes: [0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77] // 0, 0x77073096
  },
  {
    name: 'SHA-512 init', algo: 'SHA-512',
    bytes: [0x08, 0xc9, 0xbc, 0xf3, 0x67, 0xe6, 0x09, 0x6a] // 0x6a09e667f3bcc908 LE
  }
];

// Base64 alfabesi gibi metinsel imzalar
const TEXT_SIGS = [
  { name: 'Base64 alfabesi', algo: 'Base64', text: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' },
  { name: 'Base64 URL-safe', algo: 'Base64url', text: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' }
];

function detectCrypto(buf) {
  const found = [];
  for (const sig of SIGS) {
    const pat = Buffer.from(sig.bytes);
    const idx = buf.indexOf(pat);
    if (idx !== -1) found.push({ name: sig.name, algo: sig.algo, offset: '0x' + idx.toString(16) });
  }
  for (const sig of TEXT_SIGS) {
    const idx = buf.indexOf(Buffer.from(sig.text, 'latin1'));
    if (idx !== -1) found.push({ name: sig.name, algo: sig.algo, offset: '0x' + idx.toString(16) });
  }
  // Algoritmaya göre tekilleştir (aynı algo birden çok imzayla eşleşebilir)
  const algos = [...new Set(found.map((f) => f.algo))];
  return { algorithms: algos, signatures: found };
}

module.exports = { detectCrypto };
