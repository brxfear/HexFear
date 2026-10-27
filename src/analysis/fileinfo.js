'use strict';

const crypto = require('crypto');

// Sihirli baytlardan dosya türü tespiti. İçerik türü analiz hattını belirler.
function detectType(buf) {
  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) {
    return { kind: 'pe', label: 'PE (Windows exe/dll)' }; // MZ
  }
  if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    return { kind: 'elf', label: 'ELF (Linux/Unix binary)' };
  }
  // Mach-O (32/64, LE/BE) ve fat/universal
  const m = buf.length >= 4 ? buf.readUInt32BE(0) : 0;
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca].includes(m)) {
    return { kind: 'macho', label: 'Mach-O (macOS binary)' };
  }
  if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && (buf[2] === 0x03 || buf[2] === 0x05)) {
    // ZIP ailesi: APK/JAR/ZIP ayrımı içerik taramasıyla üst katmanda yapılır
    return { kind: 'zip', label: 'ZIP ailesi (APK/JAR/ZIP)' };
  }
  if (buf.length >= 4 && buf.toString('latin1', 0, 4) === 'dex\n') {
    return { kind: 'dex', label: 'Android DEX' };
  }
  if (buf.length >= 4 && buf.toString('latin1', 0, 4) === '%PDF') {
    return { kind: 'pdf', label: 'PDF' };
  }
  if (buf.length >= 4 && buf.readUInt32LE(0) === 0x0a786564) {
    return { kind: 'dex', label: 'Android DEX' };
  }
  return { kind: 'unknown', label: 'Bilinmeyen / ham ikili' };
}

function hashes(buf) {
  return {
    md5: crypto.createHash('md5').update(buf).digest('hex'),
    sha1: crypto.createHash('sha1').update(buf).digest('hex'),
    sha256: crypto.createHash('sha256').update(buf).digest('hex')
  };
}

module.exports = { detectType, hashes };
