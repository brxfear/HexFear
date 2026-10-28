'use strict';

// Minimal, savunmacı ELF (Linux/Unix) ayrıştırıcı. Harici bağımlılık yok.
// Başlık, section listesi ve dinamik bağımlılıklar (DT_NEEDED) çıkarılır.

const ET = { 0: 'none', 1: 'relocatable', 2: 'executable', 3: 'shared object (PIE/so)', 4: 'core' };
const MACHINE = {
  0x03: 'x86 (i386)', 0x3e: 'x64 (AMD64)', 0x28: 'ARM', 0xb7: 'ARM64 (AArch64)',
  0x08: 'MIPS', 0x14: 'PowerPC', 0xf3: 'RISC-V'
};
const SHT_STRTAB = 3;
const SHT_DYNAMIC = 6;

function safe(buf, off, len) {
  return off >= 0 && off + len <= buf.length;
}

function readCString(buf, off, max = 256) {
  if (off == null || off < 0 || off >= buf.length) return null;
  let end = off;
  while (end < buf.length && end - off < max && buf[end] !== 0) end++;
  return buf.toString('latin1', off, end);
}

function parseELF(buf) {
  if (!safe(buf, 0, 20)) throw new Error('ELF başlığı için fazla küçük');
  const is64 = buf[4] === 2;
  const le = buf[5] === 1;
  if (!le) {
    return { format: 'ELF', note: 'Big-endian ELF: sadece temel başlık okundu', bits: is64 ? 64 : 32 };
  }

  const r16 = (o) => buf.readUInt16LE(o);
  const r32 = (o) => buf.readUInt32LE(o);
  const rN = (o) => (is64 ? Number(buf.readBigUInt64LE(o)) : buf.readUInt32LE(o));

  const result = { format: 'ELF', warnings: [] };
  result.bits = is64 ? 64 : 32;
  result.endian = 'little';
  const eType = r16(16);
  const eMachine = r16(18);
  result.type = ET[eType] || `0x${eType.toString(16)}`;
  result.machine = MACHINE[eMachine] || `0x${eMachine.toString(16)}`;
  result.entryPoint = '0x' + rN(24).toString(16);

  const shoff = is64 ? rN(40) : r32(32);
  const shentsize = is64 ? r16(58) : r16(46);
  const shnum = is64 ? r16(60) : r16(48);
  const shstrndx = is64 ? r16(62) : r16(50);

  // Section header string tablosu
  const sections = [];
  let shstrOff = null;
  if (shoff && shentsize && safe(buf, shoff + shstrndx * shentsize, shentsize)) {
    const e = shoff + shstrndx * shentsize;
    shstrOff = is64 ? rN(e + 24) : r32(e + 16);
  }

  for (let i = 0; i < Math.min(shnum, 256); i++) {
    const e = shoff + i * shentsize;
    if (!safe(buf, e, shentsize)) {
      result.warnings.push('Section tablosu kesildi');
      break;
    }
    const nameIdx = r32(e);
    const type = r32(e + 4);
    const addr = is64 ? rN(e + 16) : r32(e + 12);
    const offset = is64 ? rN(e + 24) : r32(e + 16);
    const size = is64 ? rN(e + 32) : r32(e + 20);
    const name = shstrOff != null ? readCString(buf, shstrOff + nameIdx) : `#${i}`;
    sections.push({ name, type, addr, offset, size });
  }

  result.sections = sections.map((s) => ({
    name: s.name,
    addr: '0x' + s.addr.toString(16),
    size: s.size
  }));

  // Dinamik bağımlılıklar (DT_NEEDED) ve SONAME
  result.neededLibraries = parseDynamic(buf, sections, is64);

  // Dinamik semboller (içe/dışa aktarılan fonksiyonlar)
  result.dynamicSymbols = parseDynSym(buf, sections, is64);

  // Program header'lar: interpreter, GNU_STACK, GNU_RELRO
  const ph = parseProgramHeaders(buf, is64);
  if (ph.interp != null) result.interpreter = readCString(buf, ph.interp);

  // Güvenlik korumaları
  const hasCanary = result.dynamicSymbols.some((s) => s === '__stack_chk_fail' || s === '__stack_chk_guard');
  const relroSection = sections.find((s) => s.name === '.data.rel.ro');
  result.protections = {
    nx: ph.gnuStack ? !ph.gnuStackExec : true, // GNU_STACK yoksa genelde NX
    pie: eType === 3 && ph.hasInterp, // ET_DYN + interp = PIE
    relro: ph.gnuRelro ? (ph.bindNow ? 'full' : 'partial') : 'yok',
    canary: hasCanary,
    stripped: !sections.some((s) => s.name === '.symtab')
  };

  return result;
}

const PT_INTERP = 3;
const PT_GNU_STACK = 0x6474e551;
const PT_GNU_RELRO = 0x6474e552;

function parseProgramHeaders(buf, is64) {
  const out = { interp: null, hasInterp: false, gnuStack: false, gnuStackExec: false, gnuRelro: false, bindNow: false };
  const phoff = is64 ? Number(buf.readBigUInt64LE(32)) : buf.readUInt32LE(28);
  const phentsize = is64 ? buf.readUInt16LE(54) : buf.readUInt16LE(42);
  const phnum = is64 ? buf.readUInt16LE(56) : buf.readUInt16LE(44);
  if (!phoff || !phentsize) return out;
  for (let i = 0; i < Math.min(phnum, 128); i++) {
    const e = phoff + i * phentsize;
    if (!safe(buf, e, phentsize)) break;
    const type = buf.readUInt32LE(e);
    const flags = is64 ? buf.readUInt32LE(e + 4) : buf.readUInt32LE(e + 24);
    const offset = is64 ? Number(buf.readBigUInt64LE(e + 8)) : buf.readUInt32LE(e + 4);
    if (type === PT_INTERP) { out.interp = offset; out.hasInterp = true; }
    else if (type === PT_GNU_STACK) { out.gnuStack = true; out.gnuStackExec = !!(flags & 0x1); }
    else if (type === PT_GNU_RELRO) { out.gnuRelro = true; }
  }
  return out;
}

const SHT_DYNSYM = 11;

function parseDynSym(buf, sections, is64) {
  const dynsym = sections.find((s) => s.type === SHT_DYNSYM) || sections.find((s) => s.name === '.dynsym');
  if (!dynsym) return [];
  const dynstr = sections.find((s) => s.name === '.dynstr' && s.type === SHT_STRTAB)
    || sections.find((s) => s.type === SHT_STRTAB);
  if (!dynstr) return [];
  const step = is64 ? 24 : 16;
  const out = [];
  const seen = new Set();
  const count = Math.min(Math.floor(dynsym.size / step), 8000);
  for (let i = 0; i < count; i++) {
    const e = dynsym.offset + i * step;
    if (!safe(buf, e, step)) break;
    const nameIdx = buf.readUInt32LE(e);
    if (nameIdx === 0) continue;
    const name = readCString(buf, dynstr.offset + nameIdx, 200);
    if (name && !seen.has(name)) { seen.add(name); out.push(name); }
    if (out.length >= 2000) break;
  }
  return out;
}

function parseDynamic(buf, sections, is64) {
  const needed = [];
  const dyn = sections.find((s) => s.type === SHT_DYNAMIC);
  if (!dyn) return needed;

  // Dinamik string tablosu: genelde .dynstr; basitçe strtab tipli section'lardan seç
  const dynstr = sections.find((s) => s.name === '.dynstr' && s.type === SHT_STRTAB)
    || sections.find((s) => s.type === SHT_STRTAB);
  if (!dynstr) return needed;

  const step = is64 ? 16 : 8;
  const base = dyn.offset;
  for (let i = 0; i < dyn.size / step && i < 4000; i++) {
    const e = base + i * step;
    if (e + step > buf.length) break;
    const tag = is64 ? Number(buf.readBigUInt64LE(e)) : buf.readUInt32LE(e);
    const val = is64 ? Number(buf.readBigUInt64LE(e + 8)) : buf.readUInt32LE(e + 4);
    if (tag === 0) break; // DT_NULL
    if (tag === 1) {
      // DT_NEEDED
      let end = dynstr.offset + val;
      let s = end;
      while (s < buf.length && buf[s] !== 0) s++;
      const name = buf.toString('latin1', end, s);
      if (name) needed.push(name);
    }
  }
  return needed;
}

module.exports = { parseELF };
