'use strict';

const crypto = require('crypto');

// Minimal, savunmacı PE (Windows) ayrıştırıcı. Harici bağımlılık yok.
// Amaç: başlık, section ve import tablosu gibi gerçek verileri AI'ya sunmak.
// Tüm okumalar sınır kontrollü; bozuk/kötü niyetli dosyada güvenli biçimde durur.

const MACHINE = {
  0x014c: 'x86 (i386)',
  0x8664: 'x64 (AMD64)',
  0x01c0: 'ARM',
  0xaa64: 'ARM64',
  0x0200: 'IA64'
};

const SUBSYSTEM = {
  1: 'native',
  2: 'Windows GUI',
  3: 'Windows CUI (konsol)',
  5: 'OS/2 CUI',
  7: 'POSIX CUI',
  9: 'Windows CE GUI',
  10: 'EFI application',
  16: 'XBOX'
};

const DIR_NAMES = [
  'export', 'import', 'resource', 'exception', 'security', 'basereloc',
  'debug', 'architecture', 'globalptr', 'tls', 'load_config', 'bound_import',
  'iat', 'delay_import', 'com_descriptor (.NET)', 'reserved'
];

function safe(buf, off, len) {
  return off >= 0 && off + len <= buf.length;
}

function rvaToOffset(sections, rva) {
  for (const s of sections) {
    if (rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize)) {
      return s.rawPointer + (rva - s.virtualAddress);
    }
  }
  return null;
}

function readCString(buf, off, max = 256) {
  if (off == null || off < 0 || off >= buf.length) return null;
  let end = off;
  while (end < buf.length && end - off < max && buf[end] !== 0) end++;
  return buf.toString('latin1', off, end);
}

function parsePE(buf) {
  const result = { format: 'PE', warnings: [] };

  if (!safe(buf, 0x3c, 4)) throw new Error('Dosya PE DOS başlığı için fazla küçük');
  const peOff = buf.readUInt32LE(0x3c);
  if (!safe(buf, peOff, 24) || buf.toString('latin1', peOff, peOff + 4) !== 'PE\u0000\u0000') {
    throw new Error('Geçerli PE imzası bulunamadı');
  }

  // COFF File Header
  const coff = peOff + 4;
  const machine = buf.readUInt16LE(coff);
  const numSections = buf.readUInt16LE(coff + 2);
  const timeDateStamp = buf.readUInt32LE(coff + 4);
  const sizeOfOptional = buf.readUInt16LE(coff + 16);
  const characteristics = buf.readUInt16LE(coff + 18);

  result.machine = MACHINE[machine] || `0x${machine.toString(16)}`;
  result.numberOfSections = numSections;
  result.timeDateStamp = new Date(timeDateStamp * 1000).toISOString();
  result.characteristics = {
    raw: `0x${characteristics.toString(16)}`,
    isDll: !!(characteristics & 0x2000),
    isExecutable: !!(characteristics & 0x0002),
    largeAddressAware: !!(characteristics & 0x0020)
  };

  // Optional Header
  const opt = coff + 20;
  const magic = safe(buf, opt, 2) ? buf.readUInt16LE(opt) : 0;
  const isPlus = magic === 0x20b; // PE32+
  result.bits = isPlus ? 64 : 32;
  result.optionalMagic = isPlus ? 'PE32+ (64-bit)' : magic === 0x10b ? 'PE32 (32-bit)' : `0x${magic.toString(16)}`;

  if (safe(buf, opt, 64)) {
    result.entryPointRVA = '0x' + buf.readUInt32LE(opt + 16).toString(16);
    result.imageBase = isPlus
      ? '0x' + buf.readBigUInt64LE(opt + 24).toString(16)
      : '0x' + buf.readUInt32LE(opt + 28).toString(16);
    const subOff = opt + 68;
    if (safe(buf, subOff, 2)) {
      const sub = buf.readUInt16LE(subOff);
      result.subsystem = SUBSYSTEM[sub] || `0x${sub.toString(16)}`;
    }
    // DllCharacteristics -> güvenlik korumaları
    if (safe(buf, opt + 70, 2)) {
      const dc = buf.readUInt16LE(opt + 70);
      result.protections = {
        aslr: !!(dc & 0x0040), // DYNAMIC_BASE
        highEntropyVA: !!(dc & 0x0020),
        dep: !!(dc & 0x0100), // NX_COMPAT
        seh: !(dc & 0x0400), // NO_SEH ters
        cfg: !!(dc & 0x4000), // GUARD_CF (Control Flow Guard)
        forceIntegrity: !!(dc & 0x0080),
        appContainer: !!(dc & 0x1000)
      };
    }
  }

  // Data Directories
  const ddOff = opt + (isPlus ? 112 : 96);
  const numDD = safe(buf, opt + (isPlus ? 108 : 92), 4) ? buf.readUInt32LE(opt + (isPlus ? 108 : 92)) : 0;
  const dirs = [];
  for (let i = 0; i < Math.min(numDD, 16); i++) {
    const e = ddOff + i * 8;
    if (!safe(buf, e, 8)) break;
    const rva = buf.readUInt32LE(e);
    const size = buf.readUInt32LE(e + 4);
    dirs.push({ name: DIR_NAMES[i] || `dir${i}`, rva, size });
  }
  result.isDotNet = !!(dirs[14] && dirs[14].rva);

  // Section Table
  const secOff = opt + sizeOfOptional;
  const sections = [];
  for (let i = 0; i < numSections; i++) {
    const s = secOff + i * 40;
    if (!safe(buf, s, 40)) {
      result.warnings.push('Section tablosu kesildi');
      break;
    }
    const name = buf.toString('latin1', s, s + 8).replace(/\u0000+$/, '');
    const virtualSize = buf.readUInt32LE(s + 8);
    const virtualAddress = buf.readUInt32LE(s + 12);
    const rawSize = buf.readUInt32LE(s + 16);
    const rawPointer = buf.readUInt32LE(s + 20);
    const chars = buf.readUInt32LE(s + 36);
    sections.push({
      name,
      virtualAddress,
      virtualSize,
      rawPointer,
      rawSize,
      flags: {
        code: !!(chars & 0x20),
        initData: !!(chars & 0x40),
        execute: !!(chars & 0x20000000),
        write: !!(chars & 0x80000000),
        read: !!(chars & 0x40000000)
      }
    });
  }
  result.sections = sections.map((s) => ({
    name: s.name,
    virtualAddress: '0x' + s.virtualAddress.toString(16),
    virtualSize: s.virtualSize,
    rawPointer: '0x' + s.rawPointer.toString(16),
    rawSize: s.rawSize,
    flags: s.flags
  }));

  // Imports
  result.imports = parseImports(buf, sections, dirs[1], isPlus);
  result.imphash = computeImphash(result.imports);

  // Exports (DLL'lerde ve bazı exe'lerde)
  result.exports = parseExports(buf, sections, dirs[0]);

  // Debug dizini -> PDB yolu
  result.debug = parseDebug(buf, sections, dirs[6]);

  // Resources özeti (ikon, sürüm bilgisi, manifest)
  result.resources = parseResourcesSummary(buf, sections, dirs[2]);

  return result;
}

// imphash: içe aktarılan "dll.fonksiyon" listesinin MD5'i (örnek eşleştirmede standart)
function computeImphash(imports) {
  if (!imports || !imports.length) return null;
  const parts = [];
  for (const imp of imports) {
    const dll = imp.dll.toLowerCase().replace(/\.(dll|ocx|sys)$/i, '');
    for (const fn of imp.functions || []) {
      if (fn.startsWith('#ordinal')) parts.push(dll + '.' + fn.replace('#ordinal:', 'ord'));
      else parts.push(dll + '.' + fn.toLowerCase());
    }
  }
  if (!parts.length) return null;
  return crypto.createHash('md5').update(parts.join(',')).digest('hex');
}

function parseExports(buf, sections, dir) {
  if (!dir || !dir.rva) return null;
  const off = rvaToOffset(sections, dir.rva);
  if (off == null || !safe(buf, off, 40)) return null;
  try {
    const nameRVA = buf.readUInt32LE(off + 12);
    const numFns = buf.readUInt32LE(off + 20);
    const numNames = buf.readUInt32LE(off + 24);
    const namesRVA = buf.readUInt32LE(off + 32);
    const dllName = readCString(buf, rvaToOffset(sections, nameRVA));
    const names = [];
    const npOff = rvaToOffset(sections, namesRVA);
    for (let i = 0; i < Math.min(numNames, 2000) && npOff != null; i++) {
      if (!safe(buf, npOff + i * 4, 4)) break;
      const nRVA = buf.readUInt32LE(npOff + i * 4);
      const n = readCString(buf, rvaToOffset(sections, nRVA));
      if (n) names.push(n);
      if (names.length >= 1000) break;
    }
    return { dllName, totalFunctions: numFns, namedExports: numNames, names };
  } catch {
    return null;
  }
}

const DEBUG_TYPES = { 2: 'CodeView (PDB)', 4: 'Misc', 9: 'VC Feature', 12: 'POGO', 13: 'Reproducible', 16: 'Ex-DLL' };

function parseDebug(buf, sections, dir) {
  if (!dir || !dir.rva) return null;
  const off = rvaToOffset(sections, dir.rva);
  if (off == null) return null;
  const entries = [];
  let pdbPath = null;
  const count = Math.min(Math.floor(dir.size / 28), 32);
  for (let i = 0; i < count; i++) {
    const e = off + i * 28;
    if (!safe(buf, e, 28)) break;
    const type = buf.readUInt32LE(e + 12);
    const dataOff = buf.readUInt32LE(e + 24); // PointerToRawData (dosya offseti)
    entries.push(DEBUG_TYPES[type] || ('type' + type));
    if (type === 2 && safe(buf, dataOff, 24)) {
      // CodeView RSDS: 'RSDS' + GUID(16) + age(4) + path(asciiz)
      if (buf.toString('latin1', dataOff, dataOff + 4) === 'RSDS') {
        pdbPath = readCString(buf, dataOff + 24, 260);
      }
    }
  }
  if (!entries.length) return null;
  return { types: [...new Set(entries)], pdbPath };
}

const RES_TYPES = { 1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU', 5: 'DIALOG', 6: 'STRING', 9: 'ACCELERATOR', 10: 'RCDATA', 14: 'GROUP_ICON', 16: 'VERSION', 24: 'MANIFEST' };

function parseResourcesSummary(buf, sections, dir) {
  if (!dir || !dir.rva) return null;
  const base = rvaToOffset(sections, dir.rva);
  if (base == null || !safe(buf, base, 16)) return null;
  try {
    const numNamed = buf.readUInt16LE(base + 12);
    const numId = buf.readUInt16LE(base + 14);
    const types = [];
    for (let i = 0; i < Math.min(numNamed + numId, 64); i++) {
      const e = base + 16 + i * 8;
      if (!safe(buf, e, 8)) break;
      const nameOrId = buf.readUInt32LE(e);
      if (!(nameOrId & 0x80000000)) {
        types.push(RES_TYPES[nameOrId] || ('ID_' + nameOrId));
      }
    }
    return {
      typeCount: numNamed + numId,
      types: [...new Set(types)],
      hasVersion: types.includes('VERSION'),
      hasManifest: types.includes('MANIFEST'),
      hasIcon: types.includes('ICON') || types.includes('GROUP_ICON')
    };
  } catch {
    return null;
  }
}

function parseImports(buf, sections, importDir, isPlus) {
  const out = [];
  if (!importDir || !importDir.rva) return out;
  let off = rvaToOffset(sections, importDir.rva);
  if (off == null) return out;

  // Import Directory Table: 20 bayt/giriş, sıfır girişte biter
  for (let guard = 0; guard < 512; guard++) {
    if (!safe(buf, off, 20)) break;
    const origFirstThunk = buf.readUInt32LE(off);
    const nameRVA = buf.readUInt32LE(off + 12);
    const firstThunk = buf.readUInt32LE(off + 16);
    if (origFirstThunk === 0 && nameRVA === 0 && firstThunk === 0) break;

    const dllName = readCString(buf, rvaToOffset(sections, nameRVA)) || '(bilinmeyen)';
    const funcs = [];
    const thunkRVA = origFirstThunk || firstThunk;
    let tOff = rvaToOffset(sections, thunkRVA);
    const step = isPlus ? 8 : 4;
    const ordinalFlag = isPlus ? 0x8000000000000000n : 0x80000000;

    for (let i = 0; tOff != null && i < 2000; i++) {
      if (!safe(buf, tOff + i * step, step)) break;
      let entry = isPlus ? buf.readBigUInt64LE(tOff + i * step) : BigInt(buf.readUInt32LE(tOff + i * step));
      if (entry === 0n) break;
      const flag = isPlus ? ordinalFlag : BigInt(ordinalFlag);
      if (entry & flag) {
        funcs.push('#ordinal:' + (entry & 0xffffn).toString());
      } else {
        const hintNameOff = rvaToOffset(sections, Number(entry & 0x7fffffffn));
        const fn = readCString(buf, hintNameOff == null ? null : hintNameOff + 2);
        if (fn) funcs.push(fn);
      }
      if (funcs.length >= 500) break;
    }
    out.push({ dll: dllName, functionCount: funcs.length, functions: funcs });
    off += 20;
  }
  return out;
}

module.exports = { parsePE };
