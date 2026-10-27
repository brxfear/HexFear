'use strict';

// AI ajanının kullanabileceği tersine mühendislik "araçları" (primitifler).
// Hepsi YEREL ve salt-okunur: yüklü dosya tamponu üzerinde çalışır, dosyayı
// değiştirmez, ağa çıkmaz. Her araç JSON-serileştirilebilir sonuç döndürür ve
// çıktı boyutu sınırlanır (token/bellek güvenliği).

const { execFileSync } = require('child_process');
const { extractStrings } = require('../analysis/strings');

let _disasm = undefined; // önbellek: hangi disassembler mevcut

function detectDisassembler() {
  if (_disasm !== undefined) return _disasm;
  for (const bin of ['rizin', 'r2', 'radare2']) {
    try {
      execFileSync(bin, ['-v'], { stdio: 'ignore', timeout: 4000 });
      _disasm = bin;
      return bin;
    } catch {
      /* dene sonraki */
    }
  }
  _disasm = null;
  return null;
}

function hexDump(buf, baseOffset) {
  const lines = [];
  for (let i = 0; i < buf.length; i += 16) {
    const slice = buf.subarray(i, Math.min(i + 16, buf.length));
    const hex = Array.from(slice).map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = Array.from(slice).map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.')).join('');
    lines.push('0x' + (baseOffset + i).toString(16).padStart(8, '0') + '  ' + hex.padEnd(47) + '  ' + ascii);
  }
  return lines.join('\n');
}

function rvaToOffset(sections, rva) {
  for (const s of sections || []) {
    const va = parseInt(s.virtualAddress, 16);
    const rp = parseInt(s.rawPointer, 16);
    const vsize = Math.max(s.virtualSize || 0, s.rawSize || 0);
    if (rva >= va && rva < va + vsize) return rp + (rva - va);
  }
  return null;
}

// ---- Araç tanımları -------------------------------------------------------
const TOOLS = [
  {
    name: 'get_overview',
    description: 'Dosyanın statik analiz özetini verir: tür, hash, entropi, PE/ELF başlık ve section özeti, import/kütüphane sayıları, ilgi çekici string sayısı.',
    schema: { type: 'object', properties: {}, additionalProperties: false },
    run: (ctx) => {
      const r = ctx.report;
      return {
        file: r.file,
        type: r.type,
        hashes: r.hashes,
        entropy: r.entropy,
        structureSummary: summarizeStructure(r.structure),
        stringStats: { total: r.strings.total, interesting: r.strings.interestingCount }
      };
    }
  },
  {
    name: 'list_strings',
    description: "Okunabilir string'leri filtreleyerek listeler. 'contains' ile alt dize ara, 'encoding' ile ascii/utf16le, 'min_length', 'limit', 'offset_start' parametreleri.",
    schema: {
      type: 'object',
      properties: {
        contains: { type: 'string', description: 'Büyük/küçük harf duyarsız alt dize filtresi' },
        encoding: { type: 'string', enum: ['ascii', 'utf16le', 'any'] },
        min_length: { type: 'integer' },
        limit: { type: 'integer', description: 'En fazla kaç sonuç (varsayılan 100)' },
        offset_start: { type: 'integer', description: 'Bu offset ve sonrasındakiler' }
      },
      additionalProperties: false
    },
    run: (ctx, a = {}) => {
      const scan = extractStrings(ctx.buf, { minLen: a.min_length || 4, limit: 200000 });
      let list = scan.strings;
      if (a.encoding && a.encoding !== 'any') list = list.filter((s) => s.enc === a.encoding);
      if (a.offset_start != null) list = list.filter((s) => s.offset >= a.offset_start);
      if (a.contains) {
        const needle = a.contains.toLowerCase();
        list = list.filter((s) => s.text.toLowerCase().includes(needle));
      }
      const limit = Math.min(a.limit || 100, 500);
      return { matched: list.length, returned: Math.min(list.length, limit), results: list.slice(0, limit) };
    }
  },
  {
    name: 'read_bytes',
    description: 'Dosya offsetinden ham baytları hex dökümü olarak okur. length en fazla 1024.',
    schema: {
      type: 'object',
      properties: {
        offset: { type: 'integer' },
        length: { type: 'integer', description: 'Bayt sayısı (<=1024)' }
      },
      required: ['offset', 'length'],
      additionalProperties: false
    },
    run: (ctx, a) => {
      const len = Math.max(1, Math.min(a.length || 64, 1024));
      const off = a.offset | 0;
      if (off < 0 || off >= ctx.buf.length) return { error: 'Offset dosya sınırları dışında' };
      const slice = ctx.buf.subarray(off, Math.min(off + len, ctx.buf.length));
      return { offset: off, length: slice.length, hexdump: hexDump(slice, off) };
    }
  },
  {
    name: 'read_at_rva',
    description: 'PE için sanal adresten (RVA) baytları okur; RVA dosya offsetine çevrilir. length en fazla 1024.',
    schema: {
      type: 'object',
      properties: {
        rva: { type: 'integer', description: 'Sanal adres (RVA), image base hariç' },
        length: { type: 'integer' }
      },
      required: ['rva', 'length'],
      additionalProperties: false
    },
    run: (ctx, a) => {
      const sections = ctx.report.structure && ctx.report.structure.sections;
      if (!sections) return { error: 'Section tablosu yok (PE değil mi?)' };
      const off = rvaToOffset(sections, a.rva | 0);
      if (off == null) return { error: 'RVA hiçbir section ile eşleşmedi' };
      const len = Math.max(1, Math.min(a.length || 64, 1024));
      const slice = ctx.buf.subarray(off, Math.min(off + len, ctx.buf.length));
      return { rva: a.rva, fileOffset: off, length: slice.length, hexdump: hexDump(slice, off) };
    }
  },
  {
    name: 'search_bytes',
    description: "Dosyada bir desen arar. 'hex' (ör. '554889e5') veya 'ascii' ver. En fazla max_results offset döner.",
    schema: {
      type: 'object',
      properties: {
        hex: { type: 'string', description: 'Boşluksuz hex dizi' },
        ascii: { type: 'string' },
        max_results: { type: 'integer' }
      },
      additionalProperties: false
    },
    run: (ctx, a = {}) => {
      let pat;
      if (a.hex) pat = Buffer.from(a.hex.replace(/\s+/g, ''), 'hex');
      else if (a.ascii) pat = Buffer.from(a.ascii, 'latin1');
      else return { error: 'hex veya ascii gerekli' };
      if (!pat.length) return { error: 'Boş desen' };
      const max = Math.min(a.max_results || 50, 500);
      const offsets = [];
      let idx = ctx.buf.indexOf(pat, 0);
      while (idx !== -1 && offsets.length < max) {
        offsets.push('0x' + idx.toString(16));
        idx = ctx.buf.indexOf(pat, idx + 1);
      }
      return { pattern: a.hex ? 'hex:' + a.hex : 'ascii:' + a.ascii, found: offsets.length, offsets };
    }
  },
  {
    name: 'get_sections',
    description: 'PE/ELF section tablosunu tam olarak döndürür.',
    schema: { type: 'object', properties: {}, additionalProperties: false },
    run: (ctx) => ({ sections: (ctx.report.structure && ctx.report.structure.sections) || [] })
  },
  {
    name: 'get_imports',
    description: 'PE import tablosunu (DLL + fonksiyonlar) veya ELF bağımlı kütüphanelerini döndürür.',
    schema: { type: 'object', properties: {}, additionalProperties: false },
    run: (ctx) => {
      const s = ctx.report.structure || {};
      return { imports: s.imports || [], neededLibraries: s.neededLibraries || [] };
    }
  },
  {
    name: 'disassemble',
    description: 'Belirli bir dosya offsetinden makine kodunu disassemble eder (rizin/radare2 kuruluysa). length = disassemble edilecek bayt sayısı (<=512).',
    schema: {
      type: 'object',
      properties: {
        offset: { type: 'integer' },
        length: { type: 'integer', description: 'Bayt (<=512)' }
      },
      required: ['offset'],
      additionalProperties: false
    },
    run: (ctx, a) => {
      const bin = detectDisassembler();
      if (!bin) {
        return {
          available: false,
          note: 'Sistemde rizin/radare2 bulunamadı. read_bytes ile ham baytları inceleyebilirsin. (Kurulum: https://rizin.re)'
        };
      }
      const off = a.offset | 0;
      const len = Math.max(1, Math.min(a.length || 64, 512));
      try {
        const out = execFileSync(
          bin,
          ['-q', '-N', '-e', 'scr.color=0', '-c', `s ${off}`, '-c', `pD ${len}`, '--', ctx.filePath],
          { timeout: 15000, maxBuffer: 2 * 1024 * 1024 }
        ).toString('utf8');
        return { available: true, disassembler: bin, offset: off, length: len, listing: out.slice(0, 16000) };
      } catch (e) {
        return { available: true, error: 'Disassemble başarısız: ' + String(e.message || e).slice(0, 300) };
      }
    }
  }
];

function summarizeStructure(s) {
  if (!s || s.error) return s || null;
  const out = {
    format: s.format,
    machine: s.machine,
    bits: s.bits,
    type: s.type,
    subsystem: s.subsystem,
    entry: s.entryPoint || s.entryPointRVA,
    isDotNet: s.isDotNet,
    sectionCount: (s.sections || []).length,
    sections: (s.sections || []).map((x) => x.name)
  };
  if (s.imports) out.importedDlls = s.imports.map((i) => `${i.dll}(${i.functionCount})`);
  if (s.neededLibraries) out.neededLibraries = s.neededLibraries;
  return out;
}

function getToolDefs() {
  return TOOLS.map((t) => ({ name: t.name, description: t.description, schema: t.schema }));
}

function runTool(name, ctx, args) {
  const t = TOOLS.find((x) => x.name === name);
  if (!t) return { error: 'Bilinmeyen araç: ' + name };
  try {
    return t.run(ctx, args || {});
  } catch (e) {
    return { error: String(e.message || e) };
  }
}

module.exports = { getToolDefs, runTool, detectDisassembler };
