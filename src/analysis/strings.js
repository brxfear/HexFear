'use strict';

// İkili dosyadan okunabilir string çıkarımı. Hem ASCII hem UTF-16LE.
// Her string'in offset'i tutulur; AI ajanı daha sonra o bölgeyi inceleyebilir.

function isPrintable(b) {
  return b === 0x09 || (b >= 0x20 && b <= 0x7e);
}

function extractAscii(buf, minLen) {
  const out = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const printable = i < buf.length && isPrintable(buf[i]);
    if (printable) {
      if (start === -1) start = i;
    } else {
      if (start !== -1 && i - start >= minLen) {
        out.push({ offset: start, enc: 'ascii', text: buf.toString('latin1', start, i) });
      }
      start = -1;
    }
  }
  return out;
}

function extractUtf16(buf, minLen) {
  const out = [];
  let start = -1;
  let count = 0;
  for (let i = 0; i + 1 < buf.length; i += 2) {
    const lo = buf[i];
    const hi = buf[i + 1];
    const printable = hi === 0x00 && isPrintable(lo);
    if (printable) {
      if (start === -1) {
        start = i;
        count = 0;
      }
      count++;
    } else {
      if (start !== -1 && count >= minLen) {
        out.push({ offset: start, enc: 'utf16le', text: buf.toString('utf16le', start, i) });
      }
      start = -1;
      count = 0;
    }
  }
  return out;
}

// İlgi çekici string'leri işaretle (URL, anahtar/flag ipuçları, biçim izleri).
const INTEREST = [
  { tag: 'url', re: /https?:\/\/[^\s"']+/i },
  { tag: 'ip', re: /\b\d{1,3}(\.\d{1,3}){3}\b/ },
  { tag: 'flag-like', re: /(flag|ctf|key|serial|licen[cs]e|secret|token|passw)/i },
  { tag: 'base64-ish', re: /^[A-Za-z0-9+/]{24,}={0,2}$/ },
  { tag: 'hex-blob', re: /^(0x)?[0-9a-fA-F]{32,}$/ },
  { tag: 'path', re: /([A-Za-z]:\\|\/(usr|home|etc|var|tmp)\/)/ }
];

function tagStrings(list) {
  for (const s of list) {
    const tags = [];
    for (const { tag, re } of INTEREST) if (re.test(s.text)) tags.push(tag);
    if (tags.length) s.tags = tags;
  }
}

function extractStrings(buf, opts = {}) {
  const minLen = opts.minLen || 4;
  const limit = opts.limit || 4000;
  const ascii = extractAscii(buf, minLen);
  const utf16 = extractUtf16(buf, minLen);
  let all = ascii.concat(utf16).sort((a, b) => a.offset - b.offset);

  tagStrings(all);
  const interesting = all.filter((s) => s.tags).slice(0, 500);

  const truncated = all.length > limit;
  if (truncated) all = all.slice(0, limit);

  return {
    total: ascii.length + utf16.length,
    returned: all.length,
    truncated,
    interestingCount: interesting.length,
    interesting,
    strings: all
  };
}

module.exports = { extractStrings };
