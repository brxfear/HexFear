'use strict';

// Çıkarılmış string'lerden ilgi çekici göstergeleri kategorize eder:
// URL, IP, e-posta, alan adı, dosya yolu, registry anahtarı, ortam değişkeni.
// Tümü offset bilgisiyle; AI ve kullanıcı için hızlı bir "ipucu" paneli.

const PATTERNS = {
  urls: /\bhttps?:\/\/[^\s"'<>]+/i,
  ips: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/,
  emails: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  domains: /\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|online|site|dev|co|me|tk|ml)\b/i,
  winPaths: /\b[A-Za-z]:\\[^\s"'<>|?*]+/,
  unixPaths: /(?:^|\s)(\/(?:usr|home|etc|var|tmp|opt|bin|sbin|root)\/[^\s"'<>]+)/,
  registry: /\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[^\s"'<>]+/i,
  envVars: /%[A-Za-z_][A-Za-z0-9_]*%/
};

function extractIndicators(report) {
  const strings = (report.strings && report.strings.strings) || [];
  const out = {};
  for (const key of Object.keys(PATTERNS)) out[key] = [];
  const seen = {};
  for (const key of Object.keys(PATTERNS)) seen[key] = new Set();

  for (const s of strings) {
    for (const [key, re] of Object.entries(PATTERNS)) {
      const m = s.text.match(re);
      if (m) {
        const val = (m[1] || m[0]).trim();
        if (val && !seen[key].has(val) && out[key].length < 100) {
          seen[key].add(val);
          out[key].push({ value: val, offset: '0x' + s.offset.toString(16) });
        }
      }
    }
  }

  const counts = {};
  let total = 0;
  for (const key of Object.keys(out)) {
    counts[key] = out[key].length;
    total += out[key].length;
  }
  return { total, counts, ...out };
}

module.exports = { extractIndicators };
