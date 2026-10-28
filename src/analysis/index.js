'use strict';

const fs = require('fs');
const path = require('path');
const { detectType, hashes } = require('./fileinfo');
const { chunkedEntropy } = require('./entropy');
const { extractStrings } = require('./strings');
const { parsePE } = require('./pe');
const { parseELF } = require('./elf');
const { matchCapabilities } = require('./capabilities');
const { detectCrypto } = require('./crypto');
const { extractIndicators } = require('./indicators');

const MAX_READ = 192 * 1024 * 1024; // 192 MB üstü okunmaz
const MAX_STRINGS_SCAN = 48 * 1024 * 1024; // string taraması için üst sınır

// Tek dosya için tüm yerel statik analizi çalıştırır ve birleşik rapor döndürür.
// Bu rapor daha sonra (3. aşama) AI ajanına "kanıt" olarak verilecektir.
async function analyzeFile(filePath) {
  if (!filePath) throw new Error('Dosya yolu boş');
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) throw new Error('Bu bir dosya değil');
  if (stat.size === 0) throw new Error('Dosya boş');
  if (stat.size > MAX_READ) {
    throw new Error(`Dosya çok büyük (${(stat.size / 1048576).toFixed(0)} MB, sınır 192 MB)`);
  }

  const buf = fs.readFileSync(filePath);
  const type = detectType(buf);

  const report = {
    file: {
      name: path.basename(filePath),
      path: filePath,
      size: stat.size,
      sizeHuman: humanSize(stat.size),
      modified: stat.mtime.toISOString()
    },
    type,
    hashes: hashes(buf),
    entropy: chunkedEntropy(buf),
    structure: null,
    strings: null,
    generatedAt: new Date().toISOString()
  };

  // Yapısal ayrıştırma (tür bazlı)
  try {
    if (type.kind === 'pe') report.structure = parsePE(buf);
    else if (type.kind === 'elf') report.structure = parseELF(buf);
  } catch (err) {
    report.structure = { error: String(err.message || err) };
  }

  // String çıkarımı (büyük dosyada taranan bölge sınırlanır)
  const scanBuf = buf.length > MAX_STRINGS_SCAN ? buf.subarray(0, MAX_STRINGS_SCAN) : buf;
  report.strings = extractStrings(scanBuf, { minLen: 4, limit: 4000 });
  if (buf.length > MAX_STRINGS_SCAN) report.strings.scanNote = 'İlk 48 MB tarandı';

  // Yetenek/davranış, kripto ve gösterge tespiti (string'ler + yapı üzerinden)
  try { report.capabilities = matchCapabilities(report); } catch { report.capabilities = []; }
  try { report.crypto = detectCrypto(buf); } catch { report.crypto = { algorithms: [], signatures: [] }; }
  try { report.indicators = extractIndicators(report); } catch { report.indicators = { total: 0, counts: {} }; }

  return report;
}

function humanSize(n) {
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}

module.exports = { analyzeFile };
