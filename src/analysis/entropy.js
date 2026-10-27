'use strict';

// Shannon entropisi (0..8 bit/byte). Yüksek entropi = sıkıştırılmış/şifreli/paketlenmiş
// veri işareti olabilir. Paketleyici (UPX vb.) tespitinde ilk ipucudur.

function shannon(buf) {
  if (!buf || buf.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < buf.length; i++) counts[buf[i]]++;
  let h = 0;
  const len = buf.length;
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue;
    const p = counts[i] / len;
    h -= p * Math.log2(p);
  }
  return h;
}

// Dosyayı parçalara böl, en yüksek/ortalama entropiyi raporla.
function chunkedEntropy(buf, chunkSize = 4096) {
  const overall = shannon(buf);
  const chunks = [];
  for (let off = 0; off < buf.length; off += chunkSize) {
    const slice = buf.subarray(off, Math.min(off + chunkSize, buf.length));
    chunks.push({ offset: off, size: slice.length, entropy: +shannon(slice).toFixed(3) });
  }
  const high = chunks.filter((c) => c.entropy >= 7.2).length;
  return {
    overall: +overall.toFixed(3),
    chunkSize,
    totalChunks: chunks.length,
    highEntropyChunks: high,
    highEntropyRatio: chunks.length ? +(high / chunks.length).toFixed(3) : 0,
    likelyPackedOrEncrypted: overall >= 7.2
  };
}

module.exports = { shannon, chunkedEntropy };
