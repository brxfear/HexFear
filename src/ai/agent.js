'use strict';

// Ajan döngüsü. Statik raporu "kanıt" olarak modele verir, sonra model araç
// çağırdıkça araçları yerel olarak çalıştırıp sonuçları geri besler; model son
// cevabını verene veya adım sınırına ulaşana kadar sürer.
//
// İlerleme olayları onEvent(...) ile akıtılır (arayüzde adım adım gösterilir).

const fs = require('fs');
const { analyzeFile } = require('../analysis');
const { chat } = require('./providers');
const { getToolDefs, runTool, detectDisassembler } = require('./tools');
const { buildSystemPrompt } = require('./prompts');

const MAX_STEPS = 18;

function sleep(ms, signal) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    if (signal) signal.addEventListener('abort', () => { clearTimeout(t); resolve(); }, { once: true });
  });
}

// Hata mesajındaki "retry in 29.9s" gibi bekleme süresini (sn) çıkarır.
function retryAfterSeconds(e) {
  const m = String((e && e.message) || '').match(/retry in ([\d.]+)\s*s/i);
  return m ? parseFloat(m[1]) : null;
}

const MAX_RATE_WAIT_S = 70; // dakikalık kota için beklenir; daha uzunu (günlük kota) beklenmez

// Geçici sunucu hatalarında (429/5xx) yeniden dener. 429'da sağlayıcı bir bekleme
// süresi verdiyse (dakikalık istek kotası) o kadar bekleyip devam eder.
async function chatWithRetry(args, emit) {
  let attempt = 0;
  for (;;) {
    try {
      return await chat(args);
    } catch (e) {
      const retryable = e && e.retryable;
      const after = e && e.status === 429 ? retryAfterSeconds(e) : null;
      const rateWait = after != null && after <= MAX_RATE_WAIT_S;
      let max = 0;
      if (retryable) {
        if (e.status !== 429) max = 3;
        else if (rateWait) max = 4;
        else if (after == null) max = 1;
      }
      if (!retryable || attempt >= max || (args.signal && args.signal.aborted)) throw e;
      attempt++;
      const wait = rateWait ? Math.ceil(after + 1) * 1000 : Math.min(2000 * 2 ** (attempt - 1), 12000);
      const text = rateWait
        ? `İstek kotası doldu (429) — ${wait / 1000} sn bekleniyor, sonra kaldığı yerden devam (${attempt})…`
        : `Geçici hata (${e.status}) — ${wait / 1000}sn sonra yeniden deneniyor (${attempt})…`;
      emit && emit({ type: 'status', text });
      await sleep(wait, args.signal);
      if (args.signal && args.signal.aborted) throw e;
    }
  }
}

function compactReport(r) {
  // Modele başlangıçta verilecek özet. Tüm string'ler değil; sadece ilgi
  // çekici olanlar gönderilir — gerisini model list_strings ile isteyebilir.
  const s = r.structure || {};
  return {
    file: { name: r.file.name, size: r.file.size, sizeHuman: r.file.sizeHuman },
    type: r.type,
    sha256: r.hashes.sha256,
    entropy: { overall: r.entropy.overall, likelyPackedOrEncrypted: r.entropy.likelyPackedOrEncrypted },
    structure: s.error
      ? s
      : {
          format: s.format,
          machine: s.machine,
          bits: s.bits,
          type: s.type,
          subsystem: s.subsystem,
          entry: s.entryPoint || s.entryPointRVA,
          imageBase: s.imageBase,
          isDotNet: s.isDotNet,
          sections: s.sections,
          importedDlls: s.imports ? s.imports.map((i) => `${i.dll}(${i.functionCount})`) : undefined,
          neededLibraries: s.neededLibraries
        },
    capabilities: (r.capabilities || []).map((c) => ({ label: c.label, severity: c.severity, evidence: c.hits.slice(0, 4).map((h) => h.evidence) })),
    crypto: r.crypto && r.crypto.algorithms,
    indicators: r.indicators && r.indicators.counts,
    interestingStrings: (r.strings.interesting || []).slice(0, 120),
    stringStats: { total: r.strings.total }
  };
}

async function runAgent({ filePath, provider, apiKey, model, mode, onEvent, signal }) {
  const emit = (ev) => {
    try {
      onEvent && onEvent(ev);
    } catch {
      /* yut */
    }
  };

  emit({ type: 'status', text: 'Dosya yeniden analiz ediliyor…' });
  const report = await analyzeFile(filePath);
  const buf = fs.readFileSync(filePath);
  const ctx = { buf, report, filePath };

  const system = buildSystemPrompt(mode);
  const tools = getToolDefs();
  const disasm = detectDisassembler();

  emit({ type: 'info', text: `Sağlayıcı: ${provider} · model: ${model} · disassembler: ${disasm || 'yok'}` });

  const messages = [
    {
      role: 'user',
      content: [
        {
          type: 'text',
          text:
            'Aşağıda hedef dosyanın yerel statik analiz özeti (kanıt) var. Göreve başla; ' +
            'daha fazla veri gerekiyorsa araçları çağır.\n\n```json\n' +
            JSON.stringify(compactReport(report), null, 2) +
            '\n```'
        }
      ]
    }
  ];

  let finalText = '';
  for (let step = 1; step <= MAX_STEPS; step++) {
    if (signal && signal.aborted) {
      emit({ type: 'status', text: 'İptal edildi' });
      return { ok: false, aborted: true, report };
    }
    emit({ type: 'status', text: `Model düşünüyor… (adım ${step}/${MAX_STEPS})` });

    let resp;
    try {
      resp = await chatWithRetry({ provider, apiKey, model, system, messages, tools, signal }, emit);
    } catch (e) {
      emit({ type: 'error', text: String(e.message || e) });
      return { ok: false, error: String(e.message || e), report };
    }

    if (resp.text) emit({ type: 'assistant', text: resp.text });

    if (!resp.toolCalls || resp.toolCalls.length === 0) {
      finalText = resp.text || '(model boş yanıt verdi)';
      emit({ type: 'final', text: finalText });
      return { ok: true, finalText, steps: step, report, mode, provider, model };
    }

    // Model araç çağırdı: assistant mesajını (metin + tool_use) geçmişe ekle
    const assistantContent = [];
    if (resp.text) assistantContent.push({ type: 'text', text: resp.text });
    for (const tc of resp.toolCalls) {
      assistantContent.push({ type: 'tool_use', id: tc.id, name: tc.name, input: tc.input, thoughtSignature: tc.thoughtSignature });
    }
    messages.push({ role: 'assistant', content: assistantContent });

    // Araçları çalıştır, sonuçları geri besle
    for (const tc of resp.toolCalls) {
      emit({ type: 'tool_call', name: tc.name, input: tc.input });
      const result = runTool(tc.name, ctx, tc.input);
      const resultStr = JSON.stringify(result);
      emit({ type: 'tool_result', name: tc.name, preview: resultStr.slice(0, 600) });
      messages.push({
        role: 'tool',
        toolCallId: tc.id,
        name: tc.name,
        content: resultStr.slice(0, 60000)
      });
    }
  }

  emit({ type: 'status', text: 'Adım sınırına ulaşıldı' });
  return { ok: true, finalText: finalText || '(adım sınırına ulaşıldı, kesin sonuç yok)', steps: MAX_STEPS, report, mode, provider, model };
}

module.exports = { runAgent };
