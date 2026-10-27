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
      resp = await chat({ provider, apiKey, model, system, messages, tools, signal });
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
      assistantContent.push({ type: 'tool_use', id: tc.id, name: tc.name, input: tc.input });
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
