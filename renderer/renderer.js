'use strict';

// Not: ikili dosyadan gelen string'ler ve model/araç çıktıları güvenilmez veridir.
// Hiçbir yerde innerHTML ile basılmaz; her zaman textContent kullanılır.

const $ = (id) => document.getElementById(id);
const dropZone = $('dropZone');
const results = $('results');
const statusEl = $('status');
const aiBar = $('aiBar');
const agentFeed = $('agentFeed');
const finalReport = $('finalReport');

let META = null;
let currentFile = null; // { path, name }
let unsubscribe = null;
let activeRunId = null;

function setStatus(msg) { statusEl.textContent = msg; }

// ---- DOM yardımcıları ----
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function card(title, cls) {
  const c = el('div', 'card' + (cls ? ' ' + cls : ''));
  c.appendChild(el('h3', null, title));
  const body = el('div', 'body');
  c.appendChild(body);
  return { card: c, body };
}
function kv(pairs) {
  const dl = el('dl', 'kv');
  for (const [k, v] of pairs) {
    dl.appendChild(el('dt', null, k));
    const dd = el('dd');
    if (v instanceof Node) dd.appendChild(v);
    else dd.textContent = String(v);
    dl.appendChild(dd);
  }
  return dl;
}

// ============================================================ başlangıç
init();
async function init() {
  META = await window.hexfear.getMeta();
  $('disasmPill').textContent = 'disassembler: ' + (META.disassembler || 'yok');
  buildModeOptions();
  buildModelList();
  refreshKeyState();
  wireUI();
}

function buildModeOptions() {
  const sel = $('modeSel');
  sel.textContent = '';
  for (const m of META.modes) {
    const o = el('option', null, m.label);
    o.value = m.id;
    sel.appendChild(o);
  }
}
function buildModelList() {
  const provider = $('providerSel').value;
  const list = $('modelList');
  list.textContent = '';
  const models = (META.defaultModels && META.defaultModels[provider]) || [];
  for (const m of models) {
    const o = el('option');
    o.value = m;
    list.appendChild(o);
  }
  if (models[0]) $('modelInput').value = models[0];
}

async function refreshKeyState() {
  const st = await window.hexfear.keys.status();
  META.keys = st;
  const provider = $('providerSel').value;
  const has = st.providers[provider] && st.providers[provider].hasKey;
  const ks = $('keyState');
  ks.textContent = has ? '● anahtar kayıtlı' : '○ anahtar yok — Ayarlar';
  ks.className = 'key-state ' + (has ? 'ok' : 'missing');
  updateRunEnabled();
}

function updateRunEnabled() {
  const provider = $('providerSel').value;
  const has = META.keys && META.keys.providers[provider] && META.keys.providers[provider].hasKey;
  const scope = $('scopeChk').checked;
  const model = $('modelInput').value.trim();
  $('runBtn').disabled = !(currentFile && has && scope && model && !activeRunId);
}

function wireUI() {
  $('providerSel').addEventListener('change', () => { buildModelList(); refreshKeyState(); });
  $('modelInput').addEventListener('input', updateRunEnabled);
  $('scopeChk').addEventListener('change', updateRunEnabled);
  $('settingsBtn').addEventListener('click', openSettings);
  $('closeSettings').addEventListener('click', () => $('settingsModal').classList.add('hidden'));
  $('runBtn').addEventListener('click', runAgent);
  $('cancelBtn').addEventListener('click', cancelAgent);

  ['dragenter', 'dragover'].forEach((ev) =>
    dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.add('drag'); })
  );
  ['dragleave', 'drop'].forEach((ev) =>
    dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.remove('drag'); })
  );
  dropZone.addEventListener('drop', async (e) => {
    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (!file) return;
    const filePath = window.hexfear.getPathForFile(file);
    if (!filePath) { setStatus('Dosya yolu alınamadı'); return; }
    await runAnalysis(filePath, file.name);
  });
}

// ============================================================ statik analiz
async function runAnalysis(filePath, name) {
  setStatus(`analiz ediliyor: ${name}…`);
  results.classList.add('hidden');
  finalReport.classList.add('hidden');
  agentFeed.classList.add('hidden');
  agentFeed.textContent = '';
  const res = await window.hexfear.analyzeFile(filePath);
  if (!res.ok) { setStatus('hata: ' + res.error); renderError(res.error); return; }
  currentFile = { path: filePath, name };
  renderReport(res.report);
  aiBar.classList.remove('hidden');
  updateRunEnabled();
  setStatus(`tamam: ${name} — AI ile analiz edebilirsin`);
}

function renderError(msg) {
  results.textContent = '';
  const { card: c, body } = card('Hata');
  body.appendChild(el('p', 'danger', msg));
  results.appendChild(c);
  results.classList.remove('hidden');
}

function renderReport(r) {
  results.textContent = '';
  {
    const { card: c, body } = card('Dosya');
    body.appendChild(kv([
      ['Ad', r.file.name],
      ['Boyut', `${r.file.sizeHuman} (${r.file.size} bayt)`],
      ['Tür', el('span', 'badge ok', r.type.label)],
      ['SHA-256', r.hashes.sha256],
      ['MD5', r.hashes.md5]
    ]));
    results.appendChild(c);
  }
  {
    const { card: c, body } = card('Entropi / paketleme');
    const e = r.entropy;
    body.appendChild(kv([
      ['Genel entropi', `${e.overall} / 8.0`],
      ['Yüksek entropili bölge', `${e.highEntropyChunks} / ${e.totalChunks} (oran ${e.highEntropyRatio})`],
      ['Değerlendirme', el('span', 'badge ' + (e.likelyPackedOrEncrypted ? 'warn' : 'ok'), e.likelyPackedOrEncrypted ? 'muhtemelen paketli/şifreli' : 'normal')]
    ]));
    const bar = el('div', 'entropy-bar');
    const pin = el('div', 'pin');
    pin.style.left = `${(e.overall / 8) * 100}%`;
    bar.appendChild(pin);
    body.appendChild(bar);
    results.appendChild(c);
  }
  if (r.structure && !r.structure.error) renderStructure(r.structure);
  else if (r.structure && r.structure.error) {
    const { card: c, body } = card('Yapısal ayrıştırma');
    body.appendChild(el('p', 'warn', r.structure.error));
    results.appendChild(c);
  }
  renderStrings(r.strings);
  results.classList.remove('hidden');
}

function renderStructure(s) {
  const { card: c, body } = card(`Yapı — ${s.format}`);
  const rows = [];
  if (s.machine) rows.push(['Mimari', s.machine]);
  if (s.bits) rows.push(['Bit', s.bits + '-bit']);
  if (s.type) rows.push(['Tür', s.type]);
  if (s.optionalMagic) rows.push(['Optional magic', s.optionalMagic]);
  if (s.subsystem) rows.push(['Subsystem', s.subsystem]);
  if (s.entryPoint) rows.push(['Giriş noktası', s.entryPoint]);
  if (s.entryPointRVA) rows.push(['Entry RVA', s.entryPointRVA]);
  if (s.imageBase) rows.push(['Image base', s.imageBase]);
  if (s.timeDateStamp) rows.push(['Derleme zamanı', s.timeDateStamp]);
  if (s.characteristics) rows.push(['Özellik', `${s.characteristics.isDll ? 'DLL' : 'EXE'}${s.characteristics.largeAddressAware ? ' · LAA' : ''}`]);
  if (typeof s.isDotNet === 'boolean') rows.push(['.NET', el('span', 'badge ' + (s.isDotNet ? 'warn' : 'ok'), s.isDotNet ? 'evet (managed)' : 'hayır')]);
  body.appendChild(kv(rows));

  if (s.sections && s.sections.length) {
    const t = el('table', 'grid');
    const head = el('tr');
    ['Section', 'VAddr', 'VSize', 'RawSize', 'Bayrak'].forEach((h) => head.appendChild(el('th', null, h)));
    t.appendChild(head);
    for (const sec of s.sections) {
      const tr = el('tr');
      tr.appendChild(el('td', null, sec.name));
      tr.appendChild(el('td', null, sec.virtualAddress || sec.addr || '-'));
      tr.appendChild(el('td', null, String(sec.virtualSize != null ? sec.virtualSize : sec.size)));
      tr.appendChild(el('td', null, sec.rawSize != null ? String(sec.rawSize) : '-'));
      const f = sec.flags || {};
      tr.appendChild(el('td', null, [f.read && 'R', f.write && 'W', f.execute && 'X', f.code && 'code'].filter(Boolean).join(' ') || '-'));
      t.appendChild(tr);
    }
    body.appendChild(el('p', 'muted', 'Section tablosu:'));
    body.appendChild(t);
  }
  if (s.imports && s.imports.length) {
    const det = el('details');
    det.appendChild(el('summary', null, `Importlar — ${s.imports.length} DLL`));
    for (const imp of s.imports) {
      det.appendChild(el('p', 'badge', `${imp.dll} (${imp.functionCount})`));
      const fns = el('div', 'strlist');
      imp.functions.slice(0, 60).forEach((fn) => {
        const row = el('div', 'row');
        row.appendChild(el('span', 'txt', fn));
        fns.appendChild(row);
      });
      det.appendChild(fns);
    }
    body.appendChild(det);
  }
  if (s.neededLibraries && s.neededLibraries.length) {
    body.appendChild(el('p', 'muted', 'Bağımlı kütüphaneler:'));
    const wrap = el('div');
    s.neededLibraries.forEach((lib) => wrap.appendChild(el('span', 'badge', lib)));
    body.appendChild(wrap);
  }
  results.appendChild(c);
}

function renderStrings(str) {
  if (!str) return;
  const { card: c, body } = card(`String'ler — ${str.returned}/${str.total}`);
  if (str.interesting && str.interesting.length) {
    body.appendChild(el('p', 'muted', `İlgi çekici (${str.interestingCount}):`));
    body.appendChild(buildStrList(str.interesting));
  }
  const det = el('details');
  det.appendChild(el('summary', null, `Tüm string'ler (${str.returned})${str.truncated ? ' — kısaltıldı' : ''}`));
  det.appendChild(buildStrList(str.strings));
  body.appendChild(det);
  results.appendChild(c);
}
function buildStrList(list) {
  const wrap = el('div', 'strlist');
  for (const s of list) {
    const row = el('div', 'row');
    row.appendChild(el('span', 'off', '0x' + s.offset.toString(16)));
    row.appendChild(el('span', 'txt', s.text));
    if (s.tags) {
      const tg = el('span', 'tags');
      s.tags.forEach((t) => tg.appendChild(el('span', 'badge warn', t)));
      row.appendChild(tg);
    }
    wrap.appendChild(row);
  }
  return wrap;
}

// ============================================================ ayarlar modalı
function openSettings() {
  const grid = $('keyGrid');
  grid.textContent = '';
  $('encNote').textContent = META.keys.encryptionAvailable
    ? 'Şifreleme: OS düzeyinde aktif (safeStorage).'
    : '⚠ Bu sistemde OS şifrelemesi yok; anahtarlar base64 ile saklanacak.';
  const names = { anthropic: 'Anthropic (Claude)', openai: 'OpenAI', gemini: 'Google (Gemini)' };
  for (const p of ['anthropic', 'openai', 'gemini']) {
    const has = META.keys.providers[p] && META.keys.providers[p].hasKey;
    const row = el('div', 'key-row');
    const top = el('div', 'top');
    top.appendChild(el('span', 'name', names[p]));
    top.appendChild(el('span', 'state ' + (has ? 'ok' : 'missing'), has ? '● kayıtlı' : '○ yok'));
    row.appendChild(top);
    const enter = el('div', 'enter');
    const inp = el('input');
    inp.type = 'password';
    inp.placeholder = has ? '••••••••  (yeni anahtarla değiştir)' : 'API anahtarını yapıştır';
    enter.appendChild(inp);
    const saveB = el('button', 'btn primary small', 'Kaydet');
    saveB.addEventListener('click', async () => {
      const key = inp.value.trim();
      if (!key) return;
      const r = await window.hexfear.keys.save(p, key);
      if (r && r.ok) { inp.value = ''; await refreshKeyState(); openSettings(); }
      else alert('Kaydedilemedi: ' + (r && r.error));
    });
    enter.appendChild(saveB);
    if (has) {
      const delB = el('button', 'btn ghost small', 'Sil');
      delB.addEventListener('click', async () => { await window.hexfear.keys.remove(p); await refreshKeyState(); openSettings(); });
      enter.appendChild(delB);
    }
    row.appendChild(enter);
    grid.appendChild(row);
  }
  $('settingsModal').classList.remove('hidden');
}

// ============================================================ AI ajan
async function runAgent() {
  if (!currentFile) return;
  const provider = $('providerSel').value;
  const model = $('modelInput').value.trim();
  const mode = $('modeSel').value;

  activeRunId = 'run_' + Date.now();
  agentFeed.textContent = '';
  agentFeed.classList.remove('hidden');
  finalReport.classList.add('hidden');
  $('runBtn').classList.add('hidden');
  $('cancelBtn').classList.remove('hidden');
  updateRunEnabled();

  if (unsubscribe) unsubscribe();
  unsubscribe = window.hexfear.agent.onEvent((ev) => {
    if (ev.runId !== activeRunId) return;
    renderEvent(ev);
  });

  $('aiStatus').textContent = 'çalışıyor…';
  const res = await window.hexfear.agent.run({ filePath: currentFile.path, provider, model, mode, runId: activeRunId, scopeConfirmed: true });
  finishRun(res);
}

function cancelAgent() {
  if (activeRunId) window.hexfear.agent.cancel(activeRunId);
}

function finishRun(res) {
  $('cancelBtn').classList.add('hidden');
  $('runBtn').classList.remove('hidden');
  activeRunId = null;
  if (unsubscribe) { unsubscribe(); unsubscribe = null; }
  updateRunEnabled();

  if (!res) { $('aiStatus').textContent = ''; return; }
  if (res.aborted) { $('aiStatus').textContent = 'iptal edildi'; return; }
  if (!res.ok) { $('aiStatus').textContent = 'hata'; renderEvent({ type: 'error', text: res.error }); return; }

  $('aiStatus').textContent = `tamam — ${res.steps} adım`;
  renderFinal(res);
}

function renderEvent(ev) {
  let node;
  if (ev.type === 'status') node = mkEv('status', 'durum', ev.text);
  else if (ev.type === 'info') node = mkEv('info', 'bilgi', ev.text);
  else if (ev.type === 'assistant') { node = el('div', 'ev assistant'); node.appendChild(el('span', 'lbl', 'model')); node.appendChild(el('div', 'body', ev.text)); }
  else if (ev.type === 'tool_call') {
    node = el('div', 'ev toolc');
    node.appendChild(el('span', 'lbl', '→ araç: ' + ev.name));
    node.appendChild(el('pre', null, JSON.stringify(ev.input)));
  } else if (ev.type === 'tool_result') {
    node = el('div', 'ev toolr');
    node.appendChild(el('span', 'lbl', '← sonuç: ' + ev.name));
    node.appendChild(el('pre', null, ev.preview));
  } else if (ev.type === 'error') node = mkEv('error', 'hata', ev.text);
  else if (ev.type === 'final') return; // final ayrı kartta
  if (node) { agentFeed.appendChild(node); agentFeed.scrollTop = agentFeed.scrollHeight; }
}
function mkEv(cls, lbl, text) {
  const n = el('div', 'ev ' + cls);
  n.appendChild(el('span', 'lbl', lbl));
  n.appendChild(el('pre', null, text));
  return n;
}

function renderFinal(res) {
  finalReport.textContent = '';
  const modeLabel = (META.modes.find((m) => m.id === res.mode) || {}).label || res.mode;
  const { card: c, body } = card('Sonuç raporu — ' + modeLabel, 'final-card');
  body.appendChild(el('div', 'body-text', res.finalText));
  const meta = el('p', 'muted small');
  meta.textContent = `model: ${res.model} · ${res.provider} · ${res.steps} adım`;
  body.appendChild(meta);
  finalReport.appendChild(c);
  finalReport.classList.remove('hidden');
  finalReport.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
