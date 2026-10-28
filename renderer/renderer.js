'use strict';

// Güvenilmez veri (ikili string'ler, model/araç çıktıları) HER ZAMAN textContent
// ile basılır; innerHTML kullanılmaz.

const $ = (id) => document.getElementById(id);
const dropZone = $('dropZone');
const statusEl = $('status');
const aiBar = $('aiBar');
const fileBar = $('fileBar');
const tabBar = $('tabBar');
const tabContent = $('tabContent');

let META = null;
let currentFile = null;
let currentReport = null;
let unsubscribe = null;
let activeRunId = null;

function setStatus(m) { statusEl.textContent = m; }
function hideSettings() { $('settingsModal').classList.add('hidden'); }

// ---- DOM yardımcıları ----
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function card(title, cls) {
  const c = el('div', 'card' + (cls ? ' ' + cls : ''));
  if (title != null) c.appendChild(el('h3', null, title));
  const body = el('div', 'body');
  c.appendChild(body);
  return { card: c, body };
}
function kv(pairs) {
  const dl = el('dl', 'kv');
  for (const [k, v] of pairs) {
    if (v == null || v === '') continue;
    dl.appendChild(el('dt', null, k));
    const dd = el('dd');
    if (v instanceof Node) dd.appendChild(v);
    else dd.textContent = String(v);
    dl.appendChild(dd);
  }
  return dl;
}
function badge(text, kind) { return el('span', 'badge' + (kind ? ' ' + kind : ''), text); }

// ============================================================ init
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
  const sel = $('modeSel'); sel.textContent = '';
  for (const m of META.modes) { const o = el('option', null, m.label); o.value = m.id; sel.appendChild(o); }
}
function buildModelList() {
  const provider = $('providerSel').value;
  const list = $('modelList'); list.textContent = '';
  const models = (META.defaultModels && META.defaultModels[provider]) || [];
  for (const m of models) { const o = el('option'); o.value = m; list.appendChild(o); }
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
  const ok = currentFile && has && $('scopeChk').checked && $('modelInput').value.trim() && !activeRunId;
  $('runBtn').disabled = !ok;
}

function wireUI() {
  $('providerSel').addEventListener('change', () => { buildModelList(); refreshKeyState(); });
  $('modelInput').addEventListener('input', updateRunEnabled);
  $('scopeChk').addEventListener('change', updateRunEnabled);
  $('settingsBtn').addEventListener('click', openSettings);
  $('closeSettings').addEventListener('click', hideSettings);
  let downBg = false;
  $('settingsModal').addEventListener('mousedown', (e) => { downBg = (e.target === $('settingsModal')); });
  $('settingsModal').addEventListener('click', (e) => { if (e.target === $('settingsModal') && downBg) hideSettings(); downBg = false; });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('settingsModal').classList.contains('hidden')) hideSettings(); });
  $('mcpBtn').addEventListener('click', openMcp);
  $('closeMcp').addEventListener('click', hideMcp);
  let mcpDownBg = false;
  $('mcpModal').addEventListener('mousedown', (e) => { mcpDownBg = (e.target === $('mcpModal')); });
  $('mcpModal').addEventListener('click', (e) => { if (e.target === $('mcpModal') && mcpDownBg) hideMcp(); mcpDownBg = false; });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('mcpModal').classList.contains('hidden')) hideMcp(); });
  $('mcpCopyBtn').addEventListener('click', async () => {
    const res = await window.hexfear.mcp.copySnippet();
    $('mcpCopyBtn').textContent = res && res.ok ? '✓ Kopyalandı' : 'Kopyalanamadı';
    setTimeout(() => { $('mcpCopyBtn').textContent = '⧉ JSON’u kopyala'; }, 1600);
  });
  $('runBtn').addEventListener('click', runAgent);
  $('cancelBtn').addEventListener('click', () => { if (activeRunId) window.hexfear.agent.cancel(activeRunId); });

  ['dragenter', 'dragover'].forEach((ev) => dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((ev) => dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.remove('drag'); }));
  // Tüm pencereye bırakma
  document.addEventListener('dragover', (e) => e.preventDefault());
  document.addEventListener('drop', async (e) => {
    e.preventDefault();
    const file = e.dataTransfer.files && e.dataTransfer.files[0];
    if (!file) return;
    const p = window.hexfear.getPathForFile(file);
    if (!p) { setStatus('Dosya yolu alınamadı'); return; }
    await runAnalysis(p, file.name);
  });
}

// ============================================================ statik analiz
async function runAnalysis(filePath, name) {
  setStatus(`analiz ediliyor: ${name}…`);
  const res = await window.hexfear.analyzeFile(filePath);
  if (!res.ok) { setStatus('hata: ' + res.error); return; }
  currentFile = { path: filePath, name };
  currentReport = res.report;
  renderFileBar(res.report);
  dropZone.classList.add('hidden');
  aiBar.classList.remove('hidden');
  buildTabs(res.report);
  updateRunEnabled();
  setStatus(`tamam: ${name} — ${(res.report.capabilities || []).length} yetenek, ${res.report.strings.total} string`);
}

function renderFileBar(r) {
  fileBar.textContent = '';
  fileBar.classList.remove('hidden');
  fileBar.appendChild(el('span', 'fname', r.file.name));
  fileBar.appendChild(badge(r.type.label, 'ok'));
  fileBar.appendChild(el('span', 'fmeta', `${r.file.sizeHuman} · entropi ${r.entropy.overall}`));
  const b = el('button', 'btn ghost small', '↻ Başka dosya');
  b.style.marginLeft = 'auto';
  b.addEventListener('click', () => {
    currentFile = null; currentReport = null;
    fileBar.classList.add('hidden'); aiBar.classList.add('hidden');
    tabBar.classList.add('hidden'); tabContent.classList.add('hidden');
    dropZone.classList.remove('hidden'); setStatus('hazır');
  });
  fileBar.appendChild(b);
}

// ============================================================ sekmeler
function buildTabs(r) {
  const s = r.structure && !r.structure.error ? r.structure : null;
  const impCount = s && s.imports ? s.imports.length : 0;
  const expCount = s && s.exports ? s.exports.namedExports : 0;

  const defs = [
    { id: 'genel', label: 'Genel', icon: '◈' },
    { id: 'yapi', label: 'Yapı', icon: '▦', show: !!s || !!(r.structure && r.structure.error) },
    { id: 'impexp', label: 'İçe / Dışa', icon: '⇄', cnt: impCount + expCount, show: impCount + expCount > 0 || (s && s.neededLibraries) },
    { id: 'caps', label: 'Yetenekler', icon: '⚠', cnt: (r.capabilities || []).length },
    { id: 'indic', label: 'Göstergeler', icon: '◎', cnt: r.indicators ? r.indicators.total : 0 },
    { id: 'strings', label: "String'ler", icon: '⌯', cnt: r.strings.interestingCount },
    { id: 'ai', label: 'AI Analizi', icon: '✦' }
  ].filter((d) => d.show === undefined || d.show);

  tabBar.textContent = ''; tabContent.textContent = '';
  tabBar.classList.remove('hidden'); tabContent.classList.remove('hidden');

  for (const d of defs) {
    const btn = el('button', 'tab-btn');
    btn.appendChild(el('span', null, d.icon));
    btn.appendChild(el('span', null, d.label));
    if (d.cnt != null) btn.appendChild(el('span', 'cnt', String(d.cnt)));
    btn.addEventListener('click', () => selectTab(d.id));
    btn.dataset.tab = d.id;
    tabBar.appendChild(btn);

    const pane = el('div', 'tab-pane');
    pane.dataset.tab = d.id;
    tabContent.appendChild(pane);
    renderPane(d.id, pane, r);
  }
  selectTab('genel');
}

function selectTab(id) {
  for (const b of tabBar.querySelectorAll('.tab-btn')) b.classList.toggle('active', b.dataset.tab === id);
  for (const p of tabContent.querySelectorAll('.tab-pane')) p.classList.toggle('active', p.dataset.tab === id);
}

function renderPane(id, pane, r) {
  if (id === 'genel') renderGenel(pane, r);
  else if (id === 'yapi') renderYapi(pane, r);
  else if (id === 'impexp') renderImpExp(pane, r);
  else if (id === 'caps') renderCaps(pane, r);
  else if (id === 'indic') renderIndicators(pane, r);
  else if (id === 'strings') renderStrings(pane, r);
  else if (id === 'ai') renderAIPane(pane);
}

// ---- Genel ----
function renderGenel(pane, r) {
  const wrap = el('div', 'grid2');

  const f = card('Dosya');
  f.body.appendChild(kv([
    ['Ad', r.file.name],
    ['Boyut', `${r.file.sizeHuman} (${r.file.size} B)`],
    ['Tür', badge(r.type.label, 'ok')],
    ['SHA-256', r.hashes.sha256],
    ['MD5', r.hashes.md5]
  ]));
  wrap.appendChild(f.card);

  const e = card('Entropi / paketleme');
  const ent = r.entropy;
  e.body.appendChild(kv([
    ['Genel entropi', `${ent.overall} / 8.0`],
    ['Yüksek entropili bölge', `${ent.highEntropyChunks}/${ent.totalChunks} (${(ent.highEntropyRatio * 100).toFixed(0)}%)`],
    ['Değerlendirme', badge(ent.likelyPackedOrEncrypted ? 'muhtemelen paketli/şifreli' : 'normal', ent.likelyPackedOrEncrypted ? 'warn' : 'ok')]
  ]));
  const bar = el('div', 'entropy-bar'); const pin = el('div', 'pin');
  pin.style.left = `${(ent.overall / 8) * 100}%`; bar.appendChild(pin); e.body.appendChild(bar);
  wrap.appendChild(e.card);

  // Korumalar
  const s = r.structure;
  if (s && s.protections) {
    const p = card('Güvenlik korumaları');
    const g = el('div');
    const P = s.protections;
    if (s.format === 'PE') {
      g.appendChild(badge('ASLR' + (P.aslr ? '' : ' ✗'), P.aslr ? 'ok' : 'danger'));
      g.appendChild(badge('DEP' + (P.dep ? '' : ' ✗'), P.dep ? 'ok' : 'danger'));
      g.appendChild(badge('CFG' + (P.cfg ? '' : ' ✗'), P.cfg ? 'ok' : 'off'));
      g.appendChild(badge('SEH' + (P.seh ? '' : ' ✗'), P.seh ? 'ok' : 'off'));
      if (P.highEntropyVA) g.appendChild(badge('HighEntropyVA', 'ok'));
      if (P.forceIntegrity) g.appendChild(badge('ForceIntegrity', 'ok'));
    } else {
      g.appendChild(badge('NX' + (P.nx ? '' : ' ✗'), P.nx ? 'ok' : 'danger'));
      g.appendChild(badge('PIE' + (P.pie ? '' : ' ✗'), P.pie ? 'ok' : 'warn'));
      g.appendChild(badge('RELRO: ' + P.relro, P.relro === 'full' ? 'ok' : P.relro === 'partial' ? 'warn' : 'danger'));
      g.appendChild(badge('Canary' + (P.canary ? '' : ' ✗'), P.canary ? 'ok' : 'danger'));
      g.appendChild(badge(P.stripped ? 'stripped' : 'symboller var', P.stripped ? 'warn' : 'ok'));
    }
    p.body.appendChild(g);
    wrap.appendChild(p.card);
  }

  // Kripto
  if (r.crypto && r.crypto.algorithms && r.crypto.algorithms.length) {
    const c = card('Kriptografi izleri');
    const g = el('div');
    r.crypto.algorithms.forEach((a) => g.appendChild(badge(a, 'warn')));
    c.body.appendChild(g);
    const list = el('div', 'strlist');
    (r.crypto.signatures || []).forEach((sig) => {
      const row = el('div', 'row');
      row.appendChild(el('span', 'off', sig.offset));
      row.appendChild(el('span', 'txt', `${sig.name} (${sig.algo})`));
      list.appendChild(row);
    });
    c.body.appendChild(list);
    wrap.appendChild(c.card);
  }

  pane.appendChild(wrap);
}

// ---- Yapı ----
function renderYapi(pane, r) {
  const s = r.structure;
  if (!s) return;
  if (s.error) { const c = card('Yapısal ayrıştırma'); c.body.appendChild(el('p', 'warn', s.error)); pane.appendChild(c.card); return; }

  const info = card(`Başlık — ${s.format}`);
  const rows = [
    ['Mimari', s.machine], ['Bit', s.bits ? s.bits + '-bit' : null], ['Tür', s.type],
    ['Optional magic', s.optionalMagic], ['Subsystem', s.subsystem],
    ['Giriş', s.entryPoint || s.entryPointRVA], ['Image base', s.imageBase],
    ['Interpreter', s.interpreter], ['Derleme zamanı', s.timeDateStamp],
    ['.NET', typeof s.isDotNet === 'boolean' ? badge(s.isDotNet ? 'evet (managed)' : 'hayır', s.isDotNet ? 'warn' : 'ok') : null],
    ['imphash', s.imphash], ['PDB yolu', s.debug && s.debug.pdbPath]
  ];
  info.body.appendChild(kv(rows));
  if (s.resources) {
    const g = el('div'); g.style.marginTop = '8px';
    g.appendChild(el('span', 'muted', 'Kaynaklar: '));
    (s.resources.types || []).forEach((t) => g.appendChild(badge(t)));
    info.body.appendChild(g);
  }
  pane.appendChild(info.card);

  if (s.sections && s.sections.length) {
    const sc = card(`Section'lar (${s.sections.length})`);
    const t = el('table', 'grid');
    const h = el('tr'); ['Ad', 'VAddr', 'VSize', 'RawSize', 'Bayrak'].forEach((x) => h.appendChild(el('th', null, x))); t.appendChild(h);
    for (const sec of s.sections) {
      const tr = el('tr');
      tr.appendChild(el('td', null, sec.name));
      tr.appendChild(el('td', null, sec.virtualAddress || sec.addr || '-'));
      tr.appendChild(el('td', null, String(sec.virtualSize != null ? sec.virtualSize : sec.size)));
      tr.appendChild(el('td', null, sec.rawSize != null ? String(sec.rawSize) : '-'));
      const fl = sec.flags || {};
      tr.appendChild(el('td', null, [fl.read && 'R', fl.write && 'W', fl.execute && 'X', fl.code && 'code'].filter(Boolean).join(' ') || '-'));
      t.appendChild(tr);
    }
    sc.body.appendChild(t); pane.appendChild(sc.card);
  }
}

// ---- İçe/Dışa ----
function renderImpExp(pane, r) {
  const s = r.structure; if (!s) return;
  if (s.imports && s.imports.length) {
    const c = card(`İçe aktarımlar — ${s.imports.length} DLL`);
    for (const imp of s.imports) {
      const d = el('details');
      d.appendChild(el('summary', null, `${imp.dll} (${imp.functionCount})`));
      const list = el('div', 'strlist');
      imp.functions.forEach((fn) => { const row = el('div', 'row'); row.appendChild(el('span', 'txt', fn)); list.appendChild(row); });
      d.appendChild(list); c.body.appendChild(d);
    }
    pane.appendChild(c.card);
  }
  if (s.exports && s.exports.names && s.exports.names.length) {
    const c = card(`Dışa aktarımlar — ${s.exports.namedExports}`);
    if (s.exports.dllName) c.body.appendChild(el('p', 'muted', 'DLL: ' + s.exports.dllName));
    const list = el('div', 'strlist');
    s.exports.names.forEach((n) => { const row = el('div', 'row'); row.appendChild(el('span', 'txt', n)); list.appendChild(row); });
    c.body.appendChild(list); pane.appendChild(c.card);
  }
  if (s.neededLibraries && s.neededLibraries.length) {
    const c = card('Bağımlı kütüphaneler');
    s.neededLibraries.forEach((l) => c.body.appendChild(badge(l)));
    pane.appendChild(c.card);
  }
  if (s.dynamicSymbols && s.dynamicSymbols.length) {
    const c = card(`Dinamik semboller (${s.dynamicSymbols.length})`);
    const d = el('details'); d.appendChild(el('summary', null, 'Göster'));
    const list = el('div', 'strlist');
    s.dynamicSymbols.slice(0, 500).forEach((n) => { const row = el('div', 'row'); row.appendChild(el('span', 'txt', n)); list.appendChild(row); });
    d.appendChild(list); c.body.appendChild(d); pane.appendChild(c.card);
  }
}

// ---- Yetenekler ----
function renderCaps(pane, r) {
  const caps = r.capabilities || [];
  if (!caps.length) { pane.appendChild(el('p', 'empty-hint', 'Belirgin bir yetenek göstergesi bulunamadı.')); return; }
  const info = card('Davranış / yetenek göstergeleri');
  info.body.appendChild(el('p', 'muted', 'İçe aktarımlar ve string\'lerden çıkarıldı. Bu bir triyaj ipucudur, kanıt değil.'));
  const grid = el('div', 'cap-grid');
  for (const c of caps) {
    const box = el('div', 'cap ' + c.severity);
    const head = el('div', 'cap-head');
    head.appendChild(el('span', 'cap-name', c.label));
    head.appendChild(el('span', 'sev', c.severity));
    box.appendChild(head);
    const ev = el('div', 'ev');
    c.hits.slice(0, 6).forEach((h, i) => {
      if (i) ev.appendChild(document.createTextNode(' · '));
      ev.appendChild(el('span', null, h.evidence));
    });
    box.appendChild(ev);
    grid.appendChild(box);
  }
  info.body.appendChild(grid);
  pane.appendChild(info.card);
}

// ---- Göstergeler ----
function renderIndicators(pane, r) {
  const ind = r.indicators;
  if (!ind || !ind.total) { pane.appendChild(el('p', 'empty-hint', 'Gösterge bulunamadı.')); return; }
  const labels = { urls: 'URL', ips: 'IP adresi', emails: 'E-posta', domains: 'Alan adı', winPaths: 'Windows yolu', unixPaths: 'Unix yolu', registry: 'Registry', envVars: 'Ortam değişkeni' };
  const c = card('Göstergeler (IOC)');
  for (const key of Object.keys(labels)) {
    const arr = ind[key] || [];
    if (!arr.length) continue;
    const g = el('div', 'ind-group');
    g.appendChild(el('h4', null, `${labels[key]} (${arr.length})`));
    const list = el('div', 'strlist');
    arr.forEach((it) => {
      const row = el('div', 'row');
      row.appendChild(el('span', 'off', it.offset));
      row.appendChild(el('span', 'txt', it.value));
      list.appendChild(row);
    });
    g.appendChild(list); c.body.appendChild(g);
  }
  pane.appendChild(c.card);
}

// ---- String'ler ----
function renderStrings(pane, r) {
  const str = r.strings;
  const c = card(`String'ler — ${str.returned}/${str.total}`);
  if (str.interesting && str.interesting.length) {
    c.body.appendChild(el('p', 'muted', `İlgi çekici (${str.interestingCount}):`));
    c.body.appendChild(buildStrList(str.interesting));
  }
  const d = el('details');
  d.appendChild(el('summary', null, `Tüm string'ler (${str.returned})${str.truncated ? ' — kısaltıldı' : ''}`));
  d.appendChild(buildStrList(str.strings));
  c.body.appendChild(d);
  pane.appendChild(c.card);
}
function buildStrList(list) {
  const wrap = el('div', 'strlist');
  for (const s of list) {
    const row = el('div', 'row');
    row.appendChild(el('span', 'off', '0x' + s.offset.toString(16)));
    row.appendChild(el('span', 'txt', s.text));
    if (s.tags) { const tg = el('span', 'tags'); s.tags.forEach((t) => tg.appendChild(badge(t, 'warn'))); row.appendChild(tg); }
    wrap.appendChild(row);
  }
  return wrap;
}

// ---- AI paneli ----
function renderAIPane(pane) {
  const think = el('div'); think.id = 'thinkingHost';
  const feed = el('div', 'agent-feed'); feed.id = 'agentFeed';
  const finalHost = el('div'); finalHost.id = 'finalHost';
  const hint = el('p', 'empty-hint', 'Yukarıdan model + mod seç, kapsamı onayla ve “AI ile analiz et”e bas. Ajanın her adımı burada canlı akar.');
  hint.id = 'aiHint';
  pane.appendChild(think); pane.appendChild(hint); pane.appendChild(feed); pane.appendChild(finalHost);
}

// ============================================================ ayarlar modalı
function openSettings() {
  const grid = $('keyGrid'); grid.textContent = '';
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
    const inp = el('input'); inp.type = 'password';
    inp.placeholder = has ? '••••••••  (yeni anahtarla değiştir)' : 'API anahtarını yapıştır';
    enter.appendChild(inp);
    const saveB = el('button', 'btn primary small', 'Kaydet');
    saveB.addEventListener('click', async () => {
      const key = inp.value.trim(); if (!key) return;
      const res = await window.hexfear.keys.save(p, key);
      if (res && res.ok) { inp.value = ''; await refreshKeyState(); hideSettings(); }
      else alert('Kaydedilemedi: ' + (res && res.error));
    });
    enter.appendChild(saveB);
    if (has) {
      const delB = el('button', 'btn ghost small', 'Sil');
      delB.addEventListener('click', async () => { await window.hexfear.keys.remove(p); await refreshKeyState(); openSettings(); });
      enter.appendChild(delB);
    }
    row.appendChild(enter); grid.appendChild(row);
  }
  $('settingsModal').classList.remove('hidden');
}

// ============================================================ MCP modalı
function hideMcp() { $('mcpModal').classList.add('hidden'); }

const MCP_STATES = {
  installed: ['● kurulu', 'ok'],
  different: ['◐ farklı ayar var', 'diff'],
  none: ['○ kurulu değil', 'missing'],
  error: ['✕ ayar dosyası okunamadı', 'err']
};

async function openMcp() {
  $('mcpModal').classList.remove('hidden');
  await renderMcp();
}

async function renderMcp(note) {
  const st = await window.hexfear.mcp.status();
  const errEl = $('mcpEntryError');
  errEl.textContent = st.entryError || '';
  errEl.classList.toggle('hidden', !st.entryError);
  $('mcpCopyBtn').disabled = !st.snippet;

  const grid = $('mcpGrid'); grid.textContent = '';
  for (const c of st.clients) {
    const row = el('div', 'key-row' + (c.detected || c.state !== 'none' ? '' : ' undetected'));
    const top = el('div', 'top');
    top.appendChild(el('span', 'name', c.name));
    const [label, cls] = c.detected || c.state !== 'none' ? MCP_STATES[c.state] : ['— bu bilgisayarda bulunamadı', 'missing'];
    top.appendChild(el('span', 'state ' + cls, label));
    row.appendChild(top);
    row.appendChild(el('span', 'path', c.file));
    if (c.error) row.appendChild(el('span', 'state err small', c.error));
    if (note && note.id === c.id) row.appendChild(el('span', 'small ' + (note.ok ? 'muted' : 'warn'), note.text));

    const actions = el('div', 'enter');
    if (c.detected || c.state !== 'none') {
      const inst = el('button', 'btn primary small', c.state === 'installed' ? 'Yeniden kur' : c.state === 'different' ? 'Güncelle' : 'Kur');
      inst.disabled = !!st.entryError || c.state === 'error';
      inst.addEventListener('click', async () => {
        inst.disabled = true;
        const res = await window.hexfear.mcp.install(c.id);
        await renderMcp(res && res.ok
          ? { id: c.id, ok: true, text: '✓ Eklendi. ' + c.restartHint }
          : { id: c.id, ok: false, text: 'Kurulamadı: ' + (res && res.error) });
      });
      actions.appendChild(inst);
    }
    if (c.state === 'installed' || c.state === 'different') {
      const rm = el('button', 'btn ghost small', 'Kaldır');
      rm.addEventListener('click', async () => {
        const res = await window.hexfear.mcp.remove(c.id);
        await renderMcp(res && res.ok
          ? { id: c.id, ok: true, text: 'Kaldırıldı.' }
          : { id: c.id, ok: false, text: 'Kaldırılamadı: ' + (res && res.error) });
      });
      actions.appendChild(rm);
    }
    if (actions.childNodes.length) row.appendChild(actions);
    grid.appendChild(row);
  }
}

// ============================================================ AI ajan
async function runAgent() {
  if (!currentFile) return;
  const provider = $('providerSel').value;
  const model = $('modelInput').value.trim();
  const mode = $('modeSel').value;

  selectTab('ai');
  activeRunId = 'run_' + Date.now();
  const feed = $('agentFeed'); feed.textContent = '';
  $('finalHost').textContent = '';
  $('aiHint').classList.add('hidden');
  showThinking('Başlatılıyor…', '');
  $('runBtn').classList.add('hidden'); $('cancelBtn').classList.remove('hidden');
  updateRunEnabled();

  if (unsubscribe) unsubscribe();
  unsubscribe = window.hexfear.agent.onEvent((ev) => { if (ev.runId === activeRunId) renderEvent(ev); });

  $('aiStatus').textContent = 'çalışıyor…';
  const res = await window.hexfear.agent.run({ filePath: currentFile.path, provider, model, mode, runId: activeRunId, scopeConfirmed: true });
  finishRun(res);
}

function showThinking(title, sub) {
  const host = $('thinkingHost');
  host.textContent = '';
  const box = el('div', 'thinking');
  box.appendChild(el('div', 'orb'));
  const tx = el('div', 'tx');
  const b = el('b'); b.appendChild(document.createTextNode(title + ' '));
  const dots = el('span', 'dots'); dots.appendChild(el('span', null, '.')); dots.appendChild(el('span', null, '.')); dots.appendChild(el('span', null, '.'));
  b.appendChild(dots); tx.appendChild(b);
  tx.appendChild(el('span', 'sub', sub || ''));
  box.appendChild(tx); host.appendChild(box);
}
function hideThinking() { $('thinkingHost').textContent = ''; }

function finishRun(res) {
  $('cancelBtn').classList.add('hidden'); $('runBtn').classList.remove('hidden');
  activeRunId = null; hideThinking();
  if (unsubscribe) { unsubscribe(); unsubscribe = null; }
  updateRunEnabled();
  if (!res) { $('aiStatus').textContent = ''; return; }
  if (res.aborted) { $('aiStatus').textContent = 'iptal edildi'; return; }
  if (!res.ok) { $('aiStatus').textContent = 'hata'; renderEvent({ type: 'error', text: res.error }); return; }
  $('aiStatus').textContent = `tamam — ${res.steps} adım`;
  renderFinal(res);
}

function renderEvent(ev) {
  const feed = $('agentFeed');
  if (ev.type === 'status') { showThinking('Model düşünüyor', ev.text); return; }
  if (ev.type === 'final') return;

  let node;
  if (ev.type === 'info') { node = mkEv('info', 'ⓘ bilgi', ev.text); }
  else if (ev.type === 'assistant') { node = el('div', 'ev assistant'); node.appendChild(el('span', 'lbl', '✦ model')); node.appendChild(el('div', 'body', ev.text)); }
  else if (ev.type === 'tool_call') { node = el('div', 'ev toolc'); node.appendChild(el('span', 'lbl', '→ araç: ' + ev.name)); node.appendChild(el('pre', null, JSON.stringify(ev.input))); showThinking('Araç çalışıyor', ev.name); }
  else if (ev.type === 'tool_result') { node = el('div', 'ev toolr'); node.appendChild(el('span', 'lbl', '← sonuç: ' + ev.name)); node.appendChild(el('pre', null, ev.preview)); }
  else if (ev.type === 'error') { node = mkEv('error', '✕ hata', ev.text); }
  if (node) { feed.appendChild(node); feed.scrollTop = feed.scrollHeight; }
}
function mkEv(cls, lbl, text) {
  const n = el('div', 'ev ' + cls);
  n.appendChild(el('span', 'lbl', lbl));
  n.appendChild(el('pre', null, text));
  return n;
}

function renderFinal(res) {
  const host = $('finalHost'); host.textContent = '';
  const modeLabel = (META.modes.find((m) => m.id === res.mode) || {}).label || res.mode;
  const c = card('✓ Sonuç raporu — ' + modeLabel, 'final-card');
  c.body.appendChild(el('div', null, res.finalText));
  c.body.appendChild(el('p', 'muted small', `model: ${res.model} · ${res.provider} · ${res.steps} adım`));
  host.appendChild(c.card);
  host.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
