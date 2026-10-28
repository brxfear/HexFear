'use strict';

// MCP sunucusu uçtan uca testleri: sunucu ayrı süreç olarak başlatılır ve
// stdio üzerinden gerçek JSON-RPC konuşulur.  Çalıştır: npm test

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const pkg = require('../package.json');

const SERVER = path.join(__dirname, '..', 'src', 'mcp', 'server.js');
const FLAG = 'flag{hexfear_mcp_test}';
const FLAG_OFFSET = 0x200;
const WIN_PE = 'C:\\Windows\\System32\\find.exe';

// Basit MCP istemcisi: id ile eşleşen yanıtları bekler
function startServer(args = []) {
  const proc = spawn(process.execPath, [SERVER, ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
  const waiting = new Map();
  const lines = [];
  let buf = '';
  let nextId = 1;
  proc.stdout.setEncoding('utf8');
  proc.stdout.on('data', (d) => {
    buf += d;
    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      lines.push(line);
      const msg = JSON.parse(line);
      const w = waiting.get(msg.id);
      if (w) {
        waiting.delete(msg.id);
        w(msg);
      }
    }
  });
  const raw = (text, id) =>
    new Promise((resolve) => {
      waiting.set(id, resolve);
      proc.stdin.write(text + '\n');
    });
  const request = (method, params) => {
    const id = nextId++;
    return raw(JSON.stringify({ jsonrpc: '2.0', id, method, params }), id);
  };
  const notify = (method, params) => proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
  const close = () =>
    new Promise((resolve) => {
      proc.on('exit', resolve);
      proc.stdin.end();
    });
  return { proc, lines, raw, request, notify, close };
}

async function call(client, name, args = {}) {
  const res = await client.request('tools/call', { name, arguments: args });
  assert.ok(res.result, 'tools/call sonuç döndürmeli: ' + JSON.stringify(res.error));
  return { isError: res.result.isError, data: JSON.parse(res.result.content[0].text) };
}

let tmpDir, blob, client;

before(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexfear-test-'));
  blob = path.join(tmpDir, 'blob.bin');
  const b = Buffer.alloc(0x400, 0);
  for (let i = 0; i < 0x100; i++) b[i] = (i * 37) & 0xff;
  b.write(FLAG, FLAG_OFFSET, 'latin1');
  fs.writeFileSync(blob, b);

  client = startServer();
  const init = await client.request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'hexfear-test', version: '0' }
  });
  assert.equal(init.result.protocolVersion, '2025-06-18');
  client.notify('notifications/initialized');
});

after(async () => {
  await client.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('initialize: sunucu bilgisi ve yetenekler', async () => {
  const res = await client.request('initialize', { protocolVersion: '2025-06-18', capabilities: {} });
  assert.deepEqual(res.result.serverInfo, { name: 'hexfear', version: pkg.version });
  assert.ok(res.result.capabilities.tools);
  assert.ok(res.result.capabilities.prompts);
  assert.match(res.result.instructions, /open_file/);
});

test('initialize: bilinmeyen protokol sürümünde desteklenen sürüme düşer', async () => {
  const res = await client.request('initialize', { protocolVersion: '1999-01-01', capabilities: {} });
  assert.match(res.result.protocolVersion, /^\d{4}-\d{2}-\d{2}$/);
  assert.notEqual(res.result.protocolVersion, '1999-01-01');
});

test('ping', async () => {
  const res = await client.request('ping');
  assert.deepEqual(res.result, {});
});

test('tools/list: open_file + 11 analiz aracı, hepsi salt-okunur', async () => {
  const res = await client.request('tools/list');
  const names = res.result.tools.map((t) => t.name);
  assert.deepEqual(names.sort(), [
    'disassemble', 'get_capabilities', 'get_exports', 'get_imports', 'get_indicators', 'get_overview',
    'get_sections', 'list_strings', 'open_file', 'read_at_rva', 'read_bytes', 'search_bytes'
  ]);
  for (const t of res.result.tools) {
    assert.equal(t.inputSchema.type, 'object', t.name);
    assert.equal(t.annotations.readOnlyHint, true, t.name);
    assert.doesNotMatch(JSON.stringify(t.inputSchema), /additionalProperties|\$schema/, t.name + ' Gemini uyumlu olmalı');
  }
});

test('dosya açılmadan araç çağrısı hata verir', async () => {
  const fresh = startServer();
  try {
    const r = await call(fresh, 'get_overview');
    assert.equal(r.isError, true);
    assert.match(r.data.error, /open_file/);
  } finally {
    await fresh.close();
  }
});

test('open_file: olmayan dosya hata verir', async () => {
  const r = await call(client, 'open_file', { path: path.join(tmpDir, 'yok.exe') });
  assert.equal(r.isError, true);
  assert.match(r.data.error, /açılamadı/);
});

test('open_file: path olmadan hata verir', async () => {
  const r = await call(client, 'open_file', {});
  assert.equal(r.isError, true);
});

test('open_file + list_strings / search_bytes / read_bytes (ham dosya)', async () => {
  const opened = await call(client, 'open_file', { path: blob });
  assert.equal(opened.isError, false);
  assert.equal(opened.data.opened, blob);
  assert.match(opened.data.sha256, /^[0-9a-f]{64}$/);

  const strs = await call(client, 'list_strings', { contains: 'FLAG{' });
  assert.equal(strs.data.matched, 1);
  assert.equal(strs.data.results[0].text, FLAG);
  assert.equal(strs.data.results[0].offset, FLAG_OFFSET);

  const ascii = await call(client, 'search_bytes', { ascii: 'hexfear_mcp' });
  assert.deepEqual(ascii.data.offsets, ['0x' + (FLAG_OFFSET + 5).toString(16)]);

  const hex = await call(client, 'search_bytes', { hex: Buffer.from('flag{').toString('hex') });
  assert.equal(hex.data.found, 1);

  const none = await call(client, 'search_bytes', {});
  assert.equal(none.isError, true);

  const bytes = await call(client, 'read_bytes', { offset: FLAG_OFFSET, length: 16 });
  assert.equal(bytes.data.length, 16);
  assert.match(bytes.data.hexdump, /^0x00000200  66 6c 61 67 7b/);

  const out = await call(client, 'read_bytes', { offset: 0x10000, length: 4 });
  assert.equal(out.isError, true);

  const pe = await call(client, 'read_at_rva', { rva: 0x1000, length: 4 });
  assert.equal(pe.isError, true, 'PE olmayan dosyada read_at_rva hata vermeli');
});

test('PE: get_overview / get_sections / get_imports / read_at_rva', { skip: !fs.existsSync(WIN_PE) && 'Windows PE yok' }, async () => {
  const opened = await call(client, 'open_file', { path: WIN_PE });
  assert.equal(opened.data.type.kind, 'pe');

  const ov = await call(client, 'get_overview');
  assert.equal(ov.data.structureSummary.format, 'PE');
  assert.ok(ov.data.structureSummary.sectionCount > 0);

  const secs = await call(client, 'get_sections');
  const text = secs.data.sections.find((s) => s.name === '.text');
  assert.ok(text, '.text section bulunmalı');

  const imps = await call(client, 'get_imports');
  assert.ok(imps.data.imports.length > 0);

  const rva = await call(client, 'read_at_rva', { rva: parseInt(text.virtualAddress, 16), length: 16 });
  assert.equal(rva.isError, false);
  assert.equal(rva.data.fileOffset, parseInt(text.rawPointer, 16));

  for (const name of ['get_exports', 'get_capabilities', 'get_indicators', 'disassemble']) {
    const r = await call(client, name);
    assert.ok(r.data && typeof r.data === 'object', name);
  }
});

test('prompts/list ve prompts/get', async () => {
  const list = await client.request('prompts/list');
  const names = list.result.prompts.map((p) => p.name);
  for (const n of ['flag', 'crackme_key', 'vuln_audit', 'general']) assert.ok(names.includes(n), n);

  const got = await client.request('prompts/get', { name: 'flag', arguments: { path: 'C:/ctf/chall.exe' } });
  const text = got.result.messages[0].content.text;
  assert.match(text, /Hedef dosya: C:\/ctf\/chall\.exe/);
  assert.match(text, /KESİNLİKLE YAPILMAYACAK/);

  const bad = await client.request('prompts/get', { name: 'yok' });
  assert.equal(bad.error.code, -32602);
});

test('JSON-RPC hataları: bilinmeyen araç, bilinmeyen metot, bozuk JSON', async () => {
  const tool = await client.request('tools/call', { name: 'nope', arguments: {} });
  assert.equal(tool.error.code, -32602);

  const method = await client.request('foo/bar');
  assert.equal(method.error.code, -32601);

  const parse = await client.raw('{bozuk', null);
  assert.equal(parse.error.code, -32700);
});

test('bildirimlere yanıt verilmez', async () => {
  const before = client.lines.length;
  client.notify('notifications/cancelled', { requestId: 999 });
  await client.request('ping');
  assert.equal(client.lines.length, before + 1, 'yalnızca ping yanıtı gelmeli');
});

test('başlangıç dosyası argümanla açılır, stdout yalnızca protokol', async () => {
  const s = startServer([blob]);
  let stderr = '';
  s.proc.stderr.on('data', (d) => (stderr += d));
  try {
    const r = await call(s, 'list_strings', { contains: 'flag{' });
    assert.equal(r.data.matched, 1);
    for (const l of s.lines) assert.doesNotThrow(() => JSON.parse(l));
  } finally {
    await s.close();
  }
  assert.match(stderr, /açık dosya/);
});
