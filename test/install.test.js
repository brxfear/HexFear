'use strict';

// MCP istemci kurulumu testleri. Gerçek ayar dosyalarına dokunmamak için her
// test sahte bir ev dizini (geçici klasör) kullanır.

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const mi = require('../src/mcp/install');

const APP = path.join(__dirname, '..');
let home, env;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'hexfear-home-'));
  env = { APPDATA: path.join(home, 'AppData', 'Roaming'), LOCALAPPDATA: path.join(home, 'AppData', 'Local') };
});
afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

const clients = () => mi.getClients({ home, env, platform: 'win32' });
const client = (id) => clients().find((c) => c.id === id);
const read = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
const ENTRY = mi.resolveServerEntry({ execPath: 'C:/Program Files/HexFear/HexFear.exe', appPath: 'C:/Program Files/HexFear/resources/app.asar', isPortable: false });

test('kurulu sürüm: HexFear.exe Node olarak çalıştırılır', () => {
  assert.equal(ENTRY.command, 'C:/Program Files/HexFear/HexFear.exe');
  assert.equal(ENTRY.args[0], path.join('C:/Program Files/HexFear/resources/app.asar', 'src', 'mcp', 'server.js'));
  assert.deepEqual(ENTRY.env, { ELECTRON_RUN_AS_NODE: '1' });
});

test('portable sürüm: Node varsa kalıcı kopya, yoksa açıklayıcı hata', () => {
  const p = mi.resolveServerEntry({ execPath: 'x', appPath: 'y', isPortable: true, runtimeDir: 'C:/rt', nodeAvailable: true });
  assert.equal(p.command, 'node');
  assert.equal(p.args[0], path.join('C:/rt', 'src', 'mcp', 'server.js'));
  assert.equal(p.needsRuntimeCopy, true);
  const n = mi.resolveServerEntry({ execPath: 'x', appPath: 'y', isPortable: true, runtimeDir: 'C:/rt', nodeAvailable: false });
  assert.match(n.error, /Node\.js/);
  assert.equal(mi.manualSnippet(n), null);
  assert.throws(() => mi.install(client('cursor'), n), /Node\.js/);
});

test('istemciler algılanır; yüklü olmayanlar algılanmaz', () => {
  fs.mkdirSync(path.join(home, '.cursor'));
  fs.mkdirSync(path.join(home, '.gemini', 'antigravity'), { recursive: true });
  const st = Object.fromEntries(clients().map((c) => [c.id, mi.clientStatus(c, ENTRY)]));
  assert.equal(st.cursor.detected, true);
  assert.equal(st.antigravity.detected, true);
  assert.equal(st['gemini-cli'].detected, false, 'Antigravity klasörü Gemini CLI sayılmamalı');
  assert.equal(st['claude-code'].detected, false);
  assert.equal(st.cursor.state, 'none');
});

test('Claude Code: diğer ayarlar ve sunucular korunur, yedek alınır', () => {
  const f = path.join(home, '.claude.json');
  const orig = { numStartups: 7, projects: { a: { x: 1 } }, mcpServers: { other: { command: 'foo', args: [] } } };
  fs.writeFileSync(f, JSON.stringify(orig));

  mi.install(client('claude-code'), ENTRY);
  const j = read(f);
  assert.equal(j.numStartups, 7);
  assert.deepEqual(j.projects, orig.projects);
  assert.deepEqual(j.mcpServers.other, orig.mcpServers.other);
  assert.deepEqual(j.mcpServers.hexfear, { type: 'stdio', command: ENTRY.command, args: ENTRY.args, env: ENTRY.env });
  assert.deepEqual(read(f + mi.BACKUP_SUFFIX), orig);
  assert.equal(mi.clientStatus(client('claude-code'), ENTRY).state, 'installed');
  assert.equal(fs.existsSync(f + '.tmp-hexfear'), false);

  // İkinci kurulum ilk yedeği ezmez
  mi.install(client('claude-code'), ENTRY);
  assert.deepEqual(read(f + mi.BACKUP_SUFFIX), orig);
});

test('olmayan dosya oluşturulur; type yalnızca Claude Code’a eklenir', () => {
  fs.mkdirSync(path.join(home, '.cursor'));
  mi.install(client('cursor'), ENTRY);
  const j = read(path.join(home, '.cursor', 'mcp.json'));
  assert.deepEqual(Object.keys(j), ['mcpServers']);
  assert.equal(j.mcpServers.hexfear.type, undefined);
  assert.equal(fs.existsSync(path.join(home, '.cursor', 'mcp.json' + mi.BACKUP_SUFFIX)), false);
});

test('farklı bir hexfear ayarı "different" görünür, kurulum günceller', () => {
  const f = path.join(home, '.gemini', 'antigravity', 'mcp_config.json');
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, JSON.stringify({ mcpServers: { hexfear: { command: 'node', args: ['eski/server.js'] } } }));
  assert.equal(mi.clientStatus(client('antigravity'), ENTRY).state, 'different');
  mi.install(client('antigravity'), ENTRY);
  assert.equal(mi.clientStatus(client('antigravity'), ENTRY).state, 'installed');
});

test('bozuk JSON: durum "error", kurulum dosyaya dokunmaz', () => {
  const f = path.join(home, '.gemini', 'settings.json');
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, '{ "theme": "dark", // yorum\n }');
  const st = mi.clientStatus(client('gemini-cli'), ENTRY);
  assert.equal(st.state, 'error');
  assert.throws(() => mi.install(client('gemini-cli'), ENTRY), /okunamadı/);
  assert.equal(fs.readFileSync(f, 'utf8'), '{ "theme": "dark", // yorum\n }');
});

test('BOM’lu ve boş dosyalar okunur', () => {
  const f = path.join(home, '.codeium', 'windsurf', 'mcp_config.json');
  fs.mkdirSync(path.dirname(f), { recursive: true });
  fs.writeFileSync(f, '\uFEFF{"mcpServers":{}}');
  mi.install(client('windsurf'), ENTRY);
  assert.ok(read(f).mcpServers.hexfear);
  fs.writeFileSync(f, '');
  assert.equal(mi.clientStatus(client('windsurf'), ENTRY).state, 'none');
});

test('Claude Desktop (Microsoft Store): iki konuma da yazılır', () => {
  const msix = path.join(env.LOCALAPPDATA, 'Packages', 'Claude_abc123', 'LocalCache', 'Roaming', 'Claude');
  fs.mkdirSync(msix, { recursive: true });
  const c = client('claude-desktop');
  assert.equal(c.files.length, 2);
  assert.equal(mi.clientStatus(c, ENTRY).detected, true);
  mi.install(c, ENTRY);
  for (const f of c.files) assert.ok(read(f).mcpServers.hexfear, f);
});

test('kaldırma yalnızca hexfear’ı siler', () => {
  const f = path.join(home, '.claude.json');
  fs.writeFileSync(f, JSON.stringify({ mcpServers: { other: { command: 'foo' } } }));
  mi.install(client('claude-code'), ENTRY);
  const res = mi.uninstall(client('claude-code'));
  assert.deepEqual(res.files, [f]);
  assert.deepEqual(read(f).mcpServers, { other: { command: 'foo' } });
  assert.equal(mi.clientStatus(client('claude-code'), ENTRY).state, 'none');
  assert.deepEqual(mi.uninstall(client('cursor')).files, []);
});

// Yazılan ayardaki komutu bir MCP istemcisi gibi çalıştırıp el sıkışır
function handshake(entry) {
  return new Promise((resolve, reject) => {
    const p = spawn(entry.command, entry.args, { env: { ...process.env, ...(entry.env || {}) }, cwd: os.tmpdir() });
    let out = '';
    p.stdout.on('data', (d) => {
      out += d;
      if (out.includes('\n')) {
        p.stdin.end();
        resolve(JSON.parse(out.split('\n')[0]));
      }
    });
    p.on('error', reject);
    p.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) + '\n');
  });
}

test('kaydedilen komut gerçekten sunucuyu başlatır', async () => {
  const entry = mi.resolveServerEntry({ execPath: process.execPath, appPath: APP, isPortable: false });
  const res = await handshake(entry);
  assert.equal(res.result.tools.length, 12);
});

test('portable: kopyalanan çalışma dosyalarından sunucu başlar', async () => {
  const rt = path.join(home, 'mcp-runtime');
  mi.copyRuntime(APP, rt);
  assert.ok(fs.existsSync(path.join(rt, 'package.json')));
  const entry = mi.resolveServerEntry({ execPath: 'x', appPath: APP, isPortable: true, runtimeDir: rt, nodeAvailable: true });
  const res = await handshake({ ...entry, command: process.execPath });
  assert.equal(res.result.tools.length, 12);
});
