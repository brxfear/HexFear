'use strict';

// HexFear MCP sunucusunu yaygın MCP istemcilerinin yapılandırmasına ekler /
// çıkarır (Claude Code, Claude Desktop, Cursor, Antigravity, Gemini CLI,
// Windsurf). Yalnızca mcpServers.hexfear anahtarına dokunulur; dosyadaki diğer
// her şey korunur. İlk yazımdan önce dosyanın yedeği alınır (.bak-hexfear) ve
// yazım geçici dosya + rename ile yapılır. Electron'a bağımlı değil (test için).

const fs = require('fs');
const path = require('path');

const SERVER_KEY = 'hexfear';
const BACKUP_SUFFIX = '.bak-hexfear';

// ---- İstemciler -----------------------------------------------------------
// files[0] durumun okunduğu asıl dosyadır; diğerleri varsa onlara da yazılır.
function getClients({ home, env = process.env, platform = process.platform }) {
  const appData = env.APPDATA || path.join(home, 'AppData', 'Roaming');
  let claudeDesktopDir;
  if (platform === 'win32') claudeDesktopDir = path.join(appData, 'Claude');
  else if (platform === 'darwin') claudeDesktopDir = path.join(home, 'Library', 'Application Support', 'Claude');
  else claudeDesktopDir = path.join(home, '.config', 'Claude');

  const claudeDesktopFiles = [path.join(claudeDesktopDir, 'claude_desktop_config.json')];
  const claudeDesktopDetect = [claudeDesktopDir];
  // Microsoft Store (MSIX) kurulumu AppData'yı paket klasörüne sanallaştırır
  for (const dir of msixClaudeDirs(env)) {
    claudeDesktopDetect.push(dir);
    if (fs.existsSync(dir)) claudeDesktopFiles.push(path.join(dir, 'claude_desktop_config.json'));
  }

  return [
    {
      id: 'claude-code',
      name: 'Claude Code',
      files: [path.join(home, '.claude.json')],
      detect: [path.join(home, '.claude.json'), path.join(home, '.claude')],
      extra: { type: 'stdio' },
      restartHint: 'Yeni bir Claude Code oturumu aç.'
    },
    {
      id: 'claude-desktop',
      name: 'Claude Desktop',
      files: claudeDesktopFiles,
      detect: claudeDesktopDetect,
      restartHint: 'Claude Desktop’u tamamen kapatıp yeniden aç.'
    },
    {
      id: 'cursor',
      name: 'Cursor',
      files: [path.join(home, '.cursor', 'mcp.json')],
      detect: [path.join(home, '.cursor')],
      restartHint: 'Cursor’u yeniden başlat (Ayarlar → MCP’de görünür).'
    },
    {
      id: 'antigravity',
      name: 'Antigravity',
      files: [path.join(home, '.gemini', 'antigravity', 'mcp_config.json')],
      detect: [path.join(home, '.gemini', 'antigravity')],
      restartHint: 'Antigravity’de Manage MCP Servers ekranını yenile.'
    },
    {
      id: 'gemini-cli',
      name: 'Gemini CLI',
      files: [path.join(home, '.gemini', 'settings.json')],
      detect: [path.join(home, '.gemini', 'settings.json')],
      restartHint: 'gemini’yi yeniden başlat (/mcp ile kontrol et).'
    },
    {
      id: 'windsurf',
      name: 'Windsurf',
      files: [path.join(home, '.codeium', 'windsurf', 'mcp_config.json')],
      detect: [path.join(home, '.codeium', 'windsurf')],
      restartHint: 'Windsurf’te MCP sunucularını yenile.'
    }
  ];
}

function msixClaudeDirs(env) {
  const local = env.LOCALAPPDATA;
  if (!local) return [];
  const pkgs = path.join(local, 'Packages');
  try {
    return fs
      .readdirSync(pkgs)
      .filter((n) => /^Claude_/i.test(n))
      .map((n) => path.join(pkgs, n, 'LocalCache', 'Roaming', 'Claude'));
  } catch {
    return [];
  }
}

// ---- Sunucu komutu ----------------------------------------------------------
// Kurulu / geliştirme sürümünde HexFear'ın kendi çalıştırılabilir dosyası Node
// gibi çalıştırılır (ELECTRON_RUN_AS_NODE) — kullanıcının Node kurmasına gerek
// kalmaz. Portable sürüm her açılışta geçici klasöre açıldığından yolu kalıcı
// değildir: orada sunucu dosyaları userData'ya kopyalanır ve sistem Node'u
// kullanılır.
function resolveServerEntry({ execPath, appPath, isPortable, runtimeDir, nodeAvailable }) {
  if (!isPortable) {
    return {
      command: execPath,
      args: [path.join(appPath, 'src', 'mcp', 'server.js')],
      env: { ELECTRON_RUN_AS_NODE: '1' }
    };
  }
  if (!nodeAvailable) {
    return {
      error: 'Portable sürümde MCP için sistemde Node.js gerekli (nodejs.org). Alternatif: HexFear kurulum (Setup) sürümünü kullan — Node gerektirmez.'
    };
  }
  return { command: 'node', args: [path.join(runtimeDir, 'src', 'mcp', 'server.js')], needsRuntimeCopy: true };
}

// Sunucunun ihtiyaç duyduğu dosyaları (src/ + package.json) kalıcı bir klasöre
// kopyalar. Kaynak asar arşivi olabilir; Electron'un fs yaması bunu okur.
function copyRuntime(appPath, runtimeDir) {
  fs.rmSync(runtimeDir, { recursive: true, force: true });
  copyDir(path.join(appPath, 'src'), path.join(runtimeDir, 'src'));
  fs.writeFileSync(path.join(runtimeDir, 'package.json'), fs.readFileSync(path.join(appPath, 'package.json')));
}

function copyDir(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const name of fs.readdirSync(from)) {
    const src = path.join(from, name);
    const dst = path.join(to, name);
    if (fs.statSync(src).isDirectory()) copyDir(src, dst);
    else fs.writeFileSync(dst, fs.readFileSync(src));
  }
}

function configEntry(client, entry) {
  const out = { ...(client.extra || {}), command: entry.command, args: entry.args };
  if (entry.env) out.env = entry.env;
  return out;
}

// ---- Okuma / yazma ----------------------------------------------------------
function readConfig(file) {
  if (!fs.existsSync(file)) return {};
  const raw = fs.readFileSync(file, 'utf8').replace(/^﻿/, '');
  if (!raw.trim()) return {};
  const j = JSON.parse(raw);
  if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error('Beklenmeyen biçim (JSON nesnesi değil)');
  return j;
}

function writeConfig(file, j) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (fs.existsSync(file) && !fs.existsSync(file + BACKUP_SUFFIX)) fs.copyFileSync(file, file + BACKUP_SUFFIX);
  const tmp = file + '.tmp-hexfear';
  fs.writeFileSync(tmp, JSON.stringify(j, null, 2) + '\n');
  fs.renameSync(tmp, file);
}

function sameEntry(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

// ---- Genel API --------------------------------------------------------------
// state: 'installed' (güncel) | 'different' (başka bir hexfear ayarı var) |
//        'none' (yok) | 'error' (dosya okunamadı)
function clientStatus(client, entry) {
  const detected = client.detect.some((p) => fs.existsSync(p));
  const file = client.files[0];
  let state = 'none';
  let error;
  try {
    const cur = (readConfig(file).mcpServers || {})[SERVER_KEY];
    if (cur) state = entry && !entry.error && sameEntry(cur, configEntry(client, entry)) ? 'installed' : 'different';
  } catch (e) {
    state = 'error';
    error = String(e.message || e);
  }
  return { id: client.id, name: client.name, detected, file, state, error, restartHint: client.restartHint };
}

function install(client, entry) {
  if (entry.error) throw new Error(entry.error);
  const want = configEntry(client, entry);
  // Önce hepsini oku: biri bozuksa hiçbirine yazma
  const configs = client.files.map((f) => {
    try {
      return [f, readConfig(f)];
    } catch (e) {
      throw new Error(`${f} okunamadı (${e.message}); dosyaya dokunulmadı.`);
    }
  });
  for (const [f, j] of configs) {
    if (!j.mcpServers || typeof j.mcpServers !== 'object') j.mcpServers = {};
    j.mcpServers[SERVER_KEY] = want;
    writeConfig(f, j);
  }
  return { ok: true, files: client.files };
}

function uninstall(client) {
  const touched = [];
  for (const f of client.files) {
    if (!fs.existsSync(f)) continue;
    const j = readConfig(f);
    if (!j.mcpServers || !j.mcpServers[SERVER_KEY]) continue;
    delete j.mcpServers[SERVER_KEY];
    writeConfig(f, j);
    touched.push(f);
  }
  return { ok: true, files: touched };
}

// Elle kurulum için gösterilecek örnek yapılandırma
function manualSnippet(entry) {
  if (entry.error) return null;
  return JSON.stringify({ mcpServers: { [SERVER_KEY]: configEntry({}, entry) } }, null, 2);
}

module.exports = {
  SERVER_KEY,
  BACKUP_SUFFIX,
  getClients,
  resolveServerEntry,
  copyRuntime,
  clientStatus,
  install,
  uninstall,
  manualSnippet
};
