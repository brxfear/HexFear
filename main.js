'use strict';

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { analyzeFile } = require('./src/analysis');
const keystore = require('./src/ai/keystore');
const { runAgent } = require('./src/ai/agent');
const { modeList } = require('./src/ai/prompts');
const { DEFAULT_MODELS } = require('./src/ai/providers');
const { detectDisassembler } = require('./src/ai/tools');

const isDev = process.argv.includes('--dev');
const runs = new Map(); // runId -> AbortController

function createWindow() {
  const win = new BrowserWindow({
    width: 1240,
    height: 860,
    minWidth: 980,
    minHeight: 640,
    backgroundColor: '#0d0f14',
    title: 'HexFear',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });
  win.setMenuBarVisibility(false);
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  if (isDev) win.webContents.openDevTools({ mode: 'detach' });
}

// --- Statik analiz (yerel) -------------------------------------------------
ipcMain.handle('hf:analyze', async (_e, filePath) => {
  try {
    return { ok: true, report: await analyzeFile(filePath) };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
});

// --- Meta (modlar, varsayılan modeller, ortam) -----------------------------
ipcMain.handle('hf:meta', async () => ({
  modes: modeList(),
  defaultModels: DEFAULT_MODELS,
  disassembler: detectDisassembler(),
  keys: keystore.status()
}));

// --- Anahtar yönetimi ------------------------------------------------------
ipcMain.handle('hf:keys:status', async () => keystore.status());
ipcMain.handle('hf:keys:save', async (_e, provider, key) => {
  try {
    return keystore.saveKey(provider, key);
  } catch (err) {
    return { ok: false, error: String(err.message || err) };
  }
});
ipcMain.handle('hf:keys:remove', async (_e, provider) => keystore.removeKey(provider));

// --- AI ajan çalıştırma (akışlı) ------------------------------------------
ipcMain.handle('hf:agent:run', async (event, opts) => {
  const { filePath, provider, model, mode, runId, scopeConfirmed } = opts || {};
  if (!scopeConfirmed) return { ok: false, error: 'Kapsam onayı verilmedi' };

  const apiKey = keystore.getKey(provider);
  if (!apiKey) return { ok: false, error: `${provider} için kayıtlı API anahtarı yok` };

  const ac = new AbortController();
  runs.set(runId, ac);
  const onEvent = (ev) => {
    if (!event.sender.isDestroyed()) event.sender.send('hf:agent:event', { runId, ...ev });
  };
  try {
    const result = await runAgent({ filePath, provider, apiKey, model, mode, onEvent, signal: ac.signal });
    return result;
  } catch (err) {
    return { ok: false, error: String(err.message || err) };
  } finally {
    runs.delete(runId);
  }
});

ipcMain.handle('hf:agent:cancel', async (_e, runId) => {
  const ac = runs.get(runId);
  if (ac) ac.abort();
  return { ok: true };
});

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
