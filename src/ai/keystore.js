'use strict';

// API anahtarı deposu. Anahtarlar Electron safeStorage ile (Windows'ta DPAPI)
// işletim sistemi düzeyinde şifrelenip userData klasöründe saklanır.
// Düz metin olarak diske veya depoya ASLA yazılmaz.

const fs = require('fs');
const path = require('path');
const { app, safeStorage } = require('electron');

const PROVIDERS = ['anthropic', 'openai', 'gemini'];

function storeFile() {
  return path.join(app.getPath('userData'), 'keys.enc.json');
}

function readStore() {
  try {
    return JSON.parse(fs.readFileSync(storeFile(), 'utf8'));
  } catch {
    return {};
  }
}

function writeStore(obj) {
  fs.writeFileSync(storeFile(), JSON.stringify(obj), { mode: 0o600 });
}

function available() {
  try {
    return safeStorage.isEncryptionAvailable();
  } catch {
    return false;
  }
}

function saveKey(provider, key) {
  if (!PROVIDERS.includes(provider)) throw new Error('Bilinmeyen sağlayıcı: ' + provider);
  if (!key || typeof key !== 'string') throw new Error('Geçersiz anahtar');
  const store = readStore();
  if (available()) {
    store[provider] = { enc: safeStorage.encryptString(key).toString('base64'), method: 'safeStorage' };
  } else {
    // safeStorage yoksa (ör. Linux keyring yok) en azından açık uyarıyla sakla
    store[provider] = { enc: Buffer.from(key, 'utf8').toString('base64'), method: 'plain' };
  }
  writeStore(store);
  return { ok: true, method: store[provider].method };
}

function getKey(provider) {
  const store = readStore();
  const e = store[provider];
  if (!e) return null;
  try {
    if (e.method === 'safeStorage') {
      return safeStorage.decryptString(Buffer.from(e.enc, 'base64'));
    }
    return Buffer.from(e.enc, 'base64').toString('utf8');
  } catch {
    return null;
  }
}

function removeKey(provider) {
  const store = readStore();
  delete store[provider];
  writeStore(store);
  return { ok: true };
}

// Anahtarın kendisini DÖNDÜRMEZ — sadece hangi sağlayıcılarda anahtar var bilgisini verir.
function status() {
  const store = readStore();
  const out = { encryptionAvailable: available(), providers: {} };
  for (const p of PROVIDERS) {
    out.providers[p] = { hasKey: !!store[p], method: store[p] ? store[p].method : null };
  }
  return out;
}

module.exports = { PROVIDERS, saveKey, getKey, removeKey, status };
