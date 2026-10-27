'use strict';

const { contextBridge, ipcRenderer, webUtils } = require('electron');

// Renderer'a yalnızca gereken köprü. Dosya sistemine doğrudan erişim yok.
contextBridge.exposeInMainWorld('hexfear', {
  // Electron 32+ ile File.path kaldırıldı; sürükle-bırak için webUtils gerekli.
  getPathForFile: (file) => {
    try {
      return webUtils.getPathForFile(file);
    } catch {
      return file && file.path ? file.path : null;
    }
  },

  analyzeFile: (filePath) => ipcRenderer.invoke('hf:analyze', filePath),
  getMeta: () => ipcRenderer.invoke('hf:meta'),

  keys: {
    status: () => ipcRenderer.invoke('hf:keys:status'),
    save: (provider, key) => ipcRenderer.invoke('hf:keys:save', provider, key),
    remove: (provider) => ipcRenderer.invoke('hf:keys:remove', provider)
  },

  agent: {
    run: (opts) => ipcRenderer.invoke('hf:agent:run', opts),
    cancel: (runId) => ipcRenderer.invoke('hf:agent:cancel', runId),
    onEvent: (cb) => {
      const h = (_e, data) => cb(data);
      ipcRenderer.on('hf:agent:event', h);
      return () => ipcRenderer.removeListener('hf:agent:event', h);
    }
  }
});
