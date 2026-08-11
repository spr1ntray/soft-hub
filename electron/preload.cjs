const { contextBridge, ipcRenderer } = require('electron');

const channels = Object.freeze({
  getState: 'soft-hub:update:get-state',
  check: 'soft-hub:update:check',
  download: 'soft-hub:update:download',
  cancel: 'soft-hub:update:cancel',
  install: 'soft-hub:update:install',
  stateChanged: 'soft-hub:update:state-changed',
});

const updater = Object.freeze({
  getState: () => ipcRenderer.invoke(channels.getState),
  check: () => ipcRenderer.invoke(channels.check),
  download: () => ipcRenderer.invoke(channels.download),
  cancel: () => ipcRenderer.invoke(channels.cancel),
  install: () => ipcRenderer.invoke(channels.install),
  onStateChanged: (callback) => {
    if (typeof callback !== 'function') throw new TypeError('callback must be a function');
    const listener = (_event, state) => callback(state);
    ipcRenderer.on(channels.stateChanged, listener);
    return () => ipcRenderer.removeListener(channels.stateChanged, listener);
  },
});

contextBridge.exposeInMainWorld('softHubDesktop', Object.freeze({ updater }));
