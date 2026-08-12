const { app, BrowserWindow, dialog, ipcMain, net, powerMonitor, session, shell } = require('electron');
const { existsSync } = require('node:fs');
const { join } = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const readline = require('node:readline');

let mainWindow;
let hubProcess;
let hubUrl;
let startupTimer;
let hubStopPromise;
let hubUpdater;

const singleInstance = app.requestSingleInstanceLock();
if (!singleInstance) app.quit();
const updaterRuntime = singleInstance ? require('./updater.cjs') : null;
app.setName('Soft Hub');
app.enableSandbox();

const TRUSTED_CORE_PROXY_KEYS = Object.freeze(['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY']);

function trustedCoreProxyEnvironment(environment = process.env, platform = process.platform) {
  const proxyEnvironment = {};
  const names = Object.keys(environment);
  for (const canonicalName of TRUSTED_CORE_PROXY_KEYS) {
    let sourceName = Object.prototype.hasOwnProperty.call(environment, canonicalName)
      ? canonicalName
      : null;
    if (!sourceName && platform === 'win32') {
      sourceName = names.find((name) => name.toUpperCase() === canonicalName) || null;
    }
    const value = sourceName ? environment[sourceName] : undefined;
    if (typeof value === 'string' && value.trim()) {
      proxyEnvironment[canonicalName] = value;
    }
  }
  return proxyEnvironment;
}

function resolveCoreRoot() {
  return app.isPackaged ? process.resourcesPath : join(__dirname, '..');
}

function pythonCandidate() {
  const explicit = process.env.SOFT_HUB_PYTHON;
  const resources = resolveCoreRoot();
  const embedded = process.platform === 'win32'
    ? join(resources, 'python', 'python.exe')
    : join(resources, 'python', 'bin', 'python3');
  const candidates = app.isPackaged
    ? (existsSync(embedded) ? [{ command: embedded, prefix: ['-B', '-I'] }] : [])
    : explicit
      ? [{ command: explicit, prefix: [] }]
      : [
        ...(existsSync(embedded) ? [{ command: embedded, prefix: [] }] : []),
        ...(process.platform === 'win32'
          ? [{ command: 'py', prefix: ['-3.12'] }, { command: 'python', prefix: [] }]
          : [{ command: 'python3.12', prefix: [] }, { command: 'python3', prefix: [] }]),
      ];
  for (const candidate of candidates) {
    const probe = spawnSync(candidate.command, [
      ...candidate.prefix,
      '-c',
      'import sys, eth_account; from importlib.metadata import version; c=tuple(map(int, version("cryptography").split(".")[:2])); raise SystemExit(0 if sys.version_info[:2] == (3, 12) and (50, 0) <= c < (51, 0) else 1)',
    ], {
      encoding: 'utf8',
      windowsHide: true,
    });
    if (probe.status === 0) return candidate;
  }
  return null;
}

async function stopHubAndWait() {
  const processToStop = hubProcess;
  if (!processToStop || processToStop.exitCode !== null) return;
  if (hubStopPromise) return hubStopPromise;
  hubStopPromise = new Promise((resolve, reject) => {
    let forceTimer;
    let finalTimer;
    const finish = () => {
      clearTimeout(forceTimer);
      clearTimeout(finalTimer);
      resolve();
    };
    const fail = () => {
      clearTimeout(forceTimer);
      clearTimeout(finalTimer);
      reject(new Error('Ядро Soft Hub не завершилось вовремя.'));
    };
    processToStop.once('exit', finish);
    try {
      processToStop.kill('SIGTERM');
    } catch {
      finish();
      return;
    }
    forceTimer = setTimeout(() => {
      if (processToStop.exitCode === null) {
        try { processToStop.kill('SIGKILL'); } catch { /* Process already exited. */ }
      }
      finalTimer = setTimeout(() => {
        if (processToStop.exitCode === null) fail();
        else finish();
      }, 2_000);
      finalTimer.unref();
    }, 14_000);
    forceTimer.unref();
  }).finally(() => {
    hubStopPromise = null;
  });
  return hubStopPromise;
}

function stopHub() {
  void stopHubAndWait().catch((error) => {
    console.error('[soft-hub-core] stop failed', error instanceof Error ? error.message : String(error));
  });
}

function publicGitHubRepositoryUrl(value) {
  try {
    const candidate = new URL(value);
    const segments = candidate.pathname.split('/').filter(Boolean);
    if (
      candidate.protocol !== 'https:'
      || candidate.hostname !== 'github.com'
      || candidate.port
      || candidate.username
      || candidate.password
      || candidate.search
      || candidate.hash
      || segments.length !== 2
    ) return null;
    return candidate.href;
  } catch {
    return null;
  }
}

function hubApiConnection() {
  if (!hubUrl) throw new Error('Ядро Hub ещё не готово.');
  const parsed = new URL(hubUrl);
  const token = new URLSearchParams(parsed.hash.slice(1)).get('token');
  if (!token || parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1') {
    throw new Error('Некорректное локальное соединение Hub.');
  }
  return { origin: parsed.origin, token };
}

async function hubApi(pathname, { method = 'GET', body = undefined } = {}) {
  const { origin, token } = hubApiConnection();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    const response = await fetch(new URL(pathname, origin), {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-Soft-Hub-Token': token,
      },
      body,
      signal: controller.signal,
    });
    if (!response.ok) throw new Error('Локальное ядро Hub отклонило запрос.');
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function lockVaultForUpdate() {
  await hubApi('/api/vault/lock', { method: 'POST', body: '{}' });
}

async function lockVaultForSystemEvent() {
  if (!hubUrl) return;
  try {
    await lockVaultForUpdate();
  } catch (error) {
    console.error('[soft-hub-core] vault auto-lock failed', error instanceof Error ? error.message : String(error));
  }
}

async function activeRunsForUpdate() {
  const bootstrap = await hubApi('/api/bootstrap');
  const activeRuns = Number(bootstrap?.stats?.active_runs);
  if (!Number.isSafeInteger(activeRuns) || activeRuns < 0) {
    throw new Error('Hub вернул некорректное число активных задач.');
  }
  return activeRuns;
}

function trustedUpdaterSender(event) {
  if (!mainWindow || !hubUrl) return false;
  if (event.sender !== mainWindow.webContents) return false;
  if (event.senderFrame !== mainWindow.webContents.mainFrame) return false;
  try {
    return new URL(event.senderFrame.url).origin === new URL(hubUrl).origin;
  } catch {
    return false;
  }
}

function requireTrustedUpdaterSender(event) {
  if (!trustedUpdaterSender(event)) throw new Error('Updater IPC доступен только главному окну Hub.');
}

function broadcastUpdaterState(state) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.webContents.send(updaterRuntime.UPDATE_IPC.stateChanged, state);
}

async function confirmUpdateInstall(state) {
  const platformInstruction = process.platform === 'darwin'
    ? 'После открытия DMG замените Soft Hub в Applications.'
    : 'Откроется обычный установщик Windows и поставит версию поверх текущей.';
  const result = await dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: 'Обновить Soft Hub',
    message: `Установить Soft Hub ${state.availableVersion}?`,
    detail: `${platformInstruction}\n\nVault, аккаунты, софты и история лежат отдельно и останутся на месте.`,
    buttons: ['Открыть установщик', 'Не сейчас'],
    defaultId: 0,
    cancelId: 1,
    noLink: true,
  });
  return result.response === 0;
}

async function openVerifiedInstaller(installerPath) {
  const error = await shell.openPath(installerPath);
  if (error) throw new Error('Операционная система не смогла открыть установщик.');
}

async function recoverCoreAfterUpdateFailure() {
  if (hubProcess && hubProcess.exitCode === null) return;
  hubUrl = undefined;
  try {
    const url = await startHub();
    if (mainWindow && !mainWindow.isDestroyed()) await mainWindow.loadURL(url);
  } catch (error) {
    // A clean relaunch is the final recovery path if the existing renderer can
    // no longer be reconnected to a freshly started core.
    try { await stopHubAndWait(); } catch { /* Best effort before hard exit. */ }
    app.relaunch();
    app.exit(0);
    throw error;
  }
}

function setupUpdater() {
  const { HubUpdater, UPDATE_IPC } = updaterRuntime;
  hubUpdater = new HubUpdater({
    currentVersion: app.getVersion(),
    platform: process.platform,
    arch: process.arch,
    userDataPath: app.getPath('userData'),
    fetchImpl: (url, options) => net.fetch(url, options),
    enabled: app.isPackaged,
    onStateChange: broadcastUpdaterState,
    getActiveRuns: activeRunsForUpdate,
    confirmInstall: confirmUpdateInstall,
    lockVault: lockVaultForUpdate,
    stopCore: stopHubAndWait,
    openInstaller: openVerifiedInstaller,
    recoverCore: recoverCoreAfterUpdateFailure,
    quitApp: () => app.quit(),
  });

  const methods = [
    [UPDATE_IPC.getState, () => hubUpdater.snapshot()],
    [UPDATE_IPC.check, () => hubUpdater.check()],
    [UPDATE_IPC.download, () => hubUpdater.download()],
    [UPDATE_IPC.cancel, () => hubUpdater.cancel()],
    [UPDATE_IPC.install, () => hubUpdater.install()],
  ];
  for (const [channel, method] of methods) {
    ipcMain.handle(channel, async (event) => {
      requireTrustedUpdaterSender(event);
      return await method();
    });
  }
}

async function startHub() {
  const python = pythonCandidate();
  if (!python) {
    throw new Error(app.isPackaged
      ? 'Встроенный runtime Soft Hub отсутствует или повреждён. Переустановите приложение из установочного файла.'
      : 'Не найден Python 3.12 с зависимостями Soft Hub. Настройте .venv и SOFT_HUB_PYTHON.');
  }
  const coreRoot = resolveCoreRoot();
  const dataDir = process.env.SOFT_HUB_DATA_DIR || app.getPath('userData');
  const args = [
    ...python.prefix,
    '-m',
    'soft_hub',
    '--desktop',
    '--no-open',
    '--port',
    '0',
    '--data-dir',
    dataDir,
  ];
  hubProcess = spawn(python.command, args, {
    cwd: coreRoot,
    env: {
      PATH: process.env.PATH || '',
      SYSTEMROOT: process.env.SYSTEMROOT || '',
      TEMP: process.env.TEMP || '',
      TMP: process.env.TMP || '',
      TMPDIR: process.env.TMPDIR || '',
      LANG: process.env.LANG || 'en_US.UTF-8',
      ...trustedCoreProxyEnvironment(),
      PYTHONNOUSERSITE: '1',
      PYTHONDONTWRITEBYTECODE: '1',
      PYTHONUTF8: '1',
      PYTHONUNBUFFERED: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });

  return await new Promise((resolve, reject) => {
    let settled = false;
    startupTimer = setTimeout(() => {
      if (settled) return;
      settled = true;
      stopHub();
      reject(new Error('Ядро Soft Hub не ответило за 25 секунд.'));
    }, 25000);

    const lines = readline.createInterface({ input: hubProcess.stdout });
    lines.on('line', (line) => {
      if (!line.startsWith('SOFT_HUB_READY ') || settled) return;
      try {
        const ready = JSON.parse(line.slice('SOFT_HUB_READY '.length));
        const candidate = new URL(String(ready.url));
        if (
          candidate.protocol !== 'http:'
          || candidate.hostname !== '127.0.0.1'
          || candidate.username
          || candidate.password
          || candidate.port !== String(ready.port)
          || candidate.pathname !== '/'
        ) throw new Error('unsafe URL');
        settled = true;
        clearTimeout(startupTimer);
        hubUrl = ready.url;
        resolve(ready.url);
      } catch {
        settled = true;
        clearTimeout(startupTimer);
        reject(new Error('Ядро вернуло некорректный адрес интерфейса.'));
      }
    });
    hubProcess.stderr.on('data', (chunk) => {
      const line = String(chunk).trim();
      if (line) console.error('[soft-hub-core]', line);
    });
    hubProcess.once('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(startupTimer);
      reject(error);
    });
    hubProcess.once('exit', (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(startupTimer);
        reject(new Error(`Ядро Soft Hub завершилось при старте (code ${code}).`));
      }
    });
  });
}

async function createWindow() {
  const url = hubUrl || await startHub();
  mainWindow = new BrowserWindow({
    title: 'Soft Hub',
    width: 1380,
    height: 880,
    minWidth: 860,
    minHeight: 640,
    show: false,
    backgroundColor: '#e9e4da',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      preload: join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      devTools: !app.isPackaged,
    },
  });
  mainWindow.setMenu(null);
  mainWindow.once('ready-to-show', () => mainWindow?.show());
  mainWindow.on('closed', () => { mainWindow = undefined; });
  mainWindow.webContents.setWindowOpenHandler(({ url: target }) => {
    const external = publicGitHubRepositoryUrl(target);
    if (external) void shell.openExternal(external).catch(() => {});
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-attach-webview', (event) => event.preventDefault());
  mainWindow.webContents.on('will-navigate', (event, target) => {
    const base = new URL(url);
    const candidate = new URL(target);
    if (candidate.origin !== base.origin) event.preventDefault();
  });
  mainWindow.webContents.on('will-redirect', (event, target) => {
    const base = new URL(url);
    const candidate = new URL(target);
    if (candidate.origin !== base.origin) event.preventDefault();
  });
  await mainWindow.loadURL(url);
}

if (singleInstance) {
  app.setAppUserModelId('io.sprintray.softhub');
  app.on('second-instance', () => {
    if (!mainWindow) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  });
  app.whenReady().then(() => {
    session.defaultSession.setPermissionCheckHandler(() => false);
    session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
    powerMonitor.on('lock-screen', () => { void lockVaultForSystemEvent(); });
    powerMonitor.on('suspend', () => { void lockVaultForSystemEvent(); });
    setupUpdater();
    return createWindow();
  }).catch((error) => {
    dialog.showErrorBox('Soft Hub не запустился', error instanceof Error ? error.message : String(error));
    app.quit();
  });
  app.on('activate', () => {
    if (mainWindow) mainWindow.focus();
    else void createWindow();
  });
  app.on('before-quit', () => {
    stopHub();
  });
  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}
