const { app, BrowserWindow, dialog, powerMonitor, session, shell } = require('electron');
const { existsSync } = require('node:fs');
const { join } = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const readline = require('node:readline');

let mainWindow;
let hubProcess;
let hubUrl;
let startupTimer;

const singleInstance = app.requestSingleInstanceLock();
if (!singleInstance) app.quit();
app.setName('Soft Hub');
app.enableSandbox();

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

function stopHub() {
  if (!hubProcess || hubProcess.exitCode !== null) return;
  hubProcess.kill('SIGTERM');
  const processToStop = hubProcess;
  setTimeout(() => {
    if (processToStop.exitCode === null) processToStop.kill('SIGKILL');
  }, 14000).unref();
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

async function lockVaultForSystemEvent() {
  if (!hubUrl) return;
  try {
    const parsed = new URL(hubUrl);
    const token = new URLSearchParams(parsed.hash.slice(1)).get('token');
    if (!token) return;
    await fetch(new URL('/api/vault/lock', parsed.origin), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Soft-Hub-Token': token,
      },
      body: '{}',
    });
  } catch (error) {
    console.error('[soft-hub-core] vault auto-lock failed', error instanceof Error ? error.message : String(error));
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
    return createWindow();
  }).catch((error) => {
    dialog.showErrorBox('Soft Hub не запустился', error instanceof Error ? error.message : String(error));
    app.quit();
  });
  app.on('activate', () => {
    if (mainWindow) mainWindow.focus();
    else void createWindow();
  });
  app.on('before-quit', stopHub);
  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}
