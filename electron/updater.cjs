const { createHash } = require('node:crypto');
const {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  unlink,
} = require('node:fs/promises');
const { basename, dirname, join, resolve } = require('node:path');

const UPDATE_REPOSITORY = Object.freeze({ owner: 'spr1ntray', repo: 'soft-hub' });
const LATEST_RELEASE_URL = 'https://api.github.com/repos/spr1ntray/soft-hub/releases/latest';
const UPDATE_IPC = Object.freeze({
  getState: 'soft-hub:update:get-state',
  check: 'soft-hub:update:check',
  download: 'soft-hub:update:download',
  cancel: 'soft-hub:update:cancel',
  install: 'soft-hub:update:install',
  stateChanged: 'soft-hub:update:state-changed',
});

const MAX_INSTALLER_BYTES = 512 * 1024 * 1024;
const MAX_CHECKSUM_BYTES = 64 * 1024;
const MAX_RELEASE_NOTES_LENGTH = 4_000;
const MAX_REDIRECTS = 5;
const CHECK_TIMEOUT_MS = 30_000;
const DOWNLOAD_TIMEOUT_MS = 20 * 60_000;
const RELEASE_HOSTS = new Set([
  'github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
]);
// v0.6.14 predates repository-level immutable releases. Keep one exact,
// compiled-in bridge so older local builds can reach it without accepting an
// arbitrary mutable release. Any changed release identity, commit, asset ID,
// size or GitHub-computed digest fails closed. Remove this bridge after the
// first immutable public release has become the minimum supported version.
const LEGACY_PINNED_RELEASES = Object.freeze({
  '0.6.14': Object.freeze({
    releaseId: 369702046,
    targetCommitish: '426e39ce5c8ba9d264d0e95d641b4dc622e27b2b',
    publishedAt: '2026-08-13T06:22:20Z',
    assets: Object.freeze({
      SHA256SUMS: Object.freeze({
        id: 512584062,
        size: 182,
        digest: 'sha256:043cb96ac3eb93f6f312ccc6069acc46b1389c4d311959c9fc983dbf6efab95a',
      }),
      'Soft-Hub-0.6.14-arm64.dmg': Object.freeze({
        id: 512584063,
        size: 164471289,
        digest: 'sha256:3150eb3e0b4bf21313bfce4844821742e0821656cd8ae728976693ed2a627db5',
      }),
      'Soft-Hub-0.6.14-x64.exe': Object.freeze({
        id: 512584061,
        size: 126548589,
        digest: 'sha256:ad18af83dcf8bbe49c24805d3af3fe50855c3f3ef689730867e9faebfd0cbf47',
      }),
    }),
  }),
});
const CACHED_INSTALLER_RE = /^Soft-Hub-(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)-(?:arm64\.dmg|x64\.exe)(?:\.part)?$/;

class UpdateError extends Error {
  constructor(message, code = 'update_error') {
    super(message);
    this.name = 'UpdateError';
    this.code = code;
  }
}

function strictSemver(value) {
  if (typeof value !== 'string') return null;
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(value);
  if (!match) return null;
  const parts = match.slice(1).map(Number);
  return parts.every(Number.isSafeInteger) ? parts : null;
}

function compareSemver(left, right) {
  const leftParts = strictSemver(left);
  const rightParts = strictSemver(right);
  if (!leftParts || !rightParts) throw new UpdateError('Некорректная версия приложения.', 'invalid_version');
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] !== rightParts[index]) return leftParts[index] > rightParts[index] ? 1 : -1;
  }
  return 0;
}

function platformAssetName(version, platform, arch) {
  if (platform === 'darwin' && arch === 'arm64') return `Soft-Hub-${version}-arm64.dmg`;
  if (platform === 'win32' && arch === 'x64') return `Soft-Hub-${version}-x64.exe`;
  return null;
}

function cleanReleaseNotes(value) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '')
    .trim()
    .slice(0, MAX_RELEASE_NOTES_LENGTH);
}

function checkedHttpsUrl(value, allowedHosts, { allowSearch = true } = {}) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new UpdateError('Релиз содержит некорректную ссылку.', 'unsafe_url');
  }
  if (
    parsed.protocol !== 'https:'
    || !allowedHosts.has(parsed.hostname)
    || parsed.port
    || parsed.username
    || parsed.password
    || parsed.hash
    || (!allowSearch && parsed.search)
  ) {
    throw new UpdateError('Релиз содержит небезопасную ссылку.', 'unsafe_url');
  }
  return parsed;
}

function checkedReleaseAssetUrl(value, version, assetName) {
  const parsed = checkedHttpsUrl(value, new Set(['github.com']), { allowSearch: false });
  let pathname;
  try {
    pathname = decodeURIComponent(parsed.pathname);
  } catch {
    throw new UpdateError('Релиз содержит некорректную ссылку на файл.', 'unsafe_asset_url');
  }
  const expected = `/${UPDATE_REPOSITORY.owner}/${UPDATE_REPOSITORY.repo}/releases/download/v${version}/${assetName}`;
  if (pathname !== expected) {
    throw new UpdateError('Файл обновления ведёт не в официальный релиз Hub.', 'unsafe_asset_url');
  }
  return parsed.href;
}

function exactlyOneAsset(assets, name) {
  const matches = assets.filter((asset) => asset && asset.name === name);
  if (matches.length !== 1) {
    throw new UpdateError(`В релизе должен быть ровно один файл ${name}.`, 'asset_missing');
  }
  return matches[0];
}

function checkedAsset(asset, version, name, maximumSize) {
  const size = Number(asset.size);
  if (!Number.isSafeInteger(size) || size <= 0 || size > maximumSize) {
    throw new UpdateError(`Файл ${name} имеет недопустимый размер.`, 'unsafe_asset_size');
  }
  if (asset.state !== undefined && asset.state !== 'uploaded') {
    throw new UpdateError(`Файл ${name} ещё не готов.`, 'asset_not_ready');
  }
  const digestMatch = /^sha256:([a-f0-9]{64})$/.exec(String(asset.digest || ''));
  if (!digestMatch) {
    throw new UpdateError(`GitHub не подтвердил SHA-256 файла ${name}.`, 'asset_digest_required');
  }
  return Object.freeze({
    name,
    size,
    url: checkedReleaseAssetUrl(asset.browser_download_url, version, name),
    apiDigest: digestMatch[1],
  });
}

function matchesPinnedLegacyRelease(payload, version) {
  const pin = LEGACY_PINNED_RELEASES[version];
  if (!pin || !Array.isArray(payload.assets)) return false;
  if (
    payload.id !== pin.releaseId
    || payload.target_commitish !== pin.targetCommitish
    || payload.published_at !== pin.publishedAt
  ) return false;
  const expectedNames = Object.keys(pin.assets);
  if (payload.assets.length !== expectedNames.length) return false;
  for (const name of expectedNames) {
    const matches = payload.assets.filter((asset) => asset && asset.name === name);
    if (matches.length !== 1) return false;
    const asset = matches[0];
    const expected = pin.assets[name];
    if (
      asset.id !== expected.id
      || asset.size !== expected.size
      || asset.digest !== expected.digest
      || (asset.state !== undefined && asset.state !== 'uploaded')
    ) return false;
  }
  return true;
}

function inspectRelease(payload, currentVersion, platform, arch) {
  if (!strictSemver(currentVersion)) {
    throw new UpdateError('Текущая версия Hub имеет некорректный формат.', 'invalid_current_version');
  }
  const assetName = platformAssetName('', platform, arch);
  if (!assetName) return Object.freeze({ status: 'unsupported' });
  if (!payload || typeof payload !== 'object' || payload.draft === true || payload.prerelease === true) {
    throw new UpdateError('Последний GitHub Release не является стабильным.', 'unstable_release');
  }
  const tag = typeof payload.tag_name === 'string' ? payload.tag_name : '';
  const version = tag.startsWith('v') ? tag.slice(1) : '';
  if (!strictSemver(version) || tag !== `v${version}`) {
    throw new UpdateError('Тег последнего релиза должен иметь вид v1.2.3.', 'invalid_release_version');
  }
  if (compareSemver(version, currentVersion) <= 0) {
    return Object.freeze({ status: 'up_to_date', version, releaseNotes: cleanReleaseNotes(payload.body) });
  }
  if (payload.immutable !== true && !matchesPinnedLegacyRelease(payload, version)) {
    throw new UpdateError(
      'Новый GitHub Release не защищён от изменений. Включите immutable releases и опубликуйте версию заново.',
      'mutable_release',
    );
  }
  if (!Array.isArray(payload.assets)) {
    throw new UpdateError('В GitHub Release отсутствует список файлов.', 'assets_missing');
  }
  const canonicalName = platformAssetName(version, platform, arch);
  const installer = checkedAsset(
    exactlyOneAsset(payload.assets, canonicalName),
    version,
    canonicalName,
    MAX_INSTALLER_BYTES,
  );
  const checksum = checkedAsset(
    exactlyOneAsset(payload.assets, 'SHA256SUMS'),
    version,
    'SHA256SUMS',
    MAX_CHECKSUM_BYTES,
  );
  return Object.freeze({
    status: 'available',
    version,
    releaseNotes: cleanReleaseNotes(payload.body),
    installer,
    checksum,
  });
}

function parseChecksumManifest(value, expectedName) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAX_CHECKSUM_BYTES) {
    throw new UpdateError('SHA256SUMS имеет недопустимый размер.', 'invalid_checksum_manifest');
  }
  const seen = new Set();
  let expectedDigest = null;
  const lines = value.replace(/\r\n/g, '\n').split('\n');
  for (const rawLine of lines) {
    if (!rawLine.trim()) continue;
    const match = /^([a-fA-F0-9]{64})[ \t]+\*?([^\0\r\n]+)$/.exec(rawLine);
    if (!match) throw new UpdateError('SHA256SUMS содержит некорректную строку.', 'invalid_checksum_manifest');
    const name = match[2].trim();
    if (!name || basename(name) !== name || name === '.' || name === '..') {
      throw new UpdateError('SHA256SUMS содержит небезопасное имя файла.', 'invalid_checksum_manifest');
    }
    if (seen.has(name)) throw new UpdateError('SHA256SUMS содержит повторяющееся имя.', 'invalid_checksum_manifest');
    seen.add(name);
    if (name === expectedName) expectedDigest = match[1].toLowerCase();
  }
  if (!expectedDigest) {
    throw new UpdateError(`В SHA256SUMS нет строки для ${expectedName}.`, 'checksum_missing');
  }
  return expectedDigest;
}

async function fetchRedirectSafe(fetchImpl, initialUrl, { allowedHosts, headers, signal }) {
  let current = checkedHttpsUrl(initialUrl, allowedHosts);
  for (let redirect = 0; redirect <= MAX_REDIRECTS; redirect += 1) {
    let response;
    try {
      response = await fetchImpl(current.href, {
        method: 'GET',
        headers,
        redirect: 'manual',
        signal,
      });
    } catch (error) {
      if (error instanceof UpdateError || error?.name === 'AbortError' || signal?.aborted) throw error;
      throw new UpdateError('Не удалось подключиться к GitHub. Проверьте интернет и попробуйте ещё раз.', 'github_request_failed');
    }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      if (redirect === MAX_REDIRECTS) throw new UpdateError('Слишком много перенаправлений.', 'too_many_redirects');
      const location = response.headers.get('location');
      if (!location) throw new UpdateError('GitHub вернул пустое перенаправление.', 'unsafe_redirect');
      current = checkedHttpsUrl(new URL(location, current).href, allowedHosts);
      try { await response.body?.cancel(); } catch { /* Nothing sensitive to report. */ }
      continue;
    }
    if (!response.ok) throw new UpdateError('GitHub не отдал файл обновления.', 'github_request_failed');
    if (response.url) checkedHttpsUrl(response.url, allowedHosts);
    return response;
  }
  throw new UpdateError('Слишком много перенаправлений.', 'too_many_redirects');
}

async function readBoundedBody(response, maximumBytes, { expectedBytes = null, onChunk = null } = {}) {
  const declaredValue = response.headers.get('content-length');
  if (declaredValue !== null) {
    const declared = Number(declaredValue);
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > maximumBytes) {
      throw new UpdateError('Сервер объявил недопустимый размер файла.', 'unsafe_content_length');
    }
    if (expectedBytes !== null && declared !== expectedBytes) {
      throw new UpdateError('Размер файла на сервере не совпадает с релизом.', 'content_length_mismatch');
    }
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    throw new UpdateError('GitHub вернул пустой файл.', 'empty_response');
  }
  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = Buffer.from(value);
    received += chunk.length;
    if (received > maximumBytes || (expectedBytes !== null && received > expectedBytes)) {
      try { await reader.cancel(); } catch { /* Best effort. */ }
      throw new UpdateError('Файл обновления оказался больше заявленного.', 'download_too_large');
    }
    if (onChunk) await onChunk(chunk, received);
    else chunks.push(chunk);
  }
  if (expectedBytes !== null && received !== expectedBytes) {
    throw new UpdateError('Файл обновления скачался не полностью.', 'download_truncated');
  }
  return onChunk ? received : Buffer.concat(chunks, received);
}

async function ensureUpdateDirectory(userDataPath) {
  const dataRoot = resolve(userDataPath);
  const updateDirectory = join(dataRoot, 'updates');
  if (dirname(updateDirectory) !== dataRoot) throw new UpdateError('Некорректный каталог обновлений.', 'unsafe_update_path');
  await mkdir(updateDirectory, { recursive: true, mode: 0o700 });
  const info = await lstat(updateDirectory);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new UpdateError('Каталог обновлений повреждён.', 'unsafe_update_path');
  }
  try { await chmod(updateDirectory, 0o700); } catch { /* Windows permissions differ. */ }
  return updateDirectory;
}

async function safeUnlink(filePath, updateDirectory) {
  if (dirname(filePath) !== updateDirectory) throw new UpdateError('Некорректный путь обновления.', 'unsafe_update_path');
  try {
    const info = await lstat(filePath);
    if (!info.isFile() && !info.isSymbolicLink()) {
      throw new UpdateError('В кэше обновлений найден неожиданный объект.', 'unsafe_update_path');
    }
    await unlink(filePath);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

async function pruneUpdateCache(userDataPath, keepNames = new Set()) {
  const dataRoot = resolve(userDataPath);
  const updateDirectory = join(dataRoot, 'updates');
  if (dirname(updateDirectory) !== dataRoot) {
    throw new UpdateError('Некорректный каталог обновлений.', 'unsafe_update_path');
  }
  let directoryInfo;
  try {
    directoryInfo = await lstat(updateDirectory);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
    throw new UpdateError('Каталог обновлений повреждён.', 'unsafe_update_path');
  }
  const names = await readdir(updateDirectory);
  for (const name of names) {
    if (!CACHED_INSTALLER_RE.test(name) || keepNames.has(name)) continue;
    await safeUnlink(join(updateDirectory, name), updateDirectory);
  }
}

async function discardExactCachedInstaller(filePath, userDataPath, expectedName) {
  const updateDirectory = join(resolve(userDataPath), 'updates');
  const expectedPath = join(updateDirectory, expectedName);
  if (filePath !== expectedPath || dirname(expectedPath) !== updateDirectory || basename(expectedPath) !== expectedName) {
    return false;
  }
  try {
    const directoryInfo = await lstat(updateDirectory);
    if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) return false;
    await safeUnlink(expectedPath, updateDirectory);
    return true;
  } catch {
    return false;
  }
}

async function sha256File(filePath, expectedBytes) {
  const info = await lstat(filePath);
  if (!info.isFile() || info.isSymbolicLink() || info.size !== expectedBytes || info.size > MAX_INSTALLER_BYTES) {
    throw new UpdateError('Скачанный установщик повреждён.', 'invalid_cached_installer');
  }
  const handle = await open(filePath, 'r');
  const digest = createHash('sha256');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let offset = 0;
  try {
    while (offset < expectedBytes) {
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, expectedBytes - offset), offset);
      if (!bytesRead) break;
      digest.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
  } finally {
    await handle.close();
  }
  if (offset !== expectedBytes) throw new UpdateError('Скачанный установщик повреждён.', 'invalid_cached_installer');
  return digest.digest('hex');
}

function publicErrorMessage(error, fallback) {
  if (error instanceof UpdateError) return error.message;
  if (error?.name === 'AbortError') return 'Скачивание отменено.';
  return fallback;
}

function cleanInstallIssue(value) {
  return String(value || '')
    .replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 320);
}

class HubUpdater {
  constructor({
    currentVersion,
    platform,
    arch,
    userDataPath,
    fetchImpl,
    enabled = true,
    onStateChange = () => {},
    getActiveRuns = async () => 0,
    confirmInstall = async () => false,
    lockVault = async () => {},
    stopCore = async () => {},
    openInstaller = async () => {},
    recoverCore = async () => {},
    quitApp = () => {},
  }) {
    if (!strictSemver(currentVersion)) throw new UpdateError('Некорректная текущая версия Hub.', 'invalid_current_version');
    this.currentVersion = currentVersion;
    this.platform = platform;
    this.arch = arch;
    this.userDataPath = userDataPath;
    this.fetchImpl = fetchImpl;
    this.enabled = enabled;
    this.onStateChange = onStateChange;
    this.getActiveRuns = getActiveRuns;
    this.confirmInstall = confirmInstall;
    this.lockVault = lockVault;
    this.stopCore = stopCore;
    this.openInstaller = openInstaller;
    this.recoverCore = recoverCore;
    this.quitApp = quitApp;
    this.candidate = null;
    this.verifiedInstaller = null;
    this.checkPromise = null;
    this.downloadPromise = null;
    this.downloadController = null;
    this.installPromise = null;
    this.state = {
      status: enabled && platformAssetName(currentVersion, platform, arch) ? 'idle' : 'unsupported',
      message: enabled ? '' : 'Проверка обновлений доступна в установленной версии Hub.',
      checkedAt: null,
      transferred: 0,
      total: 0,
      percent: 0,
      installIssue: '',
    };
  }

  snapshot() {
    const availableVersion = this.candidate?.version || null;
    const installIssue = this.state.installIssue || '';
    return Object.freeze({
      status: this.state.status,
      phase: this.state.status,
      currentVersion: this.currentVersion,
      availableVersion,
      version: availableVersion,
      percent: this.state.percent,
      transferred: this.state.transferred,
      total: this.state.total,
      releaseNotes: this.candidate?.releaseNotes || '',
      message: this.state.message || '',
      issue: installIssue,
      installIssue,
      checkedAt: this.state.checkedAt,
    });
  }

  transition(status, changes = {}) {
    const installIssue = Object.prototype.hasOwnProperty.call(changes, 'installIssue')
      ? cleanInstallIssue(changes.installIssue)
      : '';
    this.state = { ...this.state, ...changes, status, installIssue };
    const snapshot = this.snapshot();
    this.onStateChange(snapshot);
    return snapshot;
  }

  async withTimeout(milliseconds, externalSignal, operation) {
    const controller = new AbortController();
    const relayAbort = () => controller.abort(externalSignal?.reason);
    if (externalSignal?.aborted) relayAbort();
    else externalSignal?.addEventListener('abort', relayAbort, { once: true });
    const timer = setTimeout(() => controller.abort(new UpdateError('Сеть не ответила вовремя.', 'network_timeout')), milliseconds);
    try {
      return await operation(controller.signal);
    } finally {
      clearTimeout(timer);
      externalSignal?.removeEventListener('abort', relayAbort);
    }
  }

  async check() {
    if (!this.enabled || !platformAssetName(this.currentVersion, this.platform, this.arch)) {
      return this.transition('unsupported', { message: 'Для этой сборки встроенное обновление недоступно.' });
    }
    if (this.downloadPromise || this.installPromise || this.state.status === 'downloaded') return this.snapshot();
    if (this.checkPromise) return this.checkPromise;
    this.checkPromise = (async () => {
      this.transition('checking', { message: 'Ищем свежую версию Hub.' });
      try {
        await pruneUpdateCache(this.userDataPath);
        const payloadBuffer = await this.withTimeout(CHECK_TIMEOUT_MS, null, async (signal) => {
          const response = await fetchRedirectSafe(
            this.fetchImpl,
            LATEST_RELEASE_URL,
            {
              allowedHosts: new Set(['api.github.com']),
              headers: {
                Accept: 'application/vnd.github+json',
                'Cache-Control': 'no-cache',
                'User-Agent': `Soft-Hub/${this.currentVersion}`,
                'X-GitHub-Api-Version': '2022-11-28',
              },
              signal,
            },
          );
          return await readBoundedBody(response, 1024 * 1024);
        });
        let payload;
        try {
          payload = JSON.parse(payloadBuffer.toString('utf8'));
        } catch {
          throw new UpdateError('GitHub вернул некорректное описание релиза.', 'invalid_release_json');
        }
        const inspected = inspectRelease(payload, this.currentVersion, this.platform, this.arch);
        this.verifiedInstaller = null;
        this.candidate = inspected.status === 'available' ? inspected : null;
        const checkedAt = new Date().toISOString();
        if (inspected.status === 'available') {
          return this.transition('available', {
            checkedAt,
            message: `Доступна версия ${inspected.version}.`,
            transferred: 0,
            total: inspected.installer.size,
            percent: 0,
          });
        }
        return this.transition(inspected.status, {
          checkedAt,
          message: inspected.status === 'up_to_date'
            ? 'У вас уже свежая версия Hub.'
            : 'Для этой системы обновление пока недоступно.',
          transferred: 0,
          total: 0,
          percent: 0,
        });
      } catch (error) {
        this.candidate = null;
        this.verifiedInstaller = null;
        return this.transition('error', {
          checkedAt: new Date().toISOString(),
          message: publicErrorMessage(error, 'Не получилось проверить обновление. Попробуйте ещё раз.'),
          transferred: 0,
          total: 0,
          percent: 0,
        });
      } finally {
        this.checkPromise = null;
      }
    })();
    return this.checkPromise;
  }

  async download() {
    if (this.downloadPromise) return this.downloadPromise;
    if (!this.candidate || !['available', 'error'].includes(this.state.status)) return this.snapshot();
    const candidate = this.candidate;
    this.downloadController = new AbortController();
    const externalSignal = this.downloadController.signal;
    this.downloadPromise = (async () => {
      let partialPath = null;
      let updateDirectory = null;
      this.transition('downloading', {
        message: `Скачиваем Hub ${candidate.version}.`,
        transferred: 0,
        total: candidate.installer.size,
        percent: 0,
      });
      try {
        const checksumBuffer = await this.withTimeout(DOWNLOAD_TIMEOUT_MS, externalSignal, async (signal) => {
          const checksumResponse = await fetchRedirectSafe(
            this.fetchImpl,
            candidate.checksum.url,
            {
              allowedHosts: RELEASE_HOSTS,
              headers: { Accept: 'application/octet-stream', 'Cache-Control': 'no-cache' },
              signal,
            },
          );
          return await readBoundedBody(checksumResponse, MAX_CHECKSUM_BYTES, {
            expectedBytes: candidate.checksum.size,
          });
        });
        const checksumDigest = createHash('sha256').update(checksumBuffer).digest('hex');
        if (candidate.checksum.apiDigest && candidate.checksum.apiDigest !== checksumDigest) {
          throw new UpdateError('SHA256SUMS не совпал с digest GitHub.', 'checksum_manifest_digest_mismatch');
        }
        const expectedDigest = parseChecksumManifest(checksumBuffer.toString('utf8'), candidate.installer.name);
        if (candidate.installer.apiDigest && candidate.installer.apiDigest !== expectedDigest) {
          throw new UpdateError('Digest GitHub не совпал с SHA256SUMS.', 'checksum_conflict');
        }

        updateDirectory = await ensureUpdateDirectory(this.userDataPath);
        const finalPath = join(updateDirectory, candidate.installer.name);
        partialPath = `${finalPath}.part`;
        if (dirname(finalPath) !== updateDirectory || basename(finalPath) !== candidate.installer.name) {
          throw new UpdateError('Некорректный путь установщика.', 'unsafe_update_path');
        }
        await safeUnlink(partialPath, updateDirectory);
        const handle = await open(partialPath, 'wx', 0o600);
        const digest = createHash('sha256');
        let writeOffset = 0;
        let lastProgressAt = 0;
        try {
          await this.withTimeout(DOWNLOAD_TIMEOUT_MS, externalSignal, async (signal) => {
            const installerResponse = await fetchRedirectSafe(
              this.fetchImpl,
              candidate.installer.url,
              {
                allowedHosts: RELEASE_HOSTS,
                headers: { Accept: 'application/octet-stream', 'Cache-Control': 'no-cache' },
                signal,
              },
            );
            await readBoundedBody(installerResponse, MAX_INSTALLER_BYTES, {
              expectedBytes: candidate.installer.size,
              onChunk: async (chunk, transferred) => {
                let written = 0;
                while (written < chunk.length) {
                  const result = await handle.write(chunk, written, chunk.length - written, writeOffset + written);
                  if (!result.bytesWritten) throw new UpdateError('Не получилось записать установщик.', 'write_failed');
                  written += result.bytesWritten;
                }
                writeOffset += chunk.length;
                digest.update(chunk);
                const now = Date.now();
                if (now - lastProgressAt >= 100 || transferred === candidate.installer.size) {
                  lastProgressAt = now;
                  this.transition('downloading', {
                    transferred,
                    total: candidate.installer.size,
                    percent: Math.min(100, Math.round((transferred / candidate.installer.size) * 100)),
                  });
                }
              },
            });
          });
          await handle.sync();
        } finally {
          await handle.close();
        }
        const actualDigest = digest.digest('hex');
        if (actualDigest !== expectedDigest) {
          throw new UpdateError('SHA-256 установщика не совпал с релизом.', 'checksum_mismatch');
        }
        await safeUnlink(finalPath, updateDirectory);
        await rename(partialPath, finalPath);
        partialPath = null;
        try { await chmod(finalPath, 0o600); } catch { /* Windows permissions differ. */ }
        this.verifiedInstaller = Object.freeze({
          path: finalPath,
          size: candidate.installer.size,
          sha256: expectedDigest,
          version: candidate.version,
        });
        return this.transition('downloaded', {
          message: 'Обновление скачано и проверено.',
          transferred: candidate.installer.size,
          total: candidate.installer.size,
          percent: 100,
        });
      } catch (error) {
        if (partialPath && updateDirectory) {
          try { await safeUnlink(partialPath, updateDirectory); } catch { /* Keep original error. */ }
        }
        this.verifiedInstaller = null;
        if (externalSignal.aborted) {
          return this.transition('available', {
            message: 'Скачивание отменено.',
            transferred: 0,
            total: candidate.installer.size,
            percent: 0,
          });
        }
        return this.transition('error', {
          message: publicErrorMessage(error, 'Не получилось скачать обновление. Попробуйте ещё раз.'),
          transferred: 0,
          total: candidate.installer.size,
          percent: 0,
        });
      } finally {
        this.downloadController = null;
        this.downloadPromise = null;
      }
    })();
    return this.downloadPromise;
  }

  async cancel() {
    if (!this.downloadController || !this.downloadPromise) return this.snapshot();
    this.downloadController.abort();
    await this.downloadPromise;
    return this.snapshot();
  }

  async install() {
    if (this.installPromise) return this.installPromise;
    if (!this.candidate || !this.verifiedInstaller || this.state.status !== 'downloaded') return this.snapshot();
    this.installPromise = (async () => {
      let coreStopped = false;
      let coreStopAttempted = false;
      try {
        this.transition('downloaded', {
          message: 'Обновление скачано и проверено.',
          installIssue: '',
        });
        const activeBefore = Number(await this.getActiveRuns());
        if (!Number.isSafeInteger(activeBefore) || activeBefore < 0) {
          throw new UpdateError('Hub не смог проверить активные задачи.', 'active_runs_unknown');
        }
        if (activeBefore > 0) {
          throw new UpdateError('Сначала дождитесь завершения активных задач.', 'active_runs');
        }
        const confirmed = await this.confirmInstall(this.snapshot());
        if (!confirmed) return this.snapshot();
        const activeAfter = Number(await this.getActiveRuns());
        if (!Number.isSafeInteger(activeAfter) || activeAfter < 0 || activeAfter > 0) {
          throw new UpdateError('Пока вы подтверждали обновление, появилась активная задача. Дождитесь её завершения.', 'active_runs');
        }
        let actualDigest;
        try {
          actualDigest = await sha256File(this.verifiedInstaller.path, this.verifiedInstaller.size);
        } catch {
          throw new UpdateError('Проверенный установщик пропал или повреждён. Скачайте его заново.', 'invalid_cached_installer');
        }
        if (actualDigest !== this.verifiedInstaller.sha256) {
          throw new UpdateError('Проверенный установщик изменился. Скачайте его заново.', 'cached_checksum_mismatch');
        }
        // The native confirmation plus checks before and after the potentially
        // expensive rehash narrow the last-moment race before the commit boundary.
        const activeAtCommit = Number(await this.getActiveRuns());
        if (!Number.isSafeInteger(activeAtCommit) || activeAtCommit < 0) {
          throw new UpdateError('Hub не смог повторно проверить активные задачи.', 'active_runs_unknown');
        }
        if (activeAtCommit > 0) {
          throw new UpdateError('Пока Hub проверял установщик, появилась активная задача. Дождитесь её завершения.', 'active_runs');
        }
        this.transition('installing', { message: 'Открываем проверенный установщик.' });
        await this.lockVault();
        // Vault lock is the commit boundary for new work. Check once more after
        // it: if another process admitted a run just before the lock, keep the
        // core alive and return to a recoverable downloaded state.
        const activeAfterLock = Number(await this.getActiveRuns());
        if (!Number.isSafeInteger(activeAfterLock) || activeAfterLock < 0) {
          throw new UpdateError('Hub не смог проверить задачи после блокировки Vault.', 'active_runs_unknown');
        }
        if (activeAfterLock > 0) {
          throw new UpdateError('Перед обновлением успела запуститься новая задача. Дождитесь её завершения.', 'active_runs');
        }
        // Re-read the exact file after Vault lock, as close as possible to the
        // native launch. This narrows the local same-user replacement window;
        // the release digest remains the authoritative expected value.
        let launchDigest;
        try {
          launchDigest = await sha256File(this.verifiedInstaller.path, this.verifiedInstaller.size);
        } catch {
          throw new UpdateError('Проверенный установщик пропал или повреждён. Скачайте его заново.', 'invalid_cached_installer');
        }
        if (launchDigest !== this.verifiedInstaller.sha256) {
          throw new UpdateError('Проверенный установщик изменился перед запуском. Скачайте его заново.', 'cached_checksum_mismatch');
        }
        if (this.platform === 'win32') {
          // NSIS may start replacing files as soon as it opens, so Windows
          // stops the core first. A failed OS launch restarts the old core.
          coreStopAttempted = true;
          await this.stopCore();
          coreStopped = true;
          await this.openInstaller(this.verifiedInstaller.path, this.platform);
        } else {
          // Opening a DMG does not replace the app. Open it first so an OS
          // failure cannot leave the current Hub without its core.
          await this.openInstaller(this.verifiedInstaller.path, this.platform);
          coreStopAttempted = true;
          await this.stopCore();
          coreStopped = true;
        }
        this.quitApp();
        return this.snapshot();
      } catch (error) {
        if (
          error instanceof UpdateError
          && ['cached_checksum_mismatch', 'invalid_cached_installer'].includes(error.code)
        ) {
          const invalidInstaller = this.verifiedInstaller;
          this.verifiedInstaller = null;
          if (invalidInstaller) {
            await discardExactCachedInstaller(
              invalidInstaller.path,
              this.userDataPath,
              this.candidate.installer.name,
            );
          }
          return this.transition('error', {
            message: error.message,
            installIssue: '',
          });
        }
        if (coreStopAttempted && this.verifiedInstaller) {
          try {
            await this.recoverCore();
            coreStopped = false;
            const reason = publicErrorMessage(
              error,
              'Не получилось передать обновление операционной системе.',
            );
            const installIssue = `${reason} Текущая версия Hub снова готова к работе — попробуйте ещё раз.`;
            return this.transition('downloaded', {
              message: installIssue,
              installIssue,
            });
          } catch {
            // The main process performs a relaunch fallback when recovery is
            // impossible. Keep the generic error below for test doubles.
          }
        }
        if (!coreStopped && this.verifiedInstaller) {
          const installIssue = publicErrorMessage(
            error,
            'Не получилось подготовить обновление. Попробуйте ещё раз.',
          );
          return this.transition('downloaded', {
            message: installIssue,
            installIssue,
          });
        }
        return this.transition('error', {
          message: publicErrorMessage(error, 'Не получилось открыть установщик. Запустите Hub снова и повторите.'),
        });
      } finally {
        this.installPromise = null;
      }
    })();
    return this.installPromise;
  }
}

module.exports = {
  CHECK_TIMEOUT_MS,
  HubUpdater,
  LEGACY_PINNED_RELEASES,
  LATEST_RELEASE_URL,
  MAX_CHECKSUM_BYTES,
  MAX_INSTALLER_BYTES,
  RELEASE_HOSTS,
  UPDATE_IPC,
  UPDATE_REPOSITORY,
  UpdateError,
  checkedHttpsUrl,
  compareSemver,
  fetchRedirectSafe,
  inspectRelease,
  parseChecksumManifest,
  platformAssetName,
  pruneUpdateCache,
  readBoundedBody,
  sha256File,
  strictSemver,
};
