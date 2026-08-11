from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
UPDATER = PROJECT_ROOT / "electron" / "updater.cjs"


def run_node(source: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["node", "-e", source, str(UPDATER)],
        cwd=PROJECT_ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


class DesktopUpdaterContractTests(unittest.TestCase):
    def test_release_contract_uses_strict_versions_exact_assets_and_safe_urls(self) -> None:
        harness = r"""
const assert = require('node:assert/strict');
const {
  compareSemver,
  fetchRedirectSafe,
  inspectRelease,
  MAX_INSTALLER_BYTES,
  parseChecksumManifest,
  platformAssetName,
  pruneUpdateCache,
  strictSemver,
} = require(process.argv[1]);
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

assert.deepEqual(strictSemver('0.6.12'), [0, 6, 12]);
for (const invalid of ['v0.6.12', '01.2.3', '1.2', '1.2.3-beta', '1.2.3+build', ' 1.2.3']) {
  assert.equal(strictSemver(invalid), null);
}
assert.equal(compareSemver('1.3.0', '1.2.99'), 1);
assert.equal(compareSemver('1.2.3', '1.2.3'), 0);
assert.equal(platformAssetName('1.2.3', 'darwin', 'arm64'), 'Soft-Hub-1.2.3-arm64.dmg');
assert.equal(platformAssetName('1.2.3', 'win32', 'x64'), 'Soft-Hub-1.2.3-x64.exe');
assert.equal(platformAssetName('1.2.3', 'darwin', 'x64'), null);
assert.equal(MAX_INSTALLER_BYTES, 512 * 1024 * 1024);

const digest = 'a'.repeat(64);
const asset = (name, size, extra = {}) => ({
  name,
  size,
  state: 'uploaded',
  digest: name === 'SHA256SUMS' ? null : `sha256:${digest}`,
  browser_download_url: `https://github.com/spr1ntray/soft-hub/releases/download/v1.2.0/${name}`,
  ...extra,
});
const release = {
  tag_name: 'v1.2.0',
  draft: false,
  prerelease: false,
  body: 'Safe release notes',
  assets: [asset('Soft-Hub-1.2.0-arm64.dmg', 123), asset('SHA256SUMS', 160)],
};
const candidate = inspectRelease(release, '1.1.9', 'darwin', 'arm64');
assert.equal(candidate.status, 'available');
assert.equal(candidate.version, '1.2.0');
assert.equal(candidate.installer.name, 'Soft-Hub-1.2.0-arm64.dmg');
assert.equal(candidate.installer.apiDigest, digest);
assert.equal(inspectRelease({ ...release, body: 'safe\u202eevil' }, '1.1.9', 'darwin', 'arm64').releaseNotes.includes('\u202e'), false);
assert.equal(inspectRelease({ ...release, assets: undefined }, '1.2.0', 'darwin', 'arm64').status, 'up_to_date');
assert.throws(() => inspectRelease({ ...release, prerelease: true }, '1.1.9', 'darwin', 'arm64'), /стабильным/);
assert.throws(() => inspectRelease({ ...release, tag_name: '1.2.0' }, '1.1.9', 'darwin', 'arm64'), /v1\.2\.3/);
assert.throws(() => inspectRelease({ ...release, assets: [...release.assets, release.assets[0]] }, '1.1.9', 'darwin', 'arm64'), /ровно один/);
assert.throws(() => inspectRelease({
  ...release,
  assets: [asset('Soft-Hub-1.2.0-arm64.dmg', 123, {
    browser_download_url: 'https://github.com.attacker.test/spr1ntray/soft-hub/releases/download/v1.2.0/Soft-Hub-1.2.0-arm64.dmg',
  }), asset('SHA256SUMS', 160)],
}, '1.1.9', 'darwin', 'arm64'), /небезопасную ссылку/);

assert.equal(parseChecksumManifest(`${digest}  Soft-Hub-1.2.0-arm64.dmg\n`, 'Soft-Hub-1.2.0-arm64.dmg'), digest);
assert.throws(() => parseChecksumManifest(`${digest}  ../escape.dmg\n`, 'escape.dmg'), /небезопасное имя/);
assert.throws(() => parseChecksumManifest(`${digest}  Soft-Hub-1.2.0-arm64.dmg\n${digest}  Soft-Hub-1.2.0-arm64.dmg\n`, 'Soft-Hub-1.2.0-arm64.dmg'), /повторяющееся/);

(async () => {
  let requests = 0;
  await assert.rejects(
    fetchRedirectSafe(async () => {
      requests += 1;
      return new Response('', { status: 302, headers: { location: 'https://attacker.test/update.exe' } });
    }, 'https://github.com/spr1ntray/soft-hub/releases/download/v1.2.0/file', {
      allowedHosts: new Set(['github.com', 'release-assets.githubusercontent.com']),
      headers: {},
      signal: new AbortController().signal,
    }),
    /небезопасную ссылку/,
  );
  assert.equal(requests, 1, 'unsafe redirects must be rejected before a second request');

  const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'soft-hub-cache-prune-'));
  const updates = path.join(cacheRoot, 'updates');
  fs.mkdirSync(updates);
  const staleInstaller = path.join(updates, 'Soft-Hub-1.0.0-arm64.dmg');
  const stalePart = path.join(updates, 'Soft-Hub-1.1.0-x64.exe.part');
  const unrelated = path.join(updates, 'keep-me.txt');
  fs.writeFileSync(staleInstaller, 'old');
  fs.writeFileSync(stalePart, 'partial');
  fs.writeFileSync(unrelated, 'user-like fixture');
  await pruneUpdateCache(cacheRoot);
  assert.equal(fs.existsSync(staleInstaller), false);
  assert.equal(fs.existsSync(stalePart), false);
  assert.equal(fs.existsSync(unrelated), true, 'cache cleanup must ignore unknown files');
  fs.rmSync(cacheRoot, { recursive: true, force: true });
})().catch((error) => { console.error(error); process.exitCode = 1; });
"""
        completed = run_node(harness)
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"release contract failed:\n{completed.stdout}\n{completed.stderr}",
        )

    def test_updater_downloads_only_after_action_and_opens_verified_installer(self) -> None:
        harness = r"""
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { HubUpdater, LATEST_RELEASE_URL } = require(process.argv[1]);

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'soft-hub-updater-'));
const installerName = 'Soft-Hub-1.2.0-arm64.dmg';
const installer = Buffer.from('verified installer fixture');
const digest = crypto.createHash('sha256').update(installer).digest('hex');
const checksum = Buffer.from(`${digest}  ${installerName}\n`);
const release = {
  tag_name: 'v1.2.0',
  draft: false,
  prerelease: false,
  body: 'What changed',
  assets: [
    {
      name: installerName,
      size: installer.length,
      state: 'uploaded',
      digest: `sha256:${digest}`,
      browser_download_url: `https://github.com/spr1ntray/soft-hub/releases/download/v1.2.0/${installerName}`,
    },
    {
      name: 'SHA256SUMS',
      size: checksum.length,
      state: 'uploaded',
      browser_download_url: 'https://github.com/spr1ntray/soft-hub/releases/download/v1.2.0/SHA256SUMS',
    },
  ],
};
const json = Buffer.from(JSON.stringify(release));
const calls = [];
const response = (payload) => new Response(payload, {
  status: 200,
  headers: { 'content-length': String(payload.length) },
});
const fetchImpl = async (url) => {
  calls.push(url);
  if (url === LATEST_RELEASE_URL) return response(json);
  if (url.endsWith('/SHA256SUMS')) return response(checksum);
  if (url.endsWith(`/${installerName}`)) return response(installer);
  throw new Error(`unexpected URL ${url}`);
};
const lifecycle = [];
const updater = new HubUpdater({
  currentVersion: '1.1.0',
  platform: 'darwin',
  arch: 'arm64',
  userDataPath: root,
  fetchImpl,
  getActiveRuns: async () => { lifecycle.push('active'); return 0; },
  confirmInstall: async () => { lifecycle.push('confirm'); return true; },
  lockVault: async () => { lifecycle.push('lock'); },
  stopCore: async () => { lifecycle.push('stop'); },
  openInstaller: async (file) => {
    lifecycle.push('open');
    assert.equal(path.basename(file), installerName);
    assert.equal(fs.readFileSync(file).toString(), installer.toString());
  },
  quitApp: () => { lifecycle.push('quit'); },
});

(async () => {
  const untouched = await updater.download();
  assert.equal(untouched.status, 'idle');
  assert.equal(calls.length, 0, 'download cannot discover or fetch an asset by itself');

  const available = await updater.check();
  assert.equal(available.status, 'available');
  assert.equal(calls.length, 1, 'checking downloads only release metadata');
  assert.equal(available.availableVersion, '1.2.0');
  assert.equal(available.releaseNotes, 'What changed');

  const downloaded = await updater.download();
  assert.equal(downloaded.status, 'downloaded');
  assert.equal(downloaded.percent, 100);
  assert.equal(downloaded.transferred, installer.length);
  assert.equal(calls.length, 3);
  const publicSnapshot = JSON.stringify(downloaded);
  assert.equal(publicSnapshot.includes(root), false, 'renderer state must never expose local paths');
  assert.equal(publicSnapshot.includes('github.com'), false, 'renderer state must never expose download URLs');
  assert.equal(fs.existsSync(path.join(root, 'updates', `${installerName}.part`)), false);

  const installing = await updater.install();
  assert.equal(installing.status, 'installing');
  assert.deepEqual(
    lifecycle,
    ['active', 'confirm', 'active', 'active', 'lock', 'active', 'open', 'stop', 'quit'],
    'the post-lock check and recoverable installer open must precede core shutdown',
  );

  fs.rmSync(root, { recursive: true, force: true });
})().catch((error) => {
  fs.rmSync(root, { recursive: true, force: true });
  console.error(error);
  process.exitCode = 1;
});
"""
        completed = run_node(harness)
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"updater flow failed:\n{completed.stdout}\n{completed.stderr}",
        )

    def test_failed_downloads_cancel_and_install_gates_preserve_safe_files(self) -> None:
        harness = r"""
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { HubUpdater, LATEST_RELEASE_URL } = require(process.argv[1]);

const installerName = 'Soft-Hub-2.0.0-arm64.dmg';
const goodInstaller = Buffer.from('the expected installer bytes');
const goodDigest = crypto.createHash('sha256').update(goodInstaller).digest('hex');
const response = (payload, declared = payload.length) => new Response(payload, {
  status: 200,
  headers: { 'content-length': String(declared) },
});
const exists = (root, suffix = '') => fs.existsSync(path.join(root, 'updates', `${installerName}${suffix}`));

function releaseAndChecksum({ apiDigest = goodDigest, checksumApiDigest = null } = {}) {
  const checksum = Buffer.from(`${goodDigest}  ${installerName}\n`);
  const release = {
    tag_name: 'v2.0.0', draft: false, prerelease: false, body: '',
    assets: [
      {
        name: installerName,
        size: goodInstaller.length,
        state: 'uploaded',
        digest: `sha256:${apiDigest}`,
        browser_download_url: `https://github.com/spr1ntray/soft-hub/releases/download/v2.0.0/${installerName}`,
      },
      {
        name: 'SHA256SUMS',
        size: checksum.length,
        state: 'uploaded',
        digest: checksumApiDigest ? `sha256:${checksumApiDigest}` : null,
        browser_download_url: 'https://github.com/spr1ntray/soft-hub/releases/download/v2.0.0/SHA256SUMS',
      },
    ],
  };
  return { checksum, release, releaseJson: Buffer.from(JSON.stringify(release)) };
}

function updaterFixture({ root, release, checksum, installerResponse, getActiveRuns, confirmInstall, lifecycle = [] }) {
  return new HubUpdater({
    currentVersion: '1.9.9', platform: 'darwin', arch: 'arm64', userDataPath: root,
    fetchImpl: async (url, options) => {
      if (url === LATEST_RELEASE_URL) return response(Buffer.from(JSON.stringify(release)));
      if (url.endsWith('/SHA256SUMS')) return response(checksum);
      if (url.endsWith(`/${installerName}`)) return installerResponse(options);
      throw new Error(`unexpected URL ${url}`);
    },
    getActiveRuns: getActiveRuns || (async () => 0),
    confirmInstall: confirmInstall || (async () => true),
    lockVault: async () => { lifecycle.push('lock'); },
    stopCore: async () => { lifecycle.push('stop'); },
    openInstaller: async () => { lifecycle.push('open'); },
    quitApp: () => { lifecycle.push('quit'); },
  });
}

async function checkedDownload(updater) {
  assert.equal((await updater.check()).status, 'available');
  return await updater.download();
}

(async () => {
  const roots = [];
  const makeRoot = () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'soft-hub-updater-gate-'));
    roots.push(root);
    return root;
  };
  try {
    // The bytes have the advertised size but not the checksum.
    {
      const root = makeRoot();
      const { release, checksum } = releaseAndChecksum();
      const wrong = Buffer.alloc(goodInstaller.length, 0x78);
      const updater = updaterFixture({ root, release, checksum, installerResponse: () => response(wrong) });
      const state = await checkedDownload(updater);
      assert.equal(state.status, 'error');
      assert.match(state.message, /SHA-256/);
      assert.equal(exists(root), false);
      assert.equal(exists(root, '.part'), false);
    }

    // GitHub's installer digest and SHA256SUMS must agree before asset download.
    {
      const root = makeRoot();
      const { release, checksum } = releaseAndChecksum({ apiDigest: 'b'.repeat(64) });
      let installerRequested = false;
      const updater = updaterFixture({
        root, release, checksum,
        installerResponse: () => { installerRequested = true; return response(goodInstaller); },
      });
      const state = await checkedDownload(updater);
      assert.equal(state.status, 'error');
      assert.match(state.message, /Digest GitHub/);
      assert.equal(installerRequested, false);
      assert.equal(exists(root), false);
      assert.equal(exists(root, '.part'), false);
    }

    // A short response never becomes a final installer.
    {
      const root = makeRoot();
      const { release, checksum } = releaseAndChecksum();
      const short = goodInstaller.subarray(0, goodInstaller.length - 2);
      const updater = updaterFixture({ root, release, checksum, installerResponse: () => response(short) });
      const state = await checkedDownload(updater);
      assert.equal(state.status, 'error');
      assert.match(state.message, /Размер файла|не полностью/);
      assert.equal(exists(root), false);
      assert.equal(exists(root, '.part'), false);
    }

    // Cancelling aborts the stream and removes its partial file.
    {
      const root = makeRoot();
      const { release, checksum } = releaseAndChecksum();
      let streamStarted;
      const started = new Promise((resolve) => { streamStarted = resolve; });
      const updater = updaterFixture({
        root, release, checksum,
        installerResponse: (options) => new Response(new ReadableStream({
          start(controller) {
            controller.enqueue(goodInstaller.subarray(0, 1));
            streamStarted();
            options.signal.addEventListener('abort', () => controller.error(new DOMException('Aborted', 'AbortError')), { once: true });
          },
        }), { status: 200, headers: { 'content-length': String(goodInstaller.length) } }),
      });
      assert.equal((await updater.check()).status, 'available');
      const downloadPromise = updater.download();
      await started;
      const cancelled = await updater.cancel();
      await downloadPromise;
      assert.equal(cancelled.status, 'available');
      assert.match(cancelled.message, /отменено/);
      assert.equal(exists(root), false);
      assert.equal(exists(root, '.part'), false);
    }

    // Active work blocks install without consuming the verified installer.
    {
      const root = makeRoot();
      const { release, checksum } = releaseAndChecksum();
      let confirmations = 0;
      const updater = updaterFixture({
        root, release, checksum, installerResponse: () => response(goodInstaller),
        getActiveRuns: async () => 1,
        confirmInstall: async () => { confirmations += 1; return true; },
      });
      assert.equal((await checkedDownload(updater)).status, 'downloaded');
      const blocked = await updater.install();
      assert.equal(blocked.status, 'downloaded');
      assert.match(blocked.message, /активных задач/);
      assert.match(blocked.installIssue, /активных задач/);
      assert.equal(blocked.issue, blocked.installIssue);
      assert.equal(confirmations, 0);
      assert.equal(exists(root), true);
      assert.equal(exists(root, '.part'), false);
    }

    // A third check immediately after rehash closes the remaining modal/hash race.
    {
      const root = makeRoot();
      const { release, checksum } = releaseAndChecksum();
      const lifecycle = [];
      const activeStates = [0, 0, 1];
      const updater = updaterFixture({
        root, release, checksum, installerResponse: () => response(goodInstaller), lifecycle,
        getActiveRuns: async () => {
          lifecycle.push('active');
          return activeStates.shift();
        },
        confirmInstall: async () => { lifecycle.push('confirm'); return true; },
      });
      assert.equal((await checkedDownload(updater)).status, 'downloaded');
      const raced = await updater.install();
      assert.equal(raced.status, 'downloaded');
      assert.match(raced.installIssue, /проверял установщик/);
      assert.deepEqual(lifecycle, ['active', 'confirm', 'active', 'active']);
      assert.equal(exists(root), true, 'a recoverable race keeps the verified installer');
      assert.equal(exists(root, '.part'), false);
    }

    // A run admitted immediately before Vault lock is caught after the lock;
    // the verified file and live core remain available for a safe retry.
    {
      const root = makeRoot();
      const { release, checksum } = releaseAndChecksum();
      const lifecycle = [];
      const activeStates = [0, 0, 0, 1];
      const updater = updaterFixture({
        root, release, checksum, installerResponse: () => response(goodInstaller), lifecycle,
        getActiveRuns: async () => {
          lifecycle.push('active');
          return activeStates.shift();
        },
        confirmInstall: async () => { lifecycle.push('confirm'); return true; },
      });
      assert.equal((await checkedDownload(updater)).status, 'downloaded');
      const raced = await updater.install();
      assert.equal(raced.status, 'downloaded');
      assert.match(raced.installIssue, /новая задача/);
      assert.deepEqual(lifecycle, ['active', 'confirm', 'active', 'active', 'lock', 'active']);
      assert.equal(exists(root), true);
      assert.equal(exists(root, '.part'), false);
    }

    // An OS launch failure happens before core shutdown and stays recoverable.
    {
      const root = makeRoot();
      const { release, checksum } = releaseAndChecksum();
      const lifecycle = [];
      const updater = new HubUpdater({
        currentVersion: '1.9.9', platform: 'darwin', arch: 'arm64', userDataPath: root,
        fetchImpl: async (url) => {
          if (url === LATEST_RELEASE_URL) return response(Buffer.from(JSON.stringify(release)));
          if (url.endsWith('/SHA256SUMS')) return response(checksum);
          if (url.endsWith(`/${installerName}`)) return response(goodInstaller);
          throw new Error(`unexpected URL ${url}`);
        },
        getActiveRuns: async () => { lifecycle.push('active'); return 0; },
        confirmInstall: async () => { lifecycle.push('confirm'); return true; },
        lockVault: async () => { lifecycle.push('lock'); },
        openInstaller: async () => { lifecycle.push('open'); throw new Error('fixture open failure'); },
        stopCore: async () => { lifecycle.push('stop'); },
        quitApp: () => { lifecycle.push('quit'); },
      });
      assert.equal((await checkedDownload(updater)).status, 'downloaded');
      const failed = await updater.install();
      assert.equal(failed.status, 'downloaded');
      assert.match(failed.installIssue, /подготовить обновление/);
      assert.deepEqual(lifecycle, ['active', 'confirm', 'active', 'active', 'lock', 'active', 'open']);
      assert.equal(exists(root), true);
    }

    // Windows stops the core before opening NSIS, but a failed launch restores
    // the old core instead of leaving a dead Hub window behind.
    {
      const root = makeRoot();
      const { release, checksum } = releaseAndChecksum();
      const lifecycle = [];
      const windowsName = 'Soft-Hub-2.0.0-x64.exe';
      const windowsChecksum = Buffer.from(`${goodDigest}  ${windowsName}\n`);
      const windowsRelease = {
        ...release,
        assets: [
          {
            ...release.assets[0],
            name: windowsName,
            browser_download_url: `https://github.com/spr1ntray/soft-hub/releases/download/v2.0.0/${windowsName}`,
          },
          { ...release.assets[1], size: windowsChecksum.length },
        ],
      };
      const updater = new HubUpdater({
        currentVersion: '1.9.9', platform: 'win32', arch: 'x64', userDataPath: root,
        fetchImpl: async (url) => {
          if (url === LATEST_RELEASE_URL) return response(Buffer.from(JSON.stringify(windowsRelease)));
          if (url.endsWith('/SHA256SUMS')) return response(windowsChecksum);
          if (url.endsWith(`/${windowsName}`)) return response(goodInstaller);
          throw new Error(`unexpected URL ${url}`);
        },
        getActiveRuns: async () => { lifecycle.push('active'); return 0; },
        confirmInstall: async () => { lifecycle.push('confirm'); return true; },
        lockVault: async () => { lifecycle.push('lock'); },
        stopCore: async () => { lifecycle.push('stop'); },
        openInstaller: async () => { lifecycle.push('open'); throw new Error('fixture open failure'); },
        recoverCore: async () => { lifecycle.push('recover'); },
        quitApp: () => { lifecycle.push('quit'); },
      });
      assert.equal((await updater.check()).status, 'available');
      assert.equal((await updater.download()).status, 'downloaded');
      const failed = await updater.install();
      assert.equal(failed.status, 'downloaded');
      assert.match(failed.installIssue, /снова готова/);
      assert.deepEqual(lifecycle, ['active', 'confirm', 'active', 'active', 'lock', 'active', 'stop', 'open', 'recover']);
      assert.equal(fs.existsSync(path.join(root, 'updates', windowsName)), true);
    }

    // A DMG open succeeds before a stop failure; Hub does not quit and reports
    // a retryable issue while its core remains under the caller's control.
    {
      const root = makeRoot();
      const { release, checksum } = releaseAndChecksum();
      const lifecycle = [];
      const updater = new HubUpdater({
        currentVersion: '1.9.9', platform: 'darwin', arch: 'arm64', userDataPath: root,
        fetchImpl: async (url) => {
          if (url === LATEST_RELEASE_URL) return response(Buffer.from(JSON.stringify(release)));
          if (url.endsWith('/SHA256SUMS')) return response(checksum);
          if (url.endsWith(`/${installerName}`)) return response(goodInstaller);
          throw new Error(`unexpected URL ${url}`);
        },
        getActiveRuns: async () => { lifecycle.push('active'); return 0; },
        confirmInstall: async () => { lifecycle.push('confirm'); return true; },
        lockVault: async () => { lifecycle.push('lock'); },
        openInstaller: async () => { lifecycle.push('open'); },
        stopCore: async () => { lifecycle.push('stop'); throw new Error('fixture stop failure'); },
        recoverCore: async () => { lifecycle.push('recover'); },
        quitApp: () => { lifecycle.push('quit'); },
      });
      assert.equal((await checkedDownload(updater)).status, 'downloaded');
      const failed = await updater.install();
      assert.equal(failed.status, 'downloaded');
      assert.match(failed.installIssue, /снова готова/);
      assert.deepEqual(lifecycle, ['active', 'confirm', 'active', 'active', 'lock', 'active', 'open', 'stop', 'recover']);
    }

    // A same-size mutation invalidates and removes cache; download can recover cleanly.
    {
      const root = makeRoot();
      const { release, checksum } = releaseAndChecksum();
      const updater = updaterFixture({
        root, release, checksum, installerResponse: () => response(goodInstaller),
      });
      assert.equal((await checkedDownload(updater)).status, 'downloaded');
      fs.writeFileSync(
        path.join(root, 'updates', installerName),
        Buffer.alloc(goodInstaller.length, 0x6d),
      );
      const invalidated = await updater.install();
      assert.equal(invalidated.status, 'error');
      assert.match(invalidated.message, /изменился/);
      assert.equal(invalidated.installIssue, '');
      assert.equal(exists(root), false, 'invalid cached installer must be removed');
      assert.equal(exists(root, '.part'), false);
      const recovered = await updater.download();
      assert.equal(recovered.status, 'downloaded');
      assert.equal(recovered.installIssue, '');
      assert.equal(exists(root), true);
      assert.equal(exists(root, '.part'), false);
    }

    // Declining the native confirmation performs no lifecycle action.
    {
      const root = makeRoot();
      const { release, checksum } = releaseAndChecksum();
      const lifecycle = [];
      const updater = updaterFixture({
        root, release, checksum, installerResponse: () => response(goodInstaller), lifecycle,
        confirmInstall: async () => false,
      });
      assert.equal((await checkedDownload(updater)).status, 'downloaded');
      const declined = await updater.install();
      assert.equal(declined.status, 'downloaded');
      assert.equal(declined.installIssue, '');
      assert.deepEqual(lifecycle, []);
      assert.equal(exists(root), true);
      assert.equal(exists(root, '.part'), false);
    }
  } finally {
    for (const root of roots) fs.rmSync(root, { recursive: true, force: true });
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
"""
        completed = run_node(harness)
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"updater failure gates failed:\n{completed.stdout}\n{completed.stderr}",
        )

    def test_preload_and_main_keep_a_narrow_sandboxed_bridge(self) -> None:
        preload = (PROJECT_ROOT / "electron" / "preload.cjs").read_text(encoding="utf-8")
        main = (PROJECT_ROOT / "electron" / "main.cjs").read_text(encoding="utf-8")
        package = json.loads((PROJECT_ROOT / "package.json").read_text(encoding="utf-8"))

        self.assertIn("exposeInMainWorld('softHubDesktop'", preload)
        for method in ("getState", "check", "download", "cancel", "install", "onStateChanged"):
            self.assertIn(f"{method}:", preload)
        self.assertNotIn("ipcRenderer.send(", preload)
        self.assertNotIn("shell", preload)
        self.assertNotIn("require('node:", preload)

        self.assertIn("preload: join(__dirname, 'preload.cjs')", main)
        self.assertIn("contextIsolation: true", main)
        self.assertIn("nodeIntegration: false", main)
        self.assertIn("sandbox: true", main)
        self.assertIn("requireTrustedUpdaterSender(event)", main)
        self.assertIn("event.senderFrame !== mainWindow.webContents.mainFrame", main)
        self.assertIn("activeRunsForUpdate", main)
        self.assertIn("lockVaultForUpdate", main)
        self.assertIn("stopHubAndWait", main)
        recovery = main.index("async function recoverCoreAfterUpdateFailure")
        relaunch = main.index("app.relaunch()", recovery)
        stop_before_relaunch = main.rfind("await stopHubAndWait()", recovery, relaunch)
        self.assertGreater(stop_before_relaunch, recovery)
        self.assertNotIn("exec(", main)
        self.assertNotIn("shell: true", main)

        typecheck = package["scripts"]["typecheck"]
        self.assertIn("node --check electron/updater.cjs", typecheck)
        self.assertIn("node --check electron/preload.cjs", typecheck)

    def test_preload_runtime_exposes_only_the_updater_contract(self) -> None:
        preload_path = PROJECT_ROOT / "electron" / "preload.cjs"
        harness = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const filename = process.argv[2];
const source = fs.readFileSync(filename, 'utf8');
const calls = [];
const listeners = new Map();
let exposedName = null;
let exposedValue = null;
const electron = {
  contextBridge: {
    exposeInMainWorld: (name, value) => {
      exposedName = name;
      exposedValue = value;
    },
  },
  ipcRenderer: {
    invoke: async (channel) => { calls.push(channel); return { status: 'idle' }; },
    on: (channel, listener) => listeners.set(channel, listener),
    removeListener: (channel, listener) => {
      if (listeners.get(channel) === listener) listeners.delete(channel);
    },
  },
};
vm.runInNewContext(source, {
  require: (specifier) => {
    assert.equal(specifier, 'electron', 'sandboxed preload must require only Electron');
    return electron;
  },
  Object,
  TypeError,
}, { filename });

assert.equal(exposedName, 'softHubDesktop');
assert.deepEqual(Object.keys(exposedValue), ['updater']);
assert.deepEqual(Object.keys(exposedValue.updater).sort(), [
  'cancel', 'check', 'download', 'getState', 'install', 'onStateChanged',
]);
assert.equal(Object.isFrozen(exposedValue), true);
assert.equal(Object.isFrozen(exposedValue.updater), true);

(async () => {
  await exposedValue.updater.getState();
  await exposedValue.updater.check();
  await exposedValue.updater.download();
  await exposedValue.updater.cancel();
  await exposedValue.updater.install();
  assert.deepEqual(calls, [
    'soft-hub:update:get-state',
    'soft-hub:update:check',
    'soft-hub:update:download',
    'soft-hub:update:cancel',
    'soft-hub:update:install',
  ]);
  let received = null;
  const unsubscribe = exposedValue.updater.onStateChanged((state) => { received = state; });
  const channel = 'soft-hub:update:state-changed';
  listeners.get(channel)({}, { status: 'available' });
  assert.deepEqual(received, { status: 'available' });
  unsubscribe();
  assert.equal(listeners.has(channel), false);
})().catch((error) => { console.error(error); process.exitCode = 1; });
"""
        completed = subprocess.run(
            ["node", "-e", harness, str(UPDATER), str(preload_path)],
            cwd=PROJECT_ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"preload runtime contract failed:\n{completed.stdout}\n{completed.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
