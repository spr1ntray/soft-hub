from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ADAPTER = PROJECT_ROOT / "electron" / "manual-fetch.cjs"
UPDATER = PROJECT_ROOT / "electron" / "updater.cjs"


class ElectronManualFetchTests(unittest.TestCase):
    def test_redirects_are_exposed_for_validation_and_safe_bodies_stream(self) -> None:
        harness = r"""
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { createElectronManualFetch } = require(process.argv[1]);
const { fetchRedirectSafe, readBoundedBody } = require(process.argv[2]);

class FakeRequest extends EventEmitter {
  constructor(options, scenario) {
    super();
    this.options = options;
    this.scenario = scenario;
    this.aborted = false;
  }
  end() { queueMicrotask(() => this.scenario(this)); }
  abort() { this.aborted = true; this.emit('abort'); }
}

const calls = [];
const requestFactory = (options) => new FakeRequest(options, (request) => {
  calls.push(options);
  const url = new URL(options.url);
  if (url.hostname === 'github.com') {
    request.emit('redirect', 302, 'GET', 'https://release-assets.githubusercontent.com/file', {
      Location: ['https://release-assets.githubusercontent.com/file'],
    });
    request.emit('error', new Error('Redirect was cancelled'));
    return;
  }
  const response = new PassThrough();
  response.statusCode = 200;
  response.headers = { 'Content-Length': ['4'], 'X-Test': ['one', 'two'] };
  request.emit('response', response);
  response.end(Buffer.from('safe'));
});

(async () => {
  const fetchImpl = createElectronManualFetch(requestFactory);
  const response = await fetchRedirectSafe(
    fetchImpl,
    'https://github.com/spr1ntray/soft-hub/releases/download/v1.0.0/file',
    {
      allowedHosts: new Set(['github.com', 'release-assets.githubusercontent.com']),
      headers: { Accept: 'application/octet-stream' },
      signal: new AbortController().signal,
    },
  );
  const body = await readBoundedBody(response, 4, { expectedBytes: 4 });
  assert.equal(body.toString('utf8'), 'safe');
  assert.equal(response.headers.get('content-length'), '4');
  assert.equal(response.headers.get('x-test'), 'one, two');
  assert.equal(calls.length, 2);
  for (const options of calls) {
    assert.equal(options.redirect, 'manual');
    assert.equal(options.credentials, 'omit');
    assert.equal(options.useSessionCookies, false);
  }

  let attackerRequested = false;
  const hostileFetch = createElectronManualFetch((options) => new FakeRequest(options, (request) => {
    if (new URL(options.url).hostname === 'attacker.test') attackerRequested = true;
    request.emit('redirect', 302, 'GET', 'https://attacker.test/payload', {
      location: ['https://attacker.test/payload'],
    });
  }));
  await assert.rejects(fetchRedirectSafe(
    hostileFetch,
    'https://github.com/spr1ntray/soft-hub/releases/download/v1.0.0/file',
    {
      allowedHosts: new Set(['github.com', 'release-assets.githubusercontent.com']),
      headers: {},
      signal: new AbortController().signal,
    },
  ), /небезопасную ссылку/);
  assert.equal(attackerRequested, false);

  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(fetchImpl('https://github.com/file', { signal: aborted.signal }), {
    name: 'AbortError',
  });
})().catch((error) => { console.error(error); process.exitCode = 1; });
"""
        completed = subprocess.run(
            ["node", "-e", harness, str(ADAPTER), str(UPDATER)],
            cwd=PROJECT_ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
