from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from soft_hub.runner import RunManager


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = PROJECT_ROOT / "electron" / "main.cjs"


class DesktopProxyEnvironmentTests(unittest.TestCase):
    def test_trusted_core_normalizes_only_supported_windows_proxy_variables(self) -> None:
        harness = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const filename = process.argv[1];
const source = fs.readFileSync(filename, 'utf8');
const app = {
  requestSingleInstanceLock: () => false,
  quit: () => {},
  setName: () => {},
  enableSandbox: () => {},
};
const sandbox = {
  __dirname: path.dirname(filename),
  console,
  URL,
  AbortController,
  fetch,
  setTimeout,
  clearTimeout,
  process: {
    platform: 'win32',
    env: {},
  },
  require: (specifier) => {
    if (specifier === 'electron') {
      return {
        app,
        BrowserWindow: function BrowserWindow() {},
        dialog: {},
        ipcMain: {},
        net: {},
        powerMonitor: {},
        session: {},
        shell: {},
      };
    }
    if (specifier === 'node:fs') return { existsSync: () => false };
    if (specifier === 'node:path') return path;
    if (specifier === 'node:child_process') {
      return { spawn: () => {}, spawnSync: () => ({ status: 1 }) };
    }
    if (specifier === 'node:readline') return {};
    throw new Error(`Unexpected require: ${specifier}`);
  },
};
vm.createContext(sandbox);
vm.runInContext(source, sandbox, { filename });
assert.match(source, /\.\.\.trustedCoreProxyEnvironment\(\),/);

const normalize = (environment, platform = 'win32') => vm.runInContext(
  `trustedCoreProxyEnvironment(${JSON.stringify(environment)}, ${JSON.stringify(platform)})`,
  sandbox,
);
const plain = (value) => JSON.parse(JSON.stringify(value));

assert.deepEqual(plain(normalize({
  hTtP_pRoXy: 'http://proxy.example.test:8080',
  Https_Proxy: 'http://secure-proxy.example.test:8443',
  no_pRoXy: '127.0.0.1,localhost',
  ALL_PROXY: 'socks5://must-not-pass.example.test:1080',
  GITHUB_TOKEN: 'must-not-pass',
})), {
  HTTP_PROXY: 'http://proxy.example.test:8080',
  HTTPS_PROXY: 'http://secure-proxy.example.test:8443',
  NO_PROXY: '127.0.0.1,localhost',
});

assert.deepEqual(plain(normalize({
  HTTP_PROXY: '',
  HTTPS_PROXY: '   ',
  ALL_PROXY: 'socks5://must-not-pass.example.test:1080',
})), {});

assert.deepEqual(plain(normalize({
  HTTP_PROXY: 'http://canonical.example.test:8080',
  http_proxy: 'http://duplicate.example.test:8081',
})), {
  HTTP_PROXY: 'http://canonical.example.test:8080',
});

assert.deepEqual(plain(normalize({
  http_proxy: 'http://unix-lowercase.example.test:8080',
  HTTPS_PROXY: 'http://unix-canonical.example.test:8443',
}, 'darwin')), {
  HTTPS_PROXY: 'http://unix-canonical.example.test:8443',
});
"""
        completed = subprocess.run(
            ["node", "-e", harness, str(LAUNCHER)],
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
            msg=f"trusted core proxy env contract failed:\n{completed.stdout}\n{completed.stderr}",
        )

    def test_plugin_runner_does_not_inherit_proxy_environment(self) -> None:
        inherited = {
            "HTTP_PROXY": "http://core-only.example.test:8080",
            "HTTPS_PROXY": "http://core-only.example.test:8443",
            "NO_PROXY": "127.0.0.1,localhost",
            "ALL_PROXY": "socks5://must-not-pass.example.test:1080",
            "http_proxy": "http://lowercase.example.test:8081",
            "Https_Proxy": "http://mixed-case.example.test:8444",
            "no_proxy": "example.test",
            "all_proxy": "socks5://lowercase.example.test:1081",
        }
        with patch.dict(os.environ, inherited, clear=False):
            child_environment = RunManager._safe_environment()
        for name in inherited:
            self.assertNotIn(name, child_environment)


if __name__ == "__main__":
    unittest.main()
