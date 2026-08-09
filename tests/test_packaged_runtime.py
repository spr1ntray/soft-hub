from __future__ import annotations

import json
import subprocess
import tomllib
import unittest
from pathlib import Path

from soft_hub.config import APP_VERSION


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class PackagedRuntimeContractTests(unittest.TestCase):
    def test_core_versions_and_visible_installer_output_stay_in_sync(self) -> None:
        package = json.loads((PROJECT_ROOT / "package.json").read_text(encoding="utf-8"))
        with (PROJECT_ROOT / "pyproject.toml").open("rb") as stream:
            pyproject = tomllib.load(stream)
        self.assertEqual(package["version"], APP_VERSION)
        self.assertEqual(pyproject["project"]["version"], APP_VERSION)
        self.assertEqual(package["build"]["directories"]["output"], "INSTALLERS")
        self.assertTrue((PROJECT_ROOT / "INSTALLERS" / "README_FIRST_RU.md").is_file())
        self.assertEqual(package["build"]["appId"], "io.sprintray.softhub")

    def test_before_pack_hook_rejects_cross_target_runtime_mixes(self) -> None:
        hook = PROJECT_ROOT / "scripts" / "verify_desktop_runtime.cjs"
        harness = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { verifyRuntime } = require(process.argv[1]);

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'soft-hub-before-pack-'));
const runtime = path.join(root, 'build', 'runtime', 'python');
fs.mkdirSync(runtime, { recursive: true });
fs.writeFileSync(path.join(runtime, 'soft-hub-runtime.json'), JSON.stringify({ os: 'win32', arch: 'x64' }));
for (const name of ['python.exe', 'python312.dll', 'vcruntime140.dll', 'vcruntime140_1.dll']) {
  fs.writeFileSync(path.join(runtime, name), 'fixture');
}

verifyRuntime(root, 'win32', 1);
assert.throws(() => verifyRuntime(root, 'darwin', 3), /Refusing to package darwin-arm64/);
fs.unlinkSync(path.join(runtime, 'vcruntime140_1.dll'));
assert.throws(() => verifyRuntime(root, 'win32', 1), /runtime is incomplete/);
fs.rmSync(root, { recursive: true, force: true });
"""
        completed = subprocess.run(
            ["node", "-e", harness, str(hook)],
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
            msg=f"beforePack contract failed:\n{completed.stdout}\n{completed.stderr}",
        )

    def test_packaged_launcher_never_falls_back_to_external_python(self) -> None:
        launcher = PROJECT_ROOT / "electron" / "main.cjs"
        harness = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const filename = process.argv[1];
const source = fs.readFileSync(filename, 'utf8');
function resolveCandidate({ platform = 'darwin', embeddedExists, probeStatus }) {
  const probeCalls = [];
  const embedded = platform === 'win32'
    ? path.join('/packaged/resources', 'python', 'python.exe')
    : path.join('/packaged/resources', 'python', 'bin', 'python3');
  const app = {
    isPackaged: true,
    requestSingleInstanceLock: () => false,
    quit: () => {},
    setName: () => {},
    enableSandbox: () => {},
  };
  const sandbox = {
    __dirname: path.dirname(filename),
    console,
    URL,
    setTimeout,
    clearTimeout,
    process: {
      platform,
      resourcesPath: '/packaged/resources',
      env: { SOFT_HUB_PYTHON: '/untrusted/external/python' },
    },
    require: (specifier) => {
      if (specifier === 'electron') {
        return { app, BrowserWindow: function BrowserWindow() {}, dialog: {}, session: {} };
      }
      if (specifier === 'node:fs') {
        return { existsSync: (candidate) => embeddedExists && candidate === embedded };
      }
      if (specifier === 'node:path') return path;
      if (specifier === 'node:child_process') {
        return {
          spawn: () => { throw new Error('spawn must not run while selecting Python'); },
          spawnSync: (...args) => {
            probeCalls.push(args);
            return { status: probeStatus };
          },
        };
      }
      if (specifier === 'node:readline') return {};
      throw new Error(`Unexpected require: ${specifier}`);
    },
  };
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename });
const result = vm.runInContext('pythonCandidate()', sandbox);
const githubPolicy = {
  valid: vm.runInContext("publicGitHubRepositoryUrl('https://github.com/owner/repository')", sandbox),
  http: vm.runInContext("publicGitHubRepositoryUrl('http://github.com/owner/repository')", sandbox),
  credentials: vm.runInContext("publicGitHubRepositoryUrl('https://user:token@github.com/owner/repository')", sandbox),
  suffixHost: vm.runInContext("publicGitHubRepositoryUrl('https://github.com.attacker.test/owner/repository')", sandbox),
  extraPath: vm.runInContext("publicGitHubRepositoryUrl('https://github.com/owner/repository/releases')", sandbox),
  query: vm.runInContext("publicGitHubRepositoryUrl('https://github.com/owner/repository?token=secret')", sandbox),
};
return { result, probeCalls, githubPolicy };
}

const absent = resolveCandidate({ embeddedExists: false, probeStatus: 0 });
assert.equal(absent.result, null);
assert.equal(absent.probeCalls.length, 0, 'external Python must not even be probed');

const corrupt = resolveCandidate({ embeddedExists: true, probeStatus: 1 });
assert.equal(corrupt.result, null);
assert.equal(corrupt.probeCalls.length, 1, 'only embedded Python may be probed');
assert.equal(corrupt.probeCalls[0][0], path.join('/packaged/resources', 'python', 'bin', 'python3'));
assert.deepEqual(Array.from(corrupt.probeCalls[0][1].slice(0, 3)), ['-B', '-I', '-c']);

const healthy = resolveCandidate({ embeddedExists: true, probeStatus: 0 });
assert.equal(healthy.probeCalls.length, 1);
assert.equal(healthy.probeCalls[0][0], path.join('/packaged/resources', 'python', 'bin', 'python3'));
assert.equal(healthy.result.command, path.join('/packaged/resources', 'python', 'bin', 'python3'));
assert.deepEqual(Array.from(healthy.result.prefix), ['-B', '-I']);
assert.notEqual(healthy.result.command, '/untrusted/external/python');
assert.equal(healthy.githubPolicy.valid, 'https://github.com/owner/repository');
assert.equal(healthy.githubPolicy.http, null);
assert.equal(healthy.githubPolicy.credentials, null);
assert.equal(healthy.githubPolicy.suffixHost, null);
assert.equal(healthy.githubPolicy.extraPath, null);
assert.equal(healthy.githubPolicy.query, null);

const healthyWindows = resolveCandidate({ platform: 'win32', embeddedExists: true, probeStatus: 0 });
const windowsEmbedded = path.join('/packaged/resources', 'python', 'python.exe');
assert.equal(healthyWindows.probeCalls.length, 1);
assert.equal(healthyWindows.probeCalls[0][0], windowsEmbedded);
assert.equal(healthyWindows.result.command, windowsEmbedded);
assert.deepEqual(Array.from(healthyWindows.result.prefix), ['-B', '-I']);
"""
        completed = subprocess.run(
            ["node", "-e", harness, str(launcher)],
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
            msg=f"Node launcher contract failed:\n{completed.stdout}\n{completed.stderr}",
        )

    def test_release_manifest_embeds_runtime_and_prepares_it_before_packaging(self) -> None:
        package = json.loads((PROJECT_ROOT / "package.json").read_text(encoding="utf-8"))
        resources = package["build"]["extraResources"]
        self.assertEqual(
            package["build"]["beforePack"],
            "./scripts/verify_desktop_runtime.cjs",
        )
        self.assertTrue(
            any(
                resource.get("from") == "build/runtime/python"
                and resource.get("to") == "python"
                for resource in resources
            ),
            "The packaged app must contain the managed Python tree",
        )
        self.assertFalse(
            any(
                resource.get("from") == "dist/plugins"
                or resource.get("to") == "plugins"
                for resource in resources
            ),
            "A clean desktop release must not ship bundled software",
        )
        packaged_docs = [
            resource
            for resource in resources
            if resource.get("from") == "docs" and resource.get("to") == "docs"
        ]
        self.assertEqual(
            packaged_docs,
            [{"from": "docs", "to": "docs", "filter": ["USER_GUIDE_RU.md"]}],
            "The installer must contain only the user guide, never internal author docs",
        )
        launcher = (PROJECT_ROOT / "electron" / "main.cjs").read_text(encoding="utf-8")
        self.assertNotIn("SOFT_HUB_BUNDLED_PLUGINS", launcher)
        self.assertIn("PYTHONDONTWRITEBYTECODE: '1'", launcher)
        expected_icon = "assets/soft-hub-icon-v2.png"
        for target in ("mac", "dmg", "win"):
            with self.subTest(icon_target=target):
                self.assertEqual(package["build"][target]["icon"], expected_icon)
        self.assertTrue((PROJECT_ROOT / expected_icon).is_file())
        for script_name in ("dist:mac", "dist:win"):
            with self.subTest(script=script_name):
                command = package["scripts"][script_name]
                self.assertIn("scripts/prepare_runtime.py", command)
                self.assertLess(
                    command.index("scripts/prepare_runtime.py"),
                    command.index("electron-builder"),
                )
                expected_target = (
                    "--target darwin-arm64"
                    if script_name == "dist:mac"
                    else "--target win32-x64"
                )
                self.assertIn(expected_target, command)
                self.assertIn(expected_target + " --check", command)
                self.assertLess(
                    command.index(expected_target + " --check"),
                    command.index("electron-builder"),
                )


if __name__ == "__main__":
    unittest.main()
