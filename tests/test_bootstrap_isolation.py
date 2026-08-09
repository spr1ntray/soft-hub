from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BootstrapIsolationTests(unittest.TestCase):
    def test_plugin_environment_dependencies_override_packaged_core_dependencies(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-bootstrap-isolation-") as temporary:
            root = Path(temporary)
            core = root / "runtime" / "lib" / "python3.12" / "site-packages"
            shutil.copytree(
                PROJECT_ROOT / "soft_hub",
                core / "soft_hub",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )

            core_dependency = core / "dependency_probe"
            core_dependency.mkdir()
            (core_dependency / "__init__.py").write_text(
                'ORIGIN = "packaged-core"\n', encoding="utf-8"
            )

            plugin_site = root / "plugin-environment" / "site-packages"
            plugin_dependency = plugin_site / "dependency_probe"
            plugin_dependency.mkdir(parents=True)
            (plugin_dependency / "__init__.py").write_text(
                'ORIGIN = "plugin-environment"\n', encoding="utf-8"
            )

            plugin_root = root / "plugin"
            package = plugin_root / "plugin"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "main.py").write_text(
                "import dependency_probe\n\n"
                "def run(context):\n"
                "    return {\"origin\": dependency_probe.ORIGIN, "
                "\"file\": dependency_probe.__file__}\n",
                encoding="utf-8",
            )

            scratch = root / "scratch"
            scratch.mkdir()
            payload = {
                "run_id": "00000000-0000-0000-0000-000000000001",
                "plugin_id": "test.bootstrap-isolation",
                "plugin_version": "1.0.0",
                "action_id": "probe",
                "options": {},
                "accounts": [],
                "plugin_root": str(plugin_root),
                "scratch_dir": str(scratch),
            }
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(plugin_site)
            environment["PYTHONNOUSERSITE"] = "1"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-u",
                    str(core / "soft_hub" / "runtime" / "bootstrap.py"),
                    str(plugin_root),
                    "plugin.main:run",
                ],
                cwd=scratch,
                env=environment,
                input=json.dumps(payload) + "\n",
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            frames = [json.loads(line) for line in completed.stdout.splitlines()]
            finished = next(frame for frame in frames if frame["type"] == "completed")
            summary = finished["data"]["summary"]
            self.assertEqual(summary["origin"], "plugin-environment")
            self.assertTrue(
                Path(summary["file"]).is_relative_to(plugin_site), summary["file"]
            )


if __name__ == "__main__":
    unittest.main()
