from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from soft_hub.config import HubPaths
from soft_hub.database import Database
from soft_hub.plugins import PluginManager
from tests.support import plugin_manifest, write_plugin_archive


class PluginRuntimeInvariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="soft-hub-plugin-runtime-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.paths = HubPaths.create(self.root / "data")
        self.database = Database(self.paths)
        self.manager = PluginManager(self.database, self.paths)

    def install_plugin(self) -> tuple[Path, Path]:
        archive = write_plugin_archive(
            self.root / "runtime-plugin.softhub.zip",
            plugin_manifest(requirements="requirements.txt"),
            files={"requirements.txt": "deterministic-package==1.0.0\n"},
        )
        installed = self.manager.install(archive)
        plugin_path = Path(installed["active_path"])
        candidate = self.manager._venv_python(plugin_path)
        candidate.parent.mkdir(parents=True)
        candidate.write_text("test interpreter placeholder", encoding="utf-8")
        return plugin_path, candidate

    @staticmethod
    def requirement_digest(plugin_path: Path) -> str:
        return hashlib.sha256((plugin_path / "requirements.txt").read_bytes()).hexdigest()

    def write_ready_state(
        self,
        plugin_path: Path,
        *,
        runtime_id: str,
        home: Path | None,
        digest: str | None = None,
    ) -> Path:
        environment = plugin_path / ".venv"
        configuration = environment / "pyvenv.cfg"
        configuration.write_text(
            f"home = {home}\n" if home is not None else "include-system-site-packages = false\n",
            encoding="utf-8",
        )
        marker = environment / ".soft-hub-ready.json"
        marker.write_text(
            json.dumps(
                {
                    "requirements_sha256": digest or self.requirement_digest(plugin_path),
                    "runtime_id": runtime_id,
                }
            ),
            encoding="utf-8",
        )
        return marker

    def test_ready_marker_requires_current_runtime_id_and_pyvenv_home(self) -> None:
        plugin_path, candidate = self.install_plugin()
        expected_home = Path(sys.executable).resolve().parent

        with mock.patch(
            "soft_hub.plugins.runtime_fingerprint", return_value="runtime-current"
        ):
            self.write_ready_state(
                plugin_path,
                runtime_id="runtime-previous",
                home=expected_home,
            )
            self.assertIsNone(self.manager.python_for(plugin_path, "requirements.txt"))

            self.write_ready_state(
                plugin_path,
                runtime_id="runtime-current",
                home=self.root / "different-runtime" / "bin",
            )
            self.assertIsNone(self.manager.python_for(plugin_path, "requirements.txt"))

            self.write_ready_state(
                plugin_path,
                runtime_id="runtime-current",
                home=None,
            )
            self.assertIsNone(self.manager.python_for(plugin_path, "requirements.txt"))

            self.write_ready_state(
                plugin_path,
                runtime_id="runtime-current",
                home=expected_home,
            )
            self.assertEqual(
                self.manager.python_for(plugin_path, "requirements.txt"), candidate
            )

    def test_legacy_ready_marker_survives_core_lock_only_runtime_change(self) -> None:
        plugin_path, candidate = self.install_plugin()
        compatibility_id = (
            "python-build-standalone:20260805:cpython-3.12.13:win32-x64"
        )
        previous_runtime_id = f"{compatibility_id}:1111111111111111"
        self.write_ready_state(
            plugin_path,
            runtime_id=previous_runtime_id,
            home=Path(sys.executable).resolve().parent,
        )

        with mock.patch(
            "soft_hub.plugins.runtime_fingerprint", return_value=compatibility_id
        ):
            self.assertEqual(
                self.manager.python_for(plugin_path, "requirements.txt"), candidate
            )

        state = json.loads(
            (plugin_path / ".venv" / ".soft-hub-ready.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(state["runtime_id"], compatibility_id)

    def test_legacy_marker_from_another_interpreter_build_is_rejected(self) -> None:
        plugin_path, _candidate = self.install_plugin()
        self.write_ready_state(
            plugin_path,
            runtime_id=(
                "python-build-standalone:20260804:cpython-3.12.13:win32-x64:"
                "1111111111111111"
            ),
            home=Path(sys.executable).resolve().parent,
        )

        with mock.patch(
            "soft_hub.plugins.runtime_fingerprint",
            return_value=(
                "python-build-standalone:20260805:cpython-3.12.13:win32-x64"
            ),
        ):
            self.assertIsNone(
                self.manager.python_for(plugin_path, "requirements.txt")
            )

    def test_prepare_uses_bundled_pip_wheel_without_package_index(self) -> None:
        plugin_path, candidate = self.install_plugin()
        runtime_id = "managed-runtime:offline-pip-test"
        self.write_ready_state(
            plugin_path,
            runtime_id=runtime_id,
            home=Path(sys.executable).resolve().parent,
        )
        wheel = self.root / "pip-26.2.1-py3-none-any.whl"
        wheel.write_bytes(b"offline pip wheel placeholder")
        succeeded = mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch(
            "soft_hub.plugins.runtime_fingerprint", return_value=runtime_id
        ), mock.patch(
            "soft_hub.plugins.bundled_pip_wheel", return_value=wheel
        ), mock.patch(
            "soft_hub.plugins.subprocess.run",
            side_effect=[succeeded, succeeded],
        ) as run:
            prepared = self.manager.prepare("test.plugin")

        self.assertEqual(prepared["health"], "ready")
        self.assertEqual(run.call_count, 2)
        pip_command = run.call_args_list[0].args[0]
        self.assertEqual(pip_command[0], str(candidate))
        self.assertIn("--no-index", pip_command)
        self.assertEqual(pip_command[-1], str(wheel))
        self.assertNotIn("pip>=26.1.2,<27", pip_command)

        marker = plugin_path / ".venv" / ".soft-hub-ready.json"
        state = json.loads(marker.read_text(encoding="utf-8"))
        self.assertEqual(state["runtime_id"], runtime_id)
        self.assertEqual(state["requirements_sha256"], self.requirement_digest(plugin_path))


if __name__ == "__main__":
    unittest.main()
