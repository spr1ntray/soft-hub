from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from soft_hub import config


class ManagedRuntimeConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="soft-hub-runtime-config-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.runtime = self.root / "python"
        self.executable = self.runtime / "bin" / "python3"
        self.executable.parent.mkdir(parents=True)
        self.executable.write_bytes(b"test interpreter placeholder")

    @property
    def marker(self) -> Path:
        return self.runtime / "soft-hub-runtime.json"

    def write_marker(self, state: object) -> None:
        self.marker.write_text(json.dumps(state), encoding="utf-8")

    def test_runtime_id_is_loaded_from_valid_marker_next_to_runtime_root(self) -> None:
        state = {
            "runtime_id": "python-build-standalone:test-runtime",
            "pip_wheel": "soft-hub-wheels/pip-test.whl",
        }
        self.write_marker(state)
        # A malformed marker closer to the executable must not hide the valid root marker.
        (self.executable.parent / "soft-hub-runtime.json").write_text(
            "not-json", encoding="utf-8"
        )

        with mock.patch.object(config.sys, "executable", str(self.executable)):
            managed = config.managed_runtime()
            self.assertIsNotNone(managed)
            assert managed is not None
            self.assertEqual(managed[0], self.runtime.resolve())
            self.assertEqual(managed[1], state)
            self.assertEqual(config.runtime_fingerprint(), state["runtime_id"])

    def test_invalid_or_empty_runtime_identity_is_fail_closed(self) -> None:
        invalid_states: list[object] = [
            [],
            {},
            {"runtime_id": ""},
            {"runtime_id": 312},
        ]
        with mock.patch.object(config.sys, "executable", str(self.executable)):
            for state in invalid_states:
                with self.subTest(state=state):
                    self.write_marker(state)
                    self.assertIsNone(config.managed_runtime())

    def test_plugin_fingerprint_ignores_only_the_core_lock_digest(self) -> None:
        base = "python-build-standalone:20260805:cpython-3.12.13:win32-x64"
        previous = f"{base}:1111111111111111"
        current = f"{base}:2222222222222222"
        self.write_marker({"runtime_id": previous})

        with mock.patch.object(config.sys, "executable", str(self.executable)):
            self.assertEqual(config.runtime_fingerprint(), base)
            self.assertTrue(config.runtime_fingerprints_compatible(previous, current))
            self.assertTrue(config.runtime_fingerprints_compatible(previous, base))
            self.assertFalse(
                config.runtime_fingerprints_compatible(
                    previous,
                    "python-build-standalone:20260806:cpython-3.12.13:win32-x64",
                )
            )
            self.assertFalse(
                config.runtime_fingerprints_compatible(
                    previous,
                    "python-build-standalone:20260805:cpython-3.13.0:win32-x64",
                )
            )

    def test_bundled_pip_wheel_must_exist_inside_managed_runtime(self) -> None:
        wheel = self.runtime / "soft-hub-wheels" / "pip-26.2.1-py3-none-any.whl"
        wheel.parent.mkdir()
        wheel.write_bytes(b"offline pip wheel placeholder")
        outside = self.root / "outside.whl"
        outside.write_bytes(b"must never be trusted")

        with mock.patch.object(config.sys, "executable", str(self.executable)):
            self.write_marker(
                {
                    "runtime_id": "runtime-with-offline-pip",
                    "pip_wheel": wheel.relative_to(self.runtime).as_posix(),
                }
            )
            self.assertEqual(config.bundled_pip_wheel(), wheel.resolve())

            unsafe_or_missing: list[object] = [
                "../outside.whl",
                "soft-hub-wheels/missing.whl",
                "",
                None,
            ]
            for pip_wheel in unsafe_or_missing:
                with self.subTest(pip_wheel=pip_wheel):
                    self.write_marker(
                        {
                            "runtime_id": "runtime-with-invalid-pip",
                            "pip_wheel": pip_wheel,
                        }
                    )
                    self.assertIsNone(config.bundled_pip_wheel())


if __name__ == "__main__":
    unittest.main()
