from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import prepare_runtime


class TargetRuntimePreparationTests(unittest.TestCase):
    def test_windows_target_is_explicit_and_never_inferred_from_macos_host(self) -> None:
        with mock.patch("scripts.prepare_runtime.platform.system", return_value="Darwin"), mock.patch(
            "scripts.prepare_runtime.platform.machine", return_value="arm64"
        ):
            spec = prepare_runtime._resolve_spec("win32-x64")

        self.assertEqual((spec.os_name, spec.arch), ("win32", "x64"))
        self.assertEqual(spec.pip_platform, "win_amd64")

    def test_windows_layout_and_cross_pip_command_are_target_specific(self) -> None:
        spec = prepare_runtime._resolve_spec("win32-x64")
        root = Path("runtime-root")
        purelib = root / "Lib" / "site-packages"
        command = prepare_runtime._cross_pip_install_command(spec, purelib)

        self.assertEqual(prepare_runtime._python_path(root, spec), root / "python.exe")
        self.assertEqual(prepare_runtime._purelib_path(root, spec), purelib)
        self.assertEqual(command[0], sys.executable)
        self.assertIn("win_amd64", command)
        self.assertIn("cp312", command)
        self.assertIn("3.12", command)
        self.assertIn("--only-binary=:all:", command)
        self.assertIn("--no-deps", command)
        self.assertNotIn(str(root / "python.exe"), command)

    def test_pe_machine_parser_and_wrong_architecture_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-pe-test-") as temporary:
            executable = Path(temporary) / "python.exe"
            payload = bytearray(128)
            payload[:2] = b"MZ"
            payload[60:64] = (64).to_bytes(4, "little")
            payload[64:68] = b"PE\0\0"
            payload[68:70] = (0x8664).to_bytes(2, "little")
            executable.write_bytes(payload)
            self.assertEqual(prepare_runtime._pe_machine(executable), 0x8664)

            payload[68:70] = (0xAA64).to_bytes(2, "little")
            executable.write_bytes(payload)
            self.assertEqual(prepare_runtime._pe_machine(executable), 0xAA64)

    def test_darwin_tree_cannot_validate_as_windows_runtime(self) -> None:
        spec = prepare_runtime._resolve_spec("win32-x64")
        with tempfile.TemporaryDirectory(prefix="soft-hub-runtime-mix-test-") as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            (root / "bin" / "python3").write_bytes(b"darwin")
            with self.assertRaisesRegex(RuntimeError, "Python/MSVC runtime DLL"):
                prepare_runtime._validate_windows_layout(root, spec)


if __name__ == "__main__":
    unittest.main()
