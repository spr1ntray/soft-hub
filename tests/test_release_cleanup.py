from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import clean_release_artifacts
from scripts import write_installer_checksums


class ReleaseCleanupTests(unittest.TestCase):
    def _workspace(self, temporary: str) -> tuple[Path, Path]:
        root = Path(temporary)
        installers = root / "INSTALLERS"
        installers.mkdir()
        (root / "package.json").write_text(
            json.dumps({"version": "9.8.7"}), encoding="utf-8"
        )
        return root, installers

    def test_after_build_keeps_only_current_installers_and_readme(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-release-clean-") as temporary:
            root, installers = self._workspace(temporary)
            current = installers / "Soft Hub-9.8.7-arm64.dmg"
            current_windows = installers / "Soft Hub-9.8.7-x64.exe"
            stale = installers / "Soft Hub-9.8.6-arm64.dmg"
            sidecar = installers / "Soft Hub-9.8.7-arm64.dmg.blockmap"
            staging = installers / "mac-arm64"
            windows_icon_staging = installers / ".icon-ico"
            loose_example = installers / "hello-soft-1.0.0.softhub.zip"
            readme = installers / "README_FIRST_RU.md"
            for path in (current, current_windows, stale, sidecar, loose_example):
                path.write_text("fixture", encoding="utf-8")
            readme.write_text("fixture", encoding="utf-8")
            staging.mkdir()
            windows_icon_staging.mkdir()

            with (
                mock.patch.object(clean_release_artifacts, "PROJECT_ROOT", root),
                mock.patch.object(clean_release_artifacts, "INSTALLERS_DIR", installers),
            ):
                clean_release_artifacts.clean(before_build=False)

            self.assertTrue(current.exists())
            self.assertTrue(current_windows.exists())
            self.assertFalse(stale.exists())
            self.assertFalse(sidecar.exists())
            self.assertFalse(staging.exists())
            self.assertFalse(windows_icon_staging.exists())
            self.assertFalse(loose_example.exists())
            self.assertTrue(readme.exists())

    def test_before_build_replaces_even_current_installer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-release-clean-") as temporary:
            root, installers = self._workspace(temporary)
            current = installers / "Soft Hub-9.8.7-x64.exe"
            other_platform = installers / "Soft Hub-9.8.7-arm64.dmg"
            stale_other_platform = installers / "Soft Hub-9.8.6-arm64.dmg"
            current.write_text("fixture", encoding="utf-8")
            other_platform.write_text("fixture", encoding="utf-8")
            stale_other_platform.write_text("fixture", encoding="utf-8")

            with (
                mock.patch.object(clean_release_artifacts, "PROJECT_ROOT", root),
                mock.patch.object(clean_release_artifacts, "INSTALLERS_DIR", installers),
            ):
                clean_release_artifacts.clean(before_build=True, platform="win")

            self.assertFalse(current.exists())
            self.assertTrue(other_platform.exists())
            self.assertFalse(stale_other_platform.exists())

    def test_refuses_symlinked_installers_without_touching_external_files(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="soft-hub-release-root-") as project,
            tempfile.TemporaryDirectory(prefix="soft-hub-release-external-") as external,
        ):
            root = Path(project)
            external_root = Path(external)
            (root / "package.json").write_text(
                json.dumps({"version": "9.8.7"}), encoding="utf-8"
            )
            fixture = external_root / "Soft Hub-9.8.6-arm64.dmg"
            fixture.write_text("must survive", encoding="utf-8")
            installers = root / "INSTALLERS"
            installers.symlink_to(external_root, target_is_directory=True)

            with (
                mock.patch.object(clean_release_artifacts, "PROJECT_ROOT", root),
                mock.patch.object(clean_release_artifacts, "INSTALLERS_DIR", installers),
            ):
                with self.assertRaisesRegex(RuntimeError, "symlink"):
                    clean_release_artifacts.clean(before_build=False)

            self.assertEqual(fixture.read_text(encoding="utf-8"), "must survive")

    def test_checksum_manifest_contains_only_current_installers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-release-sums-") as temporary:
            root, installers = self._workspace(temporary)
            mac = installers / "Soft Hub-9.8.7-arm64.dmg"
            windows = installers / "Soft Hub-9.8.7-x64.exe"
            stale = installers / "Soft Hub-9.8.6-x64.exe"
            mac.write_bytes(b"mac fixture")
            windows.write_bytes(b"windows fixture")
            stale.write_bytes(b"stale fixture")

            with (
                mock.patch.object(write_installer_checksums, "PROJECT_ROOT", root),
                mock.patch.object(write_installer_checksums, "INSTALLERS_DIR", installers),
            ):
                destination = write_installer_checksums.write_checksums()

            payload = destination.read_text(encoding="utf-8")
            self.assertIn(mac.name, payload)
            self.assertIn(windows.name, payload)
            self.assertNotIn(stale.name, payload)
            self.assertEqual(len(payload.splitlines()), 2)


if __name__ == "__main__":
    unittest.main()
