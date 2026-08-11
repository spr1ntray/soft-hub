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

    def test_after_build_keeps_only_current_installers_checksum_and_readme(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-release-clean-") as temporary:
            root, installers = self._workspace(temporary)
            current = installers / "Soft-Hub-9.8.7-arm64.dmg"
            current_zip = installers / "Soft-Hub-9.8.7-arm64.zip"
            current_windows = installers / "Soft-Hub-9.8.7-x64.exe"
            current_blockmap = installers / "Soft-Hub-9.8.7-x64.exe.blockmap"
            stale = installers / "Soft-Hub-9.8.6-arm64.dmg"
            legacy = installers / "Soft Hub-9.8.7-arm64.dmg"
            wrong_platform = installers / "Soft-Hub-9.8.7-x64.dmg"
            unused_sidecar = installers / "Soft-Hub-9.8.7-arm64.dmg.blockmap"
            staging = installers / "mac-arm64"
            windows_icon_staging = installers / ".icon-ico"
            loose_example = installers / "hello-soft-1.0.0.softhub.zip"
            latest_mac = installers / "latest-mac.yml"
            latest_windows = installers / "latest.yml"
            builder_metadata = installers / "builder-debug.yml"
            checksums = installers / "SHA256SUMS"
            readme = installers / "README_FIRST_RU.md"
            for path in (
                current,
                current_zip,
                current_windows,
                current_blockmap,
                stale,
                legacy,
                wrong_platform,
                unused_sidecar,
                loose_example,
            ):
                path.write_text("fixture", encoding="utf-8")
            latest_mac.write_text("version: 9.8.7\npath: mac.zip\n", encoding="utf-8")
            latest_windows.write_text("version: 9.8.7\npath: win.exe\n", encoding="utf-8")
            builder_metadata.write_text("fixture", encoding="utf-8")
            checksums.write_text(
                "0" * 64 + "  Soft-Hub-9.8.7-arm64.dmg\n",
                encoding="utf-8",
            )
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
            self.assertTrue(checksums.exists())
            self.assertFalse(current_zip.exists())
            self.assertFalse(current_blockmap.exists())
            self.assertFalse(latest_mac.exists())
            self.assertFalse(latest_windows.exists())
            self.assertFalse(stale.exists())
            self.assertFalse(legacy.exists())
            self.assertFalse(wrong_platform.exists())
            self.assertFalse(unused_sidecar.exists())
            self.assertFalse(staging.exists())
            self.assertFalse(windows_icon_staging.exists())
            self.assertFalse(loose_example.exists())
            self.assertFalse(builder_metadata.exists())
            self.assertTrue(readme.exists())

    def test_before_build_replaces_only_selected_platform_release_family(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-release-clean-") as temporary:
            root, installers = self._workspace(temporary)
            current = installers / "Soft-Hub-9.8.7-x64.exe"
            current_blockmap = installers / "Soft-Hub-9.8.7-x64.exe.blockmap"
            other_platform = installers / "Soft-Hub-9.8.7-arm64.dmg"
            other_platform_zip = installers / "Soft-Hub-9.8.7-arm64.zip"
            stale_other_platform = installers / "Soft-Hub-9.8.6-arm64.dmg"
            latest_windows = installers / "latest.yml"
            latest_mac = installers / "latest-mac.yml"
            checksums = installers / "SHA256SUMS"
            for path in (
                current,
                current_blockmap,
                other_platform,
                other_platform_zip,
            ):
                path.write_text("fixture", encoding="utf-8")
            stale_other_platform.write_text("fixture", encoding="utf-8")
            latest_windows.write_text("version: 9.8.7\n", encoding="utf-8")
            latest_mac.write_text("version: 9.8.7\n", encoding="utf-8")
            checksums.write_text(
                "0" * 64 + "  Soft-Hub-9.8.7-arm64.dmg\n",
                encoding="utf-8",
            )

            with (
                mock.patch.object(clean_release_artifacts, "PROJECT_ROOT", root),
                mock.patch.object(clean_release_artifacts, "INSTALLERS_DIR", installers),
            ):
                clean_release_artifacts.clean(before_build=True, platform="win")

            self.assertFalse(current.exists())
            self.assertFalse(current_blockmap.exists())
            self.assertFalse(latest_windows.exists())
            self.assertFalse(checksums.exists())
            self.assertTrue(other_platform.exists())
            self.assertFalse(other_platform_zip.exists())
            self.assertFalse(latest_mac.exists())
            self.assertFalse(stale_other_platform.exists())

    def test_after_build_removes_stale_or_malformed_update_metadata_and_sums(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-release-clean-") as temporary:
            root, installers = self._workspace(temporary)
            latest_mac = installers / "latest-mac.yml"
            latest_windows = installers / "latest.yml"
            checksums = installers / "SHA256SUMS"
            latest_mac.write_text("version: 9.8.6\n", encoding="utf-8")
            latest_windows.write_text("not update metadata", encoding="utf-8")
            checksums.write_text(
                "0" * 64 + "  Soft-Hub-9.8.6-arm64.dmg\n",
                encoding="utf-8",
            )

            with (
                mock.patch.object(clean_release_artifacts, "PROJECT_ROOT", root),
                mock.patch.object(clean_release_artifacts, "INSTALLERS_DIR", installers),
            ):
                clean_release_artifacts.clean(before_build=False)

            self.assertFalse(latest_mac.exists())
            self.assertFalse(latest_windows.exists())
            self.assertFalse(checksums.exists())

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
            fixture = external_root / "Soft-Hub-9.8.6-arm64.dmg"
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

    def test_checksum_manifest_contains_only_current_canonical_installers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-release-sums-") as temporary:
            root, installers = self._workspace(temporary)
            mac = installers / "Soft-Hub-9.8.7-arm64.dmg"
            mac_zip = installers / "Soft-Hub-9.8.7-arm64.zip"
            windows = installers / "Soft-Hub-9.8.7-x64.exe"
            blockmap = installers / "Soft-Hub-9.8.7-x64.exe.blockmap"
            latest_mac = installers / "latest-mac.yml"
            latest_windows = installers / "latest.yml"
            stale = installers / "Soft-Hub-9.8.6-x64.exe"
            mac.write_bytes(b"mac fixture")
            mac_zip.write_bytes(b"mac update fixture")
            windows.write_bytes(b"windows fixture")
            blockmap.write_bytes(b"windows blockmap")
            latest_mac.write_text("version: 9.8.7\n", encoding="utf-8")
            latest_windows.write_text("version: '9.8.7'\n", encoding="utf-8")
            stale.write_bytes(b"stale fixture")

            with (
                mock.patch.object(write_installer_checksums, "PROJECT_ROOT", root),
                mock.patch.object(write_installer_checksums, "INSTALLERS_DIR", installers),
            ):
                destination = write_installer_checksums.write_checksums()

            payload = destination.read_text(encoding="utf-8")
            for path in (mac, windows):
                with self.subTest(path=path.name):
                    self.assertIn(path.name, payload)
            for path in (mac_zip, blockmap, latest_mac, latest_windows):
                with self.subTest(excluded=path.name):
                    self.assertNotIn(path.name, payload)
            self.assertNotIn(stale.name, payload)
            self.assertEqual(len(payload.splitlines()), 2)

    def test_checksum_manifest_ignores_builder_update_metadata(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-release-sums-") as temporary:
            root, installers = self._workspace(temporary)
            (installers / "Soft-Hub-9.8.7-arm64.dmg").write_bytes(b"mac")
            (installers / "latest-mac.yml").write_text(
                "version: 9.8.6\n", encoding="utf-8"
            )

            with (
                mock.patch.object(write_installer_checksums, "PROJECT_ROOT", root),
                mock.patch.object(write_installer_checksums, "INSTALLERS_DIR", installers),
            ):
                destination = write_installer_checksums.write_checksums()

            payload = destination.read_text(encoding="utf-8")
            self.assertIn("Soft-Hub-9.8.7-arm64.dmg", payload)
            self.assertNotIn("latest-mac.yml", payload)

    def test_complete_release_gate_requires_both_platform_installers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-release-sums-") as temporary:
            root, installers = self._workspace(temporary)
            (installers / "Soft-Hub-9.8.7-arm64.dmg").write_bytes(b"mac")

            with (
                mock.patch.object(write_installer_checksums, "PROJECT_ROOT", root),
                mock.patch.object(write_installer_checksums, "INSTALLERS_DIR", installers),
            ):
                with self.assertRaisesRegex(RuntimeError, "Неполный набор"):
                    write_installer_checksums.write_checksums(require_complete=True)

                (installers / "Soft-Hub-9.8.7-x64.exe").write_bytes(b"windows")
                destination = write_installer_checksums.write_checksums(
                    require_complete=True
                )

            self.assertEqual(len(destination.read_text(encoding="utf-8").splitlines()), 2)

    def test_checksum_writer_rejects_empty_installer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-release-sums-") as temporary:
            root, installers = self._workspace(temporary)
            (installers / "Soft-Hub-9.8.7-arm64.dmg").touch()

            with (
                mock.patch.object(write_installer_checksums, "PROJECT_ROOT", root),
                mock.patch.object(write_installer_checksums, "INSTALLERS_DIR", installers),
            ):
                with self.assertRaisesRegex(RuntimeError, "пуст"):
                    write_installer_checksums.write_checksums()


if __name__ == "__main__":
    unittest.main()
