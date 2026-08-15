from __future__ import annotations

import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.build_plugin import build
from tests.support import plugin_manifest


class BuildPluginSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "plugin"
        project_root = Path(__file__).resolve().parents[1]
        shutil.copytree(project_root / "examples" / "hello-soft", self.source)
        manifest_path = self.source / "hub.plugin.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["id"] = "build.security"
        manifest["name"] = "Build Security"
        manifest["presentation"]["display_name"] = "Build Security"
        manifest["compatibility"]["os"] = ["darwin", "win32", "linux"]
        (self.source / "hub.plugin.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_rejects_common_credential_and_session_files(self) -> None:
        denied = (
            "input/private_keys.txt",
            "input/proxies.txt",
            "input/capsolver_api_key.txt",
            ".env",
            "debug/session.har",
            "state/accounts.sqlite3",
            "certs/client.key",
        )
        for index, relative in enumerate(denied):
            with self.subTest(relative=relative):
                candidate = self.source / relative
                candidate.parent.mkdir(parents=True, exist_ok=True)
                candidate.write_text("synthetic-test-value", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "Vault"):
                    build(self.source, self.root / f"denied-{index}.softhub.zip")
                candidate.unlink()

    def test_allows_documented_environment_template(self) -> None:
        (self.source / ".env.example").write_text(
            "API_KEY=replace-me\n", encoding="utf-8"
        )
        output = build(self.source, self.root / "safe.softhub.zip")
        with zipfile.ZipFile(output) as archive:
            self.assertIn(".env.example", archive.namelist())
            self.assertNotIn(".env", archive.namelist())

    def test_allows_public_certificate_but_rejects_private_key_payload(self) -> None:
        certificate = self.source / "certs" / "public-ca.pem"
        certificate.parent.mkdir(parents=True)
        certificate.write_text(
            "-----BEGIN CERTIFICATE-----\nsynthetic-public-data\n-----END CERTIFICATE-----\n",
            encoding="utf-8",
        )
        build(self.source, self.root / "public-certificate.softhub.zip")

        certificate.write_text(
            "-----BEGIN PRIVATE KEY-----\nsynthetic-private-data\n-----END PRIVATE KEY-----\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "Vault"):
            build(self.source, self.root / "private-key.softhub.zip")

    def test_reference_strict_example_builds_with_presentation_assets(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        output = build(
            project_root / "examples" / "hello-soft",
            self.root / "hello-soft-1.1.0.softhub.zip",
        )

        with zipfile.ZipFile(output) as archive:
            manifest = json.loads(archive.read("hub.plugin.json"))
            self.assertEqual(manifest["contract_version"], "SH-SOFTWARE-0.6/4")
            self.assertEqual(manifest["catalog"]["sections"], ["general"])
            self.assertIn("assets/icon.png", archive.namelist())
            self.assertIn("assets/cover.png", archive.namelist())

    def test_rejects_legacy_manifest_for_a_new_author_build(self) -> None:
        (self.source / "hub.plugin.json").write_text(
            json.dumps(plugin_manifest(plugin_id="build.legacy")),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ValueError, "только новые пакеты контракта"):
            build(self.source, self.root / "legacy.softhub.zip")

    def test_builder_rejects_noncanonical_semver(self) -> None:
        manifest_path = self.source / "hub.plugin.json"
        baseline = json.loads(manifest_path.read_text(encoding="utf-8"))
        for index, version in enumerate(
            (
                "01.0.0",
                "1.0.0-01",
                "1.0.0-alpha..1",
                "1.0.0+rebuilt",
                "1.0.0-" + "a" * 175,
            )
        ):
            with self.subTest(version=version):
                manifest = dict(baseline)
                manifest["version"] = version
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "SemVer"):
                    build(self.source, self.root / f"invalid-version-{index}.softhub.zip")

        valid = dict(baseline)
        valid["version"] = "1.2.0-rc.1"
        manifest_path.write_text(json.dumps(valid), encoding="utf-8")
        output = build(self.source, self.root / "valid-prerelease.softhub.zip")
        self.assertTrue(output.is_file())

    def test_builder_runs_the_same_final_archive_inspection_as_installer(self) -> None:
        manifest_path = self.source / "hub.plugin.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["id"] = "build.presentation"
        manifest["presentation"] = {
            "display_name": "Broken image",
            "description": "The manifest is valid, but the bitmap payload is not.",
            "assets": {"icon": "assets/icon.png", "image": "assets/cover.png"},
        }
        manifest_path.write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        assets = self.source / "assets"
        (assets / "icon.png").write_bytes(b"not-a-real-png")
        (assets / "cover.png").write_bytes(b"not-a-real-png")

        with self.assertRaisesRegex(ValueError, "формату"):
            build(self.source, self.root / "broken-presentation.softhub.zip")


if __name__ == "__main__":
    unittest.main()
