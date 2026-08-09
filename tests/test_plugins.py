from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

from soft_hub.config import HubPaths, runtime_fingerprint
from soft_hub.database import Database, utc_now
from soft_hub.github_install import GitHubPackage
from soft_hub.plugins import (
    STRICT_CONTRACT_VERSION,
    PluginError,
    PluginManager,
    validate_manifest,
)
from tests.support import (
    archive_payloads,
    directory_zip_info,
    plugin_manifest,
    regular_zip_info,
    symlink_zip_info,
    write_plugin_archive,
)


class ManifestValidationTests(unittest.TestCase):
    def test_reference_example_is_a_strict_v3_contract(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        manifest = json.loads(
            (project_root / "examples" / "hello-soft" / "hub.plugin.json").read_text(
                encoding="utf-8"
            )
        )

        validated = validate_manifest(manifest)

        self.assertEqual(validated["contract_version"], STRICT_CONTRACT_VERSION)
        self.assertEqual(validated["compatibility"]["hub"], ">=0.6.8")
        profile_preview = next(
            action for action in validated["actions"] if action["id"] == "profile_preview"
        )
        self.assertEqual(profile_preview["output"]["mode"], "account_table")
        self.assertEqual(profile_preview["output"]["primary_kind"], "profile_preview")
        for action in validated["actions"]:
            self.assertEqual(
                set(action["options"]),
                {"type", "properties", "required", "additionalProperties"},
            )
            self.assertFalse(action["options"]["additionalProperties"])
            for field in action["options"]["properties"].values():
                self.assertTrue({"group", "order"}.issubset(field["x-ui"]))
            if action["account_mode"] == "one_or_more":
                concurrency = action["options"]["properties"]["account_concurrency"]
                self.assertEqual(concurrency["type"], "integer")
                self.assertEqual(concurrency["minimum"], 1)
                self.assertEqual(concurrency["maximum"], 20)
                self.assertEqual(concurrency["multipleOf"], 1)
                self.assertEqual(concurrency["x-ui"]["group"], "Выполнение")
                self.assertNotIn("account_concurrency", action["options"]["required"])

    def test_strict_v3_rejects_ambiguous_or_unfriendly_options(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        source = json.loads(
            (project_root / "examples" / "hello-soft" / "hub.plugin.json").read_text(
                encoding="utf-8"
            )
        )

        cases: list[tuple[str, dict[str, object], str]] = []

        missing_ui = copy.deepcopy(source)
        missing_ui["actions"][0]["options"]["properties"]["steps"].pop("x-ui")
        cases.append(("missing x-ui", missing_ui, "x-ui"))

        incomplete_ui = copy.deepcopy(source)
        incomplete_ui["actions"][0]["options"]["properties"]["steps"]["x-ui"].pop("group")
        cases.append(("missing UI group", incomplete_ui, "group и order"))

        open_options = copy.deepcopy(source)
        open_options["actions"][0]["options"].pop("additionalProperties")
        cases.append(("open option object", open_options, "требует type"))

        resource_mismatch = copy.deepcopy(source)
        resource_mismatch["permissions"]["secrets"] = ["proxy"]
        resource_mismatch["actions"][0]["permissions"]["secrets"] = ["proxy"]
        cases.append(("hidden secret requirement", resource_mismatch, "точно соответствовать"))

        free_string = copy.deepcopy(source)
        free_string["actions"][0]["options"]["properties"]["note"] = {
            "type": "string",
            "title": "Заметка",
            "description": "Публичная заметка этого запуска.",
            "default": "",
            "x-ui": {"group": "Основные параметры", "order": 20},
        }
        cases.append(("unbounded string", free_string, "maxLength"))

        missing_concurrency = copy.deepcopy(source)
        missing_concurrency["actions"][1]["options"]["properties"].pop(
            "account_concurrency"
        )
        cases.append(
            ("missing reserved concurrency", missing_concurrency, "account_concurrency")
        )

        concurrency_without_accounts = copy.deepcopy(source)
        concurrency_without_accounts["actions"][0]["options"]["properties"][
            "account_concurrency"
        ] = copy.deepcopy(
            source["actions"][1]["options"]["properties"]["account_concurrency"]
        )
        cases.append(
            (
                "concurrency on account-free action",
                concurrency_without_accounts,
                "account_mode=none",
            )
        )

        for label, manifest, message in cases:
            with self.subTest(label=label), self.assertRaisesRegex(PluginError, message):
                validate_manifest(manifest)

    def test_unknown_contract_version_is_rejected_while_legacy_still_loads(self) -> None:
        legacy = plugin_manifest()
        self.assertNotIn("contract_version", validate_manifest(legacy))

        unknown = plugin_manifest()
        unknown["contract_version"] = "SH-SOFTWARE-9.9/9"
        with self.assertRaisesRegex(PluginError, "contract_version"):
            validate_manifest(unknown)

    def test_valid_manifest_is_returned_as_a_deep_copy(self) -> None:
        source = plugin_manifest()
        validated = validate_manifest(source)
        self.assertEqual(validated, source)
        self.assertIsNot(validated, source)
        self.assertIsNot(validated["runtime"], source["runtime"])

    def test_accepts_complete_action_specific_secret_contract(self) -> None:
        source = plugin_manifest(secrets=["evm_private_key", "proxy"])
        source["actions"][0]["permissions"] = {"secrets": ["proxy"]}
        source["actions"].append(
            {
                "id": "sign",
                "name": "Sign",
                "description": "Action requiring the signer secret",
                "risk": "read",
                "account_mode": "one_or_more",
                "permissions": {"secrets": ["evm_private_key"]},
            }
        )

        validated = validate_manifest(source)

        self.assertEqual(
            validated["actions"][0]["permissions"]["secrets"],
            ["proxy"],
        )
        self.assertIsNot(
            validated["actions"][0]["permissions"],
            source["actions"][0]["permissions"],
        )

    def test_rejects_invalid_action_specific_secret_contracts(self) -> None:
        partial = plugin_manifest(secrets=["proxy"])
        second_action = copy.deepcopy(partial["actions"][0])
        second_action["id"] = "second"
        partial["actions"][0]["permissions"] = {"secrets": ["proxy"]}
        partial["actions"].append(second_action)

        unknown = plugin_manifest(secrets=["proxy"])
        unknown["actions"][0]["permissions"] = {"secrets": ["unknown"]}

        duplicate = plugin_manifest(secrets=["proxy"])
        duplicate["actions"][0]["permissions"] = {"secrets": ["proxy", "proxy"]}

        outside_plugin_union = plugin_manifest(secrets=["proxy"])
        outside_plugin_union["actions"][0]["permissions"] = {"secrets": ["email"]}

        incomplete_union = plugin_manifest(secrets=["evm_private_key", "proxy"])
        incomplete_union["actions"][0]["permissions"] = {"secrets": ["proxy"]}

        unknown_field = plugin_manifest(secrets=["proxy"])
        unknown_field["actions"][0]["permissions"] = {
            "secrets": ["proxy"],
            "network": [],
        }

        null_permissions = plugin_manifest()
        null_permissions["actions"][0]["permissions"] = None

        cases = [
            ("partial declaration", partial),
            ("unknown secret", unknown),
            ("duplicate secret", duplicate),
            ("not a top-level subset", outside_plugin_union),
            ("incomplete top-level union", incomplete_union),
            ("unknown action permission field", unknown_field),
            ("null action permissions", null_permissions),
        ]
        for label, manifest in cases:
            with self.subTest(label=label), self.assertRaises(PluginError):
                validate_manifest(manifest)

    def test_schema_declares_optional_action_secret_permissions(self) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "plugin.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        action_schema = schema["properties"]["actions"]["items"]
        action_permissions = action_schema["properties"]["permissions"]

        self.assertNotIn("permissions", action_schema["required"])
        self.assertEqual(action_permissions["required"], ["secrets"])
        self.assertFalse(action_permissions["additionalProperties"])
        self.assertTrue(action_permissions["properties"]["secrets"]["uniqueItems"])

    def test_account_table_output_contract_is_optional_strict_and_bounded(self) -> None:
        source = plugin_manifest(account_mode="one_or_more")
        source["compatibility"]["hub"] = ">=0.6.8"
        source["actions"][0]["output"] = {
            "mode": "account_table",
            "title": "Account statistics",
            "primary_kind": "account_snapshot",
            "columns": [
                {
                    "key": "points",
                    "title": "Points",
                    "type": "integer",
                    "aggregate": "sum",
                },
                {
                    "key": "balance",
                    "title": "Balance",
                    "type": "decimal_string",
                    "aggregate": "avg",
                },
                {"key": "eligible", "title": "Eligible", "type": "boolean"},
            ],
        }

        validated = validate_manifest(source)
        self.assertEqual(
            validated["actions"][0]["output"],
            source["actions"][0]["output"],
        )
        self.assertNotIn("output", validate_manifest(plugin_manifest())["actions"][0])

        cases: list[tuple[str, dict[str, object], str]] = []

        incompatible_hub = copy.deepcopy(source)
        incompatible_hub["compatibility"]["hub"] = ">=0.6.7"
        cases.append(("old hub", incompatible_hub, ">=0.6.8"))

        account_free = copy.deepcopy(source)
        account_free["actions"][0]["account_mode"] = "none"
        cases.append(("account-free", account_free, "one_or_more"))

        unknown_field = copy.deepcopy(source)
        unknown_field["actions"][0]["output"]["columns"][0]["sortable"] = True
        cases.append(("unknown column field", unknown_field, "неизвестные поля"))

        duplicate_key = copy.deepcopy(source)
        duplicate_key["actions"][0]["output"]["columns"][1]["key"] = "points"
        cases.append(("duplicate key", duplicate_key, "повтор key"))

        non_numeric_aggregate = copy.deepcopy(source)
        non_numeric_aggregate["actions"][0]["output"]["columns"][2]["aggregate"] = "sum"
        cases.append(("non-numeric aggregate", non_numeric_aggregate, "числовой"))

        too_many_columns = copy.deepcopy(source)
        too_many_columns["actions"][0]["output"]["columns"] = [
            {"key": f"field_{index}", "title": f"Field {index}", "type": "string"}
            for index in range(13)
        ]
        cases.append(("too many columns", too_many_columns, "1..12"))

        too_many_aggregates = copy.deepcopy(source)
        too_many_aggregates["actions"][0]["output"]["columns"] = [
            {
                "key": f"value_{index}",
                "title": f"Value {index}",
                "type": "number",
                "aggregate": "sum",
            }
            for index in range(5)
        ]
        cases.append(("too many aggregates", too_many_aggregates, "не более 4"))

        for label, manifest, message in cases:
            with self.subTest(label=label), self.assertRaisesRegex(PluginError, message):
                validate_manifest(manifest)

        schema = json.loads(
            (Path(__file__).resolve().parents[1] / "schemas" / "plugin.schema.json").read_text(
                encoding="utf-8"
            )
        )
        output_schema = schema["properties"]["actions"]["items"]["properties"]["output"]
        self.assertEqual(output_schema, {"$ref": "#/$defs/outputContract"})
        self.assertEqual(schema["$defs"]["outputContract"]["properties"]["columns"]["maxItems"], 12)

    def test_presentation_is_strict_when_present_and_legacy_absence_is_valid(self) -> None:
        legacy = plugin_manifest()
        self.assertNotIn("presentation", validate_manifest(legacy))

        complete = plugin_manifest()
        complete["presentation"] = {
            "display_name": "Friendly test module",
            "description": "A complete, user-facing description for the module catalog.",
            "assets": {
                "icon": "assets/icon.png",
                "image": "assets/cover.webp",
            },
        }
        self.assertEqual(validate_manifest(complete)["presentation"], complete["presentation"])

        for label, icon in (
            ("null", None),
            ("empty", ""),
            ("outside assets", "images/icon.png"),
            ("traversal", "assets/../icon.png"),
            ("hidden", "assets/.hidden/icon.png"),
            ("svg", "assets/icon.svg"),
        ):
            invalid = copy.deepcopy(complete)
            invalid["presentation"]["assets"]["icon"] = icon
            with self.subTest(label=label), self.assertRaises(PluginError):
                validate_manifest(invalid)

    def test_action_resources_require_exact_grants_and_adspower_capabilities(self) -> None:
        valid = plugin_manifest(
            account_mode="one_or_more",
            secrets=["email_password", "adspower_profile", "adspower_api_key"],
        )
        valid["permissions"].update(
            {"browser": True, "local_services": ["adspower"]}
        )
        valid["actions"][0]["permissions"] = {
            "secrets": ["email_password", "adspower_profile", "adspower_api_key"]
        }
        valid["actions"][0]["resources"] = {
            "account": ["email_password", "adspower_profile"],
            "settings": ["adspower_api"],
        }
        self.assertEqual(
            validate_manifest(valid)["actions"][0]["resources"],
            valid["actions"][0]["resources"],
        )

        no_browser = copy.deepcopy(valid)
        no_browser["permissions"]["browser"] = False
        with self.assertRaisesRegex(PluginError, "browser=true"):
            validate_manifest(no_browser)

        wrong_service = copy.deepcopy(valid)
        wrong_service["permissions"]["local_services"] = ["AdsPower"]
        with self.assertRaisesRegex(PluginError, "adspower"):
            validate_manifest(wrong_service)

        no_grant = copy.deepcopy(valid)
        no_grant["actions"][0]["permissions"]["secrets"].remove("email_password")
        with self.assertRaisesRegex(PluginError, "resources"):
            validate_manifest(no_grant)

        no_accounts = copy.deepcopy(valid)
        no_accounts["actions"][0]["account_mode"] = "none"
        with self.assertRaisesRegex(PluginError, "account_mode"):
            validate_manifest(no_accounts)

    def test_schema_declares_presentation_and_resource_contract(self) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "plugin.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        presentation = schema["properties"]["presentation"]
        assets = presentation["properties"]["assets"]
        resources = schema["properties"]["actions"]["items"]["properties"]["resources"]

        self.assertNotIn("presentation", schema["required"])
        self.assertEqual(
            presentation["required"], ["display_name", "description", "assets"]
        )
        self.assertEqual(assets["required"], ["icon", "image"])
        self.assertEqual(assets["properties"]["icon"]["type"], "string")
        self.assertIn(
            "email_password",
            resources["properties"]["account"]["items"]["enum"],
        )

    def test_project_runtime_referral_requires_hub_065_and_exact_parent_grants(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        valid = json.loads(
            (project_root / "examples" / "hello-soft" / "hub.plugin.json").read_text(
                encoding="utf-8"
            )
        )
        valid["id"] = "io.sprintray.referral-contract-test"
        valid["permissions"]["secrets"] = ["proxy"]
        action = copy.deepcopy(valid["actions"][1])
        action.pop("output", None)
        action["permissions"] = {"secrets": []}
        action["resources"] = {"account": [], "settings": []}
        action["referral"] = {
            "mode": "project_runtime",
            "parent_required": True,
            "parent_access": "shared_read",
            "permissions": {"secrets": ["proxy"]},
            "resources": {"account": ["proxy"]},
        }
        valid["actions"] = [action]

        validated = validate_manifest(valid)
        self.assertEqual(
            validated["actions"][0]["referral"], action["referral"]
        )

        incompatible = copy.deepcopy(valid)
        incompatible["contract_version"] = "SH-SOFTWARE-0.6/2"
        incompatible["compatibility"]["hub"] = ">=0.6.4"
        with self.assertRaisesRegex(PluginError, ">=0.6.5"):
            validate_manifest(incompatible)

        wrong_mode = copy.deepcopy(valid)
        wrong_mode["actions"][0]["referral"]["mode"] = "stored_code"
        with self.assertRaisesRegex(PluginError, "project_runtime"):
            validate_manifest(wrong_mode)

        wrong_resource = copy.deepcopy(valid)
        wrong_resource["actions"][0]["referral"]["resources"]["account"] = []
        with self.assertRaisesRegex(PluginError, "точно соответствовать"):
            validate_manifest(wrong_resource)

        manual_code = copy.deepcopy(valid)
        manual_code["actions"][0]["options"]["properties"]["referral_code"] = {
            "type": "string",
            "title": "Referral code",
            "description": "A forbidden persisted or manually supplied code.",
            "default": "",
            "maxLength": 128,
            "x-ui": {"group": "Основные параметры", "order": 10},
        }
        with self.assertRaisesRegex(PluginError, "не принимает ручной"):
            validate_manifest(manual_code)

        manual_code_without_topology = copy.deepcopy(valid)
        manual_code_without_topology["actions"][0].pop("referral", None)
        manual_code_without_topology["actions"][0]["options"]["properties"][
            "invite_code"
        ] = manual_code["actions"][0]["options"]["properties"]["referral_code"]
        with self.assertRaisesRegex(PluginError, "не принимает ручной"):
            validate_manifest(manual_code_without_topology)

        legacy_fallback = copy.deepcopy(valid)
        legacy_fallback.pop("contract_version")
        legacy_fallback["actions"][0].pop("permissions")
        with self.assertRaisesRegex(PluginError, "explicit action.permissions"):
            validate_manifest(legacy_fallback)

    def test_schema_declares_topology_referrals_and_reserved_concurrency(self) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "plugin.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        plugin_secrets = schema["properties"]["permissions"]["properties"]["secrets"]
        action = schema["properties"]["actions"]["items"]
        action_secrets = action["properties"]["permissions"]["properties"]["secrets"]
        account_resources = action["properties"]["resources"]["properties"]["account"]
        for forbidden in ("referral_code", "referrer_code"):
            self.assertNotIn(forbidden, plugin_secrets["items"]["enum"])
            self.assertNotIn(forbidden, action_secrets["items"]["enum"])
        for forbidden in ("referral_code", "referrer"):
            self.assertNotIn(forbidden, account_resources["items"]["enum"])

        referral = schema["$defs"]["referralContract"]
        self.assertEqual(referral["properties"]["mode"]["const"], "project_runtime")
        self.assertEqual(
            referral["required"],
            ["mode", "parent_required", "parent_access", "permissions", "resources"],
        )
        parent_secrets = referral["properties"]["permissions"]["properties"]["secrets"]
        self.assertIn("proxy", parent_secrets["items"]["enum"])
        self.assertNotIn("referral_code", parent_secrets["items"]["enum"])

        concurrency = schema["$defs"]["optionsSchema"]["properties"]["properties"][
            "properties"
        ]["account_concurrency"]
        self.assertEqual(concurrency["required"], [
            "type", "title", "description", "default", "minimum", "maximum", "multipleOf", "x-ui"
        ])
        self.assertEqual(concurrency["properties"]["minimum"]["const"], 1)
        self.assertEqual(concurrency["properties"]["maximum"]["maximum"], 20)
        self.assertIn("SH-SOFTWARE-0.6/3", schema["properties"]["contract_version"]["enum"])

    def test_external_write_is_nonfinancial_account_scoped_and_chainless(self) -> None:
        source = plugin_manifest(
            action_risk="external_write",
            account_mode="one_or_more",
        )

        validated = validate_manifest(source)

        self.assertEqual(validated["actions"][0]["risk"], "external_write")
        self.assertEqual(validated["permissions"]["financial_risk"], "none")
        self.assertEqual(validated["permissions"]["chains"], [])
        self.assertNotIn("confirmation_phrase", validated["actions"][0])

        invalid_scope = copy.deepcopy(source)
        invalid_scope["actions"][0]["account_mode"] = "none"
        with self.assertRaisesRegex(PluginError, "account_mode=one_or_more"):
            validate_manifest(invalid_scope)

    def test_schema_declares_external_write_without_chain_or_financial_risk(self) -> None:
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / "plugin.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        action_schema = schema["properties"]["actions"]["items"]
        risk_enum = action_schema["properties"]["risk"]["enum"]
        self.assertIn("external_write", risk_enum)

        account_scope_rule = action_schema["allOf"][1]
        self.assertIn(
            "external_write",
            account_scope_rule["if"]["properties"]["risk"]["enum"],
        )
        chain_rule = next(
            rule
            for rule in schema["allOf"]
            if rule.get("if", {})
            .get("properties", {})
            .get("actions", {})
            .get("contains", {})
            .get("properties", {})
            .get("risk", {})
            .get("enum") == ["testnet_write", "mainnet_write"]
        )
        chain_write_risks = (
            chain_rule["if"]["properties"]["actions"]["contains"]
            ["properties"]["risk"]["enum"]
        )
        self.assertEqual(chain_write_risks, ["testnet_write", "mainnet_write"])

    def test_rejects_unsupported_or_unsafe_manifest_contracts(self) -> None:
        cases: list[tuple[str, object]] = []

        missing = plugin_manifest()
        missing.pop("actions")
        cases.append(("missing required field", missing))

        incompatible = plugin_manifest()
        incompatible["compatibility"]["hub"] = ">=99.0.0"
        cases.append(("incompatible hub", incompatible))

        unsafe_requirements = plugin_manifest(requirements="../requirements.txt")
        cases.append(("unsafe requirements", unsafe_requirements))

        duplicate_secrets = plugin_manifest(secrets=["email", "email"])
        cases.append(("duplicate secrets", duplicate_secrets))

        duplicate_actions = plugin_manifest()
        duplicate_actions["actions"].append(dict(duplicate_actions["actions"][0]))
        cases.append(("duplicate actions", duplicate_actions))

        missing_confirmation = plugin_manifest(action_risk="mainnet_write")
        missing_confirmation["actions"][0].pop("confirmation_phrase")
        cases.append(("mainnet confirmation", missing_confirmation))

        for label, manifest in cases:
            with self.subTest(label=label), self.assertRaises(PluginError):
                validate_manifest(manifest)


class PluginArchiveTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="soft-hub-plugin-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.paths = HubPaths.create(self.root / "data")
        self.database = Database(self.paths)
        self.manager = PluginManager(self.database, self.paths)

    def archive(self, name: str, version: str = "1.0.0", **kwargs: object) -> Path:
        return write_plugin_archive(
            self.root / name,
            plugin_manifest(version),
            **kwargs,
        )

    @staticmethod
    def github_source(
        version: str,
        *,
        owner: str = "Example",
        repository: str = "App.PATCH",
        filename: str | None = None,
    ) -> GitHubPackage:
        asset = filename or f"app-{version}.softhub.zip"
        return GitHubPackage(
            owner=owner,
            repository=repository,
            filename=asset,
            download_url=(
                f"https://github.com/{owner}/{repository}/releases/download/"
                f"v{version}/{asset}"
            ),
            release=f"v{version}",
        )

    def append_member(
        self,
        archive: Path,
        info: zipfile.ZipInfo,
        payload: bytes = b"malicious-test-payload",
    ) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(archive, "a") as bundle:
                bundle.writestr(info, payload)

    def test_inspects_valid_archive_and_verifies_every_checksum(self) -> None:
        archive = self.archive("valid.softhub.zip")
        inspection = self.manager.inspect_archive(archive)
        self.assertEqual(inspection["manifest"]["id"], "test.plugin")
        self.assertEqual(inspection["manifest"]["version"], "1.0.0")
        self.assertEqual(inspection["file_count"], 3)
        self.assertEqual(len(inspection["archive_sha256"]), 64)
        self.assertGreater(inspection["unpacked_bytes"], 0)

        tampered = self.root / "tampered.softhub.zip"
        write_plugin_archive(
            tampered,
            plugin_manifest(),
            checksum_overrides={"plugin/main.py": "0" * 64},
        )
        with self.assertRaisesRegex(PluginError, "Контрольная сумма"):
            self.manager.inspect_archive(tampered)

        omitted = self.root / "omitted.softhub.zip"
        payload_names = set(archive_payloads(plugin_manifest())) - {"plugin/main.py"}
        write_plugin_archive(omitted, plugin_manifest(), checksum_names=payload_names)
        with self.assertRaisesRegex(PluginError, "Список контрольных сумм"):
            self.manager.inspect_archive(omitted)

    def test_presentation_assets_are_local_checked_and_format_verified(self) -> None:
        manifest = plugin_manifest()
        manifest["presentation"] = {
            "display_name": "Visual module",
            "description": "Catalog description",
            "assets": {
                "icon": "assets/icon.png",
                "image": "assets/cover.webp",
            },
        }
        icon = b"\x89PNG\r\n\x1a\n" + b"safe-icon"
        image = b"RIFF" + (4).to_bytes(4, "little") + b"WEBP" + b"safe-cover"
        archive = write_plugin_archive(
            self.root / "presentation.zip",
            manifest,
            files={"assets/icon.png": icon, "assets/cover.webp": image},
        )
        inspected = self.manager.inspect_archive(archive)
        self.assertEqual(
            inspected["manifest"]["presentation"]["assets"],
            manifest["presentation"]["assets"],
        )

        missing = write_plugin_archive(
            self.root / "presentation-missing.zip",
            manifest,
            files={"assets/icon.png": icon},
        )
        with self.assertRaisesRegex(PluginError, "image.*отсутствует"):
            self.manager.inspect_archive(missing)

        disguised = write_plugin_archive(
            self.root / "presentation-disguised.zip",
            manifest,
            files={"assets/icon.png": b"not-a-png", "assets/cover.webp": image},
        )
        with self.assertRaisesRegex(PluginError, "формату"):
            self.manager.inspect_archive(disguised)

        with mock.patch.dict(
            "soft_hub.plugins._MAX_PRESENTATION_ASSET_BYTES", {"icon": 8, "image": 8}
        ), self.assertRaisesRegex(PluginError, "размер"):
            self.manager.inspect_archive(archive)

    def test_rejects_traversal_symlinks_reserved_names_and_nonportable_paths(self) -> None:
        malicious_members = [
            ("parent traversal", regular_zip_info("../escape.py"), b"x"),
            ("absolute path", regular_zip_info("/escape.py"), b"x"),
            ("backslash", regular_zip_info("plugin\\escape.py"), b"x"),
            ("windows device", regular_zip_info("plugin/CON"), b"x"),
            ("trailing dot", regular_zip_info("plugin/trailing."), b"x"),
            ("alternate stream", regular_zip_info("plugin/name:stream"), b"x"),
            ("symlink", symlink_zip_info("plugin/link"), b"plugin/main.py"),
        ]
        for index, (label, info, payload) in enumerate(malicious_members):
            with self.subTest(label=label):
                archive = self.archive(f"unsafe-{index}.zip")
                self.append_member(archive, info, payload)
                with self.assertRaises(PluginError):
                    self.manager.inspect_archive(archive)

    def test_rejects_duplicate_case_and_file_directory_prefix_collisions(self) -> None:
        duplicate = self.archive("duplicate.zip")
        self.append_member(duplicate, regular_zip_info("plugin/main.py"), b"duplicate")
        with self.assertRaisesRegex(PluginError, "дублирующийся|конфликт"):
            self.manager.inspect_archive(duplicate)

        case_collision = self.archive("case-collision.zip")
        self.append_member(case_collision, regular_zip_info("Plugin/Main.py"), b"case")
        with self.assertRaisesRegex(PluginError, "конфликт"):
            self.manager.inspect_archive(case_collision)

        file_directory = self.archive("file-directory.zip")
        self.append_member(file_directory, directory_zip_info("plugin/main.py"), b"")
        with self.assertRaisesRegex(PluginError, "конфликт"):
            self.manager.inspect_archive(file_directory)

        prefix_collision = self.archive("prefix-collision.zip", files={"plugin": b"file"})
        with self.assertRaisesRegex(PluginError, "конфликт"):
            self.manager.inspect_archive(prefix_collision)

        directory_case_collision = self.archive("directory-case.zip")
        self.append_member(directory_case_collision, directory_zip_info("PLUGIN"), b"")
        with self.assertRaisesRegex(PluginError, "конфликт"):
            self.manager.inspect_archive(directory_case_collision)

    def test_rejects_missing_requirements_compression_bombs_and_resource_overruns(self) -> None:
        missing_requirement = write_plugin_archive(
            self.root / "missing-requirements.zip",
            plugin_manifest(requirements="requirements.txt"),
        )
        with self.assertRaisesRegex(PluginError, "requirements"):
            self.manager.inspect_archive(missing_requirement)

        compressed = write_plugin_archive(
            self.root / "compressed.zip",
            plugin_manifest(),
            files={"compressed.bin": b"0" * (1024 * 1024 + 1)},
        )
        with self.assertRaisesRegex(PluginError, "сжат"):
            self.manager.inspect_archive(compressed)

        valid = self.archive("limited.zip")
        with mock.patch("soft_hub.plugins.MAX_ARCHIVE_FILES", 3):
            with self.assertRaisesRegex(PluginError, "много файлов"):
                self.manager.inspect_archive(valid)
        with mock.patch("soft_hub.plugins.MAX_ARCHIVE_BYTES", 1):
            with self.assertRaisesRegex(PluginError, "256 MB"):
                self.manager.inspect_archive(valid)
        with mock.patch("soft_hub.plugins.MAX_UNPACKED_BYTES", 1):
            with self.assertRaisesRegex(PluginError, "512 MB"):
                self.manager.inspect_archive(valid)

    def test_packaged_venv_is_rejected_and_ready_marker_is_host_owned(self) -> None:
        packaged = self.archive("packaged-venv.zip", files={".venv/bin/python": b"fake"})
        with self.assertRaisesRegex(PluginError, r"\.venv"):
            self.manager.inspect_archive(packaged)

        manifest = plugin_manifest(requirements="requirements.txt")
        archive = write_plugin_archive(
            self.root / "requirements.zip",
            manifest,
            files={"requirements.txt": "deterministic-package==1.0.0\n"},
        )
        installed = self.manager.install(archive)
        plugin_path = Path(installed["active_path"])
        candidate = self.manager._venv_python(plugin_path)
        candidate.parent.mkdir(parents=True)
        candidate.write_text("not executed in this test", encoding="utf-8")
        self.assertIsNone(self.manager.python_for(plugin_path, "requirements.txt"))

        digest = hashlib.sha256((plugin_path / "requirements.txt").read_bytes()).hexdigest()
        marker = plugin_path / ".venv" / ".soft-hub-ready.json"
        (plugin_path / ".venv" / "pyvenv.cfg").write_text(
            f"home = {Path(sys.executable).resolve().parent}\n",
            encoding="utf-8",
        )
        marker.write_text(
            json.dumps(
                {
                    "requirements_sha256": digest,
                    "runtime_id": runtime_fingerprint(),
                }
            ),
            encoding="utf-8",
        )
        self.assertEqual(
            self.manager.python_for(plugin_path, "requirements.txt"),
            candidate,
        )

    def test_archive_rejects_embedded_credentials_even_with_valid_checksums(self) -> None:
        denied = (
            "input/private_keys.txt",
            "input/proxies.txt",
            "input/capsolver_api_key.txt",
            ".env",
            "debug/session.har",
            "state/accounts.sqlite3",
        )
        for index, member in enumerate(denied):
            with self.subTest(member=member):
                archive = write_plugin_archive(
                    self.root / f"credential-{index}.zip",
                    plugin_manifest(),
                    files={member: "synthetic-test-value"},
                )
                with self.assertRaisesRegex(PluginError, "Vault"):
                    self.manager.inspect_archive(archive)

        private_key_archive = write_plugin_archive(
            self.root / "renamed-private-key.zip",
            plugin_manifest(),
            files={
                "certs/public-looking.pem": (
                    "-----BEGIN PRIVATE KEY-----\n"  # gitleaks:allow -- synthetic fixture
                    "synthetic-private-data\n"
                    "-----END PRIVATE KEY-----\n"
                )
            },
        )
        with self.assertRaisesRegex(PluginError, "Vault"):
            self.manager.inspect_archive(private_key_archive)

    def test_failed_reprepare_invalidates_the_previous_ready_marker(self) -> None:
        manifest = plugin_manifest(requirements="requirements.txt")
        archive = write_plugin_archive(
            self.root / "reprepare.zip",
            manifest,
            files={"requirements.txt": "deterministic-package==1.0.0\n"},
        )
        installed = self.manager.install(archive)
        plugin_path = Path(installed["active_path"])
        candidate = self.manager._venv_python(plugin_path)
        candidate.parent.mkdir(parents=True)
        candidate.write_text("not executed in this test", encoding="utf-8")
        marker = plugin_path / ".venv" / ".soft-hub-ready.json"
        (plugin_path / ".venv" / "pyvenv.cfg").write_text(
            f"home = {Path(sys.executable).resolve().parent}\n",
            encoding="utf-8",
        )
        marker.write_text(
            json.dumps(
                {
                    "requirements_sha256": hashlib.sha256(
                        (plugin_path / "requirements.txt").read_bytes()
                    ).hexdigest(),
                    "runtime_id": runtime_fingerprint(),
                }
            ),
            encoding="utf-8",
        )
        self.database.execute(
            "UPDATE modules SET health='ready' WHERE id='test.plugin'"
        )

        pip_ready = mock.Mock(returncode=0, stdout="", stderr="")
        failed = mock.Mock(returncode=1, stdout="", stderr="deterministic failure")
        with mock.patch(
            "soft_hub.plugins.subprocess.run", side_effect=[pip_ready, failed]
        ), self.assertRaisesRegex(
            PluginError, "Не удалось установить"
        ):
            self.manager.prepare("test.plugin")

        self.assertFalse(marker.exists())
        self.assertEqual(self.manager.get("test.plugin")["health"], "needs_setup")

    def test_install_is_immutable_and_only_latest_version_stays_active(self) -> None:
        v1_archive = write_plugin_archive(
            self.root / "v1.zip",
            plugin_manifest("1.0.0"),
            files={"plugin/main.py": "def run(context):\n    return {'version': 1}\n"},
        )
        v2_archive = write_plugin_archive(
            self.root / "v2.zip",
            plugin_manifest("2.0.0"),
            files={"plugin/main.py": "def run(context):\n    return {'version': 2}\n"},
        )
        first = self.manager.install(v1_archive)
        time.sleep(0.003)
        second = self.manager.install(v2_archive)

        v1_path = self.paths.plugins / "test.plugin" / "1.0.0"
        v2_path = self.paths.plugins / "test.plugin" / "2.0.0"
        self.assertEqual(first["version"], "1.0.0")
        self.assertEqual(second["version"], "2.0.0")
        self.assertEqual(Path(second["active_path"]), v2_path)
        self.assertTrue(v1_path.is_dir())
        self.assertTrue(v2_path.is_dir())
        self.assertIn("version': 1", (v1_path / "plugin/main.py").read_text())
        self.assertIn("version': 2", (v2_path / "plugin/main.py").read_text())
        if os.name != "nt":
            self.assertEqual((v2_path / "plugin/main.py").stat().st_mode & 0o777, 0o600)

        with self.assertRaisesRegex(PluginError, "уже установлена"):
            self.manager.install(v2_archive)
        downgrade_archive = self.archive("local-downgrade-v1.5.zip", "1.5.0")
        with self.assertRaisesRegex(PluginError, "понижение"):
            self.manager.install(downgrade_archive)
        self.assertFalse((self.paths.plugins / "test.plugin" / "1.5.0").exists())
        current = self.manager.get("test.plugin")
        assert current is not None
        self.assertEqual(current["version"], "2.0.0")
        self.assertNotIn("versions", current)
        self.assertNotIn("can_rollback", current)
        self.assertFalse(hasattr(self.manager, "rollback"))
        active_versions = self.database.all(
            "SELECT version FROM module_versions WHERE module_id=? AND active=1",
            ("test.plugin",),
        )
        self.assertEqual(active_versions, [{"version": "2.0.0"}])

    def test_github_install_persists_normalized_identity_and_is_idempotent(self) -> None:
        archive = self.archive("github-v1.zip", "1.0.0")
        source = self.github_source("1.0.0")

        first = self.manager.install_github(archive, source)
        repeated = self.manager.install_github(archive, source)
        version = self.database.one(
            "SELECT archive_sha256 FROM module_versions WHERE module_id=? AND version=?",
            ("test.plugin", "1.0.0"),
        )
        assert version is not None

        self.assertEqual(first["id"], "test.plugin")
        self.assertEqual(repeated["version"], "1.0.0")
        self.assertEqual(
            self.manager.github_sources(),
            [
                {
                    "module_id": "test.plugin",
                    "version": "1.0.0",
                    "owner": "example",
                    "repository": "app.patch",
                    "release_tag": "v1.0.0",
                    "asset_name": "app-1.0.0.softhub.zip",
                    "asset_url": source.download_url,
                    "archive_sha256": version["archive_sha256"],
                    "active_version": "1.0.0",
                }
            ],
        )

    def test_github_install_blocks_downgrade_content_reuse_and_identity_collisions(self) -> None:
        v1 = self.archive("github-guard-v1.zip", "1.0.0")
        v2 = self.archive("github-guard-v2.zip", "2.0.0")
        self.manager.install_github(v1, self.github_source("1.0.0"))
        self.manager.install_github(v2, self.github_source("2.0.0"))

        with self.assertRaisesRegex(PluginError, "понижение"):
            self.manager.install_github(v1, self.github_source("1.0.0"))

        changed_v2 = write_plugin_archive(
            self.root / "github-guard-v2-reused.zip",
            plugin_manifest("2.0.0"),
            files={"plugin/main.py": "def run(context):\n    return {'changed': True}\n"},
        )
        with self.assertRaisesRegex(PluginError, "другим содержимым"):
            self.manager.install_github(changed_v2, self.github_source("2.0.0"))

        v3 = self.archive("github-guard-v3.zip", "3.0.0")
        with self.assertRaisesRegex(PluginError, "другому GitHub repository"):
            self.manager.install_github(
                v3,
                self.github_source("3.0.0", repository="mirror.patch"),
            )

        other_manifest = plugin_manifest("3.0.0", plugin_id="other.plugin")
        other_archive = write_plugin_archive(
            self.root / "github-other-id.zip", other_manifest
        )
        with self.assertRaisesRegex(PluginError, "другому id софта"):
            self.manager.install_github(
                other_archive,
                self.github_source("3.0.0"),
            )

    def test_github_install_never_downgrades_a_newer_local_install(self) -> None:
        local_v2 = self.archive("local-newer-v2.zip", "2.0.0")
        github_v1 = self.archive("github-older-v1.zip", "1.0.0")
        self.manager.install(local_v2)

        with self.assertRaisesRegex(PluginError, "понижение"):
            self.manager.install_github(github_v1, self.github_source("1.0.0"))

        self.assertEqual(self.manager.get("test.plugin")["version"], "2.0.0")
        self.assertEqual(self.manager.github_sources(), [])

    def test_github_install_never_reactivates_a_legacy_inactive_version(self) -> None:
        v1 = self.archive("github-reactivate-v1.zip", "1.0.0")
        v2 = self.archive("github-reactivate-v2.zip", "2.0.0")
        self.manager.install_github(v1, self.github_source("1.0.0"))
        self.manager.install_github(v2, self.github_source("2.0.0"))
        legacy_v1 = self.database.one(
            "SELECT path,manifest_json FROM module_versions WHERE module_id=? AND version=?",
            ("test.plugin", "1.0.0"),
        )
        assert legacy_v1 is not None
        self.database.execute(
            "UPDATE module_versions SET active=CASE WHEN version='1.0.0' THEN 1 ELSE 0 END "
            "WHERE module_id='test.plugin'"
        )
        self.database.execute(
            "UPDATE modules SET version='1.0.0',active_path=?,manifest_json=? WHERE id='test.plugin'",
            (legacy_v1["path"], legacy_v1["manifest_json"]),
        )

        with self.assertRaisesRegex(PluginError, "не может быть активирована повторно"):
            self.manager.install_github(v2, self.github_source("2.0.0"))

        current = self.manager.get("test.plugin")
        assert current is not None
        self.assertEqual(current["version"], "1.0.0")
        self.assertEqual(
            self.database.all(
                "SELECT version FROM module_versions WHERE module_id=? AND active=1",
                ("test.plugin",),
            ),
            [{"version": "1.0.0"}],
        )

    def test_uninstall_cleans_github_identity_with_managed_versions(self) -> None:
        archive = self.archive("github-uninstall.zip", "1.0.0")
        self.manager.install_github(archive, self.github_source("1.0.0"))
        self.assertEqual(len(self.manager.github_sources()), 1)

        self.manager.uninstall("test.plugin")

        self.assertEqual(self.manager.github_sources(), [])
        self.assertEqual(self.database.all("SELECT * FROM github_module_sources"), [])

    def test_failed_install_removes_its_own_target_and_staging_directory(self) -> None:
        archive = self.archive("db-failure.zip")
        target = self.paths.plugins / "test.plugin" / "1.0.0"
        with mock.patch.object(
            self.database,
            "transaction",
            side_effect=RuntimeError("deterministic database failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "database failure"):
                self.manager.install(archive)
        self.assertFalse(target.exists())
        self.assertEqual(list(self.paths.staging.iterdir()), [])
        self.assertIsNone(self.manager.get("test.plugin"))

    def test_install_never_deletes_a_preexisting_unowned_target(self) -> None:
        archive = self.archive("preexisting.zip")
        target = self.paths.plugins / "test.plugin" / "1.0.0"
        target.mkdir(parents=True)
        marker = target / "owner-marker.txt"
        marker.write_text("preexisting deterministic data", encoding="utf-8")

        with self.assertRaisesRegex(PluginError, "уже существует"):
            self.manager.install(archive)
        self.assertTrue(marker.is_file())
        self.assertEqual(marker.read_text(encoding="utf-8"), "preexisting deterministic data")
        self.assertIsNone(self.manager.get("test.plugin"))

    def test_uninstall_removes_every_version_and_runtime_but_preserves_history(self) -> None:
        v1 = self.archive("uninstall-v1.zip", "1.0.0")
        v2 = self.archive("uninstall-v2.zip", "2.0.0")
        self.manager.install(v1)
        time.sleep(0.003)
        self.manager.install(v2)
        plugin_root = self.paths.plugins / "test.plugin"
        for version in ("1.0.0", "2.0.0"):
            runtime = plugin_root / version / ".venv" / "bin"
            runtime.mkdir(parents=True)
            (runtime / "python").write_text("managed runtime", encoding="utf-8")

        now = utc_now()
        self.database.execute(
            "INSERT INTO runs(id,module_id,module_version,action_id,status,requested_at,finished_at) "
            "VALUES ('historical-run','test.plugin','1.0.0','run','succeeded',?,?)",
            (now, now),
        )
        self.database.execute(
            "INSERT INTO results(id,run_id,module_id,kind,status,title,created_at) "
            "VALUES ('historical-result','historical-run','test.plugin','summary','ok','Done',?)",
            (now,),
        )

        removed = self.manager.uninstall("test.plugin")

        self.assertEqual(
            removed,
            {"id": "test.plugin", "removed": True, "cleanup_pending": False},
        )
        self.assertFalse(plugin_root.exists())
        self.assertEqual(list(self.paths.staging.iterdir()), [])
        self.assertIsNone(self.manager.get("test.plugin"))
        self.assertEqual(self.manager.list(), [])
        self.assertEqual(
            self.database.all("SELECT * FROM module_versions WHERE module_id='test.plugin'"),
            [],
        )
        tombstone = self.database.one("SELECT * FROM modules WHERE id='test.plugin'")
        assert tombstone is not None
        self.assertEqual(tombstone["health"], "removed")
        self.assertEqual(tombstone["active_path"], "")
        self.assertEqual(tombstone["enabled"], 0)
        self.assertIsNotNone(self.database.one("SELECT * FROM runs WHERE id='historical-run'"))
        self.assertIsNotNone(self.database.one("SELECT * FROM results WHERE id='historical-result'"))

        reinstalled = self.manager.install(v1)
        self.assertEqual(reinstalled["version"], "1.0.0")
        self.assertTrue(reinstalled["enabled"])
        self.assertEqual(reinstalled["health"], "ready")
        self.assertTrue((plugin_root / "1.0.0").is_dir())

    def test_uninstall_refuses_active_and_unreconciled_runs(self) -> None:
        self.manager.install(self.archive("uninstall-blocked.zip"))
        now = utc_now()
        for index, status in enumerate(("queued", "starting", "running", "cancelling", "needs_attention")):
            run_id = f"blocked-{index}"
            self.database.execute(
                "INSERT INTO runs(id,module_id,module_version,action_id,status,requested_at) "
                "VALUES (?,'test.plugin','1.0.0','run',?,?)",
                (run_id, status, now),
            )
            with self.subTest(status=status), self.assertRaisesRegex(
                PluginError,
                "активный запуск|внешнюю сверку",
            ):
                self.manager.uninstall("test.plugin")
            self.assertIsNotNone(self.manager.get("test.plugin"))
            self.assertTrue((self.paths.plugins / "test.plugin" / "1.0.0").is_dir())
            self.database.execute("DELETE FROM runs WHERE id=?", (run_id,))

    def test_uninstall_never_follows_corrupt_or_external_database_paths(self) -> None:
        self.manager.install(self.archive("uninstall-corrupt.zip"))
        outside = self.root / "outside-runtime"
        outside.mkdir()
        marker = outside / "must-survive.txt"
        marker.write_text("outside Hub plugin storage", encoding="utf-8")
        self.database.execute(
            "UPDATE modules SET active_path=? WHERE id='test.plugin'",
            (str(outside),),
        )

        with self.assertRaisesRegex(PluginError, "Пути плагина повреждены"):
            self.manager.uninstall("test.plugin")

        self.assertEqual(marker.read_text(encoding="utf-8"), "outside Hub plugin storage")
        self.assertTrue((self.paths.plugins / "test.plugin" / "1.0.0").is_dir())
        self.assertEqual(list(self.paths.staging.iterdir()), [])

    def test_uninstall_rejects_a_symlinked_plugins_root_without_touching_target(self) -> None:
        self.manager.install(self.archive("uninstall-root-symlink.zip"))
        outside = self.root / "outside-plugin-root"
        os.replace(self.paths.plugins, outside)
        self.paths.plugins.symlink_to(outside, target_is_directory=True)
        marker = outside / "test.plugin" / "1.0.0" / "must-survive.txt"
        marker.write_text("outside target", encoding="utf-8")

        with self.assertRaisesRegex(PluginError, "Корневой каталог plugins"):
            self.manager.uninstall("test.plugin")

        self.assertTrue(self.paths.plugins.is_symlink())
        self.assertEqual(marker.read_text(encoding="utf-8"), "outside target")
        self.assertIsNotNone(self.manager.get("test.plugin"))


if __name__ == "__main__":
    unittest.main()
