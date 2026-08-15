from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from soft_hub.config import HubPaths, runtime_fingerprint
from soft_hub.database import Database, utc_now
from soft_hub.plugins import PluginManager
from soft_hub.runner import (
    IdempotencyConflictError,
    Redactor,
    RunError,
    RunManager,
    _collect_secret_values,
)
from soft_hub.vault import ImportRecord, Vault, VaultError
from tests.support import (
    TEST_MASTER_PASSWORD,
    TEST_PRIVATE_KEY_A,
    TEST_PRIVATE_KEY_B,
    plugin_manifest,
    wait_until,
    write_plugin_archive,
)


TERMINAL_STATUSES = {"succeeded", "failed", "cancelled"}
TEST_JWT = "eyJabcdefghijklm.NOPQRSTUVWXYZ_123456.qwertyuiop12345"


def action_scoped_manifest(
    plugin_id: str, action_grants: dict[str, list[str]]
) -> dict[str, object]:
    union = list(
        dict.fromkeys(
            secret for grants in action_grants.values() for secret in grants
        )
    )
    manifest = plugin_manifest(
        plugin_id=plugin_id,
        account_mode="one_or_more",
        secrets=union,
    )
    base = manifest["actions"][0]
    manifest["actions"] = [
        {
            **base,
            "id": action_id,
            "name": action_id.replace("_", " ").title(),
            "permissions": {"secrets": list(grants)},
        }
        for action_id, grants in action_grants.items()
    ]
    return manifest


class RedactorTests(unittest.TestCase):
    def test_secret_named_one_off_option_joins_exact_redaction(self) -> None:
        referral = "ONE-OFF-REFERRAL-7751"
        ordinary = "visible ordinary note"
        redactor = Redactor(
            _collect_secret_values(
                [],
                {},
                {"manual_referral_code": referral, "note": ordinary},
            )
        )
        self.assertNotIn(referral, redactor.text(f"raw {referral}"))
        self.assertIn(ordinary, redactor.text(ordinary))

    def test_redacts_exact_secrets_private_keys_tokens_and_proxy_shapes(self) -> None:
        explicit = "deterministic-password"
        redactor = Redactor([explicit, "abc"])
        source = (
            f"password={explicit} key={'44' * 32} token={TEST_JWT} "
            "proxy=http://user:pass@proxy.test:8080 route=proxy2.test:8081:user2:pass2"
        )
        redacted = redactor.text(source)
        for value in (explicit, "44" * 32, TEST_JWT, "user:pass", "user2:pass2"):
            self.assertNotIn(value, redacted)
        self.assertIn("[REDACTED]", redacted)
        self.assertIn("[REDACTED_KEY]", redacted)
        self.assertIn("[REDACTED_TOKEN]", redacted)
        self.assertIn("[REDACTED_PROXY]", redacted)
        self.assertIn("abc", redactor.text("abc"), "Secrets shorter than four chars are ignored")

    def test_recursively_redacts_keys_and_values_with_bounded_output(self) -> None:
        secret = "nested-deterministic-secret"
        redactor = Redactor([secret])
        nested: object = secret
        for _ in range(12):
            nested = {f"key-{secret}": [nested]}
        value = redactor.value(
            {
                f"field-{secret}": nested,
                "many": list(range(600)),
                "number": 42,
                "flag": True,
            }
        )
        encoded = json.dumps(value, ensure_ascii=False)
        self.assertNotIn(secret, encoded)
        self.assertIn("[REDACTED]", encoded)
        self.assertIn("[TRUNCATED]", encoded)
        self.assertEqual(len(value["many"]), 500)
        self.assertEqual(redactor.text("x" * 20_000), "x" * 16_000)

    def test_redacts_secret_named_fields_headers_emails_and_generic_tokens(self) -> None:
        password = "mail-password-that-must-not-leak"
        api_token = "ApiTokenValueWithUpperLower1234567890"
        cookie = "session=browser-cookie-that-must-not-leak"
        authorization = "Bearer authorization-token-that-must-not-leak"
        email = "private.person@example.test"
        short_referral = "abc"
        redactor = Redactor()
        clean = redactor.value(
            {
                "emailPassword": password,
                "api_token": api_token,
                "headers": {
                    "Authorization": authorization,
                    "Cookie": cookie,
                },
                "message": (
                    f"email={email} password={password}\n"
                    f"Authorization: {authorization}\nCookie: {cookie}"
                ),
                "bare_high_entropy_value": api_token,
                "referral_code": short_referral,
                "externalReferrerCode": "short-external-code",
            }
        )
        encoded = json.dumps(clean, ensure_ascii=False)
        for secret in (
            password,
            api_token,
            cookie,
            authorization,
            email,
            short_referral,
            "short-external-code",
        ):
            self.assertNotIn(secret, encoded)
        self.assertIn("[REDACTED]", encoded)
        self.assertIn("[REDACTED_AUTHORIZATION]", encoded)
        self.assertIn("[REDACTED_COOKIE]", encoded)
        self.assertIn("[REDACTED_EMAIL]", encoded)


class RunnerIntegrationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="soft-hub-runner-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.paths = HubPaths.create(self.root / "data")
        self.database = Database(self.paths)
        self.vault = Vault(self.database)
        self.plugins = PluginManager(self.database, self.paths)
        self.runs = RunManager(self.database, self.paths, self.plugins, self.vault)
        self.addCleanup(self.runs.shutdown)

    def install_plugin(self, source: str, manifest: dict[str, object]) -> dict[str, object]:
        archive = write_plugin_archive(
            self.root / f"{manifest['id']}-{manifest['version']}.zip",
            manifest,
            files={"plugin/main.py": source},
        )
        return self.plugins.install(archive)

    def install_plugin_with_requirements(
        self, source: str, manifest: dict[str, object], requirements: str
    ) -> dict[str, object]:
        archive = write_plugin_archive(
            self.root / f"{manifest['id']}-{manifest['version']}.zip",
            manifest,
            files={
                "plugin/main.py": source,
                "requirements.txt": requirements,
            },
        )
        return self.plugins.install(archive)

    def mark_plugin_runtime_ready(self, installed: dict[str, object]) -> Path:
        plugin_path = Path(str(installed["active_path"]))
        candidate = self.plugins._venv_python(plugin_path)
        candidate.parent.mkdir(parents=True)
        candidate.write_text("test interpreter placeholder", encoding="utf-8")
        environment = plugin_path / ".venv"
        (environment / "pyvenv.cfg").write_text(
            f"home = {Path(sys.executable).resolve().parent}\n",
            encoding="utf-8",
        )
        (environment / ".soft-hub-ready.json").write_text(
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
        return candidate

    def wait_for_terminal(self, run_id: str) -> dict[str, object]:
        def current() -> dict[str, object] | None:
            run = self.runs.get(run_id)
            return run if run and run["status"] in TERMINAL_STATUSES else None

        return wait_until(current, timeout=12.0)

    def import_lifecycle_account(self) -> str:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "lifecycle-bridge.test:28080:user:pass",
                    "lifecycle-bridge@example.test",
                    label="Lifecycle Bridge Account",
                )
            ]
        )
        return str(self.vault.list_accounts()[0]["id"])

    @staticmethod
    def legacy_sekai_manifest() -> dict[str, object]:
        manifest = plugin_manifest(
            plugin_id="io.sprintray.sekai-testnet",
            version="1.0.0",
            account_mode="one_or_more",
            secrets=[],
        )
        manifest["actions"][0]["id"] = "run_cycle"  # type: ignore[index]
        return manifest

    def test_completion_boundary_follows_worker_and_slot_finalization(self) -> None:
        manifest = plugin_manifest(plugin_id="runner.finalization-boundary")
        self.install_plugin('def run(context):\n    return {"ok": True}\n', manifest)
        release_entered = threading.Event()
        allow_release = threading.Event()
        self.addCleanup(allow_release.set)
        original_release = self.runs._release_leases

        def delayed_release(run_id: str) -> None:
            release_entered.set()
            if not allow_release.wait(timeout=5):
                raise RuntimeError("test did not release finalization gate")
            original_release(run_id)

        with mock.patch.object(self.runs, "_release_leases", side_effect=delayed_release):
            started = self.runs.start("runner.finalization-boundary", "run", [])
            run_id = str(started["id"])
            completed = self.wait_for_terminal(run_id)
            self.assertEqual(completed["status"], "succeeded")
            self.assertTrue(release_entered.wait(timeout=3))
            with self.runs._lock:
                self.assertIn(
                    run_id,
                    self.runs._threads,
                    "A terminal DB status must not publish worker completion before finalization",
                )
            allow_release.set()
            wait_until(lambda: run_id not in self.runs._threads, timeout=3)

        self.assertEqual(self.database.all("SELECT * FROM account_leases WHERE run_id=?", (run_id,)), [])

    def test_jsonl_run_persists_results_progress_and_redacts_all_secret_surfaces(self) -> None:
        private_key = TEST_PRIVATE_KEY_A
        proxy = "runnerproxy.test:28080:runner-user:runner-pass"
        email = "runner@example.test"
        email_password = "runner-mail-pass"
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    private_key=private_key,
                    proxy=proxy,
                    email=email,
                    email_password=email_password,
                    label="Runner Account",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = plugin_manifest(
            plugin_id="runner.redaction",
            account_mode="one_or_more",
            secrets=["evm_private_key", "proxy", "email", "email_password"],
        )
        source = f'''def run(context):
    account = context.accounts[0]
    private_key = account.secret("evm_private_key")
    proxy = account.secret("proxy")
    email = account.secret("email")
    password = account.secret("email_password")
    context.log("key=" + private_key + " proxy=" + proxy + " token={TEST_JWT}")
    context.progress(0.75, message="email=" + email, data={{"password": password}})
    context.progress(0.25, message="must not lower progress")
    context.result(
        "result=" + password,
        account_id=account.id,
        data={{"private_key": private_key, "proxy": proxy, "email": email}},
    )
    print("stderr=" + private_key)
    return {{"ok": True, "private_key": private_key, "proxy": proxy}}
'''
        self.install_plugin(source, manifest)
        started = self.runs.start("runner.redaction", "run", [account_id])
        completed = self.wait_for_terminal(str(started["id"]))

        self.assertEqual(completed["status"], "succeeded")
        self.assertEqual(completed["progress"], 0.0)
        self.assertTrue(completed["summary"]["ok"])
        events = self.runs.events(str(started["id"]))
        self.assertTrue({"started", "log", "progress", "result", "completed"}.issubset(
            {event["event_type"] for event in events}
        ))
        self.assertTrue(any(event["event_type"] == "stderr" for event in events))
        self.assertEqual(
            [event["data"]["value"] for event in events if event["event_type"] == "progress"],
            [0.75, 0.25],
        )
        results = self.runs.results()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["account_id"], account_id)

        persisted = json.dumps(
            {"run": completed, "events": events, "results": results},
            ensure_ascii=False,
            default=str,
        )
        for secret in (private_key, private_key[2:], proxy, email, email_password, TEST_JWT):
            self.assertNotIn(secret, persisted)
        self.assertIn("[REDACTED]", persisted)
        self.assertIn("[REDACTED_TOKEN]", persisted)

        scratch = self.paths.runs / str(started["id"]) / "scratch"
        self.assertTrue(scratch.is_dir())
        self.assertEqual(list(scratch.iterdir()), [])

    def test_account_table_output_is_snapshotted_validated_and_reported_from_lifecycle(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "report-snapshot.test:28080:user:pass",
                    "report-snapshot@example.test",
                    label="Report Snapshot",
                )
            ]
        )
        account = self.vault.list_accounts()[0]
        manifest = plugin_manifest(
            plugin_id="runner.account-table-report",
            account_mode="one_or_more",
            secrets=[],
        )
        output = {
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
        manifest["compatibility"]["hub"] = ">=0.6.8"
        manifest["actions"][0]["output"] = output
        source = '''def run(context):
    for account in context.accounts:
        context.result(
            "Snapshot ready",
            kind="account_snapshot",
            status="succeeded",
            account_id=account.id,
            data={"points": 7, "balance": "12.50", "eligible": True, "ignored": "private renderer field"},
        )
        context.account_state(
            account.id,
            status="succeeded",
            stage="completed",
            progress=1,
            message="Done",
        )
    return {"ok": True}
'''
        self.install_plugin(source, manifest)
        started = self.runs.start(
            "runner.account-table-report", "run", [str(account["id"])]
        )
        run_id = str(started["id"])
        self.assertEqual(self.wait_for_terminal(run_id)["status"], "succeeded")
        wait_until(lambda: run_id not in self.runs._threads, timeout=3)

        stored_run = self.database.one(
            "SELECT output_schema_json FROM runs WHERE id=?", (run_id,)
        )
        self.assertEqual(json.loads(stored_run["output_schema_json"]), output)
        stored_account = self.database.one(
            "SELECT account_label,account_address FROM run_account_states "
            "WHERE run_id=? AND account_id=?",
            (run_id, account["id"]),
        )
        self.assertEqual(stored_account["account_label"], "Report Snapshot")
        self.assertEqual(stored_account["account_address"], account["evm_address"])

        self.database.execute(
            "INSERT INTO run_account_states(run_id,account_id,account_label,account_address,"
            "status,stage,progress,last_message,updated_at) VALUES "
            "(?,?,?,?,'failed','parser_failed',1,'No primary result',?)",
            (
                run_id,
                "missing-result-account",
                "Report Without Result",
                "0xmissing",
                utc_now(),
            ),
        )

        self.assertTrue(self.vault.delete_account(str(account["id"])))
        reports = self.runs.result_reports(
            module_id="runner.account-table-report", action_id="run", limit=10
        )
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["run_id"], run_id)
        self.assertEqual(reports[0]["output"], output)
        self.assertEqual(reports[0]["total"], 2)
        self.assertEqual(reports[0]["counts"]["succeeded"], 1)
        self.assertEqual(reports[0]["counts"]["failed"], 1)
        self.assertEqual(
            self.runs.result_reports(module_id="runner.other-module"), []
        )

        report = self.runs.result_report(run_id, limit=10)
        self.assertEqual(report["report"], reports[0])
        self.assertEqual(report["total"], 2)
        self.assertEqual(report["result_count"], 1)
        self.assertFalse(report["truncated"])
        self.assertEqual(
            report["aggregates"],
            {
                "points": {"aggregate": "sum", "value": 7, "count": 1},
                "balance": {"aggregate": "avg", "value": "12.50", "count": 1},
            },
        )
        self.assertEqual(len(report["rows"]), 2)
        row = next(
            item for item in report["rows"] if item["account_id"] == account["id"]
        )
        self.assertEqual(row["account_id"], account["id"])
        self.assertEqual(row["account_label"], "Report Snapshot")
        self.assertEqual(row["account_address"], account["evm_address"])
        self.assertEqual(row["status"], "succeeded")
        self.assertEqual(row["stage"], "completed")
        self.assertEqual(row["result_status"], "succeeded")
        self.assertEqual(row["title"], "Snapshot ready")
        self.assertEqual(
            row["data"],
            {"points": 7, "balance": "12.50", "eligible": True},
        )
        self.assertNotIn("ignored", row["data"])
        missing = next(
            item
            for item in report["rows"]
            if item["account_id"] == "missing-result-account"
        )
        self.assertEqual(missing["account_address"], "0xmissing")
        self.assertEqual(missing["status"], "failed")
        self.assertIsNone(missing["result_status"])
        self.assertIsNone(missing["title"])
        self.assertEqual(missing["data"], {})

        duplicate = {
            "protocol": "soft-hub-jsonl/1",
            "type": "result",
            "account_id": account["id"],
            "message": "Duplicate",
            "data": {
                "kind": "account_snapshot",
                "status": "succeeded",
                "payload": {"points": 8, "balance": "13.00", "eligible": False},
            },
        }
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.runs._handle_frame(
                run_id, "runner.account-table-report", duplicate, Redactor()
            )
        malformed = json.loads(json.dumps(duplicate))
        malformed["data"]["payload"]["points"] = True
        with self.assertRaisesRegex(ValueError, "column points"):
            self.runs._handle_frame(
                run_id, "runner.account-table-report", malformed, Redactor()
            )
        unsafe_integer = json.loads(json.dumps(duplicate))
        unsafe_integer["data"]["payload"]["points"] = 9_007_199_254_740_992
        with self.assertRaisesRegex(ValueError, "column points"):
            self.runs._handle_frame(
                run_id, "runner.account-table-report", unsafe_integer, Redactor()
            )
        self.assertEqual(
            self.database.one(
                "SELECT COUNT(*) AS count FROM results WHERE run_id=? AND kind=?",
                (run_id, "account_snapshot"),
            ),
            {"count": 1},
        )

    def test_catalog_snapshot_survives_module_update_and_uninstall(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "catalog-snapshot.test:28080:user:pass",
                    "catalog-snapshot@example.test",
                    label="Catalog Snapshot",
                )
            ]
        )
        account = self.vault.list_accounts()[0]
        v1 = plugin_manifest(
            version="1.0.0",
            plugin_id="runner.catalog-snapshot",
            action_risk="testnet_write",
            account_mode="one_or_more",
            chains=[11155111],
        )
        v1["compatibility"]["hub"] = ">=0.6.8"
        v1["actions"][0]["output"] = {
            "mode": "account_table",
            "title": "Catalog history",
            "primary_kind": "catalog_snapshot",
            "columns": [
                {
                    "key": "points",
                    "title": "Points",
                    "type": "integer",
                    "aggregate": "sum",
                }
            ],
        }
        source = '''def run(context):
    for account in context.accounts:
        context.result(
            "Catalog snapshot",
            kind="catalog_snapshot",
            status="succeeded",
            account_id=account.id,
            data={"points": 1},
        )
        context.account_state(
            account.id,
            status="succeeded",
            stage="completed",
            progress=1,
            message="Done",
        )
    return {"ok": True}
'''
        self.install_plugin(source, v1)
        started = self.runs.start(
            "runner.catalog-snapshot",
            "run",
            [str(account["id"])],
            acknowledgement="TESTNET",
        )
        run_id = str(started["id"])
        self.assertEqual(self.wait_for_terminal(run_id)["status"], "succeeded")
        wait_until(lambda: run_id not in self.runs._threads, timeout=3)

        v2 = plugin_manifest(
            version="2.0.0",
            plugin_id="runner.catalog-snapshot",
        )
        self.install_plugin('def run(context):\n    return {"ok": True}\n', v2)
        self.assertEqual(
            self.runs.get(run_id)["catalog_sections"],
            ["testnet"],
        )

        removed = self.runs.uninstall_module("runner.catalog-snapshot")
        self.assertTrue(removed["removed"])
        self.assertEqual(
            self.runs.get(run_id)["catalog_sections"],
            ["testnet"],
        )
        historical_results = [
            result for result in self.runs.results() if result["run_id"] == run_id
        ]
        self.assertEqual(len(historical_results), 1)
        self.assertEqual(historical_results[0]["catalog_sections"], ["testnet"])
        reports = self.runs.result_reports(run_id=run_id)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["catalog_sections"], ["testnet"])
        self.assertEqual(
            json.loads(
                self.database.one(
                    "SELECT catalog_sections_json FROM runs WHERE id=?", (run_id,)
                )["catalog_sections_json"]
            ),
            ["testnet"],
        )
    def test_integer_aggregates_never_serialize_as_unsafe_json_numbers(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "aggregate-a.test:28080:user:pass",
                    "aggregate-a@example.test",
                    label="Aggregate A",
                ),
                ImportRecord(
                    TEST_PRIVATE_KEY_B,
                    "aggregate-b.test:28080:user:pass",
                    "aggregate-b@example.test",
                    label="Aggregate B",
                ),
            ]
        )
        manifest = plugin_manifest(
            plugin_id="runner.safe-integer-aggregates",
            account_mode="one_or_more",
            secrets=[],
        )
        manifest["compatibility"]["hub"] = ">=0.6.8"
        manifest["actions"][0]["output"] = {
            "mode": "account_table",
            "title": "Safe integer aggregates",
            "primary_kind": "integer_snapshot",
            "columns": [
                {
                    "key": "sum_value",
                    "title": "Sum",
                    "type": "integer",
                    "aggregate": "sum",
                },
                {
                    "key": "avg_value",
                    "title": "Average",
                    "type": "integer",
                    "aggregate": "avg",
                },
                {
                    "key": "min_value",
                    "title": "Minimum",
                    "type": "integer",
                    "aggregate": "min",
                },
                {
                    "key": "max_value",
                    "title": "Maximum",
                    "type": "integer",
                    "aggregate": "max",
                },
            ],
        }
        source = '''def run(context):
    values = [9007199254740991, 9007199254740990]
    for account, value in zip(context.accounts, values):
        context.result(
            "Integer snapshot",
            kind="integer_snapshot",
            status="succeeded",
            account_id=account.id,
            data={
                "sum_value": value,
                "avg_value": value,
                "min_value": value,
                "max_value": value,
            },
        )
        context.account_state(
            account.id,
            status="succeeded",
            stage="completed",
            progress=1,
            message="Done",
        )
    return {"ok": True}
'''
        self.install_plugin(source, manifest)
        account_ids = [str(account["id"]) for account in self.vault.list_accounts()]
        started = self.runs.start(
            "runner.safe-integer-aggregates", "run", account_ids
        )
        run_id = str(started["id"])
        self.assertEqual(self.wait_for_terminal(run_id)["status"], "succeeded")
        wait_until(lambda: run_id not in self.runs._threads, timeout=3)

        serialized = json.loads(
            json.dumps(self.runs.result_report(run_id), ensure_ascii=False)
        )
        self.assertEqual(
            serialized["aggregates"],
            {
                "sum_value": {
                    "aggregate": "sum",
                    "value": "18014398509481981",
                    "count": 2,
                },
                "avg_value": {
                    "aggregate": "avg",
                    "value": "9007199254740990.5",
                    "count": 2,
                },
                "min_value": {
                    "aggregate": "min",
                    "value": 9007199254740990,
                    "count": 2,
                },
                "max_value": {
                    "aggregate": "max",
                    "value": 9007199254740991,
                    "count": 2,
                },
            },
        )
        for aggregate in serialized["aggregates"].values():
            value = aggregate["value"]
            if isinstance(value, int):
                self.assertLessEqual(abs(value), 9_007_199_254_740_991)

    def test_technical_log_export_has_a_hard_byte_bound_and_explicit_footer(self) -> None:
        manifest = plugin_manifest(plugin_id="runner.log-bound")
        self.install_plugin("def run(context):\n    return {'ok': True}\n", manifest)
        started = self.runs.start("runner.log-bound", "run", [])
        run_id = str(started["id"])
        self.wait_for_terminal(run_id)
        for index in range(12):
            self.database.execute(
                "INSERT INTO run_events(run_id,created_at,level,event_type,message,data_json) "
                "VALUES (?,?,?,?,?,?)",
                (
                    run_id,
                    utc_now(),
                    "debug",
                    "legacy",
                    f"event-{index}-" + "x" * 900,
                    "{}",
                ),
            )

        with mock.patch("soft_hub.runner._MAX_LOG_EXPORT_BYTES", 4096):
            exported = self.runs.technical_log(run_id)

        self.assertLessEqual(len(exported), 4096)
        records = [json.loads(line) for line in exported.decode("utf-8").splitlines()]
        self.assertEqual(records[-1]["record"], "end")
        self.assertTrue(records[-1]["truncated"])
        self.assertGreater(records[-1]["omitted_events"], 0)

    def test_technical_log_contains_the_complete_run_across_all_account_labels(self) -> None:
        manifest = plugin_manifest(plugin_id="runner.full-run-log")
        self.install_plugin("def run(context):\n    return {'ok': True}\n", manifest)
        run_id = "00000000-0000-0000-0000-000000000061"
        other_run_id = "00000000-0000-0000-0000-000000000062"
        now = utc_now()
        with self.database.transaction() as connection:
            connection.executemany(
                "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,"
                "account_count,requested_at,started_at,finished_at) VALUES "
                "(?,'runner.full-run-log','1.0.0','run','succeeded',1,?,?,?,?)",
                (
                    (run_id, 2, now, now, now),
                    (other_run_id, 1, now, now, now),
                ),
            )
            connection.executemany(
                "INSERT INTO run_account_states(run_id,account_id,account_label,status,"
                "stage,progress,last_message,updated_at) VALUES "
                "(?,?,?,'succeeded','completed',1,'',?)",
                (
                    (run_id, "wallet-01", "Wallet 01", now),
                    (run_id, "wallet-02", "Wallet 02", now),
                    (other_run_id, "wallet-other", "Other Wallet", now),
                ),
            )
            connection.executemany(
                "INSERT INTO run_events(run_id,created_at,level,event_type,message,"
                "account_id,data_json) VALUES (?,?,'info',?,?,?,'{}')",
                (
                    (run_id, now, "account_started", "First account", "wallet-01"),
                    (run_id, now, "account_completed", "Second account", "wallet-02"),
                    (run_id, now, "run_summary", "All accounts completed", None),
                    (other_run_id, now, "foreign_event", "Must stay isolated", "wallet-other"),
                ),
            )

        exported = self.runs.technical_log(run_id)
        records = [json.loads(line) for line in exported.decode("utf-8").splitlines()]
        header = records[0]
        events = [record for record in records if record.get("record") == "event"]

        self.assertEqual(header["scope"], "full_run_all_accounts")
        self.assertEqual(header["run"]["account_count"], 2)
        self.assertEqual(
            [event["event_type"] for event in events],
            ["account_started", "account_completed", "run_summary"],
        )
        self.assertEqual(
            {
                event["account_id"]: event["account_label"]
                for event in events
                if event["account_id"] is not None
            },
            {"wallet-01": "Wallet 01", "wallet-02": "Wallet 02"},
        )
        self.assertIsNone(events[-1]["account_id"])
        self.assertIsNone(events[-1]["account_label"])
        self.assertNotIn("foreign_event", {event["event_type"] for event in events})
        self.assertEqual(records[-1]["omitted_events"], 0)
        self.assertFalse(records[-1]["truncated"])

    def test_three_malformed_jsonl_frames_fail_and_terminate_plugin(self) -> None:
        manifest = plugin_manifest(plugin_id="runner.malformed")
        source = '''import sys
import time

def run(context):
    for line in ("not-json", "[]", "{\\"protocol\\":\\"wrong\\",\\"type\\":\\"log\\"}"):
        sys.__stdout__.write(line + "\\n")
        sys.__stdout__.flush()
    time.sleep(5)
    return {"unexpected": True}
'''
        self.install_plugin(source, manifest)
        started = self.runs.start("runner.malformed", "run", [])
        completed = self.wait_for_terminal(str(started["id"]))
        self.assertEqual(completed["status"], "failed")
        self.assertIn("protocol_error", completed["error"])
        protocol_events = [
            event for event in self.runs.events(str(started["id"]))
            if event["event_type"] == "protocol"
        ]
        self.assertEqual(len(protocol_events), 3)
        wait_until(lambda: str(started["id"]) not in self.runs._processes, timeout=3.0)

    def test_run_progress_rejects_out_of_range_values_and_regressions(self) -> None:
        manifest = plugin_manifest(plugin_id="runner.progress")
        self.install_plugin("def run(context):\n    return {}\n", manifest)
        run_id = "00000000-0000-0000-0000-000000000001"
        self.database.execute(
            "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,account_count,requested_at) "
            "VALUES (?,?,?,'run','running',0,0,?)",
            (run_id, "runner.progress", "1.0.0", utc_now()),
        )
        redactor = Redactor()
        terminal = self.runs._handle_frame(
            run_id,
            "runner.progress",
            {
                "protocol": "soft-hub-jsonl/1",
                "type": "progress",
                "data": {"value": 0.8},
            },
            redactor,
        )
        self.assertIsNone(terminal)
        for value in (0.2, 7.0, -4.0, float("nan")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.runs._handle_frame(
                    run_id,
                    "runner.progress",
                    {
                        "protocol": "soft-hub-jsonl/1",
                        "type": "progress",
                        "data": {"value": value},
                    },
                    redactor,
                )
        self.assertEqual(
            self.database.one("SELECT progress FROM runs WHERE id=?", (run_id,))["progress"],
            0.8,
        )

    def test_account_state_is_authoritative_and_late_logs_cannot_reopen_it(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "lifecycle.test:28080:user:pass",
                    "lifecycle@example.test",
                    label="Lifecycle Account",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = plugin_manifest(
            plugin_id="runner.account-state",
            account_mode="one_or_more",
            secrets=[],
        )
        self.install_plugin(
            "def run(context):\n"
            "    account = context.accounts[0]\n"
            "    context.account_state(account.id, status='running', stage='preflight', "
            "progress=0.2, message='Проверяем аккаунт')\n"
            "    context.log('Промежуточный лог', account_id=account.id)\n"
            "    context.account_state(account.id, status='succeeded', stage='completed', "
            "progress=0.9, message='Аккаунт готов')\n"
            "    context.log('Поздний технический лог', account_id=account.id)\n"
            "    return {'ok': True}\n",
            manifest,
        )

        started = self.runs.start("runner.account-state", "run", [account_id])
        run_id = str(started["id"])
        final = self.wait_for_terminal(run_id)
        self.assertEqual(final["status"], "succeeded")
        states = self.runs.account_states(run_id)
        self.assertEqual(len(states), 1)
        self.assertEqual(
            {
                "status": states[0]["status"],
                "stage": states[0]["stage"],
                "progress": states[0]["progress"],
                "last_message": states[0]["last_message"],
                "module_id": states[0]["module_id"],
                "run_id": states[0]["run_id"],
            },
            {
                "status": "succeeded",
                "stage": "completed",
                "progress": 1.0,
                "last_message": "Аккаунт готов",
                "module_id": "runner.account-state",
                "run_id": run_id,
            },
        )
        self.assertEqual(
            [
                event["data"]["status"]
                for event in self.runs.events(run_id)
                if event["event_type"] == "account_state"
            ],
            ["running", "succeeded"],
        )

    def test_completed_process_preserves_last_honest_progress_for_failed_account(self) -> None:
        account_id = self.import_lifecycle_account()
        manifest = plugin_manifest(
            plugin_id="runner.failed-progress",
            account_mode="one_or_more",
            secrets=[],
        )
        self.install_plugin(
            "def run(context):\n"
            "    account = context.accounts[0]\n"
            "    context.account_state(account.id, status='running', stage='request_sent', "
            "progress=0.35, message='Request sent')\n"
            "    context.account_state(account.id, status='failed', stage='known_failure', "
            "progress=0.99, message='Known failure')\n"
            "    return {'failed': 1}\n",
            manifest,
        )

        started = self.runs.start("runner.failed-progress", "run", [account_id])
        run_id = str(started["id"])
        final = self.wait_for_terminal(run_id)
        state = self.runs.account_states(run_id)[0]

        self.assertEqual(final["status"], "succeeded")
        self.assertEqual(final["progress"], 0.35)
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["progress"], 0.35)

    def test_successful_legacy_plugin_without_terminal_account_state_is_unknown(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "legacy-state.test:28080:user:pass",
                    "legacy-state@example.test",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = plugin_manifest(
            plugin_id="runner.legacy-account-state",
            account_mode="one_or_more",
            secrets=[],
        )
        self.install_plugin(
            "def run(context):\n"
            "    context.log('Looks successful', account_id=context.accounts[0].id)\n"
            "    return {'ok': True}\n",
            manifest,
        )

        started = self.runs.start(
            "runner.legacy-account-state", "run", [account_id]
        )
        run_id = str(started["id"])
        final = self.wait_for_terminal(run_id)
        self.assertEqual(final["status"], "succeeded")
        state = self.runs.account_states(run_id)[0]
        self.assertEqual(state["status"], "unknown")
        self.assertEqual(state["stage"], "unreported")
        self.assertEqual(state["last_message"], "Looks successful")

    def test_legacy_bridge_recovers_one_valid_sekai_account_summary(self) -> None:
        account_id = self.import_lifecycle_account()
        self.install_plugin(
            "def run(context):\n"
            "    account = context.accounts[0]\n"
            "    context.result('Sekai account complete', kind='account_summary', "
            "status='succeeded', account_id=account.id)\n"
            "    return {'ok': True}\n",
            self.legacy_sekai_manifest(),
        )

        started = self.runs.start(
            "io.sprintray.sekai-testnet", "run_cycle", [account_id]
        )
        run_id = str(started["id"])
        final = self.wait_for_terminal(run_id)
        state = self.runs.account_states(run_id)[0]

        self.assertEqual(final["status"], "succeeded")
        self.assertEqual(state["status"], "succeeded")
        self.assertEqual(state["stage"], "completed")
        self.assertEqual(state["progress"], 1.0)
        recovered = [
            event
            for event in self.runs.events(run_id)
            if event["event_type"] == "account_state"
            and event["data"].get("source") == "legacy_account_summary"
        ]
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["account_id"], account_id)
        self.assertEqual(recovered[0]["data"]["status"], "succeeded")

    def test_legacy_bridge_does_not_parse_successful_log_text(self) -> None:
        account_id = self.import_lifecycle_account()
        self.install_plugin(
            "def run(context):\n"
            "    context.log('Everything completed successfully', "
            "account_id=context.accounts[0].id)\n"
            "    return {'ok': True}\n",
            self.legacy_sekai_manifest(),
        )

        started = self.runs.start(
            "io.sprintray.sekai-testnet", "run_cycle", [account_id]
        )
        state = self.runs.account_states(
            str(self.wait_for_terminal(str(started["id"]))["id"])
        )[0]

        self.assertEqual(state["status"], "unknown")
        self.assertEqual(state["stage"], "unreported")
        self.assertEqual(state["last_message"], "Everything completed successfully")

    def test_legacy_bridge_ignores_default_result_kind(self) -> None:
        account_id = self.import_lifecycle_account()
        self.install_plugin(
            "def run(context):\n"
            "    context.result('Generic result', status='succeeded', "
            "account_id=context.accounts[0].id)\n"
            "    return {'ok': True}\n",
            self.legacy_sekai_manifest(),
        )

        started = self.runs.start(
            "io.sprintray.sekai-testnet", "run_cycle", [account_id]
        )
        run_id = str(started["id"])
        self.wait_for_terminal(run_id)

        state = self.runs.account_states(run_id)[0]
        self.assertEqual(state["status"], "unknown")
        self.assertEqual(state["stage"], "unreported")

    def test_legacy_bridge_is_not_available_to_third_party_plugins(self) -> None:
        account_id = self.import_lifecycle_account()
        manifest = plugin_manifest(
            plugin_id="third.party.summary",
            account_mode="one_or_more",
            secrets=[],
        )
        self.install_plugin(
            "def run(context):\n"
            "    context.result('Third-party summary', kind='account_summary', "
            "status='succeeded', account_id=context.accounts[0].id)\n"
            "    return {'ok': True}\n",
            manifest,
        )

        started = self.runs.start("third.party.summary", "run", [account_id])
        run_id = str(started["id"])
        self.wait_for_terminal(run_id)

        state = self.runs.account_states(run_id)[0]
        self.assertEqual(state["status"], "unknown")
        self.assertEqual(state["stage"], "unreported")

    def test_legacy_bridge_rejects_duplicate_account_summaries(self) -> None:
        account_id = self.import_lifecycle_account()
        self.install_plugin(
            "def run(context):\n"
            "    account = context.accounts[0]\n"
            "    context.result('First summary', kind='account_summary', "
            "status='succeeded', account_id=account.id)\n"
            "    context.result('Second summary', kind='account_summary', "
            "status='succeeded', account_id=account.id)\n"
            "    return {'ok': True}\n",
            self.legacy_sekai_manifest(),
        )

        started = self.runs.start(
            "io.sprintray.sekai-testnet", "run_cycle", [account_id]
        )
        run_id = str(started["id"])
        self.wait_for_terminal(run_id)

        state = self.runs.account_states(run_id)[0]
        self.assertEqual(state["status"], "unknown")
        self.assertEqual(state["stage"], "unreported")

    def test_legacy_bridge_rejects_invalid_summary_status(self) -> None:
        account_id = self.import_lifecycle_account()
        self.install_plugin(
            "def run(context):\n"
            "    context.result('Invalid summary', kind='account_summary', "
            "status='complete', account_id=context.accounts[0].id)\n"
            "    return {'ok': True}\n",
            self.legacy_sekai_manifest(),
        )

        started = self.runs.start(
            "io.sprintray.sekai-testnet", "run_cycle", [account_id]
        )
        run_id = str(started["id"])
        self.wait_for_terminal(run_id)

        state = self.runs.account_states(run_id)[0]
        self.assertEqual(state["status"], "unknown")
        self.assertEqual(state["stage"], "unreported")

    def test_explicit_account_state_wins_over_legacy_summary_bridge(self) -> None:
        account_id = self.import_lifecycle_account()
        self.install_plugin(
            "def run(context):\n"
            "    account = context.accounts[0]\n"
            "    context.account_state(account.id, status='running', stage='work', "
            "progress=0.5, message='Working')\n"
            "    context.result('Legacy-looking summary', kind='account_summary', "
            "status='succeeded', account_id=account.id)\n"
            "    context.account_state(account.id, status='failed', stage='known_failure', "
            "progress=1.0, message='Known failure')\n"
            "    return {'ok': True}\n",
            self.legacy_sekai_manifest(),
        )

        started = self.runs.start(
            "io.sprintray.sekai-testnet", "run_cycle", [account_id]
        )
        run_id = str(started["id"])
        self.wait_for_terminal(run_id)

        state = self.runs.account_states(run_id)[0]
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["stage"], "known_failure")
        self.assertEqual(state["last_message"], "Known failure")
        recovered = [
            event
            for event in self.runs.events(run_id)
            if event["event_type"] == "account_state"
            and event["data"].get("source") == "legacy_account_summary"
        ]
        self.assertEqual(recovered, [])

    def test_operations_projection_scopes_filter_before_limit_without_starvation(self) -> None:
        manifest = plugin_manifest(plugin_id="runner.operations-projection")
        self.install_plugin("def run(context):\n    return {}\n", manifest)
        runs = [
            ("active-run", "running", 2, "2026-01-01T00:00:00+00:00"),
            ("attention-run", "failed", 2, "2026-02-01T00:00:00+00:00"),
            ("unknown-run", "failed", 1, "2026-03-01T00:00:00+00:00"),
            ("historical-run", "succeeded", 1, "2026-09-01T00:00:00+00:00"),
            ("reconciled-run", "reconciled", 1, "2026-08-01T00:00:00+00:00"),
            ("ordinary-run", "succeeded", 1, "2026-10-01T00:00:00+00:00"),
        ]
        states = [
            ("active-run", "active-success", "Active Success", "succeeded", "completed", 1.0, "2026-01-01T00:00:01+00:00"),
            ("active-run", "active-failed", "Active Failed", "failed", "action_failed", 0.5, "2026-01-01T00:00:02+00:00"),
            ("attention-run", "attention-partial", "Attention", "partial", "partially_completed", 0.8, "2026-02-01T00:00:01+00:00"),
            ("attention-run", "failed-run-success", "Succeeded Inside Failed Run", "succeeded", "completed", 1.0, "2026-02-01T00:00:02+00:00"),
            ("unknown-run", "unknown-unreported", "Unknown", "unknown", "unreported", 0.0, "2026-03-01T00:00:01+00:00"),
            ("historical-run", "unknown-historical", "Historical", "unknown", "historical", 0.0, "2026-09-01T00:00:01+00:00"),
            ("reconciled-run", "unknown-reconciled", "Reconciled", "unknown", "reconciled", 0.0, "2026-08-01T00:00:01+00:00"),
            ("ordinary-run", "ordinary-success", "Ordinary", "succeeded", "completed", 1.0, "2026-10-01T00:00:01+00:00"),
        ]
        with self.database.transaction() as connection:
            connection.executemany(
                "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,"
                "account_count,requested_at) VALUES (?,'runner.operations-projection',"
                "'1.0.0','run',?,0,?,?)",
                runs,
            )
            connection.executemany(
                "INSERT INTO run_account_states(run_id,account_id,account_label,status,"
                "stage,progress,last_message,updated_at) VALUES (?,?,?,?,?,?,'',?)",
                states,
            )

        active = self.runs.account_states(scope="active", limit=20)
        attention = self.runs.account_states(scope="attention", limit=20)
        operations = self.runs.account_states(scope="operations", limit=20)
        self.assertEqual(
            {row["account_id"] for row in active},
            {"active-success", "active-failed"},
        )
        self.assertEqual(
            {row["account_id"] for row in attention},
            {
                "active-failed",
                "attention-partial",
                "failed-run-success",
                "unknown-unreported",
            },
        )
        self.assertEqual(
            {row["account_id"] for row in operations},
            {
                "active-success",
                "active-failed",
                "attention-partial",
                "failed-run-success",
                "unknown-unreported",
            },
        )
        self.assertEqual(
            {row["run_status"] for row in operations[:2]},
            {"running"},
            "Every account of an active run must sort ahead of attention history",
        )
        active_page = self.runs.account_state_page(scope="active", limit=1)
        attention_page = self.runs.account_state_page(scope="attention", limit=2)
        self.assertTrue(active_page["truncated"])
        self.assertTrue(attention_page["truncated"])
        self.assertEqual(active_page["accounts"][0]["run_id"], "active-run")
        self.assertNotIn(
            "unknown-historical",
            {row["account_id"] for row in attention},
        )
        self.assertNotIn(
            "unknown-reconciled",
            {row["account_id"] for row in attention},
        )

    def test_attention_count_includes_succeeded_run_with_failed_account(self) -> None:
        manifest = plugin_manifest(plugin_id="runner.account-attention-count")
        self.install_plugin("def run(context):\n    return {}\n", manifest)
        now = utc_now()
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,"
                "account_count,requested_at) VALUES ('account-attention-run',"
                "'runner.account-attention-count','1.0.0','run','succeeded',1,1,?)",
                (now,),
            )
            connection.execute(
                "INSERT INTO run_account_states(run_id,account_id,account_label,status,"
                "stage,progress,last_message,updated_at) VALUES ("
                "'account-attention-run','failed-account','Failed Account','failed',"
                "'action_failed',0.5,'Предметная ошибка',?)",
                (now,),
            )

        self.assertEqual(
            self.runs.status_counts(),
            {"active_runs": 0, "needs_attention": 0, "attention_runs": 1},
        )
        attention = self.runs.account_states(scope="attention", limit=10)
        self.assertEqual([row["account_id"] for row in attention], ["failed-account"])

        reviewed = self.runs.review_failure("account-attention-run")
        self.assertEqual(reviewed["status"], "reviewed")
        self.assertEqual(self.runs.account_states(scope="attention", limit=10), [])
        self.assertEqual(
            self.runs.status_counts(),
            {"active_runs": 0, "needs_attention": 0, "attention_runs": 0},
        )
        preserved = self.runs.account_states("account-attention-run")[0]
        self.assertEqual(preserved["status"], "failed")
        self.assertEqual(preserved["stage"], "action_failed")
        review_event = next(
            event
            for event in self.runs.events("account-attention-run")
            if event["event_type"] == "failure_reviewed"
        )
        self.assertEqual(review_event["data"]["original_status"], "succeeded")
        self.assertEqual(review_event["data"]["account_issue_count"], 1)

    def test_legacy_attention_can_be_hidden_and_restarted_without_confirmation(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "reconcile-restart.test:28080:user:pass",
                    "reconcile-restart@example.test",
                    label="Reconcile Restart",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = plugin_manifest(
            plugin_id="runner.reconcile-restart",
            action_risk="external_write",
            account_mode="one_or_more",
            secrets=[],
        )
        self.install_plugin(
            "def run(context):\n"
            "    account = context.accounts[0]\n"
            "    context.account_state(account.id, status='succeeded', "
            "stage='completed', progress=1, message='Done')\n"
            "    return {'ok': True}\n",
            manifest,
        )
        run_id = "00000000-0000-0000-0000-000000000011"
        now = utc_now()
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,"
                "account_count,requested_at,finished_at,error) VALUES (?,?,'1.0.0','run',"
                "'needs_attention',1,1,?,?,?)",
                (
                    run_id,
                    "runner.reconcile-restart",
                    now,
                    now,
                    "Плагин завершился без успешного terminal event",
                ),
            )
            connection.execute(
                "INSERT INTO run_account_states(run_id,account_id,account_label,status,"
                "stage,progress,last_message,updated_at) VALUES (?,?,?,'failed',"
                "'action_failed',1,'Предметная ошибка сохранена',?)",
                (run_id, account_id, "Reconcile Restart", now),
            )
            self.runs._acquire_leases(connection, run_id, [account_id], [0])

        self.assertEqual(
            self.runs.status_counts(),
            {"active_runs": 0, "needs_attention": 0, "attention_runs": 1},
        )
        reviewed = self.runs.review_failure(run_id)

        self.assertEqual(reviewed["status"], "reviewed")
        preserved = self.runs.account_states(run_id)[0]
        self.assertEqual(preserved["status"], "failed")
        self.assertEqual(preserved["stage"], "action_failed")
        self.assertEqual(preserved["last_message"], "Предметная ошибка сохранена")
        self.assertEqual(self.runs.account_states(scope="attention", limit=10), [])
        self.assertEqual(
            self.runs.status_counts(),
            {"active_runs": 0, "needs_attention": 0, "attention_runs": 0},
        )
        self.assertEqual(
            self.database.all("SELECT * FROM account_leases WHERE run_id=?", (run_id,)),
            [],
        )
        self.assertTrue(
            any(event["event_type"] == "failure_reviewed" for event in self.runs.events(run_id))
        )
        reviewed_again = self.runs.review_failure(run_id)
        self.assertEqual(reviewed_again["status"], "reviewed")
        self.assertEqual(
            sum(event["event_type"] == "failure_reviewed" for event in self.runs.events(run_id)),
            1,
        )

        restarted = self.runs.start("runner.reconcile-restart", "run", [account_id])
        restarted_id = str(restarted["id"])
        self.assertNotEqual(restarted_id, run_id)
        final = self.wait_for_terminal(restarted_id)
        self.assertEqual(final["status"], "succeeded")

    def test_hiding_legacy_account_ambiguity_preserves_evidence(self) -> None:
        manifest = plugin_manifest(plugin_id="runner.legacy-account-ambiguity")
        self.install_plugin("def run(context):\n    return {}\n", manifest)
        run_id = "00000000-0000-0000-0000-000000000013"
        now = utc_now()
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,"
                "account_count,requested_at,finished_at) VALUES (?,?,'1.0.0','run',"
                "'succeeded',1,1,?,?)",
                (run_id, "runner.legacy-account-ambiguity", now, now),
            )
            connection.execute(
                "INSERT INTO run_account_states(run_id,account_id,account_label,status,"
                "stage,progress,last_message,updated_at) VALUES (?,?,?,'needs_attention',"
                "'external_state_unknown',0.8,'Legacy ambiguity',?)",
                (run_id, "legacy-account", "Legacy Account", now),
            )
            connection.execute(
                "INSERT INTO run_account_states(run_id,account_id,account_label,status,"
                "stage,progress,last_message,updated_at) VALUES (?,?,?,'failed',"
                "'action_failed',0.7,'Known failure beside ambiguity',?)",
                (run_id, "known-account", "Known Account", now),
            )

        reviewed = self.runs.review_failure(run_id)
        self.assertEqual(reviewed["status"], "reviewed")
        preserved = next(
            state
            for state in self.runs.account_states(run_id)
            if state["account_id"] == "legacy-account"
        )
        self.assertEqual(preserved["status"], "needs_attention")
        self.assertEqual(preserved["stage"], "external_state_unknown")
        self.assertEqual(preserved["last_message"], "Legacy ambiguity")
        known = next(
            state
            for state in self.runs.account_states(run_id)
            if state["account_id"] == "known-account"
        )
        self.assertEqual(known["status"], "failed")
        self.assertEqual(self.runs.account_states(scope="attention", limit=10), [])
        self.assertEqual(self.runs.status_counts()["attention_runs"], 0)

    def test_failure_review_closes_only_known_error_without_rewriting_evidence(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "review-failure.test:28080:user:pass",
                    "review-failure@example.test",
                    label="Reviewed Failure",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = plugin_manifest(
            plugin_id="runner.review-failure",
            account_mode="one_or_more",
            secrets=[],
        )
        self.install_plugin(
            "def run(context):\n"
            "    account = context.accounts[0]\n"
            "    context.account_state(account.id, status='succeeded', "
            "stage='completed', progress=1, message='Done')\n"
            "    return {'ok': True}\n",
            manifest,
        )
        run_id = "00000000-0000-0000-0000-000000000012"
        now = utc_now()
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,"
                "account_count,requested_at,finished_at,error) VALUES (?,?,'1.0.0','run',"
                "'failed',0.4,1,?,?,?)",
                (run_id, "runner.review-failure", now, now, "known adapter failure"),
            )
            connection.execute(
                "INSERT INTO run_account_states(run_id,account_id,account_label,status,"
                "stage,progress,last_message,updated_at) VALUES (?,?,?,'failed',"
                "'action_failed',0.4,'Known account failure',?)",
                (run_id, account_id, "Reviewed Failure", now),
            )
            connection.execute(
                "INSERT INTO results(id,run_id,module_id,account_id,kind,status,title,"
                "data_json,created_at) VALUES ('review-result',?,?,?,'account_summary',"
                "'failed','Known result','{\"code\":\"known\"}',?)",
                (run_id, "runner.review-failure", account_id, now),
            )
            self.runs._insert_event(
                connection,
                run_id,
                now,
                "error",
                "adapter_error",
                "Known technical event",
                account_id,
                {"code": "known"},
            )
            self.runs._acquire_leases(connection, run_id, [account_id], [0])

        reviewed = self.runs.review_failure(run_id)
        self.assertEqual(reviewed["status"], "reviewed")
        self.assertEqual(
            self.database.all("SELECT * FROM account_leases WHERE run_id=?", (run_id,)),
            [],
        )

        self.assertEqual(reviewed["status"], "reviewed")
        self.assertEqual(reviewed["error"], "known adapter failure")
        state = self.runs.account_states(run_id)[0]
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["stage"], "action_failed")
        self.assertEqual(state["last_message"], "Known account failure")
        result = self.database.one("SELECT * FROM results WHERE id='review-result'")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["data_json"], '{"code":"known"}')
        events = self.runs.events(run_id)
        self.assertTrue(any(event["event_type"] == "adapter_error" for event in events))
        self.assertTrue(any(event["event_type"] == "failure_reviewed" for event in events))
        self.assertEqual(self.runs.account_states(scope="attention", limit=10), [])
        self.assertEqual(
            self.runs.status_counts(),
            {"active_runs": 0, "needs_attention": 0, "attention_runs": 0},
        )
        reviewed_again = self.runs.review_failure(run_id)
        self.assertEqual(reviewed_again["status"], "reviewed")
        self.assertEqual(
            sum(event["event_type"] == "failure_reviewed" for event in self.runs.events(run_id)),
            1,
        )
        restarted = self.runs.start("runner.review-failure", "run", [account_id])
        restarted_id = str(restarted["id"])
        self.assertEqual(self.wait_for_terminal(restarted_id)["status"], "succeeded")

    def test_unselected_account_id_is_rejected_without_plaintext_persistence(self) -> None:
        manifest = plugin_manifest(plugin_id="runner.account-scope")
        self.install_plugin("def run(context):\n    return {}\n", manifest)
        run_id = "00000000-0000-0000-0000-000000000009"
        self.database.execute(
            "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,account_count,requested_at) "
            "VALUES (?,?,?,'run','running',0,0,?)",
            (run_id, "runner.account-scope", "1.0.0", utc_now()),
        )
        plaintext_secret = "0x" + "99" * 32

        with self.assertRaisesRegex(ValueError, "not selected"):
            self.runs._handle_frame(
                run_id,
                "runner.account-scope",
                {
                    "protocol": "soft-hub-jsonl/1",
                    "type": "result",
                    "account_id": plaintext_secret,
                    "message": "must not persist",
                    "data": {},
                },
                Redactor(),
            )

        persisted = json.dumps(
            {
                "events": self.database.all(
                    "SELECT * FROM run_events WHERE run_id=?", (run_id,)
                ),
                "results": self.database.all(
                    "SELECT * FROM results WHERE run_id=?", (run_id,)
                ),
            }
        )
        self.assertNotIn(plaintext_secret, persisted)
        self.assertNotIn("must not persist", persisted)

    def test_account_scoped_progress_is_aggregated_instead_of_overstating_run(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "aggregate-a.test:28080:user:pass",
                    "aggregate-a@example.test",
                    label="Aggregate A",
                ),
                ImportRecord(
                    TEST_PRIVATE_KEY_B,
                    "aggregate-b.test:28080:user:pass",
                    "aggregate-b@example.test",
                    label="Aggregate B",
                ),
            ]
        )
        accounts = self.vault.list_accounts()
        manifest = plugin_manifest(plugin_id="runner.account-progress")
        self.install_plugin("def run(context):\n    return {}\n", manifest)
        run_id = "00000000-0000-0000-0000-000000000010"
        now = utc_now()
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,account_count,requested_at) "
                "VALUES (?,?,?,'run','running',0,2,?)",
                (run_id, "runner.account-progress", "1.0.0", now),
            )
            connection.executemany(
                "INSERT INTO run_account_states("
                "run_id,account_id,account_label,status,stage,progress,last_message,updated_at"
                ") VALUES (?,?,?,'queued','queued',0,'',?)",
                [
                    (run_id, account["id"], account["label"], now)
                    for account in accounts
                ],
            )

        for account, value, expected in (
            (accounts[0], 0.8, 0.4),
            (accounts[1], 0.2, 0.5),
        ):
            self.runs._handle_frame(
                run_id,
                "runner.account-progress",
                {
                    "protocol": "soft-hub-jsonl/1",
                    "type": "progress",
                    "account_id": account["id"],
                    "data": {"value": value},
                },
                Redactor(),
            )
            self.assertAlmostEqual(
                self.database.one(
                    "SELECT progress FROM runs WHERE id=?", (run_id,)
                )["progress"],
                expected,
            )

        with self.assertRaises(ValueError):
            self.runs._handle_frame(
                run_id,
                "runner.account-progress",
                {
                    "protocol": "soft-hub-jsonl/1",
                    "type": "progress",
                    "account_id": accounts[0]["id"],
                    "data": {"value": 0.7},
                },
                Redactor(),
            )

    def test_run_level_progress_cannot_overstate_an_account_run(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "aggregate-global.test:28080:user:pass",
                    "aggregate-global@example.test",
                    label="Aggregate Global",
                )
            ]
        )
        account = self.vault.list_accounts()[0]
        manifest = plugin_manifest(plugin_id="runner.account-global-progress")
        self.install_plugin("def run(context):\n    return {}\n", manifest)
        run_id = "00000000-0000-0000-0000-000000000011"
        now = utc_now()
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,account_count,requested_at) "
                "VALUES (?,?,?,'run','running',0,1,?)",
                (run_id, "runner.account-global-progress", "1.0.0", now),
            )
            connection.execute(
                "INSERT INTO run_account_states("
                "run_id,account_id,account_label,status,stage,progress,last_message,updated_at"
                ") VALUES (?,?,?,'queued','queued',0,'',?)",
                (run_id, account["id"], account["label"], now),
            )

        self.runs._handle_frame(
            run_id,
            "runner.account-global-progress",
            {
                "protocol": "soft-hub-jsonl/1",
                "type": "progress",
                "data": {"value": 0.95},
            },
            Redactor(),
        )
        self.assertEqual(
            self.database.one("SELECT progress FROM runs WHERE id=?", (run_id,))["progress"],
            0.0,
        )

    def test_child_environment_is_allowlisted(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/deterministic/test/path",
                "LANG": "C.UTF-8",
                "HOME": "/must/not/leak",
                "AWS_SECRET_ACCESS_KEY": "deterministic-not-a-real-secret",
                "SOFT_HUB_DATA_DIR": "/must/not/leak",
            },
            clear=True,
        ):
            environment = RunManager._safe_environment()
        self.assertEqual(environment["PATH"], "/deterministic/test/path")
        self.assertEqual(environment["LANG"], "C.UTF-8")
        self.assertEqual(environment["PYTHONNOUSERSITE"], "1")
        self.assertNotIn("HOME", environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
        self.assertNotIn("SOFT_HUB_DATA_DIR", environment)

    def test_shutdown_force_stops_write_run_and_releases_lease(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "shutdownproxy.test:48080:user:pass",
                    "shutdown@example.test",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = plugin_manifest(
            plugin_id="runner.shutdown",
            action_risk="testnet_write",
            account_mode="one_or_more",
            chains=[111],
        )
        self.install_plugin(
            "import time\ndef run(context):\n    time.sleep(30)\n    return {'late': True}\n",
            manifest,
        )
        started = self.runs.start(
            "runner.shutdown", "run", [account_id], acknowledgement="TESTNET"
        )
        wait_until(
            lambda: self.runs.get(str(started["id"]))["status"] in {"running", "cancelling"},
            timeout=5,
        )

        self.runs.shutdown(grace_seconds=0.2)
        final = self.runs.get(str(started["id"]))
        assert final is not None
        self.assertEqual(final["status"], "cancelled")
        self.assertEqual(
            self.database.all("SELECT * FROM account_leases WHERE run_id=?", (started["id"],)),
            [],
        )
        self.assertEqual(self.runs._processes, {})
        self.assertEqual(self.runs._threads, {})

    def test_force_stop_bypasses_safe_stop_and_kills_read_process_tree(self) -> None:
        manifest = plugin_manifest(plugin_id="runner.force-read", safe_stop=False)
        self.install_plugin(
            "import time\ndef run(context):\n    time.sleep(30)\n    return {'late': True}\n",
            manifest,
        )
        started = self.runs.start("runner.force-read", "run", [])
        run_id = str(started["id"])
        wait_until(
            lambda: self.runs.get(run_id)["status"] == "running",
            timeout=5,
        )

        with self.assertRaisesRegex(RunError, "безопасную остановку"):
            self.runs.stop(run_id)
        with self.assertRaisesRegex(RunError, "FORCE STOP"):
            self.runs.force_stop(run_id, "")
        stopping = self.runs.force_stop(run_id, "FORCE STOP")
        self.assertEqual(stopping["status"], "cancelling")
        final = wait_until(
            lambda: (
                current
                if (current := self.runs.get(run_id))
                and current["status"] in TERMINAL_STATUSES
                else None
            ),
            timeout=5,
        )
        self.assertEqual(final["status"], "cancelled")
        self.assertEqual(final["error"], "process_force_killed")
        wait_until(lambda: run_id not in self.runs._threads, timeout=5)
        self.assertNotIn(run_id, self.runs._processes)
        events = self.runs.events(run_id)
        self.assertTrue(
            any("принудительную остановку" in event["message"] for event in events)
        )

    def test_queued_safe_and_force_stop_finish_before_slot_and_release_write_lease(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "queued-stop.test:48082:user:pass",
                    "queued-stop@example.test",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        self.runs._slots = threading.BoundedSemaphore(1)
        self.install_plugin(
            "import time\ndef run(context):\n    time.sleep(30)\n    return {'late': True}\n",
            plugin_manifest(plugin_id="runner.slot-holder", safe_stop=False),
        )
        holder = self.runs.start("runner.slot-holder", "run", [])
        holder_id = str(holder["id"])

        def stop_holder() -> None:
            current = self.runs.get(holder_id)
            if current and current["status"] in {"queued", "starting", "running", "cancelling"}:
                self.runs.force_stop(holder_id, "FORCE STOP")
                self.wait_for_terminal(holder_id)

        self.addCleanup(stop_holder)
        wait_until(lambda: self.runs.get(holder_id)["status"] == "running", timeout=5)

        write_manifest = plugin_manifest(
            plugin_id="runner.queued-safe-write",
            action_risk="testnet_write",
            account_mode="one_or_more",
            chains=[111],
        )
        self.install_plugin(
            "def run(context):\n    return {'must_not_start': True}\n",
            write_manifest,
        )
        queued_write = self.runs.start(
            "runner.queued-safe-write",
            "run",
            [account_id],
            acknowledgement="TESTNET",
        )
        write_id = str(queued_write["id"])
        wait_until(
            lambda: self.runs.get(write_id)["status"] == "queued"
            and write_id in self.runs._threads,
            timeout=3,
        )
        self.assertNotIn(write_id, self.runs._processes)
        self.assertEqual(
            self.database.one(
                "SELECT chain_id,account_id FROM account_leases WHERE run_id=?",
                (write_id,),
            ),
            {"chain_id": 111, "account_id": account_id},
        )

        self.assertEqual(self.runs.stop(write_id)["status"], "cancelling")
        write_final = self.wait_for_terminal(write_id)
        self.assertEqual(write_final["status"], "cancelled")
        self.assertIsNone(write_final["error"])
        wait_until(lambda: write_id not in self.runs._threads, timeout=3)
        self.assertEqual(
            self.database.all("SELECT * FROM account_leases WHERE run_id=?", (write_id,)),
            [],
        )
        self.assertEqual(self.runs.account_states(write_id)[0]["status"], "cancelled")
        self.assertFalse((self.paths.runs / write_id / "scratch").exists())
        self.assertEqual(self.runs.get(holder_id)["status"], "running")

        self.install_plugin(
            "def run(context):\n    return {'must_not_start': True}\n",
            plugin_manifest(plugin_id="runner.queued-force-read", safe_stop=False),
        )
        queued_read = self.runs.start("runner.queued-force-read", "run", [])
        read_id = str(queued_read["id"])
        wait_until(
            lambda: self.runs.get(read_id)["status"] == "queued"
            and read_id in self.runs._threads,
            timeout=3,
        )
        self.runs.force_stop(read_id, "FORCE STOP")
        read_final = self.wait_for_terminal(read_id)
        self.assertEqual(read_final["status"], "cancelled")
        self.assertIsNone(read_final["error"])
        wait_until(lambda: read_id not in self.runs._threads, timeout=3)
        self.assertNotIn(read_id, self.runs._processes)
        self.assertFalse((self.paths.runs / read_id / "scratch").exists())
        self.assertEqual(self.runs.get(holder_id)["status"], "running")

        self.runs.force_stop(holder_id, "FORCE STOP")
        self.assertEqual(self.wait_for_terminal(holder_id)["status"], "cancelled")
        wait_until(lambda: holder_id not in self.runs._threads, timeout=5)

    def test_force_stop_write_run_is_terminal_and_releases_lease(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "forceproxy.test:48080:user:pass",
                    "force@example.test",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = plugin_manifest(
            plugin_id="runner.force-write",
            action_risk="testnet_write",
            account_mode="one_or_more",
            chains=[111],
            safe_stop=False,
        )
        self.install_plugin(
            "import time\ndef run(context):\n    time.sleep(30)\n    return {'late': True}\n",
            manifest,
        )
        started = self.runs.start(
            "runner.force-write", "run", [account_id], acknowledgement="TESTNET"
        )
        run_id = str(started["id"])
        wait_until(lambda: self.runs.get(run_id)["status"] == "running", timeout=5)

        with self.assertRaisesRegex(RunError, "FORCE STOP"):
            self.runs.force_stop(run_id, "force stop")
        self.runs.force_stop(run_id, "FORCE STOP")
        final = wait_until(
            lambda: (
                current
                if (current := self.runs.get(run_id))
                and current["status"] == "cancelled"
                else None
            ),
            timeout=5,
        )
        self.assertEqual(final["error"], "process_force_killed")
        account_state = self.runs.account_states(run_id)[0]
        self.assertEqual(account_state["status"], "cancelled")
        self.assertEqual(account_state["stage"], "cancelled")
        wait_until(lambda: run_id not in self.runs._threads, timeout=5)
        leases = self.database.all(
            "SELECT * FROM account_leases WHERE run_id=?", (run_id,)
        )
        self.assertEqual(leases, [])

        removed = self.runs.uninstall_module("runner.force-write")
        self.assertTrue(removed["removed"])
        self.assertEqual(self.database.all("SELECT * FROM account_leases"), [])

    def test_parallel_write_failures_release_both_accounts_and_allow_restart(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "parallel-a.test:48080:user-a:pass-a",
                    "parallel-a@example.test",
                    label="Parallel A",
                ),
                ImportRecord(
                    TEST_PRIVATE_KEY_B,
                    "parallel-b.test:48081:user-b:pass-b",
                    "parallel-b@example.test",
                    label="Parallel B",
                ),
            ]
        )
        account_ids = [str(account["id"]) for account in self.vault.list_accounts()]
        manifest = plugin_manifest(
            plugin_id="runner.parallel-failure",
            action_risk="testnet_write",
            account_mode="one_or_more",
            chains=[111],
        )
        self.install_plugin(
            "import time\ndef run(context):\n    time.sleep(0.2)\n"
            "    raise RuntimeError('parallel deterministic failure')\n",
            manifest,
        )

        first = self.runs.start(
            "runner.parallel-failure", "run", [account_ids[0]], acknowledgement="TESTNET"
        )
        second = self.runs.start(
            "runner.parallel-failure", "run", [account_ids[1]], acknowledgement="TESTNET"
        )
        first_id, second_id = str(first["id"]), str(second["id"])
        self.assertEqual(self.wait_for_terminal(first_id)["status"], "failed")
        self.assertEqual(self.wait_for_terminal(second_id)["status"], "failed")
        self.assertEqual(
            self.database.all(
                "SELECT * FROM account_leases WHERE run_id IN (?,?)", (first_id, second_id)
            ),
            [],
            "A visible terminal status must already mean both accounts are free",
        )
        wait_until(
            lambda: first_id not in self.runs._threads and second_id not in self.runs._threads,
            timeout=5,
        )
        self.assertEqual(self.database.all("SELECT * FROM account_leases"), [])

        restarted = self.runs.start(
            "runner.parallel-failure", "run", account_ids, acknowledgement="TESTNET"
        )
        self.assertNotIn(str(restarted["id"]), {first_id, second_id})
        self.assertEqual(self.wait_for_terminal(str(restarted["id"]))["status"], "failed")

    def test_external_write_batch_is_allowed_and_force_stop_releases_service_lease(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "externalproxy.test:48081:user:pass",
                    "external@example.test",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        quick_manifest = plugin_manifest(
            plugin_id="runner.external-batch",
            action_risk="external_write",
            account_mode="one_or_more",
        )
        self.install_plugin(
            "def run(context):\n    return {'external': True}\n",
            quick_manifest,
        )

        admitted = self.runs.start_batch(
            str(uuid.uuid4()),
            [
                {
                    "module_id": "runner.external-batch",
                    "action_id": "run",
                    "account_ids": [account_id],
                    "options": {},
                    "acknowledgement": "",
                }
            ],
        )
        self.assertIs(admitted["replayed"], False)
        batch_run_id = str(admitted["runs"][0]["id"])
        self.assertEqual(self.wait_for_terminal(batch_run_id)["status"], "succeeded")
        wait_until(lambda: batch_run_id not in self.runs._threads, timeout=3)

        slow_manifest = plugin_manifest(
            plugin_id="runner.external-force",
            action_risk="external_write",
            account_mode="one_or_more",
            safe_stop=False,
        )
        self.install_plugin(
            "import time\ndef run(context):\n    time.sleep(30)\n    return {'late': True}\n",
            slow_manifest,
        )
        started = self.runs.start("runner.external-force", "run", [account_id])
        run_id = str(started["id"])
        wait_until(lambda: self.runs.get(run_id)["status"] == "running", timeout=5)
        lease = self.database.one(
            "SELECT chain_id,account_id FROM account_leases WHERE run_id=?",
            (run_id,),
        )
        self.assertEqual(lease, {"chain_id": 0, "account_id": account_id})

        self.runs.force_stop(run_id, "FORCE STOP")
        final = wait_until(
            lambda: (
                current
                if (current := self.runs.get(run_id))
                and current["status"] == "cancelled"
                else None
            ),
            timeout=5,
        )
        self.assertEqual(final["error"], "process_force_killed")
        account_state = self.runs.account_states(run_id)[0]
        self.assertEqual(account_state["status"], "cancelled")
        self.assertEqual(account_state["stage"], "cancelled")
        wait_until(lambda: run_id not in self.runs._threads, timeout=5)
        self.assertEqual(
            self.database.all("SELECT * FROM account_leases WHERE run_id=?", (run_id,)),
            [],
        )

    def test_account_attention_becomes_failed_evidence_without_retained_lease(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "attention-elevation.test:48083:user:pass",
                    "attention-elevation@example.test",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        cases = (
            ("testnet-cancel", "testnet_write", [111], "raise CancelledError()", "TESTNET"),
            ("external-cancel", "external_write", [], "raise CancelledError()", ""),
            ("external-complete", "external_write", [], "return {'reported': True}", ""),
        )
        for suffix, risk, chains, terminal_source, acknowledgement in cases:
            with self.subTest(case=suffix):
                plugin_id = f"runner.attention-{suffix}"
                manifest = plugin_manifest(
                    plugin_id=plugin_id,
                    action_risk=risk,
                    account_mode="one_or_more",
                    chains=chains,
                )
                source = (
                    "from soft_hub.sdk import CancelledError\n"
                    "def run(context):\n"
                    "    account = context.accounts[0]\n"
                    "    context.account_state(account.id, status='needs_attention', "
                    "stage='write_unknown', progress=0.5, message='Нужна сверка')\n"
                    f"    {terminal_source}\n"
                )
                self.install_plugin(source, manifest)
                started = self.runs.start(
                    plugin_id,
                    "run",
                    [account_id],
                    acknowledgement=acknowledgement,
                )
                run_id = str(started["id"])
                final = self.wait_for_terminal(run_id)
                self.assertEqual(final["status"], "failed")
                self.assertEqual(final["error"], "external_state_unknown")
                state = self.runs.account_states(run_id)[0]
                self.assertEqual(state["status"], "failed")
                self.assertEqual(state["stage"], "write_unknown")
                wait_until(lambda: run_id not in self.runs._threads, timeout=5)
                self.assertEqual(
                    self.database.all(
                        "SELECT * FROM account_leases WHERE run_id=?", (run_id,)
                    ),
                    [],
                )

    def test_uninstall_waits_for_worker_finalization_even_after_terminal_status(self) -> None:
        manifest = plugin_manifest(plugin_id="runner.finalizing")
        self.install_plugin("def run(context):\n    return {'ok': True}\n", manifest)
        release_entered = threading.Event()
        allow_release = threading.Event()
        self.addCleanup(allow_release.set)
        original_release = self.runs._release_leases

        def delayed_release(run_id: str) -> None:
            release_entered.set()
            if not allow_release.wait(timeout=5):
                raise RuntimeError("test did not release finalization gate")
            original_release(run_id)

        with mock.patch.object(self.runs, "_release_leases", side_effect=delayed_release):
            started = self.runs.start("runner.finalizing", "run", [])
            run_id = str(started["id"])
            self.assertTrue(release_entered.wait(timeout=3))
            self.assertEqual(self.runs.get(run_id)["status"], "succeeded")
            with self.assertRaisesRegex(RunError, "финализация"):
                self.runs.uninstall_module("runner.finalizing")
            allow_release.set()
            wait_until(lambda: run_id not in self.runs._threads, timeout=5)

        removed = self.runs.uninstall_module("runner.finalizing")
        self.assertTrue(removed["removed"])
        self.assertIsNone(self.plugins.get("runner.finalizing"))
        self.assertEqual(self.runs.get(run_id)["status"], "succeeded")

    def test_start_revalidates_module_after_deterministic_uninstall_race(self) -> None:
        manifest = plugin_manifest(plugin_id="runner.start-uninstall-race")
        self.install_plugin("def run(context):\n    return {'ok': True}\n", manifest)
        initial_read = threading.Event()
        allow_start_to_continue = threading.Event()
        self.addCleanup(allow_start_to_continue.set)
        original_get = self.plugins.get
        calls = 0
        calls_lock = threading.Lock()

        def gated_get(plugin_id: str) -> dict[str, object] | None:
            nonlocal calls
            module = original_get(plugin_id)
            with calls_lock:
                calls += 1
                current_call = calls
            if current_call == 1:
                initial_read.set()
                if not allow_start_to_continue.wait(timeout=5):
                    raise RuntimeError("test did not release start gate")
            return module

        outcome: dict[str, object] = {}

        def start_in_thread() -> None:
            try:
                outcome["run"] = self.runs.start(
                    "runner.start-uninstall-race", "run", []
                )
            except BaseException as error:
                outcome["error"] = error

        with mock.patch.object(self.plugins, "get", side_effect=gated_get):
            starter = threading.Thread(target=start_in_thread)
            starter.start()
            self.assertTrue(initial_read.wait(timeout=3))
            removed = self.runs.uninstall_module("runner.start-uninstall-race")
            self.assertTrue(removed["removed"])
            allow_start_to_continue.set()
            starter.join(timeout=5)

        self.assertFalse(starter.is_alive(), "start/uninstall lock order must not deadlock")
        self.assertIsInstance(outcome.get("error"), RunError)
        self.assertRegex(str(outcome["error"]), "изменён или удалён")
        self.assertNotIn("run", outcome)
        self.assertEqual(
            self.database.all(
                "SELECT * FROM runs WHERE module_id='runner.start-uninstall-race'"
            ),
            [],
        )

    def test_start_revalidates_ready_health_before_inserting_run(self) -> None:
        manifest = plugin_manifest(
            plugin_id="runner.start-health-race",
            requirements="requirements.txt",
        )
        installed = self.install_plugin_with_requirements(
            "def run(context):\n    return {'ok': True}\n",
            manifest,
            "requests==2.32.5\n",
        )
        self.mark_plugin_runtime_ready(installed)
        self.database.execute(
            "UPDATE modules SET health='ready' WHERE id=?", (manifest["id"],)
        )
        original_get = self.plugins.get
        calls = 0

        def mutate_health_after_initial_read(plugin_id: str) -> dict[str, object] | None:
            nonlocal calls
            module = original_get(plugin_id)
            calls += 1
            if calls == 1:
                marker = (
                    Path(str(module["active_path"]))
                    / ".venv"
                    / ".soft-hub-ready.json"
                )
                marker.unlink()
            return module

        with mock.patch.object(
            self.plugins,
            "get",
            side_effect=mutate_health_after_initial_read,
        ), self.assertRaisesRegex(RunError, "подготовьте окружение"):
            self.runs.start("runner.start-health-race", "run", [])

        self.assertEqual(
            self.database.all(
                "SELECT * FROM runs WHERE module_id='runner.start-health-race'"
            ),
            [],
        )

    def test_missing_required_venv_fails_before_creating_run_or_lease(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "runtime-preflight.test:8080:user:pass",
                    "runtime-preflight@example.test",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = plugin_manifest(
            plugin_id="runner.runtime-preflight",
            requirements="requirements.txt",
            action_risk="external_write",
            account_mode="one_or_more",
        )
        self.install_plugin_with_requirements(
            "def run(context):\n    return {'ok': True}\n",
            manifest,
            "requests==2.32.5\n",
        )

        with self.assertRaisesRegex(RunError, "подготовьте окружение"):
            self.runs.start("runner.runtime-preflight", "run", [account_id])

        self.assertEqual(
            self.database.all(
                "SELECT * FROM runs WHERE module_id='runner.runtime-preflight'"
            ),
            [],
        )
        self.assertEqual(self.database.all("SELECT * FROM account_leases"), [])
        self.assertEqual(self.database.all("SELECT * FROM run_account_pins"), [])
        self.assertEqual(
            self.plugins.get("runner.runtime-preflight")["health"], "needs_setup"
        )

    def test_incompatible_required_venv_fails_before_run_or_lease(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "runtime-incompatible.test:8080:user:pass",
                    "runtime-incompatible@example.test",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = plugin_manifest(
            plugin_id="runner.runtime-incompatible",
            requirements="requirements.txt",
            action_risk="external_write",
            account_mode="one_or_more",
        )
        installed = self.install_plugin_with_requirements(
            "def run(context):\n    return {'ok': True}\n",
            manifest,
            "requests==2.32.5\n",
        )
        self.mark_plugin_runtime_ready(installed)
        marker = (
            Path(str(installed["active_path"]))
            / ".venv"
            / ".soft-hub-ready.json"
        )
        state = json.loads(marker.read_text(encoding="utf-8"))
        state["runtime_id"] = "incompatible-python-runtime"
        marker.write_text(json.dumps(state), encoding="utf-8")
        self.database.execute(
            "UPDATE modules SET health='ready' WHERE id=?", (manifest["id"],)
        )

        with self.assertRaisesRegex(RunError, "подготовьте окружение"):
            self.runs.start("runner.runtime-incompatible", "run", [account_id])

        self.assertEqual(
            self.database.all(
                "SELECT * FROM runs WHERE module_id='runner.runtime-incompatible'"
            ),
            [],
        )
        self.assertEqual(self.database.all("SELECT * FROM account_leases"), [])
        self.assertEqual(self.database.all("SELECT * FROM run_account_pins"), [])
        self.assertEqual(
            self.plugins.get("runner.runtime-incompatible")["health"],
            "needs_setup",
        )

    def test_required_venv_is_snapshotted_and_core_python_is_never_fallback(self) -> None:
        manifest = plugin_manifest(
            plugin_id="runner.runtime-python-selection",
            requirements="requirements.txt",
        )
        installed = self.install_plugin_with_requirements(
            "def run(context):\n    return {'ok': True}\n",
            manifest,
            "requests==2.32.5\n",
        )
        plugin_python = self.mark_plugin_runtime_ready(installed)
        self.database.execute(
            "UPDATE modules SET health='ready' WHERE id=?",
            (manifest["id"],),
        )

        prepared = self.runs._preflight_run(
            self.plugins.get(str(manifest["id"])),
            "run",
            [],
            {},
            "",
            batch=False,
        )

        self.assertEqual(prepared["python"], plugin_python)
        self.assertNotEqual(prepared["python"], Path(sys.executable))

    def test_actions_from_one_manifest_receive_only_their_exact_secret_grant(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "scopedproxy.test:58082:user:pass",
                    "scoped@example.test",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = action_scoped_manifest(
            "runner.action-scoped",
            {
                "key_only": ["evm_private_key"],
                "proxy_only": ["proxy"],
            },
        )
        self.install_plugin(
            "def run(context):\n"
            "    account = context.accounts[0]\n"
            "    return {\n"
            "        'action': context.action_id,\n"
            "        'has_key': 'evm_private_key' in account,\n"
            "        'has_proxy': 'proxy' in account,\n"
            "    }\n",
            manifest,
        )

        expected = {
            "key_only": {"action": "key_only", "has_key": True, "has_proxy": False},
            "proxy_only": {"action": "proxy_only", "has_key": False, "has_proxy": True},
        }
        for action_id in ("key_only", "proxy_only"):
            started = self.runs.start(
                "runner.action-scoped", action_id, [account_id]
            )
            run_id = str(started["id"])
            final = self.wait_for_terminal(run_id)
            wait_until(lambda: run_id not in self.runs._threads, timeout=3)
            self.assertEqual(final["status"], "succeeded")
            self.assertEqual(final["summary"], expected[action_id])

    def test_declared_resources_preflight_before_spawn_and_sdk_uses_exact_grants(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "adspower.test:58090:user:pass",
                    "adspower@example.test",
                    label="Browser Alpha",
                    adspower_profile="",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = plugin_manifest(
            plugin_id="runner.adspower-resources",
            account_mode="one_or_more",
            secrets=["adspower_profile", "adspower_api_key"],
        )
        manifest["permissions"].update(
            {"browser": True, "local_services": ["adspower"]}
        )
        manifest["actions"][0]["permissions"] = {
            "secrets": ["adspower_profile", "adspower_api_key"]
        }
        manifest["actions"][0]["resources"] = {
            "account": ["adspower_profile"],
            "settings": ["adspower_api"],
        }
        self.install_plugin(
            "import time\n"
            "def run(context):\n"
            "    time.sleep(0.25)\n"
            "    account = context.accounts[0]\n"
            "    try:\n"
            "        context.settings.secret('capsolver')\n"
            "        capsolver_granted = True\n"
            "    except KeyError:\n"
            "        capsolver_granted = False\n"
            "    return {\n"
            "        'profile_ok': account.secret('adspower_profile') == 'profile-opaque value',\n"
            "        'api_ok': context.settings.secret('adspower_api') == 'AdsPower-secret-value',\n"
            "        'capsolver_granted': capsolver_granted,\n"
            "        'settings_repr_safe': 'AdsPower-secret-value' not in repr(context.settings),\n"
            "    }\n",
            manifest,
        )

        with mock.patch("soft_hub.runner.subprocess.Popen") as popen:
            with self.assertRaisesRegex(VaultError, "Browser Alpha.*adspower_profile"):
                self.runs.start("runner.adspower-resources", "run", [account_id])
            popen.assert_not_called()
        self.assertEqual(
            self.database.all(
                "SELECT * FROM runs WHERE module_id='runner.adspower-resources'"
            ),
            [],
        )

        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "adspower.test:58090:user:pass",
                    "adspower@example.test",
                    label="Browser Alpha",
                    adspower_profile="profile-opaque value",
                )
            ]
        )
        with mock.patch("soft_hub.runner.subprocess.Popen") as popen:
            with self.assertRaisesRegex(VaultError, "adspower_api"):
                self.runs.start("runner.adspower-resources", "run", [account_id])
            popen.assert_not_called()

        self.vault.set_adspower_api_key("AdsPower-secret-value")
        started = self.runs.start(
            "runner.adspower-resources", "run", [account_id]
        )
        final = self.wait_for_terminal(str(started["id"]))
        self.assertEqual(final["status"], "succeeded")
        self.assertEqual(
            final["summary"],
            {
                "profile_ok": True,
                "api_ok": True,
                "capsolver_granted": False,
                "settings_repr_safe": True,
            },
        )

    def test_project_runtime_referral_separates_parent_grants_and_redacts_issued_code(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "ref-parent.test:58100:user-a:pass-a",
                    "ref-parent@example.test",
                    label="Referral Parent",
                ),
                ImportRecord(
                    TEST_PRIVATE_KEY_B,
                    "ref-child.test:58101:user-b:pass-b",
                    "ref-child@example.test",
                    label="Referral Child",
                ),
            ]
        )
        identifiers = {
            account["label"]: account["id"] for account in self.vault.list_accounts()
        }
        manifest = plugin_manifest(
            plugin_id="runner.project-runtime-referral",
            account_mode="one_or_more",
            secrets=["proxy"],
        )
        manifest["compatibility"]["hub"] = ">=0.6.5"
        manifest["actions"][0]["permissions"] = {"secrets": []}
        manifest["actions"][0]["resources"] = {
            "account": [],
            "settings": [],
        }
        manifest["actions"][0]["referral"] = {
            "mode": "project_runtime",
            "parent_required": True,
            "parent_access": "shared_read",
            "permissions": {"secrets": ["proxy"]},
            "resources": {"account": ["proxy"]},
        }
        manifest["actions"][0]["options"] = {
            "type": "object",
            "properties": {
                "account_concurrency": {
                    "type": "integer",
                    "title": "Parallel accounts",
                    "description": "Bounded target-account concurrency for this action.",
                    "default": 4,
                    "minimum": 1,
                    "maximum": 20,
                    "multipleOf": 1,
                    "x-ui": {"group": "Выполнение", "order": 0},
                }
            },
            "required": [],
            "additionalProperties": False,
        }
        self.install_plugin(
            "def run(context):\n"
            "    child = context.accounts[0]\n"
            "    parent = context.referrals.parent_for(child.id)\n"
            "    assert parent is not None\n"
            "    try:\n"
            "        child.secret('proxy')\n"
            "        target_proxy_granted = True\n"
            "    except KeyError:\n"
            "        target_proxy_granted = False\n"
            "    parent_proxy = parent.secret('proxy')\n"
            "    issued = 'PROJECT-RUNTIME-CODE-' + parent.id[:8] + '-' + child.id[:8]\n"
            "    context.protect_secret(issued)\n"
            "    print('raw-print=' + issued)\n"
            "    import logging\n"
            "    logging.warning('raw-logging=' + issued)\n"
            "    import sys\n"
            "    sys.stderr.buffer.write(('raw-bytes=' + issued + '\\n').encode())\n"
            "    sys.stderr.buffer.flush()\n"
            "    context.log('issued=' + issued, account_id=child.id, "
            "data={'runtime_code': issued})\n"
            "    context.result('Referral checked ' + issued, account_id=child.id, "
            "data={'runtime_code': issued})\n"
            "    context.account_state(child.id, status='succeeded', stage='completed', "
            "progress=1.0, message='completed with ' + issued)\n"
            "    return {'runtime_code': issued, 'target_ids': [item.id for item in context.accounts], "
            "'parent_ids': [item.id for item in context.referrals.parents], "
            "'child_parent_id': child.referrer_account_id, "
            "'child_referral_depth': child.referral_depth, "
            "'target_proxy_granted': target_proxy_granted, "
            "'parent_proxy_granted': bool(parent_proxy), "
            "'effective_concurrency': context.account_concurrency}\n",
            manifest,
        )

        with mock.patch("soft_hub.runner.subprocess.Popen") as popen:
            with self.assertRaisesRegex(VaultError, "Referral Child.*не назначен реферер"):
                self.runs.start(
                    "runner.project-runtime-referral",
                    "run",
                    [identifiers["Referral Child"]],
                )
            popen.assert_not_called()

        initial = self.vault.referral_topology(self.vault.list_accounts())
        self.vault.update_referral_topology(
            initial["revision"],
            [
                {
                    "child_account_id": identifiers["Referral Parent"],
                    "parent_account_id": None,
                },
                {
                    "child_account_id": identifiers["Referral Child"],
                    "parent_account_id": identifiers["Referral Parent"],
                },
            ],
        )
        started = self.runs.start(
            "runner.project-runtime-referral",
            "run",
            [identifiers["Referral Child"]],
            {"account_concurrency": 20},
        )
        run_id = str(started["id"])
        self.assertEqual(started["account_concurrency"], 1)
        pins = self.database.all(
            "SELECT account_id,role FROM run_account_pins WHERE run_id=? ORDER BY role",
            (run_id,),
        )
        self.assertEqual(
            {(row["account_id"], row["role"]) for row in pins},
            {
                (identifiers["Referral Child"], "target"),
                (identifiers["Referral Parent"], "referral_parent"),
            },
        )
        final = self.wait_for_terminal(run_id)
        wait_until(lambda: run_id not in self.runs._threads, timeout=3)
        self.assertEqual(final["status"], "succeeded")
        self.assertEqual(final["summary"]["target_ids"], [identifiers["Referral Child"]])
        self.assertEqual(final["summary"]["parent_ids"], [identifiers["Referral Parent"]])
        self.assertEqual(
            final["summary"]["child_parent_id"], identifiers["Referral Parent"]
        )
        self.assertEqual(final["summary"]["child_referral_depth"], 0)
        self.assertIs(final["summary"]["target_proxy_granted"], False)
        self.assertIs(final["summary"]["parent_proxy_granted"], True)
        self.assertEqual(final["summary"]["effective_concurrency"], 1)
        self.assertEqual(final["summary"]["runtime_code"], "[REDACTED_RUNTIME_SECRET]")
        self.assertEqual(
            self.database.all("SELECT * FROM run_account_pins WHERE run_id=?", (run_id,)),
            [],
            "Terminal finalization must release both target and parent pins",
        )
        secret = (
            "PROJECT-RUNTIME-CODE-"
            + identifiers["Referral Parent"][:8]
            + "-"
            + identifiers["Referral Child"][:8]
        )
        events = self.runs.events(run_id, 0, 500)
        self.assertNotIn(
            "protect_secret",
            {event["event_type"] for event in events},
            "protect_secret is an in-memory control frame, not history",
        )
        persisted = json.dumps(
            {
                "events": events,
                "results": self.runs.results(100),
                "run": final,
                "log": self.runs.technical_log(run_id).decode("utf-8"),
            },
            ensure_ascii=False,
        )
        self.assertNotIn(secret, persisted)
        self.assertIn("[REDACTED_RUNTIME_SECRET]", persisted)

    def test_account_concurrency_is_capped_persisted_and_passed_to_context(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "concurrency-a.test:58110:user-a:pass-a",
                    "concurrency-a@example.test",
                    label="Concurrency A",
                ),
                ImportRecord(
                    TEST_PRIVATE_KEY_B,
                    "concurrency-b.test:58111:user-b:pass-b",
                    "concurrency-b@example.test",
                    label="Concurrency B",
                ),
            ]
        )
        account_ids = [account["id"] for account in self.vault.list_accounts()]
        manifest = plugin_manifest(
            plugin_id="runner.account-concurrency",
            account_mode="one_or_more",
        )
        manifest["compatibility"]["hub"] = ">=0.6.5"
        manifest["actions"][0]["options"] = {
            "type": "object",
            "properties": {
                "account_concurrency": {
                    "type": "integer",
                    "title": "Parallel accounts",
                    "description": "Maximum target workers for this run.",
                    "default": 20,
                    "minimum": 1,
                    "maximum": 20,
                    "multipleOf": 1,
                    "x-ui": {"group": "Выполнение", "order": 0},
                }
            },
            "required": [],
            "additionalProperties": False,
        }
        self.install_plugin(
            "def run(context):\n"
            "    for account in context.accounts:\n"
            "        context.account_state(account.id, status='succeeded', "
            "stage='completed', progress=1.0)\n"
            "    return {'effective': context.account_concurrency, "
            "'option': context.options['account_concurrency'], "
            "'count': len(context.accounts)}\n",
            manifest,
        )

        started = self.runs.start(
            "runner.account-concurrency",
            "run",
            account_ids,
            {"account_concurrency": 20},
        )
        run_id = str(started["id"])
        self.assertEqual(started["account_concurrency"], 2)
        persisted = self.database.one(
            "SELECT account_concurrency FROM runs WHERE id=?", (run_id,)
        )
        assert persisted is not None
        self.assertEqual(persisted["account_concurrency"], 2)
        final = self.wait_for_terminal(run_id)
        self.assertEqual(
            final["summary"], {"effective": 2, "option": 2, "count": 2}
        )
        projected = self.runs.account_states(run_id)
        self.assertEqual({row["account_concurrency"] for row in projected}, {2})

    def test_legacy_capsolver_account_grant_remains_compatible_with_settings(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "capsolver.test:58091:user:pass",
                    "capsolver@example.test",
                )
            ]
        )
        self.vault.set_capsolver_api_key("legacy-capsolver-value")
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = plugin_manifest(
            plugin_id="runner.legacy-capsolver",
            account_mode="one_or_more",
            secrets=["capsolver_api_key"],
        )
        self.install_plugin(
            "def run(context):\n"
            "    return {\n"
            "        'legacy_account': context.accounts[0].secret('capsolver_api_key') == 'legacy-capsolver-value',\n"
            "        'new_settings': context.settings.secret('capsolver') == 'legacy-capsolver-value',\n"
            "    }\n",
            manifest,
        )

        started = self.runs.start("runner.legacy-capsolver", "run", [account_id])
        final = self.wait_for_terminal(str(started["id"]))
        self.assertEqual(final["status"], "succeeded")
        self.assertEqual(
            final["summary"],
            {"legacy_account": True, "new_settings": True},
        )

    def test_heterogeneous_batch_never_unions_action_secret_grants(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "batchscope.test:58083:user:pass",
                    "batchscope@example.test",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = action_scoped_manifest(
            "runner.batch-action-scoped",
            {
                "key_only": ["evm_private_key"],
                "email_only": ["email"],
            },
        )
        self.install_plugin(
            "def run(context):\n"
            "    account = context.accounts[0]\n"
            "    return {\n"
            "        'action': context.action_id,\n"
            "        'has_key': 'evm_private_key' in account,\n"
            "        'has_email': 'email' in account,\n"
            "    }\n",
            manifest,
        )
        admitted = self.runs.start_batch(
            str(uuid.uuid4()),
            [
                {
                    "module_id": "runner.batch-action-scoped",
                    "action_id": action_id,
                    "account_ids": [account_id],
                    "options": {},
                    "acknowledgement": "",
                }
                for action_id in ("key_only", "email_only")
            ],
        )

        summaries: dict[str, dict[str, object]] = {}
        for run in admitted["runs"]:
            run_id = str(run["id"])
            final = self.wait_for_terminal(run_id)
            wait_until(lambda run_id=run_id: run_id not in self.runs._threads, timeout=3)
            self.assertEqual(final["status"], "succeeded")
            summaries[str(final["action_id"])] = final["summary"]
        self.assertEqual(
            summaries,
            {
                "key_only": {
                    "action": "key_only",
                    "has_key": True,
                    "has_email": False,
                },
                "email_only": {
                    "action": "email_only",
                    "has_key": False,
                    "has_email": True,
                },
            },
        )

    def test_locked_vault_denies_account_action_even_with_empty_secret_grant(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "publicscope.test:58084:user:pass",
                    "publicscope@example.test",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = action_scoped_manifest(
            "runner.public-action-locked-vault",
            {
                "public": [],
                "private": ["evm_private_key"],
            },
        )
        self.install_plugin(
            "def run(context):\n"
            "    account = context.accounts[0]\n"
            "    return {'has_key': 'evm_private_key' in account}\n",
            manifest,
        )
        self.vault.lock()

        with self.assertRaisesRegex(VaultError, "Vault заблокирован"):
            self.runs.start(
                "runner.public-action-locked-vault", "public", [account_id]
            )
        with self.assertRaisesRegex(VaultError, "Vault заблокирован"):
            self.runs.start(
                "runner.public-action-locked-vault", "private", [account_id]
            )

    def test_batch_is_persistent_idempotent_and_rejects_key_reuse(self) -> None:
        manifest = plugin_manifest(plugin_id="runner.batch-idempotent")
        self.install_plugin("def run(context):\n    return {'batch': True}\n", manifest)
        idempotency_key = str(uuid.uuid4())
        requests = [
            {
                "module_id": "runner.batch-idempotent",
                "action_id": "run",
                "account_ids": [],
                "options": {},
                "acknowledgement": "",
            },
            {
                "module_id": "runner.batch-idempotent",
                "action_id": "run",
                "account_ids": [],
                "options": {},
                "acknowledgement": "",
            },
        ]

        admitted = self.runs.start_batch(idempotency_key, requests)
        self.assertIs(admitted["replayed"], False)
        run_ids = [str(run["id"]) for run in admitted["runs"]]
        self.assertEqual(len(run_ids), 2)
        self.assertEqual(len(set(run_ids)), 2)
        for run_id in run_ids:
            self.wait_for_terminal(run_id)
            wait_until(lambda run_id=run_id: run_id not in self.runs._threads, timeout=3)

        replayed = self.runs.start_batch(idempotency_key, requests)
        self.assertIs(replayed["replayed"], True)
        self.assertEqual([run["id"] for run in replayed["runs"]], run_ids)
        self.assertEqual(
            self.database.one(
                "SELECT length(request_sha256) AS digest_length FROM run_batches "
                "WHERE idempotency_key=?",
                (idempotency_key,),
            ),
            {"digest_length": 64},
        )
        self.assertEqual(
            self.database.all(
                "SELECT ordinal,run_id FROM run_batch_items WHERE idempotency_key=? "
                "ORDER BY ordinal",
                (idempotency_key,),
            ),
            [
                {"ordinal": 0, "run_id": run_ids[0]},
                {"ordinal": 1, "run_id": run_ids[1]},
            ],
        )

        replacement = RunManager(self.database, self.paths, self.plugins, self.vault)
        persistent_replay = replacement.start_batch(idempotency_key, requests)
        self.assertIs(persistent_replay["replayed"], True)
        self.assertEqual(
            [run["id"] for run in persistent_replay["runs"]],
            run_ids,
        )

        with self.assertRaisesRegex(IdempotencyConflictError, "другой пачки"):
            self.runs.start_batch(idempotency_key, requests[:1])
        self.assertEqual(
            self.database.one(
                "SELECT COUNT(*) AS count FROM runs WHERE module_id=?",
                ("runner.batch-idempotent",),
            ),
            {"count": 2},
        )

    def test_batch_preflight_and_lease_failure_are_all_or_nothing(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "batchproxy.test:58080:user:pass",
                    "batch@example.test",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        read_manifest = plugin_manifest(plugin_id="runner.batch-read")
        write_manifest = plugin_manifest(
            plugin_id="runner.batch-write",
            action_risk="testnet_write",
            account_mode="one_or_more",
            chains=[111],
        )
        self.install_plugin("def run(context):\n    return {'read': True}\n", read_manifest)
        self.install_plugin("def run(context):\n    return {'write': True}\n", write_manifest)
        owner_id = "existing-batch-lease-owner"
        self.database.execute(
            "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,account_count,requested_at) "
            "VALUES (?,'runner.batch-write','1.0.0','run','queued',0,1,?)",
            (owner_id, utc_now()),
        )
        with self.database.transaction() as connection:
            self.runs._acquire_leases(connection, owner_id, [account_id], [111])

        requests = [
            {
                "module_id": "runner.batch-read",
                "action_id": "run",
                "account_ids": [],
                "options": {},
                "acknowledgement": "",
            },
            {
                "module_id": "runner.batch-write",
                "action_id": "run",
                "account_ids": [account_id],
                "options": {},
                "acknowledgement": "TESTNET",
            },
        ]
        before = self.database.one("SELECT COUNT(*) AS count FROM runs")["count"]
        with self.assertRaisesRegex(RunError, "chainId=111"):
            self.runs.start_batch(str(uuid.uuid4()), requests)
        self.assertEqual(
            self.database.one("SELECT COUNT(*) AS count FROM runs")["count"], before
        )
        self.assertEqual(self.database.all("SELECT * FROM run_batches"), [])
        self.assertEqual(self.database.all("SELECT * FROM run_batch_items"), [])
        self.assertEqual(self.runs._threads, {})

        with self.assertRaisesRegex(RunError, "не найден или выключен"):
            self.runs.start_batch(
                str(uuid.uuid4()),
                [requests[0], {**requests[0], "module_id": "runner.missing"}],
            )
        self.assertEqual(
            self.database.one("SELECT COUNT(*) AS count FROM runs")["count"], before
        )

    def test_batch_denies_mainnet_before_creating_any_run(self) -> None:
        manifest = plugin_manifest(
            plugin_id="runner.batch-mainnet",
            action_risk="mainnet_write",
            account_mode="one_or_more",
            chains=[1],
        )
        self.install_plugin("def run(context):\n    return {'unsafe': True}\n", manifest)
        with self.assertRaisesRegex(RunError, "Mainnet"):
            self.runs.start_batch(
                str(uuid.uuid4()),
                [
                    {
                        "module_id": "runner.batch-mainnet",
                        "action_id": "run",
                        "account_ids": [],
                        "options": {},
                        "acknowledgement": "CONFIRM TEST MAINNET",
                    }
                ],
            )
        self.assertEqual(
            self.database.all(
                "SELECT * FROM runs WHERE module_id='runner.batch-mainnet'"
            ),
            [],
        )
        self.assertEqual(self.database.all("SELECT * FROM run_batches"), [])

    def test_queued_secret_run_decrypts_only_after_it_owns_a_slot(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "queuedproxy.test:58081:user:pass",
                    "queued@example.test",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = plugin_manifest(
            plugin_id="runner.deferred-secrets",
            action_risk="testnet_write",
            account_mode="one_or_more",
            secrets=["evm_private_key", "proxy"],
            chains=[222],
        )
        self.install_plugin("def run(context):\n    return {'late': True}\n", manifest)

        self.runs._slots = threading.BoundedSemaphore(1)
        self.runs._slots.acquire()
        slot_released = False
        try:
            with mock.patch.object(
                self.vault,
                "bundles_for_runner",
                wraps=self.vault.bundles_for_runner,
            ) as bundles:
                started = self.runs.start(
                    "runner.deferred-secrets",
                    "run",
                    [account_id],
                    acknowledgement="TESTNET",
                )
                run_id = str(started["id"])
                wait_until(lambda: run_id in self.runs._threads, timeout=3)
                self.assertEqual(bundles.call_count, 0)
                self.assertEqual(self.runs.get(run_id)["status"], "queued")
                self.assertEqual(
                    len(
                        self.database.all(
                            "SELECT * FROM account_leases WHERE run_id=?", (run_id,)
                        )
                    ),
                    1,
                )

                self.vault.lock()
                self.runs._slots.release()
                slot_released = True
                final = self.wait_for_terminal(run_id)
                wait_until(lambda: run_id not in self.runs._threads, timeout=3)
                self.assertEqual(bundles.call_count, 1)
                self.assertEqual(final["status"], "failed")
                self.assertIn("Vault заблокирован", final["error"])
                self.assertNotIn(run_id, self.runs._processes)
                self.assertEqual(
                    self.database.all(
                        "SELECT * FROM account_leases WHERE run_id=?", (run_id,)
                    ),
                    [],
                )
        finally:
            if not slot_released:
                self.runs._slots.release()

    def test_run_options_are_validated_server_side_before_run_creation(self) -> None:
        manifest = plugin_manifest(plugin_id="runner.validated-options")
        manifest["actions"][0]["options"] = {
            "type": "object",
            "required": ["count", "ratio", "mode", "enabled"],
            "properties": {
                "count": {
                    "type": "integer",
                    "minimum": 2,
                    "maximum": 6,
                    "multipleOf": 2,
                },
                "ratio": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                    "multipleOf": 0.1,
                },
                "mode": {"type": "string", "enum": ["safe", "fast"]},
                "enabled": {"type": "boolean"},
                "delay_from": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10,
                    "multipleOf": 1,
                    "x-ui": {"control": "dual_range", "range": {"id": "delay", "role": "from"}},
                },
                "delay_to": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10,
                    "multipleOf": 1,
                    "x-ui": {"control": "dual_range", "range": {"id": "delay", "role": "to"}},
                },
            },
        }
        self.install_plugin(
            "def run(context):\n    return {'options': context.options}\n",
            manifest,
        )
        valid = {"count": 4, "ratio": 0.3, "mode": "safe", "enabled": True, "delay_from": 3, "delay_to": 8}
        invalid_cases = (
            ("unknown", {**valid, "injected": "bypass"}, "неизвестное поле"),
            ("required", {key: value for key, value in valid.items() if key != "mode"}, "обязательное"),
            ("bool as integer", {**valid, "count": True}, "неверный тип"),
            ("bool as number", {**valid, "ratio": False}, "неверный тип"),
            ("integer as bool", {**valid, "enabled": 1}, "неверный тип"),
            ("enum", {**valid, "mode": "unsafe"}, "недопустимое значение"),
            ("minimum", {**valid, "count": 0}, "minimum"),
            ("maximum", {**valid, "count": 8}, "maximum"),
            ("integer multiple", {**valid, "count": 3}, "multipleOf"),
            ("number multiple", {**valid, "ratio": 0.35}, "multipleOf"),
            ("reversed range", {**valid, "delay_from": 9, "delay_to": 4}, "from больше to"),
            ("half range", {key: value for key, value in valid.items() if key != "delay_to"}, "требует значения from и to"),
            ("nan", {**valid, "ratio": float("nan")}, "неверный тип"),
            ("infinity", {**valid, "ratio": float("inf")}, "неверный тип"),
        )
        for label, options, message in invalid_cases:
            with self.subTest(label=label), self.assertRaisesRegex(RunError, message):
                self.runs.start("runner.validated-options", "run", [], options)
        self.assertEqual(
            self.database.all(
                "SELECT * FROM runs WHERE module_id='runner.validated-options'"
            ),
            [],
        )

        started = self.runs.start("runner.validated-options", "run", [], valid)
        run_id = str(started["id"])
        final = wait_until(
            lambda: (
                current
                if (current := self.runs.get(run_id))
                and current["status"] in TERMINAL_STATUSES
                else None
            ),
            timeout=5,
        )
        self.assertEqual(final["status"], "succeeded")
        self.assertEqual(final["summary"], {"options": valid})


class AccountLeaseTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="soft-hub-lease-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.paths = HubPaths.create(self.root / "data")
        self.database = Database(self.paths)
        self.vault = Vault(self.database)
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "leaseproxy1.test:38080:user-a:pass-a",
                    "lease-a@example.test",
                    label="Lease A",
                ),
                ImportRecord(
                    TEST_PRIVATE_KEY_B,
                    "leaseproxy2.test:38081:user-b:pass-b",
                    "lease-b@example.test",
                    label="Lease B",
                ),
            ]
        )
        self.account_ids = [item["id"] for item in self.vault.list_accounts()]
        self.manifest = plugin_manifest(
            plugin_id="lease.plugin",
            action_risk="testnet_write",
            account_mode="one_or_more",
            chains=[111, 222],
        )
        now = utc_now()
        self.database.execute(
            "INSERT INTO modules(id,name,version,description,active_path,manifest_json,enabled,"
            "trust_status,health,installed_at,updated_at) VALUES (?,?,?,?,?,?,1,'local_unsigned','ready',?,?)",
            (
                "lease.plugin",
                "Lease Plugin",
                "1.0.0",
                "Lease fixture",
                str(self.root / "unused-plugin"),
                json.dumps(self.manifest),
                now,
                now,
            ),
        )
        self.plugins = PluginManager(self.database, self.paths)
        self.runs = RunManager(self.database, self.paths, self.plugins, self.vault)

    def insert_run(self, run_id: str, status: str = "queued") -> None:
        self.database.execute(
            "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,account_count,requested_at) "
            "VALUES (?,'lease.plugin','1.0.0','run',?,0,2,?)",
            (run_id, status, utc_now()),
        )

    def test_conflicting_lease_acquisition_rolls_back_the_entire_batch(self) -> None:
        self.insert_run("owner")
        self.insert_run("contender")
        with self.database.transaction() as connection:
            self.runs._acquire_leases(connection, "owner", [self.account_ids[1]], [222])

        with self.assertRaisesRegex(RunError, "chainId=222"):
            with self.database.transaction() as connection:
                self.runs._acquire_leases(
                    connection,
                    "contender",
                    self.account_ids,
                    [111, 222],
                )

        leases = self.database.all(
            "SELECT chain_id,account_id,run_id FROM account_leases ORDER BY chain_id,account_id"
        )
        self.assertEqual(
            leases,
            [{"chain_id": 222, "account_id": self.account_ids[1], "run_id": "owner"}],
        )

    def test_expired_leases_are_replaced_and_release_is_scoped_to_run(self) -> None:
        self.insert_run("expired-owner")
        self.insert_run("replacement")
        with self.database.transaction() as connection:
            self.runs._acquire_leases(connection, "expired-owner", [self.account_ids[0]], [111])
        self.database.execute(
            "UPDATE account_leases SET expires_at=? WHERE run_id='expired-owner'",
            ((datetime.now(UTC) - timedelta(minutes=1)).isoformat(),),
        )

        with self.database.transaction() as connection:
            self.runs._acquire_leases(connection, "replacement", [self.account_ids[0]], [111])
        lease = self.database.one("SELECT * FROM account_leases WHERE chain_id=111")
        assert lease is not None
        self.assertEqual(lease["run_id"], "replacement")
        self.assertGreater(lease["expires_at"], datetime.now(UTC).isoformat())

        self.runs._release_leases("expired-owner")
        self.assertIsNotNone(self.database.one("SELECT * FROM account_leases WHERE run_id='replacement'"))
        self.runs._release_leases("replacement")
        self.assertEqual(self.database.all("SELECT * FROM account_leases"), [])

    def test_leased_account_cannot_be_deleted_until_lease_is_released(self) -> None:
        self.insert_run("delete-owner")
        account_id = self.account_ids[0]
        with self.database.transaction() as connection:
            self.runs._acquire_leases(connection, "delete-owner", [account_id], [111])

        with self.assertRaisesRegex(VaultError, "занят write-задачей"):
            self.vault.delete_account(account_id)
        self.assertIsNotNone(
            self.database.one("SELECT id FROM accounts WHERE id=?", (account_id,))
        )
        self.assertIsNotNone(
            self.database.one("SELECT run_id FROM account_leases WHERE account_id=?", (account_id,))
        )

        self.runs._release_leases("delete-owner")
        self.assertTrue(self.vault.delete_account(account_id))
        self.assertIsNone(
            self.database.one("SELECT id FROM accounts WHERE id=?", (account_id,))
        )

    def test_startup_recovery_fails_orphans_and_releases_stale_leases(self) -> None:
        active_statuses = ("queued", "starting", "running", "cancelling")
        for status in (*active_statuses, "succeeded", "needs_attention"):
            self.insert_run(f"run-{status}", status)
        with self.database.transaction() as connection:
            self.runs._acquire_leases(connection, "run-running", [self.account_ids[0]], [111])
            self.runs._acquire_leases(
                connection, "run-needs_attention", [self.account_ids[0]], [222]
            )

        RunManager(self.database, self.paths, self.plugins, self.vault)
        for status in active_statuses:
            row = self.database.one("SELECT * FROM runs WHERE id=?", (f"run-{status}",))
            assert row is not None
            self.assertEqual(row["status"], "failed")
            self.assertIsNotNone(row["finished_at"])
            self.assertIn("restarted", row["error"])
        self.assertEqual(
            self.database.one("SELECT status FROM runs WHERE id='run-succeeded'")["status"],
            "succeeded",
        )
        legacy_attention = self.database.one(
            "SELECT status,error FROM runs WHERE id='run-needs_attention'"
        )
        self.assertEqual(
            legacy_attention,
            {"status": "failed", "error": "external_state_unknown"},
        )
        self.assertTrue(
            any(
                event["event_type"] == "attention_released"
                for event in self.runs.events("run-needs_attention")
            )
        )
        self.assertEqual(self.database.all("SELECT * FROM account_leases"), [])


if __name__ == "__main__":
    unittest.main()
