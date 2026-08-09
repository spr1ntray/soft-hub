from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

from soft_hub.config import HubPaths
from soft_hub.database import Database
from soft_hub.plugins import PluginManager
from soft_hub.runner import RunError, RunManager
from soft_hub.vault import ImportRecord, Vault
from tests.support import (
    TEST_MASTER_PASSWORD,
    TEST_PRIVATE_KEY_A,
    plugin_manifest,
    wait_until,
    write_plugin_archive,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATIC_ROOT = PROJECT_ROOT / "soft_hub" / "static"
TERMINAL_STATUSES = {"succeeded", "failed", "cancelled", "needs_attention"}


class RunFormSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (STATIC_ROOT / "index.html").read_text(encoding="utf-8")
        cls.javascript = (STATIC_ROOT / "app.js").read_text(encoding="utf-8")

    def test_numeric_options_have_explicit_steps_and_testnet_ack_is_hub_owned(self) -> None:
        """Keep decimal defaults valid and expose only the Hub risk confirmation."""
        helper = re.search(
            r"function optionNumberStep\(type, field\) \{(?P<body>.*?)\n\}",
            self.javascript,
            re.DOTALL,
        )
        self.assertIsNotNone(helper)
        helper_body = helper.group("body")
        self.assertRegex(
            helper_body,
            r"type\s*===\s*['\"]integer['\"].*return\s+['\"]1['\"]",
        )
        self.assertIn("field.multipleOf", helper_body)
        self.assertIn("Number.isFinite(multiple)", helper_body)
        self.assertRegex(helper_body, r"multiple\s*>\s*0")
        self.assertRegex(helper_body, r"return.*['\"]any['\"]")
        self.assertIn("optionNumberStep(type, field)", self.javascript)
        self.assertRegex(self.javascript, r"step=.{0,100}optionNumberStep\(type, field\)")
        option_entries = self.javascript[
            self.javascript.index("function optionEntries(action)"):
            self.javascript.index("function optionValueLabel(value)")
        ]
        self.assertIn("Object.entries(properties)", option_entries)
        self.assertIn("key === 'acknowledge_testnet_transactions'", option_entries)
        self.assertIn("field.type === 'boolean'", option_entries)
        self.assertEqual(
            self.html.count('id="risk-confirmation"'),
            1,
            "A testnet action must have exactly one visible Hub-owned confirmation",
        )

    def test_run_form_has_singleton_default_empty_state_and_client_account_guard(self) -> None:
        self.assertIn('id="run-form" class="run-workbench" novalidate', self.html)
        self.assertIn('class="run-account-empty"', self.javascript)
        self.assertIn("data-import-for-run", self.javascript)
        self.assertIn("function updateRunAccountSelection", self.javascript)
        self.assertRegex(
            self.javascript,
            r"boxes\.length\s*===\s*1",
        )
        self.assertIn("updateRunForm({ applyAccountDefault: true })", self.javascript)
        self.assertRegex(
            self.javascript,
            r"account_mode\s*===\s*['\"]one_or_more['\"].{0,1000}!accountIds\.length|"
            r"!accountIds\.length.{0,1000}account_mode\s*===\s*['\"]one_or_more['\"]",
        )
        guard_position = self.javascript.find("!accountIds.length")
        post_position = self.javascript.find("jsonPost(`/api/modules/", guard_position)
        self.assertGreaterEqual(guard_position, 0)
        self.assertGreater(
            post_position,
            guard_position,
            "The empty-account guard must run before the API request",
        )
        self.assertRegex(
            self.javascript,
            r"action\.account_mode\s*===\s*['\"]none['\"]\s*\?\s*\[\]",
            "Switching to an account-free action must not submit preserved checkbox IDs",
        )
        self.assertRegex(
            self.javascript,
            r"(?s)const selectedIds\s*=\s*actionChanged\s*\?\s*\[\]\s*:\s*"
            r"\$\$\(['\"]input\[name=['\"]run-account['\"]\]:checked['\"]\)",
            "A multi-account selection must never carry into a different action",
        )
        self.assertIn("renderRunAccounts(action, selectedIds)", self.javascript)
        self.assertIn("input[name=\"run-account\"]:not(:disabled)", self.javascript)
        self.assertIn("$('#run-modal').dataset.busy === 'true'", self.javascript)
        self.assertNotIn("safeBatchDefault", self.javascript)


class TrustedTestnetAcknowledgementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="soft-hub-testnet-ack-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.paths = HubPaths.create(self.root / "data")
        self.database = Database(self.paths)
        self.vault = Vault(self.database)
        self.plugins = PluginManager(self.database, self.paths)
        self.runs = RunManager(self.database, self.paths, self.plugins, self.vault)
        self.addCleanup(self.runs.shutdown)

    def wait_for_terminal(self, run_id: str) -> dict[str, object]:
        def current() -> dict[str, object] | None:
            run = self.runs.get(run_id)
            return run if run and run["status"] in TERMINAL_STATUSES else None

        return wait_until(current, timeout=12.0)

    def test_verified_testnet_ack_is_injected_and_cannot_be_spoofed_by_options(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)
        self.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "trusted-ack-proxy.test:38080:user:pass",
                    "trusted-ack@example.test",
                    label="Trusted Ack Account",
                )
            ]
        )
        account_id = self.vault.list_accounts()[0]["id"]
        manifest = plugin_manifest(
            plugin_id="runner.trusted-testnet-ack",
            action_risk="testnet_write",
            account_mode="one_or_more",
            chains=[84532],
        )
        manifest["actions"][0]["options"] = {
            "type": "object",
            "required": ["acknowledge_testnet_transactions"],
            "properties": {
                "acknowledge_testnet_transactions": {
                    "type": "boolean",
                    "default": False,
                },
                "marker": {"type": "string"},
            },
        }
        source = '''def run(context):
    trusted = context.options.get("acknowledge_testnet_transactions")
    if trusted is not True:
        raise RuntimeError("trusted testnet acknowledgement missing")
    return {"trusted_ack": trusted, "marker": context.options.get("marker")}
'''
        archive = write_plugin_archive(
            self.root / "trusted-testnet-ack.zip",
            manifest,
            files={"plugin/main.py": source},
        )
        self.plugins.install(archive)

        with self.assertRaisesRegex(RunError, "TESTNET"):
            self.runs.start(
                "runner.trusted-testnet-ack",
                "run",
                [account_id],
                {"acknowledge_testnet_transactions": True},
                acknowledgement="",
            )

        client_options = {
            "acknowledge_testnet_transactions": False,
            "marker": "preserved",
        }
        started = self.runs.start(
            "runner.trusted-testnet-ack",
            "run",
            [account_id],
            client_options,
            acknowledgement="TESTNET",
        )
        completed = self.wait_for_terminal(str(started["id"]))
        wait_until(
            lambda: str(started["id"]) not in self.runs._threads,
            timeout=3.0,
        )

        self.assertEqual(completed["status"], "succeeded")
        self.assertEqual(
            completed["summary"],
            {"trusted_ack": True, "marker": "preserved"},
        )
        self.assertIs(
            client_options["acknowledge_testnet_transactions"],
            False,
            "Admission must copy caller options before injecting its trusted value",
        )


if __name__ == "__main__":
    unittest.main()
