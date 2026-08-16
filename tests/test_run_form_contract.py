from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from soft_hub.config import HubPaths
from soft_hub.database import Database
from soft_hub.plugins import PluginManager
from soft_hub.runner import RunManager
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

    def test_numeric_options_have_explicit_steps_without_confirmation_inputs(self) -> None:
        """Keep decimal defaults valid without adding a second launch gate."""
        helper = re.search(
            r"function optionNumberStep\(type, field\) \{(?P<body>.*?)\n\}",
            self.javascript,
            re.DOTALL,
        )
        self.assertIsNotNone(helper)
        helper_body = helper.group("body")
        self.assertIn("field.multipleOf", helper_body)
        self.assertIn("Number.isFinite(multiple)", helper_body)
        self.assertRegex(helper_body, r"multiple\s*>\s*0")
        self.assertIn("return type === 'integer' ? '1' : 'any'", helper_body)
        self.assertLess(
            helper_body.index("return String(multiple)"),
            helper_body.index("type === 'integer'"),
            "An integer multipleOf must win over the fallback step of one",
        )
        self.assertIn("optionNumberStep(type, field)", self.javascript)
        self.assertRegex(self.javascript, r"step=.{0,100}optionNumberStep\(type, field\)")
        for contract in (
            "function optionSliderConfig(type, field)",
            "function optionSingleSliderMarkup(",
            "function optionRangeFieldMarkup(",
            "function bindOptionSliders(root)",
            'type="range" data-option-slider',
            'data-option-range-slider="minimum"',
            'data-option-range-slider="maximum"',
            "field.dataset.optionMultiple",
        ):
            self.assertIn(contract, self.javascript)
        option_entries = self.javascript[
            self.javascript.index("function optionEntries(action)"):
            self.javascript.index("function optionValueLabel(value)")
        ]
        self.assertIn("Object.entries(properties)", option_entries)
        self.assertIn("key === 'acknowledge_testnet_transactions'", option_entries)
        self.assertIn("field.type === 'boolean'", option_entries)
        self.assertNotIn('id="risk-confirmation"', self.html)
        self.assertNotIn('id="mainnet-confirmation"', self.html)
        run_submit = self.javascript[
            self.javascript.index("async function handleRunSubmit("):
            self.javascript.index("function drawerAccountTableMarkup(")
        ]
        self.assertNotIn("acknowledgement", run_submit)

    def test_dual_range_uses_two_canonical_values_and_rejects_reversed_bounds(self) -> None:
        range_renderer = self.javascript[
            self.javascript.index("function optionRangeFieldMarkup("):
            self.javascript.index("function optionFieldMarkup(")
        ]
        self.assertIn("<fieldset", range_renderer)
        self.assertIn('<legend class="sr-only">', range_renderer)
        self.assertEqual(range_renderer.count("optionNumericInputMarkup("), 2)
        self.assertNotIn('data-option-key=', range_renderer.split('type="range"')[1])
        collector = self.javascript[
            self.javascript.index("function collectOptions()"):
            self.javascript.index("async function handleRunSubmit(")
        ]
        self.assertIn("[data-option-range-group]", collector)
        self.assertIn("Number(fromField.value) > Number(toField.value)", collector)

    def test_slider_math_respects_integer_multiple_and_control_size_limit(self) -> None:
        helpers = self.javascript[
            self.javascript.index("function optionNumberStep("):
            self.javascript.index("function optionUi(")
        ]
        script = "\n".join(
            (
                helpers,
                "if (optionNumberStep('integer', {multipleOf:2}) !== '2') throw new Error('integer multiple');",
                "if (optionNumberStep('integer', {}) !== '1') throw new Error('integer fallback');",
                "const integer = optionSliderConfig('integer', {minimum:2,maximum:20,multipleOf:2});",
                "if (!integer || integer.step !== 2 || integer.minimum !== 2 || integer.maximum !== 20) throw new Error(JSON.stringify(integer));",
                "const decimal = optionSliderConfig('number', {minimum:0,maximum:1,multipleOf:0.1});",
                "if (!decimal || decimal.step !== 0.1) throw new Error(JSON.stringify(decimal));",
                "if (optionSliderConfig('integer', {minimum:0,maximum:5000,multipleOf:1}) !== null) throw new Error('too many ticks');",
                "if (optionSliderConfig('integer', {minimum:1,maximum:10,multipleOf:0.5}) !== null) throw new Error('fractional integer grid');",
            )
        )
        completed = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

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

    def test_testnet_legacy_flag_is_injected_without_typed_confirmation(self) -> None:
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

        client_options = {
            "acknowledge_testnet_transactions": False,
            "marker": "preserved",
        }
        started = self.runs.start(
            "runner.trusted-testnet-ack",
            "run",
            [account_id],
            client_options,
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
