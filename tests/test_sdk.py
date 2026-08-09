from __future__ import annotations

import json
import threading
import time
import unittest

from soft_hub.sdk import HubAccount, HubContext, HubReferrals, decode_context


class HubSdkContractTests(unittest.TestCase):
    @staticmethod
    def context(
        *,
        accounts: int = 4,
        concurrency: int = 2,
        events: list[dict[str, object]] | None = None,
    ) -> HubContext:
        return HubContext(
            run_id="00000000-0000-0000-0000-000000000001",
            plugin_id="test.sdk",
            plugin_version="1.0.0",
            action_id="run",
            options={"account_concurrency": concurrency},
            accounts=tuple(
                HubAccount({"id": f"account-{index}", "label": f"Account {index}"})
                for index in range(accounts)
            ),
            plugin_root="/plugin",
            scratch_dir="/scratch",
            _emit_raw=(events.append if events is not None else lambda _event: None),
            _cancelled=threading.Event(),
            account_concurrency=concurrency,
        )

    def test_map_accounts_is_bounded_and_preserves_input_order(self) -> None:
        context = self.context(accounts=6, concurrency=2)
        lock = threading.Lock()
        active = 0
        maximum_active = 0

        def worker(account: HubAccount) -> str:
            nonlocal active, maximum_active
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.02)
            with lock:
                active -= 1
            return account.id

        results = context.map_accounts(worker)

        self.assertEqual(results, tuple(f"account-{index}" for index in range(6)))
        self.assertEqual(maximum_active, 2)

    def test_runtime_project_secret_is_removed_from_every_structured_output(self) -> None:
        events: list[dict[str, object]] = []
        context = self.context(events=events)
        issued_code = "PROJECT-ISSUED-CODE-884291"
        context.protect_secret(issued_code)
        context.protect_secret(issued_code)

        sanitized = context.sanitize_value(
            {
                "summary": issued_code,
                issued_code: [f"prefix:{issued_code}:suffix"],
            }
        )

        projection = json.dumps(sanitized, ensure_ascii=False)
        self.assertNotIn(issued_code, projection)
        self.assertIn("REDACTED_RUNTIME_SECRET", projection)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "protect_secret")

    def test_referral_view_exposes_only_exact_direct_parents(self) -> None:
        referrals = HubReferrals(
            {
                "mode": "project_runtime",
                "revision": "a" * 64,
                "links": [
                    {
                        "child_account_id": "child-a",
                        "parent_account_id": "parent-a",
                        "depth": 1,
                    },
                    {
                        "child_account_id": "root-b",
                        "parent_account_id": None,
                        "depth": 0,
                    },
                ],
                "parents": [
                    {"id": "parent-a", "label": "Parent A", "proxy": "secret-proxy"}
                ],
            }
        )

        parent = referrals.parent_for("child-a")
        assert parent is not None
        self.assertEqual(parent.id, "parent-a")
        self.assertEqual(parent.secret("proxy"), "secret-proxy")
        self.assertIsNone(referrals.parent_for("root-b"))
        with self.assertRaises(KeyError):
            referrals.parent_for("not-selected")
        self.assertNotIn("secret-proxy", repr(referrals))

    def test_decode_context_rejects_invalid_concurrency(self) -> None:
        base = {
            "run_id": "run",
            "plugin_id": "plugin",
            "plugin_version": "1.0.0",
            "action_id": "run",
            "options": {},
            "accounts": [],
            "plugin_root": "/plugin",
            "scratch_dir": "/scratch",
        }
        for value in (True, 0, 21, 1.5, "4"):
            with self.subTest(value=value), self.assertRaisesRegex(
                ValueError, "account_concurrency"
            ):
                decode_context(
                    json.dumps({**base, "account_concurrency": value}),
                    lambda _event: None,
                    threading.Event(),
                )


if __name__ == "__main__":
    unittest.main()
