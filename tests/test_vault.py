from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from eth_account import Account

from soft_hub.config import HubPaths
from soft_hub.database import Database
from soft_hub import vault as vault_module
from soft_hub.vault import (
    PLAINTEXT_EXPORT_ACKNOWLEDGEMENT,
    ImportRecord,
    ReferralRevisionConflict,
    Vault,
    VaultError,
    normalize_private_key,
    parse_proxy,
)
from tests.support import (
    TEST_MASTER_PASSWORD,
    TEST_PRIVATE_KEY_A,
    TEST_PRIVATE_KEY_B,
    TEST_PRIVATE_KEY_C,
)


class VaultTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="soft-hub-vault-test-")
        self.addCleanup(self.temporary.cleanup)
        self.paths = HubPaths.create(Path(self.temporary.name))
        self.database = Database(self.paths)
        self.vault = Vault(self.database)

    @staticmethod
    def record(
        private_key: str = TEST_PRIVATE_KEY_A,
        *,
        proxy: str = "proxy1.test:18080:user-a:pass-a",
        email: str = "alpha@example.test",
        email_password: str = "mail-pass-a",
        twitter: str | None = "@alpha:twitter-pass-a",
        adspower_profile: str | None = None,
        label: str = "Alpha",
        tags: tuple[str, ...] = ("beta", "alpha", "beta"),
    ) -> ImportRecord:
        return ImportRecord(
            private_key=private_key,
            proxy=proxy,
            email=email,
            email_password=email_password,
            twitter=twitter,
            adspower_profile=adspower_profile,
            label=label,
            tags=tags,
        )

    def create_vault(self) -> None:
        self.vault.create(TEST_MASTER_PASSWORD)

    def test_create_lock_unlock_and_key_zeroization(self) -> None:
        self.assertFalse(self.vault.exists)
        self.assertFalse(self.vault.unlocked)

        for password in ("short", "aaaaaaaaaaaaaa"):
            with self.subTest(password=password), self.assertRaises(VaultError):
                self.vault.create(password)
        self.assertFalse(self.vault.exists)

        self.create_vault()
        self.assertTrue(self.vault.exists)
        self.assertTrue(self.vault.unlocked)
        with self.assertRaisesRegex(VaultError, "уже создан"):
            self.vault.create(TEST_MASTER_PASSWORD)

        live_key = self.vault._key
        self.assertIsNotNone(live_key)
        self.assertTrue(any(live_key or b""))
        self.vault.lock()
        self.assertFalse(self.vault.unlocked)
        self.assertEqual(live_key, bytearray(len(live_key or b"")))

        with self.assertRaisesRegex(VaultError, "Неверный"):
            self.vault.unlock("Wrong Password 99!")
        self.assertFalse(self.vault.unlocked)
        self.vault.unlock(TEST_MASTER_PASSWORD)
        self.assertTrue(self.vault.unlocked)

    def test_verify_password_never_changes_current_lock_state_or_live_key(self) -> None:
        with self.assertRaisesRegex(VaultError, "ещё не создан"):
            self.vault.verify_password(TEST_MASTER_PASSWORD)

        self.create_vault()
        live_key = self.vault._key
        assert live_key is not None
        live_copy = bytes(live_key)
        self.assertTrue(self.vault.verify_password(TEST_MASTER_PASSWORD))
        self.assertFalse(self.vault.verify_password("Wrong Password 99!"))
        self.assertIs(self.vault._key, live_key)
        self.assertEqual(bytes(live_key), live_copy)
        self.assertTrue(self.vault.unlocked)

        self.vault.lock()
        self.assertTrue(self.vault.verify_password(TEST_MASTER_PASSWORD))
        self.assertFalse(self.vault.verify_password("Wrong Password 99!"))
        self.assertFalse(self.vault.unlocked)

    def test_kdf_profile_and_password_size_are_bounded_fail_closed(self) -> None:
        with self.assertRaisesRegex(VaultError, "размер"):
            self.vault.create("Correct Horse " + "x" * 5000)

        self.create_vault()
        self.vault.lock()
        for config in (
            {**vault_module._KDF, "n": 2**30},
            {**vault_module._KDF, "p": True},
            {**vault_module._KDF, "extra": 1},
            [vault_module._KDF],
        ):
            with self.subTest(config=config):
                self.database.execute(
                    "UPDATE vault_meta SET kdf_json=? WHERE singleton=1",
                    (json.dumps(config),),
                )
                with self.assertRaisesRegex(VaultError, "KDF|целостности"):
                    self.vault.unlock(TEST_MASTER_PASSWORD)

    def test_private_key_and_proxy_normalization_rejects_ambiguous_input(self) -> None:
        self.assertEqual(normalize_private_key("  " + "AB" * 32 + "  "), "0x" + "ab" * 32)
        self.assertEqual(normalize_private_key("0X" + "CD" * 32), "0x" + "cd" * 32)
        for invalid in ("", "0x1234", "gg" * 32, "0x" + "11" * 33):
            with self.subTest(private_key=invalid), self.assertRaises(VaultError):
                normalize_private_key(invalid)

        self.assertEqual(
            parse_proxy(" http://Proxy1.Test:8080:user:pass "),
            ("proxy1.test:8080:user:pass", "Proxy1.Test:8080"),
        )
        self.assertEqual(
            parse_proxy("user:pass@proxy2.test:8081"),
            ("proxy2.test:8081:user:pass", "proxy2.test:8081"),
        )
        for invalid in (
            "https://proxy1.test:8080:user:pass",
            "proxy1.test:0:user:pass",
            "proxy1.test:65536:user:pass",
            "proxy1.test:not-a-port:user:pass",
            "proxy1.test:8080:user",
            "proxy1.test:8080::pass",
        ):
            with self.subTest(proxy=invalid), self.assertRaises(VaultError):
                parse_proxy(invalid)

    def test_import_encrypts_secrets_and_only_grants_requested_permissions(self) -> None:
        self.create_vault()
        outcome = self.vault.import_records([self.record()])
        self.assertEqual(outcome, {"inserted": 1, "updated": 0, "total": 1})

        accounts = self.vault.list_accounts()
        self.assertEqual(len(accounts), 1)
        account = accounts[0]
        self.assertEqual(account["label"], "Alpha")
        self.assertEqual(account["proxy_label"], "proxy1.test:18080")
        self.assertEqual(account["email_label"], "a••••@example.test")
        self.assertIs(account["twitter_configured"], True)
        self.assertIs(account["email_password_configured"], True)
        self.assertIs(account["adspower_configured"], False)
        self.assertEqual(account["tags"], ["alpha", "beta"])
        public_json = json.dumps(account, ensure_ascii=False)
        for secret in (
            TEST_PRIVATE_KEY_A,
            "user-a",
            "pass-a",
            "mail-pass-a",
            "@alpha",
            "twitter-pass-a",
        ):
            self.assertNotIn(secret, public_json)

        encrypted = self.database.one(
            "SELECT nonce,ciphertext FROM account_secrets WHERE account_id=?", (account["id"],)
        )
        self.assertIsNotNone(encrypted)
        assert encrypted is not None
        self.assertEqual(len(encrypted["nonce"]), 12)
        for secret in (
            TEST_PRIVATE_KEY_A.encode(),
            b"proxy1.test:18080:user-a:pass-a",
            b"alpha@example.test",
            b"mail-pass-a",
            b"@alpha:twitter-pass-a",
        ):
            self.assertNotIn(secret, encrypted["ciphertext"])

        email_only = self.vault.bundles_for_runner([account["id"]], ["email"])
        self.assertEqual(
            set(email_only[0]),
            {"id", "label", "evm_address", "email"},
        )
        self.assertEqual(email_only[0]["email"], "alpha@example.test")

        complete = self.vault.bundles_for_runner(
            [account["id"]],
            ["evm_private_key", "proxy", "email", "email_password", "twitter"],
        )[0]
        self.assertEqual(complete["evm_private_key"], TEST_PRIVATE_KEY_A)
        self.assertEqual(complete["proxy"], "proxy1.test:18080:user-a:pass-a")
        self.assertEqual(complete["email_password"], "mail-pass-a")
        self.assertEqual(complete["twitter"], "@alpha:twitter-pass-a")
        with self.assertRaisesRegex(VaultError, "неизвестный"):
            self.vault.bundles_for_runner([account["id"]], ["arbitrary_secret"])

    def test_optional_twitter_is_atomic_and_omitted_when_not_configured(self) -> None:
        self.create_vault()
        self.vault.import_records([self.record(twitter="")])
        account = self.vault.list_accounts()[0]
        self.assertIs(account["twitter_configured"], False)
        self.assertNotIn(
            "twitter",
            self.vault.bundles_for_runner([account["id"]], ["twitter"])[0],
        )

        invalid_batch = [
            self.record(
                TEST_PRIVATE_KEY_B,
                proxy="proxy2.test:18081:user-b:pass-b",
                email="bravo@example.test",
                twitter="@bravo:credential",
            ),
            self.record(
                TEST_PRIVATE_KEY_C,
                proxy="proxy3.test:18082:user-c:pass-c",
                email="charlie@example.test",
                twitter="invalid\ncredential",
            ),
        ]
        with self.assertRaisesRegex(VaultError, "twitter"):
            self.vault.import_records(invalid_batch)
        with self.assertRaisesRegex(VaultError, "строкой"):
            self.vault.import_records(
                [
                    {
                        "private_key": TEST_PRIVATE_KEY_B,
                        "proxy": "proxy2.test:18081:user-b:pass-b",
                        "email": "bravo@example.test",
                        "twitter": 123,
                    }
                ]
            )
        self.assertEqual(len(self.vault.list_accounts()), 1)

    def test_adspower_profile_is_encrypted_validated_and_required_per_account(self) -> None:
        self.create_vault()
        profile_id = "profile-demo-01"
        self.vault.import_records(
            [self.record(adspower_profile=profile_id, label="AdsPower Alpha")]
        )
        account = self.vault.list_accounts()[0]
        self.assertIs(account["adspower_configured"], True)
        self.assertNotIn(profile_id, json.dumps(account, ensure_ascii=False))
        self.assertNotIn("adspower_profile", account)
        encrypted = self.database.one(
            "SELECT ciphertext FROM account_secrets WHERE account_id=?", (account["id"],)
        )
        assert encrypted is not None
        self.assertNotIn(profile_id.encode(), encrypted["ciphertext"])
        exported = self.vault.export_rows(
            TEST_MASTER_PASSWORD, PLAINTEXT_EXPORT_ACKNOWLEDGEMENT
        )
        self.assertEqual(exported[0]["adspower_profile"], profile_id)

        ordinary = self.vault.bundles_for_runner([account["id"]], ["email"])[0]
        self.assertNotIn("adspower_profile", ordinary)
        granted = self.vault.bundles_for_runner(
            [account["id"]],
            ["adspower_profile"],
            ["adspower_profile"],
        )[0]
        self.assertEqual(granted["adspower_profile"], profile_id)
        self.vault.validate_runner_access(
            [account["id"]],
            ["adspower_profile"],
            ["adspower_profile"],
        )

        # None preserves an existing optional profile; an empty string explicitly clears it.
        self.vault.import_records([self.record(adspower_profile=None)])
        preserved = self.vault.bundles_for_runner(
            [account["id"]], ["adspower_profile"], ["adspower_profile"]
        )[0]
        self.assertEqual(preserved["adspower_profile"], profile_id)
        self.vault.import_records([self.record(adspower_profile="")])
        self.assertIs(self.vault.list_accounts()[0]["adspower_configured"], False)
        with self.assertRaisesRegex(
            VaultError, "AdsPower Alpha|Alpha.*adspower_profile"
        ):
            self.vault.validate_runner_access(
                [account["id"]],
                ["adspower_profile"],
                ["adspower_profile"],
            )

        for invalid in (" profile", "profile ", "bad\nprofile", "x" * 257):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                VaultError, "adspower_profile"
            ):
                self.vault.import_records([self.record(adspower_profile=invalid)])

    def test_email_password_resource_has_a_nonsecret_configured_preflight_flag(self) -> None:
        self.create_vault()
        self.vault.import_records([self.record(email_password="")])
        account = self.vault.list_accounts()[0]
        self.assertIs(account["email_password_configured"], False)
        with self.assertRaisesRegex(VaultError, "Alpha.*email_password"):
            self.vault.validate_runner_access(
                [account["id"]],
                ["email_password"],
                ["email_password"],
            )

    def test_import_is_atomic_for_batch_duplicates_and_database_conflicts(self) -> None:
        self.create_vault()
        self.vault.import_records([self.record()])

        duplicate_batch = [
            self.record(
                TEST_PRIVATE_KEY_B,
                proxy="proxy2.test:18081:user-b:pass-b",
                email="bravo@example.test",
            ),
            self.record(
                TEST_PRIVATE_KEY_B,
                proxy="proxy3.test:18082:user-c:pass-c",
                email="charlie@example.test",
            ),
        ]
        with self.assertRaisesRegex(VaultError, "private key повторяется"):
            self.vault.import_records(duplicate_batch)
        self.assertEqual(len(self.vault.list_accounts()), 1)

        conflict_after_first_insert = [
            self.record(
                TEST_PRIVATE_KEY_B,
                proxy="proxy2.test:18081:user-b:pass-b",
                email="bravo@example.test",
                label="Bravo",
            ),
            self.record(
                TEST_PRIVATE_KEY_C,
                proxy="proxy1.test:18080:user-a:pass-a",
                email="charlie@example.test",
                label="Charlie",
            ),
        ]
        with self.assertRaisesRegex(VaultError, "уже привязан"):
            self.vault.import_records(conflict_after_first_insert)
        self.assertEqual([item["label"] for item in self.vault.list_accounts()], ["Alpha"])

    def test_reimport_updates_in_place_and_locked_vault_denies_secret_operations(self) -> None:
        self.create_vault()
        self.vault.import_records([self.record()])
        account_id = self.vault.list_accounts()[0]["id"]

        outcome = self.vault.import_records(
            [
                self.record(
                    proxy="proxy9.test:19090:user-z:pass-z",
                    email="updated@example.test",
                    email_password="mail-pass-z",
                    twitter=None,
                    label="Updated",
                    tags=("updated",),
                )
            ]
        )
        self.assertEqual(outcome, {"inserted": 0, "updated": 1, "total": 1})
        account = self.vault.list_accounts()[0]
        self.assertEqual(account["id"], account_id)
        self.assertEqual(account["label"], "Updated")
        self.assertEqual(account["proxy_label"], "proxy9.test:19090")
        bundle = self.vault.bundles_for_runner([account_id], ["proxy", "email_password"])[0]
        self.assertEqual(bundle["proxy"], "proxy9.test:19090:user-z:pass-z")
        self.assertEqual(bundle["email_password"], "mail-pass-z")
        twitter = self.vault.bundles_for_runner([account_id], ["twitter"])[0]
        self.assertEqual(twitter["twitter"], "@alpha:twitter-pass-a")

        self.vault.lock()
        with self.assertRaisesRegex(VaultError, "заблокирован"):
            self.vault.list_accounts()
        with self.assertRaisesRegex(VaultError, "заблокирован"):
            self.vault.bundles_for_runner([account_id], ["email"])
        with self.assertRaisesRegex(VaultError, "заблокирован"):
            self.vault.delete_account(account_id)

    def test_locked_vault_denies_metadata_even_without_secret_permissions(self) -> None:
        self.create_vault()
        self.vault.import_records([self.record()])
        account_id = self.vault.list_accounts()[0]["id"]
        self.vault.lock()

        with self.assertRaisesRegex(VaultError, "заблокирован"):
            self.vault.list_accounts()
        with self.assertRaisesRegex(VaultError, "заблокирован"):
            self.vault.validate_runner_access([account_id], [])
        with self.assertRaisesRegex(VaultError, "заблокирован"):
            self.vault.bundles_for_runner([account_id], [])

        # Account-free actions remain usable: they do not receive protected
        # account metadata and do not need a Vault key.
        self.vault.validate_runner_access([], [])
        self.assertEqual(self.vault.bundles_for_runner([], []), [])

    def test_referral_topology_is_encrypted_projected_and_cas_safe(self) -> None:
        self.create_vault()
        self.vault.import_records(
            [
                self.record(label="Alpha"),
                self.record(
                    TEST_PRIVATE_KEY_B,
                    proxy="proxy2.test:18081:user-b:pass-b",
                    email="bravo@example.test",
                    label="Bravo",
                ),
                self.record(
                    TEST_PRIVATE_KEY_C,
                    proxy="proxy3.test:18082:user-c:pass-c",
                    email="charlie@example.test",
                    label="Charlie",
                ),
            ]
        )
        identifiers = {
            account["label"]: account["id"] for account in self.vault.list_accounts()
        }
        initial = self.vault.referral_topology(self.vault.list_accounts())
        self.assertEqual(initial["roots"], 3)
        self.assertEqual(initial["links"], 0)
        self.assertEqual(initial["max_depth"], 0)
        self.assertRegex(initial["revision"], r"^[0-9a-f]{64}$")

        relationships = [
            {
                "child_account_id": identifiers["Alpha"],
                "parent_account_id": None,
            },
            {
                "child_account_id": identifiers["Bravo"],
                "parent_account_id": identifiers["Alpha"],
            },
            {
                "child_account_id": identifiers["Charlie"],
                "parent_account_id": identifiers["Bravo"],
            },
        ]
        result = self.vault.update_referral_topology(
            initial["revision"], relationships
        )
        self.assertNotEqual(result["revision"], initial["revision"])
        self.assertEqual(result["relationships"], relationships)
        self.assertEqual(result["roots"], 1)
        self.assertEqual(result["links"], 2)
        self.assertEqual(result["max_depth"], 2)

        accounts = {account["label"]: account for account in self.vault.list_accounts()}
        self.assertIsNone(accounts["Alpha"]["referrer_account_id"])
        self.assertIs(accounts["Alpha"]["referral_is_root"], True)
        self.assertEqual(accounts["Alpha"]["referral_children_count"], 1)
        self.assertEqual(accounts["Alpha"]["referral_depth"], 0)
        self.assertEqual(accounts["Bravo"]["referrer_account_id"], identifiers["Alpha"])
        self.assertEqual(accounts["Bravo"]["referrer_label"], "Alpha")
        self.assertEqual(accounts["Bravo"]["referral_children_count"], 1)
        self.assertEqual(accounts["Bravo"]["referral_depth"], 1)
        self.assertEqual(accounts["Charlie"]["referrer_account_id"], identifiers["Bravo"])
        self.assertEqual(accounts["Charlie"]["referral_depth"], 2)
        self.assertFalse(any("code" in key for account in accounts.values() for key in account))

        for row in self.database.all("SELECT ciphertext FROM account_secrets"):
            for account_id in identifiers.values():
                self.assertNotIn(account_id.encode(), row["ciphertext"])

        with self.assertRaisesRegex(ReferralRevisionConflict, "другом окне"):
            self.vault.update_referral_topology(initial["revision"], relationships)
        self.assertEqual(
            self.vault.referral_topology(self.vault.list_accounts())["revision"],
            result["revision"],
        )

    def test_referral_topology_is_atomic_cycle_safe_preserved_and_cleaned_on_delete(self) -> None:
        self.create_vault()
        records = [
            self.record(label="Alpha"),
            self.record(
                TEST_PRIVATE_KEY_B,
                proxy="proxy2.test:18081:user-b:pass-b",
                email="bravo@example.test",
                label="Bravo",
            ),
            self.record(
                TEST_PRIVATE_KEY_C,
                proxy="proxy3.test:18082:user-c:pass-c",
                email="charlie@example.test",
                label="Charlie",
            ),
        ]
        self.vault.import_records(records)
        identifiers = {
            account["label"]: account["id"] for account in self.vault.list_accounts()
        }
        initial = self.vault.referral_topology(self.vault.list_accounts())
        stable = self.vault.update_referral_topology(
            initial["revision"],
            [
                {
                    "child_account_id": identifiers["Alpha"],
                    "parent_account_id": None,
                },
                {
                    "child_account_id": identifiers["Bravo"],
                    "parent_account_id": identifiers["Alpha"],
                },
                {
                    "child_account_id": identifiers["Charlie"],
                    "parent_account_id": identifiers["Bravo"],
                },
            ],
        )
        with self.assertRaisesRegex(VaultError, "цикл"):
            self.vault.update_referral_topology(
                stable["revision"],
                [
                    {
                        "child_account_id": identifiers["Alpha"],
                        "parent_account_id": identifiers["Charlie"],
                    },
                    {
                        "child_account_id": identifiers["Bravo"],
                        "parent_account_id": identifiers["Alpha"],
                    },
                    {
                        "child_account_id": identifiers["Charlie"],
                        "parent_account_id": identifiers["Bravo"],
                    },
                ],
            )
        self.assertEqual(
            self.vault.referral_topology(self.vault.list_accounts())["revision"],
            stable["revision"],
        )

        with self.assertRaisesRegex(VaultError, "каждый аккаунт"):
            self.vault.update_referral_topology(
                stable["revision"],
                [{"child_account_id": identifiers["Alpha"], "parent_account_id": None}],
            )

        self.vault.import_records([records[1]])
        bravo = next(
            account for account in self.vault.list_accounts() if account["label"] == "Bravo"
        )
        self.assertEqual(bravo["referrer_account_id"], identifiers["Alpha"])
        self.assertTrue(self.vault.delete_account(identifiers["Bravo"]))
        accounts = {account["label"]: account for account in self.vault.list_accounts()}
        self.assertIsNone(accounts["Charlie"]["referrer_account_id"])
        self.assertIs(accounts["Charlie"]["referral_is_root"], True)
        self.assertEqual(accounts["Alpha"]["referral_children_count"], 0)

    def test_referral_topology_rejects_codes_bad_revisions_and_locked_updates(self) -> None:
        self.create_vault()
        self.vault.import_records([self.record()])
        accounts = self.vault.list_accounts()
        account_id = accounts[0]["id"]
        revision = self.vault.referral_topology(accounts)["revision"]
        with self.assertRaisesRegex(VaultError, "только child_account_id"):
            self.vault.update_referral_topology(
                revision,
                [
                    {
                        "child_account_id": account_id,
                        "parent_account_id": None,
                        "referral_code": "FORBIDDEN-CODE",
                    }
                ],
            )
        with self.assertRaisesRegex(VaultError, "expected_revision"):
            self.vault.update_referral_topology(
                "not-a-revision",
                [{"child_account_id": account_id, "parent_account_id": None}],
            )

        self.vault.lock()
        with self.assertRaisesRegex(VaultError, "заблокирован"):
            self.vault.update_referral_topology(
                revision,
                [{"child_account_id": account_id, "parent_account_id": None}],
            )

    def test_tampered_ciphertext_is_detected(self) -> None:
        self.create_vault()
        self.vault.import_records([self.record()])
        account_id = self.vault.list_accounts()[0]["id"]
        row = self.database.one(
            "SELECT ciphertext FROM account_secrets WHERE account_id=?", (account_id,)
        )
        assert row is not None
        damaged = bytearray(row["ciphertext"])
        damaged[-1] ^= 1
        self.database.execute(
            "UPDATE account_secrets SET ciphertext=? WHERE account_id=?",
            (bytes(damaged), account_id),
        )
        with self.assertRaisesRegex(VaultError, "целостности"):
            self.vault.bundles_for_runner([account_id], ["email"])

    def test_global_capsolver_is_encrypted_and_only_granted_by_permission(self) -> None:
        self.create_vault()
        self.vault.import_records([self.record()])
        account_id = self.vault.list_accounts()[0]["id"]
        capsolver = "CAP-very-sensitive-api-key-123456"

        self.assertEqual(self.vault.capsolver_status(), {"configured": False})
        with self.assertRaisesRegex(VaultError, "минимум 4"):
            self.vault.set_capsolver_api_key("  ")
        with self.assertRaisesRegex(VaultError, "минимум 4"):
            self.vault.set_capsolver_api_key("abc")
        self.vault.set_capsolver_api_key(capsolver)
        self.assertEqual(self.vault.capsolver_status(), {"configured": True})
        self.assertTrue(self.vault.capsolver_configured)

        encrypted = self.database.one(
            "SELECT name,nonce,ciphertext FROM vault_secrets WHERE name='capsolver_api_key'"
        )
        assert encrypted is not None
        self.assertEqual(encrypted["name"], "capsolver_api_key")
        self.assertEqual(len(encrypted["nonce"]), 12)
        self.assertNotIn(capsolver.encode(), encrypted["ciphertext"])
        self.assertNotIn(capsolver, json.dumps(self.vault.capsolver_status()))
        self.assertNotIn(
            "capsolver_api_key",
            self.vault.bundles_for_runner([account_id], ["email"])[0],
        )
        granted = self.vault.bundles_for_runner(
            [account_id], ["capsolver_api_key"]
        )[0]
        self.assertEqual(granted["capsolver_api_key"], capsolver)
        combined = self.vault.bundles_for_runner(
            [account_id], ["twitter", "capsolver_api_key"]
        )[0]
        self.assertEqual(combined["twitter"], "@alpha:twitter-pass-a")
        self.assertEqual(combined["capsolver_api_key"], capsolver)
        self.assertEqual(
            self.vault.settings_for_runner(["capsolver_api_key"]),
            {"capsolver": capsolver},
        )

        damaged = bytearray(encrypted["ciphertext"])
        damaged[-1] ^= 1
        self.database.execute(
            "UPDATE vault_secrets SET ciphertext=? WHERE name='capsolver_api_key'",
            (bytes(damaged),),
        )
        ordinary = self.vault.bundles_for_runner([account_id], ["email"])[0]
        self.assertEqual(ordinary["email"], "alpha@example.test")
        with self.assertRaisesRegex(VaultError, "Глобальный секрет"):
            self.vault.bundles_for_runner([account_id], ["capsolver_api_key"])
        self.vault.set_capsolver_api_key(capsolver)

        self.vault.lock()
        self.assertEqual(self.vault.capsolver_status(), {"configured": True})
        with self.assertRaisesRegex(VaultError, "заблокирован"):
            self.vault.set_capsolver_api_key("replacement")
        with self.assertRaisesRegex(VaultError, "заблокирован"):
            self.vault.clear_capsolver_api_key()
        with self.assertRaisesRegex(VaultError, "заблокирован"):
            self.vault.bundles_for_runner([account_id], ["capsolver_api_key"])

        self.vault.unlock(TEST_MASTER_PASSWORD)
        self.assertTrue(self.vault.clear_capsolver_api_key())
        self.assertFalse(self.vault.clear_capsolver_api_key())
        self.assertEqual(self.vault.capsolver_status(), {"configured": False})

    def test_global_adspower_api_is_encrypted_status_only_and_exact_grant(self) -> None:
        self.create_vault()
        api_key = "AdsPower-Bearer-secret-123456789"
        self.assertEqual(self.vault.adspower_api_status(), {"configured": False})
        with self.assertRaisesRegex(VaultError, "минимум 4"):
            self.vault.set_adspower_api_key("abc")
        self.vault.set_adspower_api_key(api_key)
        self.assertTrue(self.vault.adspower_api_configured)
        self.assertEqual(self.vault.adspower_api_status(), {"configured": True})
        self.assertNotIn(api_key, json.dumps(self.vault.adspower_api_status()))

        encrypted = self.database.one(
            "SELECT nonce,ciphertext FROM vault_secrets WHERE name='adspower_api_key'"
        )
        assert encrypted is not None
        self.assertEqual(len(encrypted["nonce"]), 12)
        self.assertNotIn(api_key.encode(), encrypted["ciphertext"])
        self.assertEqual(self.vault.settings_for_runner([]), {})
        self.assertEqual(
            self.vault.settings_for_runner(["adspower_api_key"]),
            {"adspower_api": api_key},
        )
        with self.assertRaisesRegex(VaultError, "не разрешён"):
            self.vault.settings_for_runner([], ["adspower_api"])

        self.assertTrue(self.vault.clear_adspower_api_key())
        self.assertFalse(self.vault.clear_adspower_api_key())
        with self.assertRaisesRegex(VaultError, "adspower_api"):
            self.vault.validate_runner_access(
                [], ["adspower_api_key"], [], ["adspower_api"]
            )

    def test_plaintext_export_requires_all_three_guards_and_never_exports_capsolver(self) -> None:
        self.create_vault()
        self.vault.import_records([self.record()])
        self.vault.set_capsolver_api_key("CAP-never-export-this-key")
        self.vault.set_adspower_api_key("ADS-never-export-this-key")

        with self.assertRaisesRegex(VaultError, "точная фраза"):
            self.vault.export_rows(TEST_MASTER_PASSWORD, "EXPORT")
        with self.assertRaisesRegex(VaultError, "Неверный мастер-пароль"):
            self.vault.export_rows(
                "Wrong Password 99!", PLAINTEXT_EXPORT_ACKNOWLEDGEMENT
            )

        rows = self.vault.export_rows(
            TEST_MASTER_PASSWORD, PLAINTEXT_EXPORT_ACKNOWLEDGEMENT
        )
        self.assertEqual(
            rows,
            [
                {
                    "label": "Alpha",
                    "private_key": TEST_PRIVATE_KEY_A,
                    "proxy": "proxy1.test:18080:user-a:pass-a",
                    "email": "alpha@example.test",
                    "email_password": "mail-pass-a",
                    "twitter": "@alpha:twitter-pass-a",
                    "adspower_profile": "",
                    "tags": ["alpha", "beta"],
                }
            ],
        )
        self.assertNotIn("CAP-never-export-this-key", json.dumps(rows))
        self.assertNotIn("ADS-never-export-this-key", json.dumps(rows))

        self.vault.lock()
        with self.assertRaisesRegex(VaultError, "заблокирован"):
            self.vault.export_rows(
                TEST_MASTER_PASSWORD, PLAINTEXT_EXPORT_ACKNOWLEDGEMENT
            )

    def test_migration_reencrypts_legacy_payloads_into_topology_only_format(self) -> None:
        legacy_root = Path(self.temporary.name) / "legacy"
        legacy_paths = HubPaths.create(legacy_root)
        connection = sqlite3.connect(legacy_paths.database)
        migrations = Path(vault_module.__file__).resolve().parent / "migrations"
        connection.executescript((migrations / "001_init.sql").read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO schema_migrations(version,applied_at) VALUES (1,'legacy')"
        )
        connection.executescript(
            (migrations / "002_account_leases.sql").read_text(encoding="utf-8")
        )
        connection.execute(
            "INSERT INTO schema_migrations(version,applied_at) VALUES (2,'legacy')"
        )

        salt = os.urandom(16)
        key = vault_module._derive_key(TEST_MASTER_PASSWORD, salt, vault_module._KDF)
        verifier_nonce = os.urandom(12)
        verifier = AESGCM(key).encrypt(
            verifier_nonce, vault_module._VERIFIER, b"vault-meta-v1"
        )
        connection.execute(
            "INSERT INTO vault_meta(singleton,salt,nonce,verifier,kdf_json,created_at,updated_at) "
            "VALUES (1,?,?,?,?,?,?)",
            (
                salt,
                verifier_nonce,
                verifier,
                json.dumps(vault_module._KDF),
                "legacy",
                "legacy",
            ),
        )
        private_key = normalize_private_key(TEST_PRIVATE_KEY_A)
        account_id = "legacy-account"
        proxy = "proxy1.test:18080:user-a:pass-a"
        email = "legacy@example.test"
        connection.execute(
            "INSERT INTO accounts(id,label,evm_address,key_fingerprint,proxy_label,"
            "proxy_fingerprint,email_label,email_fingerprint,tags_json,status,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,'ready','legacy','legacy')",
            (
                account_id,
                "Legacy",
                Account.from_key(private_key).address,
                hashlib.sha256(bytes.fromhex(private_key[2:])).hexdigest(),
                "proxy1.test:18080",
                hashlib.sha256(proxy.encode()).hexdigest(),
                "l•••••@example.test",
                hashlib.sha256(email.encode()).hexdigest(),
                "[]",
            ),
        )
        empty_account_id = "legacy-account-empty"
        empty_private_key = normalize_private_key(TEST_PRIVATE_KEY_B)
        empty_proxy = "proxy2.test:18081:user-b:pass-b"
        empty_email = "legacy-empty@example.test"
        connection.execute(
            "INSERT INTO accounts(id,label,evm_address,key_fingerprint,proxy_label,"
            "proxy_fingerprint,email_label,email_fingerprint,tags_json,status,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,'ready','legacy','legacy')",
            (
                empty_account_id,
                "Legacy Empty",
                Account.from_key(empty_private_key).address,
                hashlib.sha256(bytes.fromhex(empty_private_key[2:])).hexdigest(),
                "proxy2.test:18081",
                hashlib.sha256(empty_proxy.encode()).hexdigest(),
                "l•••••@example.test",
                hashlib.sha256(empty_email.encode()).hexdigest(),
                "[]",
            ),
        )
        payload = json.dumps(
            {
                "evm_private_key": private_key,
                "proxy": proxy,
                "email": email,
                "email_password": "legacy-mail-password",
                "referral_code": "LEGACY-OWN-CODE-MUST-DISAPPEAR",
                "external_referrer_code": "LEGACY-EXTERNAL-CODE-MUST-DISAPPEAR",
            },
            separators=(",", ":"),
        ).encode()
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(
            nonce, payload, f"account:{account_id}:v1".encode()
        )
        connection.execute(
            "INSERT INTO account_secrets(account_id,nonce,ciphertext,updated_at) "
            "VALUES (?,?,?,'legacy')",
            (account_id, nonce, ciphertext),
        )
        empty_payload = json.dumps(
            {
                "evm_private_key": empty_private_key,
                "proxy": empty_proxy,
                "email": empty_email,
                "email_password": "",
            },
            separators=(",", ":"),
        ).encode()
        empty_nonce = os.urandom(12)
        empty_ciphertext = AESGCM(key).encrypt(
            empty_nonce,
            empty_payload,
            f"account:{empty_account_id}:v1".encode(),
        )
        connection.execute(
            "INSERT INTO account_secrets(account_id,nonce,ciphertext,updated_at) "
            "VALUES (?,?,?,'legacy')",
            (empty_account_id, empty_nonce, empty_ciphertext),
        )
        connection.commit()
        connection.close()

        migrated_database = Database(legacy_paths)
        versions = [
            row["version"]
            for row in migrated_database.all(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        ]
        self.assertEqual(versions, list(range(1, 13)))
        before_unlock = migrated_database.one(
            "SELECT a.email_password_configured,s.nonce,s.ciphertext "
            "FROM accounts a JOIN account_secrets s ON s.account_id=a.id "
            "WHERE a.id=?",
            (account_id,),
        )
        assert before_unlock is not None
        self.assertEqual(before_unlock["email_password_configured"], 0)
        self.assertEqual(before_unlock["nonce"], nonce)
        self.assertEqual(before_unlock["ciphertext"], ciphertext)
        empty_before_unlock = migrated_database.one(
            "SELECT a.email_password_configured,s.nonce,s.ciphertext "
            "FROM accounts a JOIN account_secrets s ON s.account_id=a.id "
            "WHERE a.id=?",
            (empty_account_id,),
        )
        assert empty_before_unlock is not None
        self.assertEqual(empty_before_unlock["email_password_configured"], 0)
        self.assertEqual(empty_before_unlock["nonce"], empty_nonce)
        self.assertEqual(empty_before_unlock["ciphertext"], empty_ciphertext)

        migrated_vault = Vault(migrated_database)
        migrated_vault.unlock(TEST_MASTER_PASSWORD)
        public_accounts = {
            row["id"]: row for row in migrated_vault.list_accounts()
        }
        public = public_accounts[account_id]
        self.assertIs(public["twitter_configured"], False)
        self.assertIs(public["adspower_configured"], False)
        self.assertIs(public["email_password_configured"], True)
        self.assertIs(
            public_accounts[empty_account_id]["email_password_configured"], False
        )
        after_unlock = migrated_database.one(
            "SELECT email_password_configured FROM accounts WHERE id=?",
            (account_id,),
        )
        secret_after_unlock = migrated_database.one(
            "SELECT nonce,ciphertext FROM account_secrets WHERE account_id=?",
            (account_id,),
        )
        assert after_unlock is not None and secret_after_unlock is not None
        self.assertEqual(after_unlock["email_password_configured"], 1)
        self.assertNotEqual(secret_after_unlock["nonce"], nonce)
        self.assertNotEqual(secret_after_unlock["ciphertext"], ciphertext)
        empty_secret_after_unlock = migrated_database.one(
            "SELECT nonce,ciphertext FROM account_secrets WHERE account_id=?",
            (empty_account_id,),
        )
        assert empty_secret_after_unlock is not None
        self.assertNotEqual(empty_secret_after_unlock["nonce"], empty_nonce)
        self.assertNotEqual(empty_secret_after_unlock["ciphertext"], empty_ciphertext)
        migrated_payload = migrated_vault._decrypt_account_payload(
            migrated_vault._require_key(),
            account_id,
            secret_after_unlock["nonce"],
            secret_after_unlock["ciphertext"],
        )
        self.assertEqual(migrated_payload["email_password"], "legacy-mail-password")
        self.assertEqual(migrated_payload["referrer_account_id"], "")
        self.assertNotIn("referral_code", migrated_payload)
        self.assertNotIn("external_referrer_code", migrated_payload)
        marker = migrated_database.one(
            "SELECT value_json FROM settings WHERE key=?",
            (vault_module._EMAIL_PASSWORD_FLAG_BACKFILL_SETTING,),
        )
        assert marker is not None
        self.assertEqual(json.loads(marker["value_json"]), True)
        topology_marker = migrated_database.one(
            "SELECT value_json FROM settings WHERE key=?",
            (vault_module._REFERRAL_TOPOLOGY_MIGRATION_SETTING,),
        )
        assert topology_marker is not None
        self.assertEqual(json.loads(topology_marker["value_json"]), True)

        migrated_vault.lock()
        with mock.patch.object(
            migrated_vault,
            "_decrypt_account_payload",
            wraps=migrated_vault._decrypt_account_payload,
        ) as decrypt_account:
            migrated_vault.unlock(TEST_MASTER_PASSWORD)
        self.assertEqual(
            decrypt_account.call_count,
            0,
            "Both completion markers must skip all account payload scans on later unlocks",
        )
        migrated_vault.validate_runner_access(
            [account_id],
            ["email_password"],
            ["email_password"],
        )
        bundle = migrated_vault.bundles_for_runner(
            [account_id], ["email", "email_password", "twitter"]
        )[0]
        self.assertEqual(bundle["email"], email)
        self.assertEqual(bundle["email_password"], "legacy-mail-password")
        self.assertNotIn("twitter", bundle)

    def test_unlock_backfill_is_fail_closed_and_rolls_back_partial_metadata(self) -> None:
        self.create_vault()
        self.vault.import_records(
            [
                self.record(email_password="alpha-password"),
                self.record(
                    TEST_PRIVATE_KEY_B,
                    proxy="proxy2.test:18081:user-b:pass-b",
                    email="bravo@example.test",
                    email_password="bravo-password",
                    label="Bravo",
                ),
            ]
        )
        self.database.execute("UPDATE accounts SET email_password_configured=0")
        secret_rows = self.database.all(
            "SELECT account_id,nonce,ciphertext FROM account_secrets ORDER BY account_id"
        )
        self.assertEqual(len(secret_rows), 2)
        damaged = bytearray(secret_rows[1]["ciphertext"])
        damaged[-1] ^= 1
        self.database.execute(
            "UPDATE account_secrets SET ciphertext=? WHERE account_id=?",
            (bytes(damaged), secret_rows[1]["account_id"]),
        )
        ciphertext_before = {
            row["account_id"]: (
                row["nonce"],
                bytes(damaged)
                if row["account_id"] == secret_rows[1]["account_id"]
                else row["ciphertext"],
            )
            for row in secret_rows
        }

        self.vault.lock()
        with self.assertRaisesRegex(VaultError, "целостности"):
            self.vault.unlock(TEST_MASTER_PASSWORD)

        self.assertFalse(self.vault.unlocked)
        self.assertIsNone(
            self.database.one(
                "SELECT value_json FROM settings WHERE key=?",
                (vault_module._EMAIL_PASSWORD_FLAG_BACKFILL_SETTING,),
            ),
            "A failed transaction must not publish the completion marker",
        )
        flags = self.database.all(
            "SELECT id,email_password_configured FROM accounts ORDER BY id"
        )
        self.assertEqual(
            [row["email_password_configured"] for row in flags],
            [0, 0],
            "The first metadata update must roll back when a later row is damaged",
        )
        for row in self.database.all(
            "SELECT account_id,nonce,ciphertext FROM account_secrets ORDER BY account_id"
        ):
            self.assertEqual(
                (row["nonce"], row["ciphertext"]),
                ciphertext_before[row["account_id"]],
                "Backfill must never rewrite account ciphertext",
            )

    def test_referral_graph_handles_the_full_topology_limit_without_recursion(self) -> None:
        account_ids = [f"account-{index:05d}" for index in range(10_000)]
        parents = {
            account_id: account_ids[index - 1] if index else ""
            for index, account_id in enumerate(account_ids)
        }

        depths = vault_module._validate_referral_graph(parents)

        self.assertEqual(depths[account_ids[0]], 0)
        self.assertEqual(depths[account_ids[-1]], 9_999)
        parents[account_ids[0]] = account_ids[-1]
        with self.assertRaisesRegex(VaultError, "цикл"):
            vault_module._validate_referral_graph(parents)


if __name__ == "__main__":
    unittest.main()
