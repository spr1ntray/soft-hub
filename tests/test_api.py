from __future__ import annotations

import csv
import http.client
import io
import json
import tempfile
import threading
import unittest
import uuid
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Mapping

from soft_hub.api import HubApplication, create_server
from soft_hub.github_install import GitHubPackage
from soft_hub.instance_lock import InstanceLockError
from soft_hub.vault import ImportRecord, PLAINTEXT_EXPORT_ACKNOWLEDGEMENT
from tests.support import (
    TEST_MASTER_PASSWORD,
    TEST_PRIVATE_KEY_A,
    TEST_PRIVATE_KEY_B,
    plugin_manifest,
    regular_zip_info,
    wait_until,
    write_plugin_archive,
)


TEST_API_TOKEN = "deterministic-soft-hub-api-token"


class ApiSecurityTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="soft-hub-api-test-")
        self.addCleanup(self.temporary.cleanup)
        self.application = HubApplication(Path(self.temporary.name))
        self.addCleanup(self.application.close)
        self.server, token = create_server(self.application, token=TEST_API_TOKEN, port=0)
        self.assertEqual(token, TEST_API_TOKEN)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)

    def _stop_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=dict(headers or {}))
            response = connection.getresponse()
            response_body = response.read()
            return response.status, {key.lower(): value for key, value in response.getheaders()}, response_body
        finally:
            connection.close()

    def assert_security_headers(self, headers: Mapping[str, str]) -> None:
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(headers.get("x-frame-options"), "DENY")
        self.assertEqual(headers.get("referrer-policy"), "no-referrer")
        self.assertEqual(headers.get("cross-origin-resource-policy"), "same-origin")
        self.assertEqual(headers.get("cache-control"), "no-store")
        csp = headers.get("content-security-policy", "")
        for directive in (
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self' data: blob:",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            "form-action 'self'",
            "frame-ancestors 'none'",
        ):
            self.assertIn(directive, csp)
        self.assertNotIn("'unsafe-inline'", csp)
        self.assertNotIn("'unsafe-eval'", csp)
        self.assertNotIn("access-control-allow-origin", headers)

    def test_static_assets_need_no_token_and_receive_strict_csp(self) -> None:
        for path, content_type in (
            ("/", "text/html"),
            ("/index.html", "text/html"),
            ("/app.js", "text/javascript"),
            ("/style.css", "text/css"),
            ("/brand-icon.png", "image/png"),
        ):
            with self.subTest(path=path):
                status, headers, body = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertTrue(headers["content-type"].startswith(content_type))
                self.assertEqual(int(headers["content-length"]), len(body))
                self.assert_security_headers(headers)
                self.assertNotIn(TEST_API_TOKEN.encode(), body)

        for path in ("/../api.py", "/%2e%2e/api.py", "/missing.txt"):
            with self.subTest(path=path):
                status, headers, _ = self.request("GET", path)
                self.assertEqual(status, 404)
                self.assert_security_headers(headers)

    def test_fresh_hub_has_no_bundled_catalog_or_rollback_endpoints(self) -> None:
        headers = {
            "X-Soft-Hub-Token": TEST_API_TOKEN,
            "Content-Type": "application/json",
        }
        status, response_headers, body = self.request(
            "GET", "/api/bootstrap", headers={"X-Soft-Hub-Token": TEST_API_TOKEN}
        )
        self.assertEqual(status, 200)
        bootstrap = json.loads(body)
        self.assertEqual(bootstrap["modules"], [])
        self.assertEqual(bootstrap["stats"]["modules"], 0)
        self.assertNotIn("discovery", bootstrap)
        self.assert_security_headers(response_headers)

        for method, path, payload in (
            ("GET", "/api/discovery", None),
            ("POST", "/api/modules/install/bundled", {}),
            ("POST", "/api/modules/example.plugin/rollback", {}),
        ):
            with self.subTest(method=method, path=path):
                status, response_headers, body = self.request(
                    method,
                    path,
                    body=None if payload is None else json.dumps(payload),
                    headers=headers,
                )
                self.assertEqual(status, 404)
                self.assertEqual(json.loads(body), {"error": "Маршрут не найден"})
                self.assert_security_headers(response_headers)

    def test_local_install_accepts_browser_renamed_patch_but_still_inspects_contents(self) -> None:
        archive = write_plugin_archive(
            Path(self.temporary.name) / "renamed.softhub.zip",
            plugin_manifest(plugin_id="api.browser-renamed"),
        )
        headers = {
            "X-Soft-Hub-Token": TEST_API_TOKEN,
            "Content-Type": "application/zip",
            "X-Soft-Hub-Filename": "renamed.softhub%20(1).zip",
        }
        status, response_headers, body = self.request(
            "POST",
            "/api/modules/install",
            body=archive.read_bytes(),
            headers=headers,
        )
        self.assertEqual(status, 201, body.decode(errors="replace"))
        self.assertEqual(json.loads(body)["id"], "api.browser-renamed")
        self.assert_security_headers(response_headers)

        source_buffer = io.BytesIO()
        with zipfile.ZipFile(source_buffer, "w") as source:
            source.writestr(
                regular_zip_info("project-main/hub.plugin.json"),
                json.dumps(plugin_manifest(plugin_id="api.source-zip")),
            )
            source.writestr(
                regular_zip_info("project-main/plugin/main.py"),
                "def run(context): pass\n",
            )
        status, response_headers, body = self.request(
            "POST",
            "/api/modules/install",
            body=source_buffer.getvalue(),
            headers={
                **headers,
                "X-Soft-Hub-Filename": "source-code.zip",
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("Source code ZIP", json.loads(body)["error"])
        self.assert_security_headers(response_headers)

    def test_local_install_accepts_generic_zip_name_after_content_validation(self) -> None:
        archive = write_plugin_archive(
            Path(self.temporary.name) / "wrong-name.softhub.zip",
            plugin_manifest(plugin_id="api.wrong-name"),
        )
        status, response_headers, body = self.request(
            "POST",
            "/api/modules/install",
            body=archive.read_bytes(),
            headers={
                "X-Soft-Hub-Token": TEST_API_TOKEN,
                "Content-Type": "application/zip",
                "X-Soft-Hub-Filename": "source-code.zip",
            },
        )
        self.assertEqual(status, 201, body.decode(errors="replace"))
        self.assertEqual(json.loads(body)["id"], "api.wrong-name")
        self.assertIsNotNone(
            self.application.database.one("SELECT id FROM modules WHERE id=?", ("api.wrong-name",))
        )
        self.assert_security_headers(response_headers)

    def test_presentation_assets_are_authenticated_bounded_images_without_path_disclosure(self) -> None:
        manifest = plugin_manifest(plugin_id="api.presentation-test")
        manifest["presentation"] = {
            "display_name": "Presentation Fixture",
            "description": "A complete renderer-owned presentation.",
            "assets": {"icon": "assets/icon.png", "image": "assets/cover.png"},
        }
        png = (Path(__file__).resolve().parents[1] / "soft_hub" / "static" / "brand-icon.png").read_bytes()
        archive = write_plugin_archive(
            Path(self.temporary.name) / "presentation.softhub.zip",
            manifest,
            files={"assets/icon.png": png, "assets/cover.png": png},
        )
        installed = self.application.plugins.install(archive)
        active_path = str(installed["active_path"])

        status, _, body = self.request(
            "GET",
            "/api/bootstrap",
            headers={"X-Soft-Hub-Token": TEST_API_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertNotIn(b"active_path", body)
        self.assertNotIn(active_path.encode(), body)

        status, _, body = self.request(
            "GET", "/api/modules/api.presentation-test/presentation/icon"
        )
        self.assertEqual(status, 401)
        self.assertNotIn(active_path.encode(), body)

        for kind in ("icon", "image"):
            with self.subTest(kind=kind):
                status, headers, body = self.request(
                    "GET",
                    f"/api/modules/api.presentation-test/presentation/{kind}",
                    headers={"X-Soft-Hub-Token": TEST_API_TOKEN},
                )
                self.assertEqual(status, 200)
                self.assertEqual(headers["content-type"], "image/png")
                self.assertEqual(body, png)
                self.assertNotIn(active_path.encode(), body)
                self.assert_security_headers(headers)

        status, headers, body = self.request(
            "GET",
            "/api/modules/api.presentation-test/presentation/source",
            headers={"X-Soft-Hub-Token": TEST_API_TOKEN},
        )
        self.assertEqual(status, 404)
        self.assertNotIn(active_path.encode(), body)
        self.assert_security_headers(headers)

    def test_manual_account_import_accepts_adspower_ids_but_only_returns_status(self) -> None:
        self.application.vault.create(TEST_MASTER_PASSWORD)
        profile_id = "opaque AdsPower profile 42"
        status, _, body = self.request(
            "POST",
            "/api/accounts/import",
            body=json.dumps(
                {
                    "private_keys": [TEST_PRIVATE_KEY_A],
                    "proxies": ["192.0.2.10:8080:proxy-user:proxy-password"],
                    "emails": ["ads@example.test"],
                    "twitters": ["@ads"],
                    "adspower_profiles": [profile_id],
                }
            ),
            headers={
                "X-Soft-Hub-Token": TEST_API_TOKEN,
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(status, 201, body.decode(errors="replace"))
        payload = json.loads(body)
        self.assertIs(payload["accounts"][0]["adspower_configured"], True)
        self.assertNotIn(profile_id, body.decode())

    def test_referral_topology_api_is_full_cas_safe_and_never_accepts_codes(self) -> None:
        self.application.vault.create(TEST_MASTER_PASSWORD)
        self.application.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "ref-api-a.test:18080:user-a:pass-a",
                    "ref-api-a@example.test",
                    label="Alpha",
                ),
                ImportRecord(
                    TEST_PRIVATE_KEY_B,
                    "ref-api-b.test:18081:user-b:pass-b",
                    "ref-api-b@example.test",
                    label="Bravo",
                ),
            ]
        )
        identifiers = {
            account["label"]: account["id"]
            for account in self.application.vault.list_accounts()
        }
        headers = {
            "X-Soft-Hub-Token": TEST_API_TOKEN,
            "Content-Type": "application/json",
        }
        status, response_headers, body = self.request(
            "GET", "/api/accounts/referral-topology", headers=headers
        )
        self.assertEqual(status, 200)
        initial = json.loads(body)
        self.assertRegex(initial["revision"], r"^[0-9a-f]{64}$")
        self.assertEqual(initial["roots"], 2)
        self.assertEqual(initial["links"], 0)
        self.assertEqual(initial["max_depth"], 0)
        self.assertEqual(len(initial["relationships"]), 2)
        self.assert_security_headers(response_headers)

        relationships = [
            {
                "child_account_id": identifiers["Alpha"],
                "parent_account_id": None,
            },
            {
                "child_account_id": identifiers["Bravo"],
                "parent_account_id": identifiers["Alpha"],
            },
        ]
        status, response_headers, body = self.request(
            "POST",
            "/api/accounts/referral-topology",
            body=json.dumps(
                {
                    "expected_revision": initial["revision"],
                    "relationships": relationships,
                }
            ),
            headers=headers,
        )
        self.assertEqual(status, 200, body.decode(errors="replace"))
        payload = json.loads(body)
        self.assertIs(payload["ok"], True)
        self.assertNotEqual(payload["revision"], initial["revision"])
        self.assertEqual(payload["relationships"], relationships)
        self.assertEqual(payload["roots"], 1)
        self.assertEqual(payload["links"], 1)
        self.assertEqual(payload["max_depth"], 1)
        bravo = next(
            account for account in payload["accounts"] if account["label"] == "Bravo"
        )
        self.assertEqual(bravo["referrer_account_id"], identifiers["Alpha"])
        self.assertEqual(bravo["referrer_label"], "Alpha")
        self.assertFalse(any("code" in key for key in bravo))
        self.assert_security_headers(response_headers)

        # A stale editor cannot overwrite a newer complete topology.
        status, _, body = self.request(
            "POST",
            "/api/accounts/referral-topology",
            body=json.dumps(
                {
                    "expected_revision": initial["revision"],
                    "relationships": relationships,
                }
            ),
            headers=headers,
        )
        self.assertEqual(status, 409)
        self.assertIn("другом окне", json.loads(body)["error"])

        cyclic = [
            {
                "child_account_id": identifiers["Alpha"],
                "parent_account_id": identifiers["Bravo"],
            },
            {
                "child_account_id": identifiers["Bravo"],
                "parent_account_id": identifiers["Alpha"],
            },
        ]
        status, _, body = self.request(
            "POST",
            "/api/accounts/referral-topology",
            body=json.dumps(
                {
                    "expected_revision": payload["revision"],
                    "relationships": cyclic,
                }
            ),
            headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("цикл", json.loads(body)["error"])

        forbidden = [
            {
                "child_account_id": identifiers["Alpha"],
                "parent_account_id": None,
                "referral_code": "FORBIDDEN-PERSISTED-CODE",
            },
            relationships[1],
        ]
        status, _, body = self.request(
            "POST",
            "/api/accounts/referral-topology",
            body=json.dumps(
                {
                    "expected_revision": payload["revision"],
                    "relationships": forbidden,
                }
            ),
            headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("только child_account_id", json.loads(body)["error"])

        # The legacy code-bearing route is gone rather than silently translated.
        status, _, body = self.request(
            "POST",
            "/api/accounts/referrals",
            body=json.dumps({"relationships": []}),
            headers=headers,
        )
        self.assertEqual(status, 404)

        self.application.vault.lock()
        for method, request_body in (
            ("GET", None),
            (
                "POST",
                json.dumps(
                    {
                        "expected_revision": payload["revision"],
                        "relationships": relationships,
                    }
                ),
            ),
        ):
            with self.subTest(method=method):
                status, _, body = self.request(
                    method,
                    "/api/accounts/referral-topology",
                    body=request_body,
                    headers=headers,
                )
                self.assertEqual(status, 423)
                self.assertEqual(json.loads(body), {"error": "Vault заблокирован"})

    def test_module_delete_api_removes_only_an_exact_installed_id(self) -> None:
        archive = write_plugin_archive(
            Path(self.temporary.name) / "delete-api.softhub.zip",
            plugin_manifest(plugin_id="api.delete-test"),
        )
        installed = self.application.plugins.install(archive)
        plugin_root = Path(installed["active_path"]).parent
        self.assertTrue(plugin_root.is_dir())
        headers = {"X-Soft-Hub-Token": TEST_API_TOKEN}

        status, response_headers, body = self.request(
            "DELETE",
            "/api/modules/api.delete-test",
            headers=headers,
        )

        self.assertEqual(status, 200, body.decode(errors="replace"))
        self.assertEqual(
            json.loads(body),
            {
                "id": "api.delete-test",
                "removed": True,
                "cleanup_pending": False,
            },
        )
        self.assertFalse(plugin_root.exists())
        self.assertIsNone(self.application.plugins.get("api.delete-test"))
        self.assert_security_headers(response_headers)

        status, _, body = self.request(
            "DELETE",
            "/api/modules/../api.delete-test",
            headers=headers,
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "Маршрут не найден"})

    def test_force_stop_api_is_distinct_from_safe_stop(self) -> None:
        archive = write_plugin_archive(
            Path(self.temporary.name) / "force-api.softhub.zip",
            plugin_manifest(plugin_id="api.force-test", safe_stop=False),
            files={
                "plugin/main.py": (
                    "import time\n"
                    "def run(context):\n"
                    "    time.sleep(30)\n"
                    "    return {'late': True}\n"
                )
            },
        )
        self.application.plugins.install(archive)
        started = self.application.runs.start("api.force-test", "run", [])
        run_id = str(started["id"])
        wait_until(
            lambda: self.application.runs.get(run_id)["status"] == "running",
            timeout=5,
        )
        headers = {
            "X-Soft-Hub-Token": TEST_API_TOKEN,
            "Content-Type": "application/json",
        }

        status, _, body = self.request(
            "POST",
            f"/api/runs/{run_id}/stop",
            body=b"{}",
            headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("безопасную остановку", json.loads(body)["error"])

        status, response_headers, body = self.request(
            "POST",
            f"/api/runs/{run_id}/force-stop",
            body=b"{}",
            headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("FORCE STOP", json.loads(body)["error"])
        self.assert_security_headers(response_headers)

        status, response_headers, body = self.request(
            "POST",
            f"/api/runs/{run_id}/force-stop",
            body=json.dumps({"acknowledgement": "FORCE STOP"}),
            headers=headers,
        )
        self.assertEqual(status, 202, body.decode(errors="replace"))
        self.assertEqual(json.loads(body)["status"], "cancelling")
        self.assert_security_headers(response_headers)
        final = wait_until(
            lambda: (
                current
                if (current := self.application.runs.get(run_id))
                and current["status"] == "cancelled"
                else None
            ),
            timeout=5,
        )
        self.assertEqual(final["error"], "process_force_killed")

    def test_known_failure_review_api_preserves_evidence_and_reconcile_route_is_removed(self) -> None:
        archive = write_plugin_archive(
            Path(self.temporary.name) / "review-api.softhub.zip",
            plugin_manifest(plugin_id="api.review-test"),
            files={
                "plugin/main.py": (
                    "def run(context):\n"
                    "    raise RuntimeError('deterministic known failure')\n"
                )
            },
        )
        self.application.plugins.install(archive)
        started = self.application.runs.start("api.review-test", "run", [])
        run_id = str(started["id"])
        failed = wait_until(
            lambda: (
                current
                if (current := self.application.runs.get(run_id))
                and current["status"] == "failed"
                else None
            ),
            timeout=5,
        )
        original_error = failed["error"]
        headers = {
            "X-Soft-Hub-Token": TEST_API_TOKEN,
            "Content-Type": "application/json",
        }

        status, response_headers, body = self.request(
            "POST",
            f"/api/runs/{run_id}/review",
            body=json.dumps({"acknowledgement": "RECONCILED"}),
            headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("не нужны", json.loads(body)["error"])
        self.assertEqual(self.application.runs.get(run_id)["status"], "failed")
        self.assert_security_headers(response_headers)

        status, response_headers, body = self.request(
            "POST",
            f"/api/runs/{run_id}/review",
            body=b"{}",
            headers=headers,
        )
        self.assertEqual(status, 200, body.decode(errors="replace"))
        reviewed = json.loads(body)
        self.assertEqual(reviewed["status"], "reviewed")
        self.assertEqual(reviewed["error"], original_error)
        self.assertEqual(self.application.bootstrap()["stats"]["attention_runs"], 0)
        self.assertTrue(
            any(
                event["event_type"] == "failure_reviewed"
                for event in self.application.runs.events(run_id)
            )
        )
        self.assert_security_headers(response_headers)

        status, _, body = self.request(
            "POST",
            f"/api/runs/{run_id}/reconcile",
            body=json.dumps({"acknowledgement": "RECONCILED"}),
            headers=headers,
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "Маршрут не найден"})

    def test_technical_log_export_is_authenticated_exact_and_redacted_again(self) -> None:
        archive = write_plugin_archive(
            Path(self.temporary.name) / "log-export.softhub.zip",
            plugin_manifest(plugin_id="api.log-export"),
            files={"plugin/main.py": "def run(context):\n    return {'ok': True}\n"},
        )
        self.application.plugins.install(archive)
        started = self.application.runs.start("api.log-export", "run", [])
        run_id = str(started["id"])
        wait_until(
            lambda: self.application.runs.get(run_id)["status"] == "succeeded",
            timeout=5,
        )

        private_key = "0x" + "ab" * 32
        proxy = "192.0.2.10:8080:proxy-user:proxy-password"
        email = "private-export@example.test"
        email_password = "email-password-must-not-leak"
        api_token = "ApiTokenValueWithUpperLower1234567890"
        cookie = "session=browser-cookie-must-not-leak"
        authorization = "Bearer auth-token-must-not-leak"
        self.application.database.execute(
            "INSERT INTO run_events(run_id,created_at,level,event_type,message,account_id,data_json) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                run_id,
                "2026-08-08T12:00:00.000+00:00",
                "debug",
                "legacy_unredacted",
                (
                    f"private_key={private_key} proxy={proxy} email={email} "
                    f"password={email_password} api_key={api_token}\n"
                    f"Authorization: {authorization}\nCookie: {cookie}"
                ),
                None,
                json.dumps(
                    {
                        "privateKey": private_key,
                        "proxy": proxy,
                        "email": email,
                        "email_password": email_password,
                        "apiToken": api_token,
                        "headers": {
                            "authorization": authorization,
                            "cookies": cookie,
                        },
                        "nested": [{"clientSecret": "nested-secret-must-not-leak"}],
                    }
                ),
            ),
        )
        invalid_data_secret = "invalid-json-secret-must-not-leak"
        self.application.database.execute(
            "INSERT INTO run_events(run_id,created_at,level,event_type,message,account_id,data_json) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                run_id,
                "2026-08-08T12:00:01.000+00:00",
                "debug",
                "legacy_invalid_data",
                "Malformed historic payload",
                None,
                "{invalid-json:" + invalid_data_secret,
            ),
        )

        status, response_headers, _ = self.request(
            "GET", f"/api/runs/{run_id}/log"
        )
        self.assertEqual(status, 401)
        self.assert_security_headers(response_headers)

        status, response_headers, body = self.request(
            "GET",
            f"/api/runs/{run_id}/log",
            headers={"X-Soft-Hub-Token": TEST_API_TOKEN},
        )
        self.assertEqual(status, 200, body.decode(errors="replace"))
        self.assertEqual(response_headers["content-type"], "text/plain; charset=utf-8")
        self.assertEqual(
            response_headers["content-disposition"],
            f'attachment; filename="soft-hub-run-{run_id}.log"',
        )
        self.assertEqual(response_headers["x-soft-hub-redacted"], "true")
        self.assertEqual(int(response_headers["content-length"]), len(body))
        self.assert_security_headers(response_headers)

        decoded = body.decode("utf-8")
        for secret in (
            private_key,
            private_key[2:],
            proxy,
            "proxy-user",
            "proxy-password",
            email,
            email_password,
            api_token,
            cookie,
            authorization,
            "nested-secret-must-not-leak",
            invalid_data_secret,
        ):
            self.assertNotIn(secret, decoded)
        self.assertNotIn('"manifest"', decoded)
        self.assertNotIn('"options"', decoded)
        records = [json.loads(line) for line in decoded.splitlines()]
        self.assertEqual(records[0]["record"], "soft_hub_technical_log")
        self.assertEqual(records[-1]["record"], "end")
        self.assertEqual(records[-1]["omitted_events"], 0)
        self.assertFalse(records[-1]["truncated"])
        self.assertTrue(
            any(record.get("event_type") == "legacy_unredacted" for record in records)
        )

        status, _, events_body = self.request(
            "GET",
            f"/api/runs/{run_id}/events?limit=1000",
            headers={"X-Soft-Hub-Token": TEST_API_TOKEN},
        )
        self.assertEqual(status, 200)
        visible_events = events_body.decode("utf-8")
        for secret in (private_key, proxy, email, email_password, api_token, cookie):
            self.assertNotIn(secret, visible_events)
        self.assertNotIn(invalid_data_secret, visible_events)

    def test_run_account_projection_endpoints_are_compact_and_authenticated(self) -> None:
        self.application.vault.create(TEST_MASTER_PASSWORD)
        self.application.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "api-lifecycle.test:48080:user:pass",
                    "api-lifecycle@example.test",
                    label="API Lifecycle",
                )
            ]
        )
        account_id = self.application.vault.list_accounts()[0]["id"]
        archive = write_plugin_archive(
            Path(self.temporary.name) / "account-projection.softhub.zip",
            plugin_manifest(
                plugin_id="api.account-projection",
                account_mode="one_or_more",
                secrets=[],
            ),
            files={
                "plugin/main.py": (
                    "def run(context):\n"
                    "    account = context.accounts[0]\n"
                    "    context.account_state(account.id, status='succeeded', "
                    "stage='completed', progress=1, message='Готово')\n"
                    "    return {'ok': True}\n"
                )
            },
        )
        self.application.plugins.install(archive)
        started = self.application.runs.start(
            "api.account-projection", "run", [account_id]
        )
        run_id = str(started["id"])
        wait_until(
            lambda: self.application.runs.get(run_id)["status"] == "succeeded",
            timeout=5,
        )

        status, _, body = self.request("GET", f"/api/runs/{run_id}/accounts")
        self.assertEqual(status, 401)
        headers = {"X-Soft-Hub-Token": TEST_API_TOKEN}
        for path in (f"/api/runs/{run_id}/accounts", "/api/run-accounts?limit=10"):
            with self.subTest(path=path):
                status, response_headers, body = self.request(
                    "GET", path, headers=headers
                )
                self.assertEqual(status, 200, body.decode(errors="replace"))
                payload = json.loads(body)
                self.assertEqual(len(payload["accounts"]), 1)
                if path.startswith("/api/run-accounts"):
                    self.assertIs(payload["truncated"], False)
                row = payload["accounts"][0]
                self.assertEqual(row["run_id"], run_id)
                self.assertEqual(row["module_id"], "api.account-projection")
                self.assertEqual(row["account_id"], account_id)
                self.assertEqual(row["status"], "succeeded")
                self.assertEqual(row["stage"], "completed")
                self.assertEqual(row["progress"], 1.0)
                self.assertEqual(row["last_message"], "Готово")
                self.assertNotIn("private_key", row)
                self.assertNotIn("proxy", row)
                self.assertNotIn("email", row)
                self.assert_security_headers(response_headers)

        status, _, body = self.request(
            "GET",
            "/api/run-accounts?scope=active&limit=10",
            headers=headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"accounts": [], "truncated": False})

        wait_until(lambda: run_id not in self.application.runs._threads, timeout=3)
        self.application.database.execute(
            "UPDATE runs SET status='running' WHERE id=?", (run_id,)
        )
        status, _, body = self.request(
            "GET",
            "/api/run-accounts?scope=active&limit=10",
            headers=headers,
        )
        self.assertEqual(status, 200)
        active_payload = json.loads(body)
        self.assertEqual(len(active_payload["accounts"]), 1)
        self.assertEqual(active_payload["accounts"][0]["status"], "succeeded")
        self.assertEqual(active_payload["accounts"][0]["run_status"], "running")
        self.assertIs(active_payload["truncated"], False)

        self.application.database.execute(
            "UPDATE runs SET status='failed' WHERE id=?", (run_id,)
        )
        status, _, body = self.request(
            "GET",
            "/api/run-accounts?scope=attention&limit=10",
            headers=headers,
        )
        self.assertEqual(status, 200)
        attention_payload = json.loads(body)
        self.assertEqual(len(attention_payload["accounts"]), 1)
        self.assertEqual(attention_payload["accounts"][0]["status"], "succeeded")
        self.assertEqual(attention_payload["accounts"][0]["run_status"], "failed")
        self.assertEqual(self.application.bootstrap()["stats"]["attention_runs"], 1)
        self.assertEqual(self.application.bootstrap()["stats"]["needs_attention"], 0)

        status, _, body = self.request(
            "GET",
            "/api/run-accounts?scope=unknown-scope",
            headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("scope", json.loads(body)["error"])

    def test_result_report_endpoints_filter_project_and_require_unlocked_vault(self) -> None:
        self.application.vault.create(TEST_MASTER_PASSWORD)
        self.application.vault.import_records(
            [
                ImportRecord(
                    TEST_PRIVATE_KEY_A,
                    "api-report.test:48080:user:pass",
                    "api-report@example.test",
                    label="API Report Account",
                )
            ]
        )
        account = self.application.vault.list_accounts()[0]
        manifest = plugin_manifest(
            plugin_id="api.result-report",
            account_mode="one_or_more",
            secrets=[],
        )
        manifest["compatibility"]["hub"] = ">=0.6.8"
        manifest["actions"][0]["output"] = {
            "mode": "account_table",
            "title": "Parser report",
            "primary_kind": "parser_snapshot",
            "columns": [
                {
                    "key": "points",
                    "title": "Points",
                    "type": "integer",
                    "aggregate": "sum",
                },
                {"key": "balance", "title": "Balance", "type": "decimal_string"},
            ],
        }
        archive = write_plugin_archive(
            Path(self.temporary.name) / "result-report.softhub.zip",
            manifest,
            files={
                "plugin/main.py": (
                    "def run(context):\n"
                    "    account = context.accounts[0]\n"
                    "    context.result('Parsed', kind='parser_snapshot', "
                    "status='succeeded', account_id=account.id, "
                    "data={'points': 42, 'balance': '9.75', 'ignored': 'hidden'})\n"
                    "    context.account_state(account.id, status='succeeded', "
                    "stage='completed', progress=1, message='Done')\n"
                    "    return {'ok': True}\n"
                )
            },
        )
        self.application.plugins.install(archive)
        started = self.application.runs.start(
            "api.result-report", "run", [str(account["id"])]
        )
        run_id = str(started["id"])
        wait_until(
            lambda: self.application.runs.get(run_id)["status"] == "succeeded",
            timeout=5,
        )
        headers = {"X-Soft-Hub-Token": TEST_API_TOKEN}

        for path in ("/api/results/overview", f"/api/results/report?run_id={run_id}"):
            status, response_headers, body = self.request("GET", path)
            self.assertEqual(status, 401, body.decode(errors="replace"))
            self.assert_security_headers(response_headers)

        status, response_headers, body = self.request(
            "GET",
            "/api/results/overview?module_id=api.result-report&action_id=run&limit=10",
            headers=headers,
        )
        self.assertEqual(status, 200, body.decode(errors="replace"))
        overview = json.loads(body)
        self.assertEqual(len(overview["reports"]), 1)
        metadata = overview["reports"][0]
        self.assertEqual(metadata["run_id"], run_id)
        self.assertEqual(metadata["module_id"], "api.result-report")
        self.assertEqual(metadata["action_id"], "run")
        self.assertEqual(metadata["total"], 1)
        self.assertEqual(metadata["counts"]["succeeded"], 1)
        self.assertEqual(metadata["output"]["primary_kind"], "parser_snapshot")
        self.assert_security_headers(response_headers)

        status, _, body = self.request(
            "GET",
            "/api/results/overview?module_id=api.missing",
            headers=headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"reports": []})

        status, response_headers, body = self.request(
            "GET",
            f"/api/results/report?run_id={run_id}&limit=2000",
            headers=headers,
        )
        self.assertEqual(status, 200, body.decode(errors="replace"))
        report = json.loads(body)
        self.assertEqual(report["report"], metadata)
        self.assertEqual(report["total"], 1)
        self.assertEqual(report["result_count"], 1)
        self.assertFalse(report["truncated"])
        self.assertEqual(
            report["aggregates"],
            {"points": {"aggregate": "sum", "value": 42, "count": 1}},
        )
        self.assertEqual(len(report["rows"]), 1)
        row = report["rows"][0]
        self.assertEqual(row["account_id"], account["id"])
        self.assertEqual(row["account_label"], "API Report Account")
        self.assertEqual(row["account_address"], account["evm_address"])
        self.assertEqual(row["status"], "succeeded")
        self.assertEqual(row["result_status"], "succeeded")
        self.assertEqual(row["data"], {"points": 42, "balance": "9.75"})
        self.assertNotIn("ignored", row["data"])
        self.assert_security_headers(response_headers)

        status, _, body = self.request("GET", "/api/results", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(set(json.loads(body)), {"results"})

        status, _, body = self.request(
            "POST",
            "/api/vault/lock",
            body=b"{}",
            headers={**headers, "Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        for path in ("/api/results/overview", f"/api/results/report?run_id={run_id}"):
            with self.subTest(path=path):
                status, protected_headers, body = self.request("GET", path, headers=headers)
                self.assertEqual(status, 423)
                self.assertEqual(json.loads(body), {"error": "Vault заблокирован"})
                self.assert_security_headers(protected_headers)

    def test_bootstrap_keeps_old_active_runs_and_uses_full_database_stats(self) -> None:
        archive = write_plugin_archive(
            Path(self.temporary.name) / "bootstrap-feed.softhub.zip",
            plugin_manifest(plugin_id="api.bootstrap-feed"),
        )
        self.application.plugins.install(archive)
        terminal_rows = [
            (
                f"terminal-{index:02d}",
                "succeeded",
                f"2026-01-{index + 1:02d}T00:00:00+00:00",
            )
            for index in range(31)
        ]
        attention_rows = [
            (
                f"attention-{index:03d}",
                "failed",
                f"2026-02-01T00:{index // 60:02d}:{index % 60:02d}+00:00",
            )
            for index in range(501)
        ]
        with self.application.database.transaction() as connection:
            connection.executemany(
                "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,"
                "account_count,requested_at) VALUES (?,'api.bootstrap-feed','1.0.0',"
                "'run',?,0,0,?)",
                [
                    ("active-older-than-terminals", "running", "2025-01-01T00:00:00+00:00"),
                    *terminal_rows,
                    *attention_rows,
                ],
            )

        payload = self.application.bootstrap()
        run_ids = [run["id"] for run in payload["runs"]]
        self.assertEqual(payload["stats"]["active_runs"], 1)
        self.assertEqual(payload["stats"]["needs_attention"], 0)
        self.assertEqual(payload["stats"]["attention_runs"], 501)
        self.assertFalse(payload["runs_truncated"])
        self.assertEqual(run_ids[0], "active-older-than-terminals")
        self.assertIn("active-older-than-terminals", run_ids)
        self.assertNotIn("terminal-00", run_ids)
        self.assertEqual(len(run_ids), 31)

    def test_run_api_cannot_bypass_manifest_option_schema(self) -> None:
        manifest = plugin_manifest(plugin_id="api.option-guard")
        manifest["actions"][0]["options"] = {
            "type": "object",
            "required": ["count"],
            "properties": {
                "count": {
                    "type": "integer",
                    "minimum": 2,
                    "maximum": 6,
                    "multipleOf": 2,
                }
            },
            "additionalProperties": False,
        }
        archive = write_plugin_archive(
            Path(self.temporary.name) / "option-guard.softhub.zip",
            manifest,
        )
        self.application.plugins.install(archive)
        headers = {
            "X-Soft-Hub-Token": TEST_API_TOKEN,
            "Content-Type": "application/json",
        }
        for label, options in (
            ("bool-is-not-integer", {"count": True}),
            ("unknown-property", {"count": 4, "injected": "bypass"}),
            ("multiple-of", {"count": 3}),
        ):
            with self.subTest(label=label):
                status, response_headers, body = self.request(
                    "POST",
                    "/api/modules/api.option-guard/run",
                    body=json.dumps(
                        {
                            "action_id": "run",
                            "account_ids": [],
                            "options": options,
                        }
                    ),
                    headers=headers,
                )
                self.assertEqual(status, 400, body.decode(errors="replace"))
                self.assert_security_headers(response_headers)
        self.assertEqual(
            self.application.database.all(
                "SELECT * FROM runs WHERE module_id='api.option-guard'"
            ),
            [],
        )

    def test_batch_api_is_atomic_persistent_and_idempotent(self) -> None:
        for plugin_id in ("api.batch-one", "api.batch-two"):
            archive = write_plugin_archive(
                Path(self.temporary.name) / f"{plugin_id}.softhub.zip",
                plugin_manifest(plugin_id=plugin_id),
            )
            self.application.plugins.install(archive)
        headers = {
            "X-Soft-Hub-Token": TEST_API_TOKEN,
            "Content-Type": "application/json",
        }
        idempotency_key = str(uuid.uuid4())
        runs = [
            {
                "module_id": plugin_id,
                "action_id": "run",
                "account_ids": [],
                "options": {},
                "acknowledgement": "",
            }
            for plugin_id in ("api.batch-one", "api.batch-two")
        ]
        payload = {"idempotency_key": idempotency_key, "runs": runs}

        status, response_headers, body = self.request(
            "POST",
            "/api/runs/batch",
            body=json.dumps(payload),
            headers=headers,
        )
        self.assertEqual(status, 202, body.decode(errors="replace"))
        first = json.loads(body)
        self.assertIs(first["replayed"], False)
        self.assertEqual(len(first["runs"]), 2)
        run_ids = [run["id"] for run in first["runs"]]
        self.assertEqual(len(set(run_ids)), 2)
        self.assert_security_headers(response_headers)

        status, response_headers, body = self.request(
            "POST",
            "/api/runs/batch",
            body=json.dumps(payload),
            headers=headers,
        )
        self.assertEqual(status, 202, body.decode(errors="replace"))
        replay = json.loads(body)
        self.assertIs(replay["replayed"], True)
        self.assertEqual([run["id"] for run in replay["runs"]], run_ids)
        self.assert_security_headers(response_headers)

        status, response_headers, body = self.request(
            "POST",
            "/api/runs/batch",
            body=json.dumps({**payload, "runs": runs[:1]}),
            headers=headers,
        )
        self.assertEqual(status, 409)
        self.assertIn("другой пачки", json.loads(body)["error"])
        self.assert_security_headers(response_headers)

        before = self.application.database.one("SELECT COUNT(*) AS count FROM runs")["count"]
        status, response_headers, body = self.request(
            "POST",
            "/api/runs/batch",
            body=json.dumps(
                {
                    "idempotency_key": str(uuid.uuid4()),
                    "runs": [runs[0], {**runs[1], "module_id": "api.batch-missing"}],
                }
            ),
            headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("не найден или выключен", json.loads(body)["error"])
        self.assertEqual(
            self.application.database.one("SELECT COUNT(*) AS count FROM runs")["count"],
            before,
        )
        self.assertEqual(
            self.application.database.one("SELECT COUNT(*) AS count FROM run_batches"),
            {"count": 1},
        )
        self.assert_security_headers(response_headers)
        for run_id in run_ids:
            wait_until(
                lambda run_id=run_id: run_id not in self.application.runs._threads,
                timeout=5,
            )

    def test_api_token_is_required_in_header_and_never_accepted_from_query(self) -> None:
        for label, path, headers in (
            ("missing", "/api/health", {}),
            ("wrong", "/api/health", {"X-Soft-Hub-Token": "wrong-test-token"}),
            ("query", f"/api/health?token={TEST_API_TOKEN}", {}),
        ):
            with self.subTest(label=label):
                status, response_headers, body = self.request("GET", path, headers=headers)
                self.assertEqual(status, 401)
                self.assertEqual(json.loads(body), {"error": "Не авторизовано"})
                self.assert_security_headers(response_headers)

        status, headers, body = self.request(
            "GET",
            "/api/health",
            headers={"X-Soft-Hub-Token": TEST_API_TOKEN},
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])
        self.assertTrue(headers["content-type"].startswith("application/json"))
        self.assert_security_headers(headers)

    def test_host_allowlist_blocks_dns_rebinding_for_static_and_api(self) -> None:
        for path, headers in (
            ("/", {"Host": "attacker.example"}),
            (
                "/api/health",
                {"Host": "attacker.example", "X-Soft-Hub-Token": TEST_API_TOKEN},
            ),
            ("/", {"Host": "127.0.0.1.attacker.example"}),
            ("/", {"Host": f"127.0.0.1:{self.port + 1}"}),
            ("/", {"Host": f"localhost:{self.port + 1}"}),
        ):
            with self.subTest(path=path, host=headers["Host"]):
                status, response_headers, body = self.request("GET", path, headers=headers)
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(body), {"error": "Недопустимый Host"})
                self.assert_security_headers(response_headers)

    def test_mutations_reject_foreign_origin_after_authentication(self) -> None:
        base_headers = {
            "X-Soft-Hub-Token": TEST_API_TOKEN,
            "Content-Type": "application/json",
        }
        for origin in (
            "https://localhost",
            "http://attacker.example",
            "http://127.0.0.1.attacker.example",
            "http://127.0.0.1:12345",
            "http://localhost:54321",
            f"http://localhost:{self.port}",
            "null",
        ):
            with self.subTest(origin=origin):
                status, headers, body = self.request(
                    "POST",
                    "/api/vault/lock",
                    body=b"{}",
                    headers={**base_headers, "Origin": origin},
                )
                self.assertEqual(status, 403)
                self.assertEqual(json.loads(body), {"error": "Недопустимый Origin"})
                self.assert_security_headers(headers)

        for origin in (None, f"http://127.0.0.1:{self.port}"):
            with self.subTest(origin=origin):
                request_headers = dict(base_headers)
                if origin:
                    request_headers["Origin"] = origin
                status, headers, body = self.request(
                    "POST",
                    "/api/vault/lock",
                    body=b"{}",
                    headers=request_headers,
                )
                self.assertEqual(status, 200)
                self.assertFalse(json.loads(body)["vault"]["unlocked"])
                self.assert_security_headers(headers)

        status, headers, body = self.request(
            "POST",
            "/api/vault/lock",
            body=b"{}",
            headers={
                **base_headers,
                "Host": f"localhost:{self.port}",
                "Origin": f"http://localhost:{self.port}",
            },
        )
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["vault"]["unlocked"])
        self.assert_security_headers(headers)

        status, _, body = self.request(
            "POST",
            "/api/vault/lock",
            body=b"{}",
            headers={
                "X-Soft-Hub-Token": "wrong-test-token",
                "Content-Type": "application/json",
                "Origin": "http://attacker.example",
            },
        )
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body), {"error": "Не авторизовано"})

    def test_options_is_denied_with_the_same_security_headers(self) -> None:
        status, headers, _ = self.request("OPTIONS", "/api/health")
        self.assertEqual(status, 405)
        self.assert_security_headers(headers)

    def test_plaintext_account_export_requires_reauthentication_and_has_exact_columns(self) -> None:
        self.application.vault.create(TEST_MASTER_PASSWORD)
        self.application.vault.import_records(
            [
                ImportRecord(
                    private_key=TEST_PRIVATE_KEY_A,
                    proxy="-proxy.example.test:8080:proxy-user:proxy-password",
                    email="=2+2@example.test",
                    twitter="@SUM(1+1)",
                    adspower_profile="opaque profile 7",
                )
            ]
        )
        self.application.vault.set_capsolver_api_key("CAP-never-export")
        self.application.vault.set_adspower_api_key("ADS-never-export")
        headers = {
            "X-Soft-Hub-Token": TEST_API_TOKEN,
            "Content-Type": "application/json",
        }
        status, response_headers, body = self.request(
            "POST",
            "/api/accounts/export",
            body=json.dumps(
                {
                    "password": TEST_MASTER_PASSWORD,
                    "acknowledgement": "EXPORT",
                }
            ),
            headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertNotIn(TEST_PRIVATE_KEY_A.encode(), body)
        self.assert_security_headers(response_headers)

        status, response_headers, body = self.request(
            "POST",
            "/api/accounts/export",
            body=json.dumps(
                {
                    "password": TEST_MASTER_PASSWORD,
                    "acknowledgement": PLAINTEXT_EXPORT_ACKNOWLEDGEMENT,
                }
            ),
            headers=headers,
        )
        self.assertEqual(status, 200)
        self.assertTrue(response_headers["content-type"].startswith("text/csv"))
        self.assertIn("attachment", response_headers["content-disposition"])
        self.assertEqual(response_headers["x-soft-hub-spreadsheet-safe"], "false")
        decoded = body.decode("utf-8-sig")
        self.assertEqual(
            decoded.splitlines()[0],
            "private_key,proxy,email,twitter,adspower_profile",
        )
        self.assertIn(TEST_PRIVATE_KEY_A, decoded)
        self.assertIn("-proxy.example.test:8080:proxy-user:proxy-password", decoded)
        self.assertIn("=2+2@example.test", decoded)
        self.assertIn("@SUM(1+1)", decoded)
        self.assertIn("opaque profile 7", decoded)
        self.assertNotIn("CAP-never-export", decoded)
        self.assertNotIn("ADS-never-export", decoded)
        self.assertEqual(
            list(csv.reader(io.StringIO(decoded))),
            [
                ["private_key", "proxy", "email", "twitter", "adspower_profile"],
                [
                    TEST_PRIVATE_KEY_A,
                    "-proxy.example.test:8080:proxy-user:proxy-password",
                    "=2+2@example.test",
                    "@SUM(1+1)",
                    "opaque profile 7",
                ],
            ],
        )
        self.assert_security_headers(response_headers)

        status, response_headers, body = self.request(
            "POST",
            "/api/accounts/export",
            body=json.dumps(
                {
                    "password": TEST_MASTER_PASSWORD,
                    "acknowledgement": PLAINTEXT_EXPORT_ACKNOWLEDGEMENT,
                    "format": "xlsx",
                }
            ),
            headers=headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            response_headers["content-type"],
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.assertIn("soft-hub-accounts.xlsx", response_headers["content-disposition"])
        self.assertEqual(response_headers["x-soft-hub-spreadsheet-safe"], "true")
        self.assert_security_headers(response_headers)
        with zipfile.ZipFile(io.BytesIO(body)) as workbook:
            self.assertEqual(
                set(workbook.namelist()),
                {
                    "[Content_Types].xml",
                    "_rels/.rels",
                    "xl/workbook.xml",
                    "xl/_rels/workbook.xml.rels",
                    "xl/worksheets/sheet1.xml",
                },
            )
            sheet_bytes = workbook.read("xl/worksheets/sheet1.xml")
        self.assertNotIn(b"<f", sheet_bytes, "XLSX export must never create formula cells")
        namespace = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        sheet = ET.fromstring(sheet_bytes)
        extracted: list[list[str]] = []
        for row in sheet.findall(".//s:sheetData/s:row", namespace):
            cells: list[str] = []
            for cell in row.findall("s:c", namespace):
                self.assertEqual(cell.get("t"), "inlineStr")
                text = cell.find("s:is/s:t", namespace)
                self.assertIsNotNone(text)
                cells.append(text.text or "")
            extracted.append(cells)
        self.assertEqual(
            extracted,
            [
                ["private_key", "proxy", "email", "twitter", "adspower_profile"],
                [
                    TEST_PRIVATE_KEY_A,
                    "-proxy.example.test:8080:proxy-user:proxy-password",
                    "=2+2@example.test",
                    "@SUM(1+1)",
                    "opaque profile 7",
                ],
            ],
        )
        self.assertNotIn(b"CAP-never-export", body)
        self.assertNotIn(b"ADS-never-export", body)

        status, response_headers, body = self.request(
            "POST",
            "/api/accounts/export",
            body=json.dumps(
                {
                    "password": TEST_MASTER_PASSWORD,
                    "acknowledgement": PLAINTEXT_EXPORT_ACKNOWLEDGEMENT,
                    "format": "unsafe-spreadsheet",
                }
            ),
            headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("csv или xlsx", json.loads(body)["error"])
        self.assertNotIn(TEST_PRIVATE_KEY_A.encode(), body)
        self.assert_security_headers(response_headers)

    def test_import_rejects_malformed_rows_atomically_in_both_payload_shapes(self) -> None:
        self.application.vault.create(TEST_MASTER_PASSWORD)
        headers = {
            "X-Soft-Hub-Token": TEST_API_TOKEN,
            "Content-Type": "application/json",
        }
        valid = {
            "private_key": TEST_PRIVATE_KEY_A,
            "proxy": "192.0.2.10:8080:proxy-user:proxy-password",
            "email": "alpha@example.test",
            "twitter": "@alpha",
        }

        status, _, body = self.request(
            "POST",
            "/api/accounts/import",
            body=json.dumps({"records": [valid, None]}),
            headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("строка импорта", json.loads(body)["error"].lower())
        self.assertEqual(self.application.vault.list_accounts(), [])

        status, _, body = self.request(
            "POST",
            "/api/accounts/import",
            body=json.dumps(
                {
                    "private_keys": [TEST_PRIVATE_KEY_A],
                    "proxies": [valid["proxy"]],
                    "emails": [valid["email"]],
                    "twitters": [123],
                }
            ),
            headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("строками", json.loads(body)["error"])
        self.assertEqual(self.application.vault.list_accounts(), [])

    def test_global_settings_are_encrypted_and_bootstrap_only_exposes_status(self) -> None:
        self.application.vault.create(TEST_MASTER_PASSWORD)
        capsolver = "CAP-sensitive-key-123456"
        adspower = "ADS-sensitive-key-123456"
        headers = {
            "X-Soft-Hub-Token": TEST_API_TOKEN,
            "Content-Type": "application/json",
        }
        status, _, body = self.request(
            "POST",
            "/api/settings/capsolver",
            body=json.dumps({"action": "save", "api_key": capsolver}),
            headers=headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"capsolver": {"configured": True}})
        status, _, body = self.request(
            "POST",
            "/api/settings/adspower",
            body=json.dumps({"action": "save", "api_key": adspower}),
            headers=headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"adspower": {"configured": True}})
        status, _, body = self.request(
            "GET",
            "/api/bootstrap",
            headers={"X-Soft-Hub-Token": TEST_API_TOKEN},
        )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertIs(payload["vault"]["capsolver_configured"], True)
        self.assertIs(payload["vault"]["adspower_api_configured"], True)
        self.assertNotIn(capsolver, body.decode())
        self.assertNotIn(adspower, body.decode())

    def test_locked_vault_hides_all_account_and_run_projections(self) -> None:
        self.application.vault.create(TEST_MASTER_PASSWORD)
        self.application.vault.import_records(
            [
                ImportRecord(
                    private_key=TEST_PRIVATE_KEY_A,
                    proxy="locked-canary.test:17777:canary-user:canary-pass",
                    email="locked-canary@example.test",
                    twitter="@locked-canary",
                    label="LOCKED CANARY ACCOUNT",
                    tags=("locked-canary-tag",),
                    adspower_profile="locked-canary-profile",
                )
            ]
        )
        self.application.vault.set_capsolver_api_key("LOCKED-CANARY-CAPSOLVER")
        self.application.vault.set_adspower_api_key("LOCKED-CANARY-ADSPOWER")
        account = self.application.vault.list_accounts()[0]
        manifest = plugin_manifest(
            plugin_id="api.locked-projection",
            account_mode="none",
            secrets=[],
        )
        archive = write_plugin_archive(
            Path(self.temporary.name) / "locked-projection.softhub.zip",
            manifest,
        )
        self.application.plugins.install(archive)
        run_id = str(uuid.uuid4())
        now = "2026-08-08T12:00:00+00:00"
        with self.application.database.transaction() as connection:
            connection.execute(
                "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,"
                "account_count,requested_at,finished_at,summary_json,error) "
                "VALUES (?,'api.locked-projection','1.0.0','run','failed',0.25,1,?,?,?,?)",
                (
                    run_id,
                    now,
                    now,
                    json.dumps({"canary": "LOCKED CANARY SUMMARY"}),
                    "LOCKED CANARY ERROR",
                ),
            )
            connection.execute(
                "INSERT INTO run_account_states(run_id,account_id,account_label,status,stage,"
                "progress,last_message,updated_at) VALUES (?,?,?,'failed','canary',0.25,?,?)",
                (
                    run_id,
                    account["id"],
                    account["label"],
                    "LOCKED CANARY ACCOUNT MESSAGE",
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO run_events(run_id,created_at,level,event_type,message,account_id,data_json) "
                "VALUES (?,?,'error','log',?,?,?)",
                (
                    run_id,
                    now,
                    "LOCKED CANARY EVENT",
                    account["id"],
                    json.dumps({"canary": "LOCKED CANARY EVENT DATA"}),
                ),
            )
            connection.execute(
                "INSERT INTO results(id,run_id,module_id,account_id,kind,status,title,data_json,created_at) "
                "VALUES (?,?, 'api.locked-projection',?,'summary','failed',?,?,?)",
                (
                    str(uuid.uuid4()),
                    run_id,
                    account["id"],
                    "LOCKED CANARY RESULT",
                    json.dumps({"canary": "LOCKED CANARY RESULT DATA"}),
                    now,
                ),
            )

        headers = {"X-Soft-Hub-Token": TEST_API_TOKEN}
        status, _, unlocked_body = self.request("GET", "/api/bootstrap", headers=headers)
        self.assertEqual(status, 200)
        self.assertIn(b"LOCKED CANARY ACCOUNT", unlocked_body)

        status, _, body = self.request(
            "POST",
            "/api/vault/lock",
            body=b"{}",
            headers={**headers, "Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["vault"]["unlocked"])

        status, response_headers, locked_body = self.request(
            "GET", "/api/bootstrap", headers=headers
        )
        self.assertEqual(status, 200)
        self.assert_security_headers(response_headers)
        payload = json.loads(locked_body)
        self.assertEqual(payload["accounts"], [])
        self.assertEqual(
            payload["referral_topology"],
            {"revision": "", "relationships": [], "roots": 0, "links": 0, "max_depth": 0},
        )
        self.assertEqual(payload["runs"], [])
        self.assertEqual(payload["results"], [])
        self.assertEqual(payload["stats"]["accounts"], 0)
        self.assertEqual(payload["stats"]["results"], 0)
        self.assertIsNone(payload["vault"]["capsolver_configured"])
        self.assertIsNone(payload["vault"]["adspower_api_configured"])
        for canary in (
            "LOCKED CANARY ACCOUNT",
            "LOCKED CANARY SUMMARY",
            "LOCKED CANARY ERROR",
            "LOCKED CANARY EVENT",
            "LOCKED CANARY RESULT",
            str(account["id"]),
            str(account["evm_address"]),
            "locked-canary.test",
            "locked-canary@example.test",
            "locked-canary-profile",
        ):
            self.assertNotIn(canary, locked_body.decode())

        protected_paths = (
            "/api/accounts",
            "/api/accounts/referral-topology",
            "/api/runs",
            "/api/run-accounts",
            "/api/results",
            f"/api/runs/{run_id}",
            f"/api/runs/{run_id}/accounts",
            f"/api/runs/{run_id}/events",
            f"/api/runs/{run_id}/log",
        )
        for path in protected_paths:
            with self.subTest(path=path):
                status, protected_headers, protected_body = self.request(
                    "GET", path, headers=headers
                )
                self.assertEqual(status, 423)
                self.assertEqual(json.loads(protected_body), {"error": "Vault заблокирован"})
                self.assert_security_headers(protected_headers)

        protected_posts = (
            (
                "/api/runs/batch",
                {"idempotency_key": str(uuid.uuid4()), "runs": []},
            ),
            (f"/api/runs/{run_id}/stop", {}),
            (f"/api/runs/{run_id}/force-stop", {"acknowledgement": "FORCE STOP"}),
            (f"/api/runs/{run_id}/review", {}),
            ("/api/settings/capsolver", {"action": "clear"}),
            ("/api/settings/adspower", {"action": "clear"}),
            (
                "/api/accounts/export",
                {
                    "password": TEST_MASTER_PASSWORD,
                    "acknowledgement": PLAINTEXT_EXPORT_ACKNOWLEDGEMENT,
                    "format": "csv",
                },
            ),
        )
        for path, request_body in protected_posts:
            with self.subTest(path=path):
                status, protected_headers, protected_body = self.request(
                    "POST",
                    path,
                    body=json.dumps(request_body),
                    headers={**headers, "Content-Type": "application/json"},
                )
                self.assertEqual(status, 423)
                self.assertEqual(json.loads(protected_body), {"error": "Vault заблокирован"})
                self.assert_security_headers(protected_headers)

        status, protected_headers, protected_body = self.request(
            "DELETE", f"/api/accounts/{account['id']}", headers=headers
        )
        self.assertEqual(status, 423)
        self.assertEqual(json.loads(protected_body), {"error": "Vault заблокирован"})
        self.assert_security_headers(protected_headers)

        status, _, body = self.request(
            "POST",
            "/api/modules/api.locked-projection/run",
            body=json.dumps(
                {"action_id": "run", "account_ids": [], "options": {}}
            ),
            headers={**headers, "Content-Type": "application/json"},
        )
        self.assertEqual(status, 423)
        self.assertEqual(json.loads(body), {"error": "Vault заблокирован"})

        status, _, body = self.request(
            "POST",
            "/api/vault/unlock",
            body=json.dumps({"password": TEST_MASTER_PASSWORD}),
            headers={**headers, "Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        status, _, body = self.request("GET", "/api/accounts", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["accounts"][0]["id"], account["id"])

    def test_patch_feed_scan_normalizes_and_persists_owner_without_accepting_renderer_metadata(self) -> None:
        calls: list[str] = []

        class StubPatchFeed:
            def scan(self, owner: str) -> list[dict[str, str | None]]:
                calls.append(owner)
                return [
                    {
                        "owner": owner,
                        "repository": "sample.patch",
                        "repository_url": f"https://github.com/{owner}/sample.patch",
                        "pushed_at": None,
                        "description": "Sample",
                        "release_tag": "v1.0.0",
                        "asset_url": f"https://github.com/{owner}/sample.patch/releases/download/v1/sample.softhub.zip",
                        "status": "ready",
                        "reason": "single_installable_asset",
                    }
                ]

        self.application.patch_feed = StubPatchFeed()  # type: ignore[assignment]
        status, response_headers, body = self.request(
            "POST",
            "/api/patch-feed/scan",
            body=json.dumps({"owner": "https://github.com/Spr1ntray"}),
            headers={
                "X-Soft-Hub-Token": TEST_API_TOKEN,
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["owner"], "spr1ntray")
        self.assertEqual(calls, ["spr1ntray"])
        self.assertEqual(self.application.database.setting("github_patch_owner"), "spr1ntray")
        self.assertEqual(payload["patches"][0]["status"], "ready")
        self.assert_security_headers(response_headers)

    def test_patch_radar_marks_an_installed_github_asset_current_and_only_offers_newer(self) -> None:
        owner = "spr1ntray"
        repository = "sample.patch"
        archive = write_plugin_archive(
            Path(self.temporary.name) / "sample-1.0.0.softhub.zip",
            plugin_manifest("1.0.0", plugin_id="io.example.sample"),
        )

        class StubGithub:
            def download(self, url: str, destination: Path) -> GitHubPackage:
                destination.write_bytes(archive.read_bytes())
                return GitHubPackage(
                    owner=owner,
                    repository=repository,
                    filename="sample-1.0.0.softhub.zip",
                    download_url=url,
                    release="v1.0.0",
                )

        class MutablePatchFeed:
            version = "1.0.0"

            def scan(self, _owner: str) -> list[dict[str, object]]:
                version = self.version
                asset_name = f"sample-{version}.softhub.zip"
                asset_url = (
                    f"https://github.com/{owner}/{repository}/releases/download/"
                    f"v{version}/{asset_name}"
                )
                return [
                    {
                        "owner": owner,
                        "repository": repository,
                        "repository_url": f"https://github.com/{owner}/{repository}",
                        "pushed_at": None,
                        "description": "Sample",
                        "release_tag": f"v{version}",
                        "asset_name": asset_name,
                        "asset_url": asset_url,
                        "status": "ready",
                        "reason": "single_installable_asset",
                    }
                ]

        feed = MutablePatchFeed()
        self.application.patch_feed = feed  # type: ignore[assignment]
        self.application.github = StubGithub()  # type: ignore[assignment]
        headers = {
            "X-Soft-Hub-Token": TEST_API_TOKEN,
            "Content-Type": "application/json",
        }

        def scan() -> dict[str, object]:
            status, _, body = self.request(
                "POST",
                "/api/patch-feed/scan",
                body=json.dumps({"owner": owner}),
                headers=headers,
            )
            self.assertEqual(status, 200, body.decode(errors="replace"))
            return json.loads(body)["patches"][0]

        initial = scan()
        self.assertEqual(initial["version_state"], "untracked")
        self.assertIs(initial["installable"], True)

        status, _, body = self.request(
            "POST",
            "/api/modules/install/github",
            body=json.dumps({"url": initial["asset_url"]}),
            headers=headers,
        )
        self.assertEqual(status, 201, body.decode(errors="replace"))
        self.assertEqual(json.loads(body)["version"], "1.0.0")

        current = scan()
        self.assertEqual(current["version_state"], "installed")
        self.assertEqual(current["installed_module_id"], "io.example.sample")
        self.assertEqual(current["installed_version"], "1.0.0")
        self.assertIs(current["installable"], False)

        feed.version = "1.1.0"
        update = scan()
        self.assertEqual(update["version_state"], "update_available")
        self.assertIs(update["installable"], True)

        feed.version = "0.9.0"
        obsolete = scan()
        self.assertEqual(obsolete["version_state"], "newer_installed")
        self.assertIs(obsolete["installable"], False)

        status, _, body = self.request(
            "POST",
            "/api/modules/install/github",
            body=json.dumps(
                {
                    "url": initial["asset_url"],
                    "module_id": "renderer.spoof",
                    "version": "99.0.0",
                }
            ),
            headers=headers,
        )
        self.assertEqual(status, 400)
        self.assertIn("только URL", json.loads(body)["error"])

    def test_data_directory_has_a_cross_process_exclusive_owner(self) -> None:
        with self.assertRaisesRegex(InstanceLockError, "уже открыт"):
            HubApplication(self.application.paths.data_dir)


if __name__ == "__main__":
    unittest.main()
