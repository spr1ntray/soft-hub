from __future__ import annotations

import socket
import ssl
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from soft_hub.tls import ca_bundle_path, github_connection_error, public_https_context


class PublicTlsTests(unittest.TestCase):
    def test_context_keeps_system_roots_and_adds_bundled_mozilla_roots(self) -> None:
        with tempfile.TemporaryDirectory(prefix="soft-hub-ca-test-") as temporary:
            bundle = Path(temporary) / "cacert.pem"
            bundle.write_text("fixture", encoding="ascii")
            context = mock.Mock(spec=ssl.SSLContext)
            with mock.patch("soft_hub.tls.certifi.where", return_value=str(bundle)), mock.patch(
                "soft_hub.tls.ssl.create_default_context", return_value=context
            ) as create_default:
                result = public_https_context()

        self.assertIs(result, context)
        create_default.assert_called_once_with()
        context.load_verify_locations.assert_called_once_with(cafile=str(bundle.resolve()))

    def test_missing_bundled_roots_fail_closed(self) -> None:
        with mock.patch(
            "soft_hub.tls.certifi.where", return_value="/missing/soft-hub/cacert.pem"
        ):
            with self.assertRaisesRegex(RuntimeError, "TLS-сертификатов"):
                ca_bundle_path()

    def test_connection_errors_are_safe_and_actionable(self) -> None:
        certificate = urllib.error.URLError(
            ssl.SSLCertVerificationError(1, "certificate verify failed")
        )
        self.assertIn("дату и время на компьютере", github_connection_error(certificate))
        self.assertIn("не ответил вовремя", github_connection_error(urllib.error.URLError(socket.timeout())))
        self.assertIn(
            "DNS",
            github_connection_error(urllib.error.URLError(socket.gaierror(-2, "fixture"))),
        )
        generic = github_connection_error(urllib.error.URLError(OSError("secret detail")))
        self.assertIn("VPN", generic)
        self.assertNotIn("secret detail", generic)
        proxy = github_connection_error(
            urllib.error.URLError(OSError("Tunnel connection failed: 407 Proxy Authentication Required"))
        )
        self.assertIn("Прокси-сервер", proxy)


if __name__ == "__main__":
    unittest.main()
