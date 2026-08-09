from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from soft_hub.config import MAX_ARCHIVE_BYTES
from soft_hub.github_install import GitHubInstallError, GitHubPackageFetcher


class StubResponse(io.BytesIO):
    def __init__(self, payload: bytes, *, url: str, headers: dict[str, str] | None = None):
        super().__init__(payload)
        self._url = url
        self.headers = headers or {}

    def __enter__(self) -> "StubResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def geturl(self) -> str:
        return self._url


class QueueOpener:
    def __init__(self, *responses: StubResponse):
        self.responses = list(responses)
        self.requests: list[Any] = []

    def open(self, request: Any, timeout: int) -> StubResponse:
        self.requests.append((request, timeout))
        if not self.responses:
            raise AssertionError("No response queued")
        return self.responses.pop(0)


class GitHubPackageFetcherTests(unittest.TestCase):
    def test_direct_release_asset_is_resolved_without_api(self) -> None:
        opener = QueueOpener()
        package = GitHubPackageFetcher(opener).resolve(
            "https://github.com/sprintray/example/releases/download/v1.2.3/"
            "example-1.2.3.softhub.zip"
        )
        self.assertEqual(package.owner, "sprintray")
        self.assertEqual(package.repository, "example")
        self.assertEqual(package.release, "v1.2.3")
        self.assertEqual(package.filename, "example-1.2.3.softhub.zip")
        self.assertEqual(opener.requests, [])

    def test_repository_url_selects_single_softhub_asset_from_latest_release(self) -> None:
        payload = json.dumps(
            {
                "tag_name": "v2.0.0",
                "assets": [
                    {
                        "name": "notes.txt",
                        "browser_download_url": "https://github.com/o/r/releases/download/v2.0.0/notes.txt",
                    },
                    {
                        "name": "r-2.0.0.softhub.zip",
                        "browser_download_url": (
                            "https://github.com/o/r/releases/download/v2.0.0/"
                            "r-2.0.0.softhub.zip"
                        ),
                    },
                ],
            }
        ).encode()
        opener = QueueOpener(
            StubResponse(payload, url="https://api.github.com/repos/o/r/releases/latest")
        )
        package = GitHubPackageFetcher(opener).resolve("https://github.com/o/r")
        self.assertEqual(package.filename, "r-2.0.0.softhub.zip")
        self.assertEqual(package.release, "v2.0.0")
        self.assertEqual(opener.requests[0][1], 30)

    def test_ambiguous_release_requires_direct_asset_url(self) -> None:
        payload = json.dumps(
            {
                "tag_name": "v1",
                "assets": [
                    {
                        "name": "mac.softhub.zip",
                        "browser_download_url": "https://github.com/o/r/releases/download/v1/mac.softhub.zip",
                    },
                    {
                        "name": "win.softhub.zip",
                        "browser_download_url": "https://github.com/o/r/releases/download/v1/win.softhub.zip",
                    },
                ],
            }
        ).encode()
        fetcher = GitHubPackageFetcher(
            QueueOpener(StubResponse(payload, url="https://api.github.com/repos/o/r/releases/latest"))
        )
        with self.assertRaisesRegex(GitHubInstallError, "несколько"):
            fetcher.resolve("https://github.com/o/r/releases/latest")

    def test_non_github_and_non_release_urls_are_rejected(self) -> None:
        invalid = [
            "http://github.com/o/r",
            "https://example.com/o/r/releases/download/v1/a.zip",
            "https://user:password@github.com/o/r",
            "https://github.com/o/r/archive/refs/heads/main.zip",
            "https://github.com/o/r/tree/main",
            "https://github.com/o/r?asset=a.zip",
        ]
        fetcher = GitHubPackageFetcher(QueueOpener())
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(GitHubInstallError):
                fetcher.resolve(value)

    def test_download_is_bounded_and_validates_final_redirect_host(self) -> None:
        direct = "https://github.com/o/r/releases/download/v1/plugin.softhub.zip"
        with tempfile.TemporaryDirectory(prefix="soft-hub-github-test-") as temporary:
            root = Path(temporary)
            destination = root / "plugin.zip"
            response = StubResponse(
                b"PK deterministic package",
                url="https://release-assets.githubusercontent.com/github-production-release-asset/x",
                headers={"Content-Length": "24"},
            )
            package = GitHubPackageFetcher(QueueOpener(response)).download(direct, destination)
            self.assertEqual(package.filename, "plugin.softhub.zip")
            self.assertEqual(destination.read_bytes(), b"PK deterministic package")

            oversized = StubResponse(
                b"ignored",
                url=direct,
                headers={"Content-Length": str(MAX_ARCHIVE_BYTES + 1)},
            )
            with self.assertRaisesRegex(GitHubInstallError, "256 MB"):
                GitHubPackageFetcher(QueueOpener(oversized)).download(
                    direct, root / "oversized.zip"
                )

            truncated = StubResponse(
                b"PK short",
                url=direct,
                headers={"Content-Length": "100"},
            )
            with self.assertRaisesRegex(GitHubInstallError, "Content-Length"):
                GitHubPackageFetcher(QueueOpener(truncated)).download(
                    direct, root / "truncated.zip"
                )
            self.assertFalse((root / "truncated.zip").exists())

            existing = root / "existing.zip"
            existing.write_bytes(b"owned by caller")
            with self.assertRaises(GitHubInstallError):
                GitHubPackageFetcher(QueueOpener(response)).download(direct, existing)
            self.assertEqual(existing.read_bytes(), b"owned by caller")

            unsafe = StubResponse(b"PK", url="https://attacker.invalid/plugin.zip")
            with self.assertRaises(GitHubInstallError):
                GitHubPackageFetcher(QueueOpener(unsafe)).download(
                    direct, root / "unsafe.zip"
                )


if __name__ == "__main__":
    unittest.main()
