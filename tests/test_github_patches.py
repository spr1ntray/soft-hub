from __future__ import annotations

import io
import json
import ssl
import unittest
import urllib.error
import urllib.request
from typing import Any
from unittest import mock
from urllib.parse import urlsplit

from soft_hub.config import MAX_ARCHIVE_BYTES
from soft_hub.github_patches import (
    API_HOST,
    MAX_REPOSITORIES,
    MAX_RESPONSE_BYTES,
    GitHubPatchFeed,
    GitHubPatchFeedError,
    annotate_patch_versions,
    normalize_owner,
    release_asset_version_hint,
)


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
    def __init__(self, *responses: StubResponse | BaseException):
        self.responses = list(responses)
        self.requests: list[tuple[Any, int]] = []

    def open(self, request: Any, timeout: int) -> StubResponse:
        self.requests.append((request, timeout))
        if not self.responses:
            raise AssertionError("No response queued")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def json_response(payload: Any, url: str) -> StubResponse:
    return StubResponse(
        json.dumps(payload).encode("utf-8"),
        url=url,
        headers={"Content-Type": "application/json"},
    )


def http_error(url: str, code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, code, "stub", {}, None)


class GitHubPatchFeedTests(unittest.TestCase):
    def test_default_opener_uses_the_hardened_public_tls_context(self) -> None:
        context = ssl.create_default_context()
        with mock.patch(
            "soft_hub.github_patches.public_https_context", return_value=context
        ) as context_factory:
            feed = GitHubPatchFeed()

        context_factory.assert_called_once_with()
        self.assertTrue(
            any(
                isinstance(handler, urllib.request.HTTPSHandler)
                and getattr(handler, "_context", None) is context
                for handler in feed.opener.handlers
            )
        )

    @staticmethod
    def ready_patch(version: str, *, owner: str = "owner", repository: str = "app.patch") -> dict[str, Any]:
        return {
            "owner": owner,
            "repository": repository,
            "repository_url": f"https://github.com/{owner}/{repository}",
            "pushed_at": None,
            "description": "App",
            "release_tag": f"v{version}",
            "asset_name": f"app-{version}.softhub.zip",
            "asset_url": (
                f"https://github.com/{owner}/{repository}/releases/download/"
                f"v{version}/app-{version}.softhub.zip"
            ),
            "status": "ready",
            "reason": "single_installable_asset",
        }

    @staticmethod
    def installed_source(version: str, *, module_id: str = "io.example.app") -> dict[str, Any]:
        return {
            "module_id": module_id,
            "version": version,
            "active_version": version,
            "owner": "owner",
            "repository": "app.patch",
            "release_tag": f"v{version}",
            "asset_name": f"app-{version}.softhub.zip",
            "asset_url": (
                "https://github.com/owner/app.patch/releases/download/"
                f"v{version}/app-{version}.softhub.zip"
            ),
        }

    def test_patch_version_annotation_distinguishes_same_newer_and_older_releases(self) -> None:
        source = self.installed_source("2.1.0")
        same = annotate_patch_versions([self.ready_patch("2.1.0")], [source])[0]
        newer = annotate_patch_versions([self.ready_patch("2.2.0")], [source])[0]
        older = annotate_patch_versions([self.ready_patch("2.0.9")], [source])[0]

        self.assertEqual(same["version_state"], "installed")
        self.assertIs(same["installable"], False)
        self.assertEqual(same["installed_module_id"], "io.example.app")
        self.assertEqual(newer["version_state"], "update_available")
        self.assertEqual(newer["candidate_version"], "2.2.0")
        self.assertIs(newer["installable"], True)
        self.assertEqual(older["version_state"], "newer_installed")
        self.assertIs(older["installable"], False)

        local_newer_source = self.installed_source("1.0.0")
        local_newer_source["active_version"] = "3.0.0"
        local_newer = annotate_patch_versions(
            [self.ready_patch("2.5.0")], [local_newer_source]
        )[0]
        self.assertEqual(local_newer["installed_version"], "3.0.0")
        self.assertEqual(local_newer["version_state"], "newer_installed")
        self.assertIs(local_newer["installable"], False)

    def test_removed_module_tombstone_only_offers_a_strictly_newer_release(self) -> None:
        source = self.installed_source("2.1.0")
        source.update(
            {
                "active_version": None,
                "version_floor": "2.1.0",
                "module_removed": True,
            }
        )

        same = annotate_patch_versions([self.ready_patch("2.1.0")], [source])[0]
        newer = annotate_patch_versions([self.ready_patch("2.2.0")], [source])[0]
        older = annotate_patch_versions([self.ready_patch("2.0.9")], [source])[0]

        self.assertEqual(same["version_state"], "removed_current")
        self.assertIs(same["installable"], False)
        self.assertIs(same["module_removed"], True)
        self.assertEqual(newer["version_state"], "removed_update_available")
        self.assertIs(newer["installable"], True)
        self.assertEqual(older["version_state"], "removed_newer_known")
        self.assertIs(older["installable"], False)

    def test_invalid_legacy_history_does_not_hide_healthy_repositories(self) -> None:
        broken = self.installed_source("01.0.0", module_id="io.example.broken")
        broken.update(
            {
                "version_floor": None,
                "version_history_valid": False,
            }
        )
        healthy = self.installed_source("2.0.0", module_id="io.example.healthy")
        healthy.update(
            {
                "repository": "healthy.patch",
                "release_tag": "v2.0.0",
                "asset_name": "app-2.0.0.softhub.zip",
                "asset_url": (
                    "https://github.com/owner/healthy.patch/releases/download/"
                    "v2.0.0/app-2.0.0.softhub.zip"
                ),
            }
        )
        patches = [
            self.ready_patch("1.0.0"),
            self.ready_patch("2.1.0", repository="healthy.patch"),
        ]

        broken_patch, healthy_patch = annotate_patch_versions(
            patches,
            [broken, healthy],
        )

        self.assertEqual(broken_patch["version_state"], "identity_conflict")
        self.assertEqual(broken_patch["version_reason"], "version_history_invalid")
        self.assertIs(broken_patch["installable"], False)
        self.assertEqual(healthy_patch["version_state"], "update_available")
        self.assertIs(healthy_patch["installable"], True)

    def test_patch_annotation_fails_closed_on_identity_or_version_metadata_collision(self) -> None:
        source = self.installed_source("1.0.0")
        conflicting_identity = {
            **source,
            "module_id": "io.attacker.other",
            "version": "0.1.0",
            "active_version": "0.1.0",
        }
        collision = annotate_patch_versions(
            [self.ready_patch("1.1.0")], [source, conflicting_identity]
        )[0]
        self.assertEqual(collision["version_state"], "identity_conflict")
        self.assertIs(collision["installable"], False)

        inconsistent = self.ready_patch("1.1.0")
        inconsistent["asset_name"] = "app-9.0.0.softhub.zip"
        unknown = annotate_patch_versions([inconsistent], [source])[0]
        self.assertEqual(unknown["version_state"], "version_unknown")
        self.assertIs(unknown["installable"], False)
        self.assertEqual(
            release_asset_version_hint("v1.1.0", inconsistent["asset_name"]),
            (None, "release_asset_version_conflict"),
        )

    def test_patch_semver_hints_keep_prerelease_precedence_and_reject_leading_zeroes(self) -> None:
        source = self.installed_source("2.0.0-rc.2")
        stable = annotate_patch_versions([self.ready_patch("2.0.0")], [source])[0]
        self.assertEqual(stable["version_state"], "update_available")
        self.assertIs(stable["installable"], True)
        self.assertEqual(
            release_asset_version_hint("v02.0.0", "app-02.0.0.softhub.zip"),
            (None, "version_missing"),
        )

    def test_normalize_owner_accepts_username_or_exact_profile_url(self) -> None:
        self.assertEqual(normalize_owner("  OpenAI  "), "openai")
        self.assertEqual(normalize_owner("https://github.com/Sprint-Ray/"), "sprint-ray")
        self.assertEqual(normalize_owner("https://github.com:443/A"), "a")

        invalid = [
            "",
            "https://example.com/owner",
            "http://github.com/owner",
            "https://user:password@github.com/owner",
            "https://github.com:444/owner",
            "https://github.com/owner/repository",
            "https://github.com/owner?tab=repositories",
            "https://github.com/owner#repositories",
            "owner/name",
            "owner_name",
            "owner--name",
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(GitHubPatchFeedError):
                normalize_owner(value)

    def test_scan_filters_exact_patch_suffix_and_returns_ready_metadata(self) -> None:
        owner = "exampleuser"
        list_url = (
            f"https://{API_HOST}/users/{owner}/repos"
            "?type=owner&sort=full_name&direction=asc&per_page=100&page=1"
        )
        release_url = f"https://{API_HOST}/repos/{owner}/Wallet.PATCH/releases/latest"
        repositories = [
            {"name": "wallet.patch.zip", "private": False},
            {"name": "wallet.patch-old", "private": False},
            {"name": "secret.patch", "private": True},
            {
                "name": "other.patch",
                "private": False,
                "owner": {"login": "someone-else"},
            },
            {
                "name": "Wallet.PATCH",
                "private": False,
                "owner": {"login": "ExampleUser"},
                "pushed_at": "2026-08-06T12:34:56Z",
                "description": "  Wallet\n automation  ",
            },
        ]
        release = {
            "tag_name": "v3.0.0",
            "assets": [
                {
                    "name": "notes.zip",
                    "browser_download_url": (
                        "https://github.com/exampleuser/Wallet.PATCH/releases/download/"
                        "v3.0.0/notes.zip"
                    ),
                },
                {
                    "name": "wallet-v3.SOFTHUB.ZIP",
                    "size": 1024,
                    "browser_download_url": (
                        "https://github.com/ExampleUser/Wallet.PATCH/releases/download/"
                        "v3.0.0/wallet-v3.SOFTHUB.ZIP"
                    ),
                },
            ],
        }
        opener = QueueOpener(
            json_response(repositories, list_url),
            json_response(release, release_url),
        )

        results = GitHubPatchFeed(opener).scan("https://github.com/ExampleUser")

        self.assertEqual(
            results,
            [
                {
                    "owner": "exampleuser",
                    "repository": "Wallet.PATCH",
                    "repository_url": "https://github.com/exampleuser/Wallet.PATCH",
                    "pushed_at": "2026-08-06T12:34:56Z",
                    "description": "Wallet automation",
                    "release_tag": "v3.0.0",
                    "asset_name": "wallet-v3.SOFTHUB.ZIP",
                    "asset_url": (
                        "https://github.com/ExampleUser/Wallet.PATCH/releases/download/"
                        "v3.0.0/wallet-v3.SOFTHUB.ZIP"
                    ),
                    "status": "ready",
                    "reason": "single_installable_asset",
                }
            ],
        )
        self.assertEqual(len(opener.requests), 2)
        for request, timeout in opener.requests:
            self.assertEqual(urlsplit(request.full_url).hostname, API_HOST)
            self.assertEqual(request.get_method(), "GET")
            self.assertIsNone(request.get_header("Authorization"))
            self.assertEqual(timeout, 30)

    def test_missing_release_and_non_unique_asset_statuses_are_stable(self) -> None:
        owner = "owner"
        list_url = (
            f"https://{API_HOST}/users/{owner}/repos"
            "?type=owner&sort=full_name&direction=asc&per_page=100&page=1"
        )
        repositories = [
            {"name": "c.patch", "description": "multiple"},
            {"name": "a.patch", "description": "no release"},
            {"name": "b.PATCH", "description": "no package"},
        ]
        a_url = f"https://{API_HOST}/repos/{owner}/a.patch/releases/latest"
        b_url = f"https://{API_HOST}/repos/{owner}/b.PATCH/releases/latest"
        c_url = f"https://{API_HOST}/repos/{owner}/c.patch/releases/latest"
        opener = QueueOpener(
            json_response(repositories, list_url),
            http_error(a_url, 404),
            json_response(
                {
                    "tag_name": "v1",
                    "assets": [
                        {
                            "name": "generic.zip",
                            "browser_download_url": (
                                "https://github.com/owner/b.PATCH/releases/download/v1/generic.zip"
                            ),
                        }
                    ],
                },
                b_url,
            ),
            json_response(
                {
                    "tag_name": "v2",
                    "assets": [
                        {
                            "name": "mac.softhub.zip",
                            "browser_download_url": (
                                "https://github.com/owner/c.patch/releases/download/"
                                "v2/mac.softhub.zip"
                            ),
                        },
                        {
                            "name": "win.softhub",
                            "browser_download_url": (
                                "https://github.com/owner/c.patch/releases/download/v2/win.softhub"
                            ),
                        },
                    ],
                },
                c_url,
            ),
        )

        results = GitHubPatchFeed(opener).scan(owner)

        self.assertEqual(
            [item["repository"] for item in results],
            ["a.patch", "b.PATCH", "c.patch"],
        )
        self.assertEqual([item["status"] for item in results], [
            "missing_release",
            "ambiguous_asset",
            "ambiguous_asset",
        ])
        self.assertEqual([item["reason"] for item in results], [
            "latest_release_not_found",
            "installable_asset_missing",
            "multiple_installable_assets",
        ])
        self.assertIsNone(results[0]["release_tag"])
        self.assertEqual(results[1]["release_tag"], "v1")
        self.assertTrue(all(item["asset_url"] is None for item in results))

    def test_single_candidate_with_unsafe_url_is_not_installable(self) -> None:
        owner = "owner"
        list_url = (
            f"https://{API_HOST}/users/{owner}/repos"
            "?type=owner&sort=full_name&direction=asc&per_page=100&page=1"
        )
        release_url = f"https://{API_HOST}/repos/{owner}/unsafe.patch/releases/latest"
        opener = QueueOpener(
            json_response([{"name": "unsafe.patch"}], list_url),
            json_response(
                {
                    "tag_name": "v1",
                    "assets": [
                        {
                            "name": "plugin.softhub.zip",
                            "size": 1024,
                            "browser_download_url": "https://attacker.invalid/plugin.softhub.zip",
                        }
                    ],
                },
                release_url,
            ),
        )

        result = GitHubPatchFeed(opener).scan(owner)[0]

        self.assertEqual(result["status"], "ambiguous_asset")
        self.assertEqual(result["reason"], "unsafe_or_incomplete_asset_metadata")
        self.assertIsNone(result["asset_url"])
        self.assertEqual(len(opener.requests), 2)

    def test_single_asset_requires_bounded_url_and_integer_archive_size(self) -> None:
        owner = "owner"
        repository = "bounded.patch"
        release_url = (
            f"https://{API_HOST}/repos/{owner}/{repository}/releases/latest"
        )
        valid_url = (
            f"https://github.com/{owner}/{repository}/releases/download/"
            "v1/plugin.softhub.zip"
        )

        def metadata(asset: dict[str, Any]) -> dict[str, Any]:
            feed = GitHubPatchFeed(
                QueueOpener(
                    json_response(
                        {"tag_name": "v1", "assets": [asset]},
                        release_url,
                    )
                )
            )
            return feed._release_metadata(owner, repository, {"name": repository})

        for invalid_size in (None, True, False, "1024", 0, -1, MAX_ARCHIVE_BYTES + 1):
            with self.subTest(size=invalid_size):
                asset = {
                    "name": "plugin.softhub.zip",
                    "browser_download_url": valid_url,
                }
                if invalid_size is not None:
                    asset["size"] = invalid_size
                result = metadata(asset)
                self.assertEqual(result["status"], "ambiguous_asset")
                self.assertEqual(
                    result["reason"], "unsafe_or_incomplete_asset_metadata"
                )
                self.assertIsNone(result["asset_url"])

        oversized_url = (
            f"https://github.com/{owner}/{repository}/releases/download/"
            + "x" * 2048
            + "/plugin.softhub.zip"
        )
        result = metadata(
            {
                "name": "plugin.softhub.zip",
                "size": 1024,
                "browser_download_url": oversized_url,
            }
        )
        self.assertEqual(result["status"], "ambiguous_asset")
        self.assertEqual(result["reason"], "unsafe_or_incomplete_asset_metadata")
        self.assertIsNone(result["asset_url"])

        ready = metadata(
            {
                "name": "plugin.softhub.zip",
                "size": MAX_ARCHIVE_BYTES,
                "browser_download_url": valid_url,
            }
        )
        self.assertEqual(ready["status"], "ready")
        self.assertEqual(ready["asset_url"], valid_url)

    def test_repository_pagination_is_capped_at_one_hundred_items(self) -> None:
        owner = "owner"
        list_url = (
            f"https://{API_HOST}/users/{owner}/repos"
            "?type=owner&sort=full_name&direction=asc&per_page=100&page=1"
        )
        repositories = [{"name": f"ordinary-{index}"} for index in range(MAX_REPOSITORIES)]
        repositories.append({"name": "not-fetched.patch"})
        opener = QueueOpener(json_response(repositories, list_url))

        self.assertEqual(GitHubPatchFeed(opener).scan(owner), [])
        self.assertEqual(len(opener.requests), 1)
        self.assertIn("per_page=100", opener.requests[0][0].full_url)
        self.assertIn("page=1", opener.requests[0][0].full_url)

    def test_api_response_is_bounded_and_final_host_is_revalidated(self) -> None:
        owner = "owner"
        list_url = (
            f"https://{API_HOST}/users/{owner}/repos"
            "?type=owner&sort=full_name&direction=asc&per_page=100&page=1"
        )
        oversized = StubResponse(b"x" * (MAX_RESPONSE_BYTES + 1), url=list_url)
        with self.assertRaisesRegex(GitHubPatchFeedError, "слишком большой"):
            GitHubPatchFeed(QueueOpener(oversized)).scan(owner)

        bad_length = StubResponse(b"[]", url=list_url, headers={"Content-Length": "unknown"})
        with self.assertRaisesRegex(GitHubPatchFeedError, "Content-Length"):
            GitHubPatchFeed(QueueOpener(bad_length)).scan(owner)

        redirected = StubResponse(b"[]", url="https://github.com/owner")
        with self.assertRaisesRegex(GitHubPatchFeedError, "небезопасный URL"):
            GitHubPatchFeed(QueueOpener(redirected)).scan(owner)

    def test_rate_limit_and_transport_errors_have_stable_messages(self) -> None:
        for status in (403, 429):
            with self.subTest(status=status):
                feed = GitHubPatchFeed(
                    QueueOpener(http_error("https://api.github.com/users/o/repos", status))
                )
                with self.assertRaises(GitHubPatchFeedError) as raised:
                    feed.scan("o")
                self.assertEqual(
                    str(raised.exception),
                    "GitHub API временно ограничил запросы; попробуйте позже",
                )

        with self.assertRaisesRegex(GitHubPatchFeedError, "owner не найден"):
            GitHubPatchFeed(
                QueueOpener(http_error("https://api.github.com/users/o/repos", 404))
            ).scan("o")
        with self.assertRaisesRegex(
            GitHubPatchFeedError,
            "недоступен из этой сети",
        ):
            GitHubPatchFeed(QueueOpener(urllib.error.URLError("offline"))).scan("o")
        with self.assertRaisesRegex(GitHubPatchFeedError, "некорректный JSON"):
            GitHubPatchFeed(
                QueueOpener(StubResponse(b"not-json", url="https://api.github.com/users/o/repos"))
            ).scan("o")

    def test_timeout_is_explicit_and_bounded(self) -> None:
        with self.assertRaises(ValueError):
            GitHubPatchFeed(QueueOpener(), timeout=0)
        with self.assertRaises(ValueError):
            GitHubPatchFeed(QueueOpener(), timeout=61)
        with self.assertRaises(ValueError):
            GitHubPatchFeed(QueueOpener(), timeout=True)


if __name__ == "__main__":
    unittest.main()
