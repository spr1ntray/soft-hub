from __future__ import annotations

import http.client
import json
import re
import urllib.error
import urllib.request
from typing import Any, BinaryIO
from urllib.parse import quote, unquote, urlsplit

from .config import APP_VERSION, MAX_ARCHIVE_BYTES
from .versions import compare_semantic_versions, parse_semantic_version


API_HOST = "api.github.com"
MAX_REPOSITORIES = 100
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_ASSET_URL_LENGTH = 2048
REQUEST_TIMEOUT_SECONDS = 30

_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_PATCH_SUFFIX = ".patch"
_PACKAGE_SUFFIXES = (".softhub.zip", ".softhub")
_ASSET_VERSION_RE = re.compile(
    r"(?<![0-9A-Za-z])"
    r"(?P<version>[vV]?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)"
    r"(?![0-9A-Za-z])"
)


class GitHubPatchFeedError(ValueError):
    """A stable, user-facing failure while reading the public GitHub patch feed."""


def normalize_owner(value: str) -> str:
    """Normalize a public GitHub username or an exact ``github.com/<owner>`` URL."""

    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise GitHubPatchFeedError(
            "Введите public GitHub username или https://github.com/<owner>"
        )
    normalized = value.strip()
    if "://" in normalized or "/" in normalized:
        try:
            parsed = urlsplit(normalized)
            port = parsed.port
        except ValueError as error:
            raise GitHubPatchFeedError("Некорректный GitHub owner") from error
        host = (parsed.hostname or "").lower()
        if (
            parsed.scheme != "https"
            or host != "github.com"
            or port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise GitHubPatchFeedError(
                "Разрешён только HTTPS URL вида https://github.com/<owner>"
            )
        raw_owner = parsed.path.removeprefix("/")
        if raw_owner.endswith("/"):
            raw_owner = raw_owner[:-1]
        if not raw_owner or "/" in raw_owner:
            raise GitHubPatchFeedError(
                "GitHub URL должен содержать только owner"
            )
        owner = unquote(raw_owner)
    else:
        owner = normalized

    if not _OWNER_RE.fullmatch(owner) or "--" in owner:
        raise GitHubPatchFeedError("Некорректный GitHub owner")
    return owner.lower()


def _validated_https_url(
    value: str,
    *,
    hosts: set[str],
    allow_query: bool,
) -> tuple[str, str]:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError) as error:
        raise GitHubPatchFeedError(
            "GitHub API вернул небезопасный URL"
        ) from error
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or host not in hosts
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (parsed.query and not allow_query)
    ):
        raise GitHubPatchFeedError("GitHub API вернул небезопасный URL")
    return host, parsed.path


class _SafeGitHubApiRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: BinaryIO,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request | None:
        _validated_https_url(new_url, hosts={API_HOST}, allow_query=True)
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


class GitHubPatchFeed:
    """Discover installable Soft Hub assets in public ``*.patch`` repositories.

    The scanner only performs bounded metadata GETs against ``api.github.com``. It never
    downloads, opens, verifies, installs, or executes a release asset.
    """

    def __init__(self, opener: Any | None = None, *, timeout: int = REQUEST_TIMEOUT_SECONDS):
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 60:
            raise ValueError("GitHub Patch Feed timeout должен быть integer 1..60")
        self.opener = opener or urllib.request.build_opener(_SafeGitHubApiRedirects())
        self.timeout = timeout

    def scan(self, value: str) -> list[dict[str, Any]]:
        owner = normalize_owner(value)
        repositories_url = (
            f"https://{API_HOST}/users/{quote(owner, safe='')}/repos"
            "?type=owner&sort=full_name&direction=asc&per_page=100&page=1"
        )
        payload = self._json(repositories_url, missing_release=False)
        if not isinstance(payload, list):
            raise GitHubPatchFeedError(
                "GitHub API вернул некорректный список repositories"
            )

        repositories: dict[str, dict[str, Any]] = {}
        for raw_repository in payload[:MAX_REPOSITORIES]:
            if not isinstance(raw_repository, dict):
                continue
            name = raw_repository.get("name")
            if (
                not isinstance(name, str)
                or not _REPOSITORY_RE.fullmatch(name)
                or name in {".", ".."}
                or not name.casefold().endswith(_PATCH_SUFFIX)
                or raw_repository.get("private") is True
                or raw_repository.get("visibility") == "private"
            ):
                continue
            repository_owner = raw_repository.get("owner")
            if isinstance(repository_owner, dict):
                login = repository_owner.get("login")
                if isinstance(login, str) and login.casefold() != owner.casefold():
                    continue
            repositories.setdefault(name.casefold(), raw_repository)

        results = [
            self._release_metadata(owner, repository["name"], repository)
            for repository in sorted(
                repositories.values(),
                key=lambda item: (str(item["name"]).casefold(), str(item["name"])),
            )
        ]
        return results

    def _release_metadata(
        self,
        owner: str,
        repository: str,
        raw_repository: dict[str, Any],
    ) -> dict[str, Any]:
        release_url = (
            f"https://{API_HOST}/repos/{quote(owner, safe='')}/"
            f"{quote(repository, safe='._-')}/releases/latest"
        )
        release = self._json(release_url, missing_release=True)
        base = {
            "owner": owner,
            "repository": repository,
            "repository_url": (
                f"https://github.com/{quote(owner, safe='')}/{quote(repository, safe='._-')}"
            ),
            "pushed_at": _optional_public_text(raw_repository.get("pushed_at"), 64),
            "description": _normalized_description(raw_repository.get("description")),
            "release_tag": None,
            "asset_name": None,
            "asset_url": None,
        }
        if release is None:
            return {
                **base,
                "status": "missing_release",
                "reason": "latest_release_not_found",
            }
        if not isinstance(release, dict) or not isinstance(release.get("assets"), list):
            raise GitHubPatchFeedError("GitHub API вернул некорректный release")

        release_tag = _optional_public_text(release.get("tag_name"), 180)
        base["release_tag"] = release_tag
        matching_assets: list[dict[str, Any]] = []
        for asset in release["assets"]:
            if not isinstance(asset, dict):
                continue
            name = asset.get("name")
            if _is_installable_asset_name(name):
                matching_assets.append(asset)

        if not matching_assets:
            return {
                **base,
                "status": "ambiguous_asset",
                "reason": "installable_asset_missing",
            }
        if len(matching_assets) != 1:
            return {
                **base,
                "status": "ambiguous_asset",
                "reason": "multiple_installable_assets",
            }

        asset = matching_assets[0]
        asset_url = asset.get("browser_download_url")
        asset_name = asset.get("name")
        asset_size = asset.get("size")
        if (
            release_tag is None
            or not isinstance(asset_url, str)
            or not isinstance(asset_name, str)
            or isinstance(asset_size, bool)
            or not isinstance(asset_size, int)
            or not 1 <= asset_size <= MAX_ARCHIVE_BYTES
            or not _is_repository_asset_url(asset_url, owner, repository, asset_name)
        ):
            return {
                **base,
                "status": "ambiguous_asset",
                "reason": "unsafe_or_incomplete_asset_metadata",
            }
        return {
            **base,
            "status": "ready",
            "reason": "single_installable_asset",
            "asset_name": asset_name,
            "asset_url": asset_url,
        }

    def _json(self, url: str, *, missing_release: bool) -> Any | None:
        _validated_https_url(url, hosts={API_HOST}, allow_query=True)
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Accept-Encoding": "identity",
                "User-Agent": f"Soft-Hub/{APP_VERSION}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="GET",
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                final_url = response.geturl()
                _validated_https_url(final_url, hosts={API_HOST}, allow_query=True)
                declared_length = response.headers.get("Content-Length")
                if declared_length is not None:
                    try:
                        size = int(declared_length)
                    except (TypeError, ValueError) as error:
                        raise GitHubPatchFeedError(
                            "GitHub API вернул некорректный Content-Length"
                        ) from error
                    if size < 0 or size > MAX_RESPONSE_BYTES:
                        raise GitHubPatchFeedError(
                            "Ответ GitHub API слишком большой"
                        )
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            if error.code == 404 and missing_release:
                return None
            if error.code == 404:
                raise GitHubPatchFeedError(
                    "GitHub owner не найден или не является публичным"
                ) from error
            if error.code in {403, 429}:
                raise GitHubPatchFeedError(
                    "GitHub API временно ограничил запросы; попробуйте позже"
                ) from error
            raise GitHubPatchFeedError(f"GitHub API ответил HTTP {error.code}") from error
        except GitHubPatchFeedError:
            raise
        except (OSError, urllib.error.URLError, http.client.HTTPException) as error:
            raise GitHubPatchFeedError(
                "Не удалось подключиться к GitHub"
            ) from error

        if len(raw) > MAX_RESPONSE_BYTES:
            raise GitHubPatchFeedError("Ответ GitHub API слишком большой")
        try:
            return json.loads(raw)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise GitHubPatchFeedError(
                "GitHub API вернул некорректный JSON"
            ) from error


def _is_installable_asset_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 240
        and "/" not in value
        and "\\" not in value
        and value.casefold().endswith(_PACKAGE_SUFFIXES)
    )


def _is_repository_asset_url(
    url: str,
    owner: str,
    repository: str,
    asset_name: str,
) -> bool:
    if not 1 <= len(url) <= MAX_ASSET_URL_LENGTH:
        return False
    try:
        _host, path = _validated_https_url(url, hosts={"github.com"}, allow_query=False)
        segments = [unquote(segment) for segment in path.split("/") if segment]
    except GitHubPatchFeedError:
        return False
    return (
        len(segments) >= 6
        and segments[0].casefold() == owner.casefold()
        and segments[1].casefold() == repository.casefold()
        and segments[2:4] == ["releases", "download"]
        and segments[-1] == asset_name
        and all(segment and segment.isprintable() for segment in segments)
    )


def release_asset_version_hint(
    release_tag: object,
    asset_name: object,
) -> tuple[str | None, str]:
    """Read a version only when release and filename metadata do not disagree."""

    release_version = parse_semantic_version(release_tag, allow_v_prefix=True)
    asset_versions = []
    if isinstance(asset_name, str) and len(asset_name) <= 240:
        comparable_name = asset_name
        for suffix in _PACKAGE_SUFFIXES:
            if comparable_name.casefold().endswith(suffix):
                comparable_name = comparable_name[: -len(suffix)]
                break
        for match in _ASSET_VERSION_RE.finditer(comparable_name):
            parsed = parse_semantic_version(
                match.group("version"), allow_v_prefix=True
            )
            if parsed is not None and parsed not in asset_versions:
                asset_versions.append(parsed)
    asset_version = asset_versions[0] if len(asset_versions) == 1 else None
    if len(asset_versions) > 1:
        return None, "asset_version_ambiguous"
    if release_version is not None and asset_version is not None:
        if compare_semantic_versions(release_version, asset_version) != 0:
            return None, "release_asset_version_conflict"
        return release_version.canonical, "release_and_asset"
    if release_version is not None:
        return release_version.canonical, "release_tag"
    if asset_version is not None:
        return asset_version.canonical, "asset_name"
    return None, "version_missing"


def annotate_patch_versions(
    patches: list[dict[str, Any]],
    sources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach installed/update state without trusting renderer-provided identity.

    A repository becomes bound to a module id only after its package was downloaded,
    inspected and installed by the core. Subsequent metadata is comparable only when
    that repository has already demonstrated a consistent SemVer convention.
    """

    annotated: list[dict[str, Any]] = []
    for raw_patch in patches:
        patch = dict(raw_patch)
        patch.update(
            {
                "version_state": "unavailable",
                "candidate_version": None,
                "installed_module_id": None,
                "installed_version": None,
                "installable": False,
                "version_reason": "package_unavailable",
            }
        )
        if patch.get("status") != "ready":
            annotated.append(patch)
            continue

        owner = patch.get("owner")
        repository = patch.get("repository")
        repository_sources = [
            source
            for source in sources
            if isinstance(owner, str)
            and isinstance(repository, str)
            and str(source.get("owner", "")).casefold() == owner.casefold()
            and str(source.get("repository", "")).casefold() == repository.casefold()
        ]
        if not repository_sources:
            candidate, reason = release_asset_version_hint(
                patch.get("release_tag"), patch.get("asset_name")
            )
            patch.update(
                {
                    "version_state": "untracked",
                    "candidate_version": candidate,
                    "installable": True,
                    "version_reason": reason,
                }
            )
            annotated.append(patch)
            continue

        module_ids = {str(source.get("module_id", "")) for source in repository_sources}
        active_versions = {
            str(source.get("active_version", "")) for source in repository_sources
        }
        if "" in module_ids or "" in active_versions or len(module_ids) != 1 or len(active_versions) != 1:
            patch.update(
                {
                    "version_state": "identity_conflict",
                    "version_reason": "repository_identity_conflict",
                }
            )
            annotated.append(patch)
            continue

        module_id = next(iter(module_ids))
        installed_version = next(iter(active_versions))
        patch["installed_module_id"] = module_id
        patch["installed_version"] = installed_version

        exact_sources = [
            source
            for source in repository_sources
            if source.get("release_tag") == patch.get("release_tag")
            and source.get("asset_name") == patch.get("asset_name")
            and source.get("asset_url") == patch.get("asset_url")
        ]
        exact_versions = {str(source.get("version", "")) for source in exact_sources}
        if "" in exact_versions or len(exact_versions) > 1:
            patch.update(
                {
                    "version_state": "identity_conflict",
                    "version_reason": "asset_identity_conflict",
                }
            )
            annotated.append(patch)
            continue

        if exact_versions:
            candidate_version = next(iter(exact_versions))
            hint_reason = "known_release_asset"
        else:
            trusted_convention = False
            for source in repository_sources:
                source_hint, _source_reason = release_asset_version_hint(
                    source.get("release_tag"), source.get("asset_name")
                )
                source_version = parse_semantic_version(source.get("version"))
                parsed_hint = parse_semantic_version(source_hint)
                if (
                    source_version is not None
                    and parsed_hint is not None
                    and compare_semantic_versions(source_version, parsed_hint) == 0
                ):
                    trusted_convention = True
                    break
            candidate_version, hint_reason = release_asset_version_hint(
                patch.get("release_tag"), patch.get("asset_name")
            )
            if not trusted_convention:
                candidate_version = None
                hint_reason = "repository_version_convention_unverified"

        patch["candidate_version"] = candidate_version
        if candidate_version is None:
            patch.update(
                {
                    "version_state": "version_unknown",
                    "version_reason": hint_reason,
                }
            )
            annotated.append(patch)
            continue

        if candidate_version == installed_version:
            patch.update(
                {
                    "version_state": "installed",
                    "version_reason": hint_reason,
                }
            )
            annotated.append(patch)
            continue

        candidate = parse_semantic_version(candidate_version)
        installed = parse_semantic_version(installed_version)
        if candidate is None or installed is None:
            patch.update(
                {
                    "version_state": "version_unknown",
                    "version_reason": "manifest_version_not_semver",
                }
            )
            annotated.append(patch)
            continue
        precedence = compare_semantic_versions(candidate, installed)
        if precedence == 0:
            patch.update(
                {
                    "version_state": "installed",
                    "version_reason": hint_reason,
                }
            )
        elif precedence > 0:
            patch.update(
                {
                    "version_state": "update_available",
                    "installable": True,
                    "version_reason": hint_reason,
                }
            )
        else:
            patch.update(
                {
                    "version_state": "newer_installed",
                    "version_reason": hint_reason,
                }
            )
        annotated.append(patch)
    return annotated


def _optional_public_text(value: Any, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > maximum or not text.isprintable():
        return None
    return text


def _normalized_description(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    printable = "".join(character if character.isprintable() else " " for character in value)
    return " ".join(printable.split())[:500]
