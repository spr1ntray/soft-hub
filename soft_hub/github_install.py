from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO
from urllib.parse import quote, unquote, urlsplit

from .config import APP_VERSION, MAX_ARCHIVE_BYTES
from .tls import github_connection_error, public_https_context


_OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$")
_DOWNLOAD_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}
_API_HOST = "api.github.com"
_PACKAGE_SUFFIXES = (".softhub.zip", ".softhub")


class GitHubInstallError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class GitHubPackage:
    owner: str
    repository: str
    filename: str
    download_url: str
    release: str


def _validated_https_url(
    value: str,
    *,
    hosts: set[str],
    allow_query: bool,
) -> tuple[str, str]:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise GitHubInstallError("Некорректный GitHub URL") from error
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
        raise GitHubInstallError("Разрешены только безопасные HTTPS-ссылки GitHub")
    return host, parsed.path


class _SafeGitHubRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: BinaryIO,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request | None:
        _validated_https_url(new_url, hosts=_DOWNLOAD_HOSTS, allow_query=True)
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


class GitHubPackageFetcher:
    """Resolve and download a public GitHub release package without generic URL fetching."""

    def __init__(self, opener: Any | None = None):
        self.opener = opener or urllib.request.build_opener(
            _SafeGitHubRedirects(),
            urllib.request.HTTPSHandler(context=public_https_context()),
        )

    @staticmethod
    def _segments(value: str) -> tuple[list[str], str]:
        if not isinstance(value, str) or not value.strip() or len(value) > 2048:
            raise GitHubInstallError("Вставьте ссылку на GitHub repository или release asset")
        normalized = value.strip()
        _host, path = _validated_https_url(
            normalized,
            hosts={"github.com"},
            allow_query=False,
        )
        segments = [unquote(segment) for segment in path.split("/") if segment]
        if len(segments) < 2:
            raise GitHubInstallError("GitHub URL должен содержать owner и repository")
        return segments, normalized

    def resolve(self, value: str) -> GitHubPackage:
        segments, normalized = self._segments(value)
        owner, repository = segments[:2]
        if repository.endswith(".git"):
            repository = repository[:-4]
        if not _OWNER_REPO_RE.fullmatch(owner) or not _OWNER_REPO_RE.fullmatch(repository):
            raise GitHubInstallError("Некорректные owner или repository в GitHub URL")

        tail = segments[2:]
        if not tail or tail == ["releases", "latest"]:
            return self._release_asset(owner, repository, tag=None)
        if len(tail) == 3 and tail[:2] == ["releases", "tag"]:
            return self._release_asset(owner, repository, tag=tail[2])
        if len(tail) >= 4 and tail[:2] == ["releases", "download"]:
            tag = tail[2]
            filename = PurePosixPath("/".join(tail[3:])).name
            self._validate_filename(filename)
            _validated_https_url(normalized, hosts={"github.com"}, allow_query=False)
            return GitHubPackage(owner, repository, filename, normalized, tag)
        raise GitHubInstallError(
            "Поддерживаются repository, release tag или прямая ссылка на release asset"
        )

    @staticmethod
    def _validate_filename(filename: str) -> None:
        lowered = filename.lower()
        if (
            not filename
            or len(filename) > 240
            or "/" in filename
            or "\\" in filename
            or not lowered.endswith(_PACKAGE_SUFFIXES)
        ):
            raise GitHubInstallError(
                "Нужен готовый release asset .softhub.zip — GitHub Source code ZIP не подходит"
            )

    def _release_asset(
        self,
        owner: str,
        repository: str,
        *,
        tag: str | None,
    ) -> GitHubPackage:
        if tag is not None and (not tag or len(tag) > 180 or any(ord(char) < 33 for char in tag)):
            raise GitHubInstallError("Некорректный release tag")
        suffix = "latest" if tag is None else f"tags/{quote(tag, safe='')}"
        api_url = (
            f"https://{_API_HOST}/repos/{quote(owner, safe='')}/"
            f"{quote(repository, safe='')}/releases/{suffix}"
        )
        payload = self._json(api_url)
        assets = payload.get("assets")
        if not isinstance(assets, list):
            raise GitHubInstallError("GitHub release не содержит списка assets")

        candidates: list[tuple[str, str]] = []
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            name = asset.get("name")
            url = asset.get("browser_download_url")
            if not isinstance(name, str) or not isinstance(url, str):
                continue
            lowered = name.lower()
            if lowered.endswith((".softhub.zip", ".softhub")):
                candidates.append((name, url))
        selected = candidates
        if not selected:
            raise GitHubInstallError("В GitHub release нет .softhub.zip asset")
        if len(selected) != 1:
            raise GitHubInstallError(
                "В release несколько подходящих assets — вставьте прямую ссылку на нужный"
            )
        filename, download_url = selected[0]
        self._validate_filename(filename)
        _validated_https_url(download_url, hosts={"github.com"}, allow_query=False)
        release = str(payload.get("tag_name") or tag or "latest")
        return GitHubPackage(owner, repository, filename, download_url, release)

    def _json(self, url: str) -> dict[str, Any]:
        _validated_https_url(url, hosts={_API_HOST}, allow_query=False)
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"Soft-Hub/{APP_VERSION}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise GitHubInstallError("GitHub repository или release не найден") from error
            if error.code == 407:
                raise GitHubInstallError("Прокси-сервер просит авторизацию. Проверьте настройки сети") from error
            if error.code == 403:
                raise GitHubInstallError("GitHub API временно ограничил запросы; попробуйте позже") from error
            raise GitHubInstallError(f"GitHub API ответил HTTP {error.code}") from error
        except (OSError, urllib.error.URLError) as error:
            raise GitHubInstallError(github_connection_error(error)) from error
        if len(raw) > 2 * 1024 * 1024:
            raise GitHubInstallError("Ответ GitHub API слишком большой")
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise GitHubInstallError("GitHub API вернул некорректный ответ") from error
        if not isinstance(payload, dict):
            raise GitHubInstallError("GitHub API вернул некорректный release")
        return payload

    def download(self, value: str, destination: Path) -> GitHubPackage:
        package = self.resolve(value)
        _validated_https_url(
            package.download_url,
            hosts={"github.com"},
            allow_query=False,
        )
        request = urllib.request.Request(
            package.download_url,
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": f"Soft-Hub/{APP_VERSION}",
            },
        )
        total = 0
        declared_length: int | None = None
        created_destination = False
        try:
            with self.opener.open(request, timeout=45) as response:
                final_url = response.geturl()
                _validated_https_url(final_url, hosts=_DOWNLOAD_HOSTS, allow_query=True)
                raw_length = response.headers.get("Content-Length")
                if raw_length:
                    try:
                        declared_length = int(raw_length)
                    except ValueError as error:
                        raise GitHubInstallError("GitHub вернул некорректный размер asset") from error
                    if declared_length <= 0 or declared_length > MAX_ARCHIVE_BYTES:
                        raise GitHubInstallError("GitHub package превышает лимит 256 MB")
                with destination.open("xb") as output:
                    created_destination = True
                    try:
                        os.chmod(destination, 0o600)
                    except OSError:
                        pass
                    while chunk := response.read(1024 * 1024):
                        total += len(chunk)
                        if total > MAX_ARCHIVE_BYTES:
                            raise GitHubInstallError("GitHub package превышает лимит 256 MB")
                        output.write(chunk)
        except GitHubInstallError:
            if created_destination:
                destination.unlink(missing_ok=True)
            raise
        except urllib.error.HTTPError as error:
            if created_destination:
                destination.unlink(missing_ok=True)
            if error.code == 407:
                raise GitHubInstallError("Прокси-сервер просит авторизацию. Проверьте настройки сети") from error
            raise GitHubInstallError(f"Не удалось скачать release asset: HTTP {error.code}") from error
        except (OSError, urllib.error.URLError) as error:
            if created_destination:
                destination.unlink(missing_ok=True)
            raise GitHubInstallError(github_connection_error(error)) from error
        if total == 0:
            if created_destination:
                destination.unlink(missing_ok=True)
            raise GitHubInstallError("GitHub release asset оказался пустым")
        if declared_length is not None and total != declared_length:
            if created_destination:
                destination.unlink(missing_ok=True)
            raise GitHubInstallError("Размер GitHub release asset не совпал с Content-Length")
        return package
