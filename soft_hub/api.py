from __future__ import annotations

import csv
import io
import json
import mimetypes
import os
import re
import secrets
import shutil
import threading
import uuid
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse
from xml.sax.saxutils import escape as xml_escape

from .config import APP_VERSION, MAX_ARCHIVE_BYTES, MAX_JSON_BYTES, HubPaths
from .database import Database
from .github_install import GitHubInstallError, GitHubPackageFetcher
from .github_patches import (
    GitHubPatchFeed,
    GitHubPatchFeedError,
    annotate_patch_versions,
    normalize_owner,
)
from .instance_lock import DataDirectoryLock
from .plugins import PluginError, PluginManager
from .runner import IdempotencyConflictError, RunError, RunManager
from .vault import ImportRecord, ReferralRevisionConflict, Vault, VaultError

_RUN_ROUTE = re.compile(r"^/api/runs/([0-9a-f-]+)$")
_RUN_EVENTS_ROUTE = re.compile(r"^/api/runs/([0-9a-f-]+)/events$")
_RUN_LOG_ROUTE = re.compile(r"^/api/runs/([0-9a-f-]+)/log$")
_RUN_ACCOUNTS_ROUTE = re.compile(r"^/api/runs/([0-9a-f-]+)/accounts$")
_RUN_STOP_ROUTE = re.compile(r"^/api/runs/([0-9a-f-]+)/stop$")
_RUN_FORCE_STOP_ROUTE = re.compile(r"^/api/runs/([0-9a-f-]+)/force-stop$")
_RUN_RECONCILE_ROUTE = re.compile(r"^/api/runs/([0-9a-f-]+)/reconcile$")
_RUN_REVIEW_ROUTE = re.compile(r"^/api/runs/([0-9a-f-]+)/review$")
_MODULE_ROUTE = re.compile(r"^/api/modules/([a-z0-9.-]+)$")
_MODULE_RUN_ROUTE = re.compile(r"^/api/modules/([a-z0-9.-]+)/run$")
_MODULE_PREPARE_ROUTE = re.compile(r"^/api/modules/([a-z0-9.-]+)/prepare$")
_MODULE_TOGGLE_ROUTE = re.compile(r"^/api/modules/([a-z0-9.-]+)/enabled$")
_MODULE_PRESENTATION_ROUTE = re.compile(
    r"^/api/modules/([a-z0-9.-]+)/presentation/(icon|image)$"
)
_ACCOUNT_ROUTE = re.compile(r"^/api/accounts/([0-9a-f-]+)$")
_EXCEL_ESCAPE_RE = re.compile(r"(?i)_x[0-9a-f]{4}_")
_EXPORT_FIELDS = ("private_key", "proxy", "email", "twitter", "adspower_profile")
_PRESENTATION_CONTENT_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".avif": "image/avif",
    ".ico": "image/x-icon",
}
_PRESENTATION_ASSET_LIMITS = {"icon": 2 * 1024 * 1024, "image": 16 * 1024 * 1024}


def _valid_presentation_signature(payload: bytes, suffix: str) -> bool:
    checks = {
        ".png": payload.startswith(b"\x89PNG\r\n\x1a\n"),
        ".jpg": payload.startswith(b"\xff\xd8\xff"),
        ".jpeg": payload.startswith(b"\xff\xd8\xff"),
        ".gif": payload.startswith((b"GIF87a", b"GIF89a")),
        ".webp": len(payload) >= 12
        and payload[:4] == b"RIFF"
        and payload[8:12] == b"WEBP",
        ".avif": len(payload) >= 12
        and payload[4:8] == b"ftyp"
        and payload[8:12] in {b"avif", b"avis", b"mif1"},
        ".ico": payload.startswith(b"\x00\x00\x01\x00"),
    }
    return checks.get(suffix, False)


def _local_plugin_filename(encoded: str) -> str:
    try:
        filename = unquote(encoded, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ApiError("Некорректное имя файла патча") from error
    if (
        not filename
        or len(filename) > 255
        or "/" in filename
        or "\\" in filename
        or any(ord(character) < 32 or ord(character) == 127 for character in filename)
    ):
        raise ApiError("Некорректное имя файла патча")
    if filename.lower().endswith((".zip", ".softhub")):
        return filename
    raise ApiError(
        "Выберите ZIP-пакет Soft Hub или файл .softhub"
    )


def _excel_inline_text(value: Any) -> str:
    """Encode an exact cell string for SpreadsheetML inlineStr storage."""
    text = _EXCEL_ESCAPE_RE.sub(
        lambda match: "_x005F_" + match.group(0)[1:], str(value)
    )
    encoded: list[str] = []
    for character in text:
        codepoint = ord(character)
        if (
            character == "\r"
            or (codepoint < 0x20 and character not in {"\t", "\n"})
            or 0xD800 <= codepoint <= 0xDFFF
            or codepoint in {0xFFFE, 0xFFFF}
        ):
            encoded.append(f"_x{codepoint:04X}_")
        else:
            encoded.append(character)
    return xml_escape("".join(encoded))


def _xlsx_workbook(rows: list[dict[str, Any]]) -> bytes:
    row_xml: list[str] = []
    values = [list(_EXPORT_FIELDS)] + [
        [str(row.get(field, "")) for field in _EXPORT_FIELDS] for row in rows
    ]
    columns = ("A", "B", "C", "D", "E")
    for row_number, row_values in enumerate(values, start=1):
        cells = "".join(
            f'<c r="{column}{row_number}" t="inlineStr"><is>'
            f'<t xml:space="preserve">{_excel_inline_text(value)}</t>'
            f"</is></c>"
            for column, value in zip(columns, row_values, strict=True)
        )
        row_xml.append(f'<row r="{row_number}">{cells}</row>')
    last_row = max(1, len(values))
    worksheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<dimension ref="A1:E{last_row}"/><sheetData>{"".join(row_xml)}</sheetData>'
        "</worksheet>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        "</Types>"
    )
    root_relationships = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Accounts" sheetId="1" r:id="rId1"/></sheets>'
        "</workbook>"
    )
    workbook_relationships = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/>'
        "</Relationships>"
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        package.writestr("[Content_Types].xml", content_types)
        package.writestr("_rels/.rels", root_relationships)
        package.writestr("xl/workbook.xml", workbook)
        package.writestr("xl/_rels/workbook.xml.rels", workbook_relationships)
        package.writestr("xl/worksheets/sheet1.xml", worksheet)
    return output.getvalue()


def _public_module(module: dict[str, Any]) -> dict[str, Any]:
    """Keep host filesystem layout on the trusted core side of the API boundary."""
    return {key: value for key, value in module.items() if key != "active_path"}


class ApiError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


class HubApplication:
    def __init__(self, data_dir: Path | str | None = None, *, max_concurrent: int = 4):
        self.paths = HubPaths.create(data_dir)
        self._instance_lock = DataDirectoryLock(self.paths.data_dir)
        self._closed = False
        try:
            self.database = Database(self.paths)
            self.vault = Vault(self.database)
            self.plugins = PluginManager(self.database, self.paths)
            self.github = GitHubPackageFetcher()
            self.patch_feed = GitHubPatchFeed()
            self.runs = RunManager(
                self.database, self.paths, self.plugins, self.vault, max_concurrent=max_concurrent
            )
        except BaseException:
            self._instance_lock.release()
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.runs.shutdown()
        finally:
            self.vault.lock()
            self._instance_lock.release()

    def bootstrap(self) -> dict[str, Any]:
        modules = [_public_module(module) for module in self.plugins.list()]
        protected = self.vault.exists and not self.vault.unlocked
        accounts = self.vault.list_accounts() if self.vault.unlocked else []
        referral_topology = (
            self.vault.referral_topology(accounts)
            if self.vault.unlocked
            else {
                "revision": "",
                "relationships": [],
                "roots": 0,
                "links": 0,
                "max_depth": 0,
            }
        )
        run_feed = (
            {"runs": [], "truncated": False}
            if protected
            else self.runs.bootstrap_runs()
        )
        runs = run_feed["runs"]
        run_counts = self.runs.status_counts()
        # Keep enough rows for useful per-software grouping without loading an
        # unbounded history into the desktop bootstrap response.
        results = [] if protected else self.runs.results(100)
        configured_status_visible = self.vault.unlocked or not self.vault.exists
        return {
            "app": {"name": "Soft Hub", "version": APP_VERSION, "platform": os.sys.platform},
            "vault": {
                "exists": self.vault.exists,
                "unlocked": self.vault.unlocked,
                "capsolver_configured": (
                    self.vault.capsolver_configured
                    if configured_status_visible
                    else None
                ),
                "adspower_api_configured": (
                    self.vault.adspower_api_configured
                    if configured_status_visible
                    else None
                ),
            },
            "stats": {
                "modules": len(modules),
                "accounts": len(accounts),
                "active_runs": run_counts["active_runs"],
                "needs_attention": run_counts["needs_attention"],
                "attention_runs": run_counts["attention_runs"],
                "results": (
                    0
                    if protected
                    else self.database.one("SELECT COUNT(*) AS count FROM results")["count"]
                ),
            },
            "modules": modules,
            "accounts": accounts,
            "referral_topology": referral_topology,
            "runs": runs,
            "runs_truncated": run_feed["truncated"],
            "results": results,
            "patch_feed": {
                "owner": self.database.setting("github_patch_owner", ""),
            },
        }


class HubRequestHandler(BaseHTTPRequestHandler):
    server_version = f"SoftHub/{APP_VERSION}"
    application: HubApplication
    api_token: str
    static_root = Path(__file__).resolve().parent / "static"

    def do_GET(self) -> None:  # noqa: N802
        try:
            self._validate_host()
            parsed = urlparse(self.path)
            if parsed.path.startswith("/api/"):
                self._require_token()
                self._handle_get(parsed.path, parse_qs(parsed.query))
            else:
                self._serve_static(parsed.path)
        except BaseException as error:
            self._handle_error(error)

    def do_POST(self) -> None:  # noqa: N802
        try:
            self._validate_host()
            self._require_token()
            self._validate_origin()
            path = urlparse(self.path).path
            if path == "/api/modules/install":
                self._install_archive()
                return
            body = self._read_json()
            self._handle_post(path, body)
        except BaseException as error:
            self._handle_error(error)

    def do_DELETE(self) -> None:  # noqa: N802
        try:
            self._validate_host()
            self._require_token()
            self._validate_origin()
            path = urlparse(self.path).path
            if match := _ACCOUNT_ROUTE.fullmatch(path):
                deleted = self.application.vault.delete_account(match.group(1))
                if not deleted:
                    raise ApiError("Аккаунт не найден", 404)
                self._json({"ok": True})
            elif match := _MODULE_ROUTE.fullmatch(path):
                self._json(self.application.runs.uninstall_module(match.group(1)))
            else:
                raise ApiError("Маршрут не найден", 404)
        except BaseException as error:
            self._handle_error(error)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._json({"error": "Метод не поддерживается"}, status=HTTPStatus.METHOD_NOT_ALLOWED)

    def _handle_get(self, path: str, query: dict[str, list[str]]) -> None:
        app = self.application
        if path == "/api/health":
            self._json({"ok": True, "version": APP_VERSION})
        elif path == "/api/bootstrap":
            self._json(app.bootstrap())
        elif path == "/api/modules":
            self._json({"modules": [_public_module(module) for module in app.plugins.list()]})
        elif path == "/api/accounts":
            self._json({"accounts": app.vault.list_accounts()})
        elif path == "/api/accounts/referral-topology":
            accounts = app.vault.list_accounts()
            self._json(app.vault.referral_topology(accounts))
        elif path == "/api/runs":
            self._require_unlocked_projection()
            self._json({"runs": app.runs.list(self._query_int(query, "limit", 50))})
        elif path == "/api/run-accounts":
            self._require_unlocked_projection()
            scope = query.get("scope", ["historical"])[0]
            self._json(
                app.runs.account_state_page(
                    scope=scope,
                    limit=self._query_int(query, "limit", 500),
                )
            )
        elif path == "/api/results/overview":
            self._require_unlocked_projection()
            self._json(
                {
                    "reports": app.runs.result_reports(
                        run_id=self._query_text(query, "run_id"),
                        module_id=self._query_text(query, "module_id"),
                        action_id=self._query_text(query, "action_id"),
                        limit=self._query_int(query, "limit", 100),
                    )
                }
            )
        elif path == "/api/results/report":
            self._require_unlocked_projection()
            run_id = self._query_text(query, "run_id")
            if run_id is None:
                raise ApiError("Для отчёта нужен run_id")
            self._json(
                app.runs.result_report(
                    run_id,
                    limit=self._query_int(query, "limit", 2_000),
                )
            )
        elif path == "/api/results":
            self._require_unlocked_projection()
            self._json({"results": app.runs.results(self._query_int(query, "limit", 100))})
        elif match := _MODULE_PRESENTATION_ROUTE.fullmatch(path):
            self._presentation_asset(match.group(1), match.group(2))
        elif match := _RUN_ACCOUNTS_ROUTE.fullmatch(path):
            self._require_unlocked_projection()
            run_id = match.group(1)
            if not app.runs.get(run_id):
                raise ApiError("Запуск не найден", 404)
            self._json(
                {
                    "accounts": app.runs.account_states(
                        run_id, self._query_int(query, "limit", 500)
                    )
                }
            )
        elif match := _RUN_EVENTS_ROUTE.fullmatch(path):
            self._require_unlocked_projection()
            run_id = match.group(1)
            if not app.runs.get(run_id):
                raise ApiError("Запуск не найден", 404)
            self._json(
                {
                    "events": app.runs.events(
                        run_id,
                        self._query_int(query, "after", 0),
                        self._query_int(query, "limit", 500),
                    )
                }
            )
        elif match := _RUN_LOG_ROUTE.fullmatch(path):
            self._require_unlocked_projection()
            run_id = match.group(1)
            if not app.runs.get(run_id):
                raise ApiError("Запуск не найден", 404)
            self._technical_log_export(run_id)
        elif match := _RUN_ROUTE.fullmatch(path):
            self._require_unlocked_projection()
            run = app.runs.get(match.group(1))
            if not run:
                raise ApiError("Запуск не найден", 404)
            self._json(run)
        else:
            raise ApiError("Маршрут не найден", 404)

    def _handle_post(self, path: str, body: dict[str, Any]) -> None:
        app = self.application
        if path == "/api/vault/create":
            password = body.get("password")
            if not isinstance(password, str):
                raise ApiError("Нужен мастер-пароль")
            app.vault.create(password)
            self._json({"vault": {"exists": True, "unlocked": True}}, status=201)
        elif path == "/api/vault/unlock":
            password = body.get("password")
            if not isinstance(password, str):
                raise ApiError("Нужен мастер-пароль")
            app.vault.unlock(password)
            self._json({"vault": {"exists": True, "unlocked": True}})
        elif path == "/api/vault/lock":
            app.vault.lock()
            self._json({"vault": {"exists": app.vault.exists, "unlocked": False}})
        elif path == "/api/accounts/import":
            records = self._parse_import(body)
            outcome = app.vault.import_records(records)
            self._json({"ok": True, **outcome, "accounts": app.vault.list_accounts()}, status=201)
        elif path == "/api/accounts/referral-topology":
            if set(body) != {"expected_revision", "relationships"}:
                raise ApiError(
                    "Запрос topology ожидает только expected_revision и relationships"
                )
            outcome = app.vault.update_referral_topology(
                body["expected_revision"], body["relationships"]
            )
            self._json(
                {"ok": True, **outcome, "accounts": app.vault.list_accounts()}
            )
        elif path == "/api/accounts/export":
            password = body.get("password")
            acknowledgement = body.get("acknowledgement")
            export_format = body.get("format", "csv")
            if not isinstance(password, str) or not isinstance(acknowledgement, str):
                raise ApiError("Для экспорта нужны мастер-пароль и фраза подтверждения")
            if not isinstance(export_format, str) or export_format not in {"csv", "xlsx"}:
                raise ApiError("Формат экспорта должен быть csv или xlsx")
            rows = app.vault.export_rows(password, acknowledgement)
            if export_format == "xlsx":
                self._xlsx_export(rows)
            else:
                self._csv_export(rows)
        elif path == "/api/settings/capsolver":
            action = body.get("action")
            if action == "save":
                value = body.get("api_key")
                if not isinstance(value, str):
                    raise ApiError("Введите Capsolver API key")
                app.vault.set_capsolver_api_key(value)
            elif action == "clear":
                app.vault.clear_capsolver_api_key()
            else:
                raise ApiError("Неизвестное действие Capsolver")
            self._json({"capsolver": app.vault.capsolver_status()})
        elif path == "/api/settings/adspower":
            action = body.get("action")
            if action == "save":
                value = body.get("api_key")
                if not isinstance(value, str):
                    raise ApiError("Введите AdsPower API key")
                app.vault.set_adspower_api_key(value)
            elif action == "clear":
                app.vault.clear_adspower_api_key()
            else:
                raise ApiError("Неизвестное действие AdsPower")
            self._json({"adspower": app.vault.adspower_api_status()})
        elif path == "/api/patch-feed/scan":
            if set(body) != {"owner"}:
                raise ApiError("Patch Radar ожидает только GitHub owner")
            value = body.get("owner")
            if not isinstance(value, str):
                raise ApiError("Введите GitHub username или URL профиля")
            try:
                owner = normalize_owner(value)
                app.database.set_setting("github_patch_owner", owner)
                patches = annotate_patch_versions(
                    app.patch_feed.scan(owner),
                    app.plugins.github_sources(),
                )
            except GitHubPatchFeedError as error:
                raise ApiError(str(error), 400) from error
            self._json({"owner": owner, "patches": patches})
        elif path == "/api/modules/install/github":
            if set(body) != {"url"}:
                raise ApiError("GitHub install ожидает только URL release asset")
            url = body.get("url")
            if not isinstance(url, str):
                raise ApiError("Нужна GitHub URL")
            temporary = app.paths.imports / f"{uuid.uuid4()}.softhub.zip"
            try:
                try:
                    source = app.github.download(url, temporary)
                except GitHubInstallError as error:
                    raise ApiError(str(error), 400) from error
                module = _public_module(app.plugins.install_github(temporary, source))
                self._json(
                    {
                        **module,
                        "github": {
                            "owner": source.owner,
                            "repository": source.repository,
                            "release": source.release,
                            "asset": source.filename,
                        },
                    },
                    status=201,
                )
            finally:
                temporary.unlink(missing_ok=True)
        elif path == "/api/runs/batch":
            self._require_unlocked_projection()
            unknown = sorted(set(body) - {"idempotency_key", "runs"})
            if unknown:
                raise ApiError(f"Неизвестное поле batch request: {unknown[0]}")
            try:
                result = app.runs.start_batch(
                    body.get("idempotency_key"),
                    body.get("runs"),
                )
            except IdempotencyConflictError as error:
                raise ApiError(str(error), HTTPStatus.CONFLICT) from error
            self._json(result, status=HTTPStatus.ACCEPTED)
        elif match := _MODULE_RUN_ROUTE.fullmatch(path):
            self._require_unlocked_projection()
            unknown = sorted(
                set(body) - {"action_id", "account_ids", "options", "acknowledgement"}
            )
            if unknown:
                raise ApiError(f"Неизвестное поле run request: {unknown[0]}")
            action_id = body.get("action_id")
            if not isinstance(action_id, str):
                raise ApiError("Не выбрано действие")
            account_ids = body.get("account_ids", [])
            options = body.get("options", {})
            if not isinstance(account_ids, list) or not isinstance(options, dict):
                raise ApiError("Некорректный контекст запуска")
            run = app.runs.start(
                match.group(1),
                action_id,
                account_ids,
                options,
                str(body.get("acknowledgement", "")),
            )
            self._json(run, status=202)
        elif match := _RUN_STOP_ROUTE.fullmatch(path):
            self._require_unlocked_projection()
            self._json(app.runs.stop(match.group(1)), status=202)
        elif match := _RUN_FORCE_STOP_ROUTE.fullmatch(path):
            self._require_unlocked_projection()
            acknowledgement = body.get("acknowledgement", "")
            if not isinstance(acknowledgement, str):
                raise ApiError("acknowledgement должен быть строкой")
            self._json(
                app.runs.force_stop(match.group(1), acknowledgement),
                status=202,
            )
        elif match := _RUN_RECONCILE_ROUTE.fullmatch(path):
            self._require_unlocked_projection()
            self._json(
                app.runs.reconcile(match.group(1), str(body.get("acknowledgement", "")))
            )
        elif match := _RUN_REVIEW_ROUTE.fullmatch(path):
            self._require_unlocked_projection()
            if body:
                raise ApiError("Для отметки просмотра не нужны дополнительные поля")
            self._json(app.runs.review_failure(match.group(1)))
        elif match := _MODULE_PREPARE_ROUTE.fullmatch(path):
            self._json(_public_module(app.plugins.prepare(match.group(1))))
        elif match := _MODULE_TOGGLE_ROUTE.fullmatch(path):
            if not isinstance(body.get("enabled"), bool):
                raise ApiError("enabled должен быть boolean")
            self._json(_public_module(app.plugins.set_enabled(match.group(1), body["enabled"])))
        else:
            raise ApiError("Маршрут не найден", 404)

    @staticmethod
    def _parse_import(body: dict[str, Any]) -> list[ImportRecord]:
        if "records" in body:
            raw_records = body["records"]
            if not isinstance(raw_records, list):
                raise ApiError("records должен быть списком объектов")
            if any(not isinstance(item, dict) for item in raw_records):
                raise ApiError("Каждая строка импорта должна быть объектом")
            try:
                return [ImportRecord(**item) for item in raw_records]
            except TypeError as error:
                raise ApiError("Строка импорта содержит неизвестные или пропущенные поля") from error
        keys = body.get("private_keys")
        proxies = body.get("proxies")
        emails = body.get("emails")
        passwords = body.get("email_passwords", [])
        labels = body.get("labels", [])
        twitters = body.get("twitters", [])
        adspower_profiles = body.get("adspower_profiles", [])
        if not all(
            isinstance(values, list)
            for values in (
                keys,
                proxies,
                emails,
                passwords,
                labels,
                twitters,
                adspower_profiles,
            )
        ):
            raise ApiError("Импорт ожидает списки private_keys, proxies и emails")
        if not keys or len(keys) != len(proxies) or len(keys) != len(emails):
            raise ApiError("Количество private keys, proxies и emails должно совпадать 1:1")
        if passwords and len(passwords) != len(keys):
            raise ApiError("Количество email passwords должно совпадать с аккаунтами")
        if labels and len(labels) != len(keys):
            raise ApiError("Количество labels должно совпадать с аккаунтами")
        if twitters and len(twitters) != len(keys):
            raise ApiError("Количество Twitter accounts должно совпадать с аккаунтами")
        if adspower_profiles and len(adspower_profiles) != len(keys):
            raise ApiError("Количество AdsPower profile IDs должно совпадать с аккаунтами")
        for values, field in (
            (keys, "private keys"),
            (proxies, "proxies"),
            (emails, "emails"),
            (passwords, "email passwords"),
            (labels, "labels"),
            (twitters, "Twitter accounts"),
            (adspower_profiles, "AdsPower profile IDs"),
        ):
            if any(not isinstance(value, str) for value in values):
                raise ApiError(f"Все значения {field} должны быть строками")
        return [
            ImportRecord(
                private_key=key,
                proxy=proxies[index],
                email=emails[index],
                email_password=passwords[index] if passwords else "",
                twitter=twitters[index] if twitters else None,
                adspower_profile=(
                    adspower_profiles[index] if adspower_profiles else None
                ),
                label=labels[index] if labels else "",
            )
            for index, key in enumerate(keys)
        ]

    def _csv_export(self, rows: list[dict[str, Any]]) -> None:
        output = io.StringIO(newline="")
        fieldnames = list(_EXPORT_FIELDS)
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\r\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: str(row.get(key, "")) for key in fieldnames})
        body = ("\ufeff" + output.getvalue()).encode("utf-8")
        self.send_response(200)
        self._security_headers()
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="soft-hub-accounts.csv"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Soft-Hub-Spreadsheet-Safe", "false")
        self.end_headers()
        self.wfile.write(body)

    def _xlsx_export(self, rows: list[dict[str, Any]]) -> None:
        body = _xlsx_workbook(rows)
        self.send_response(200)
        self._security_headers()
        self.send_header(
            "Content-Type",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.send_header("Content-Disposition", 'attachment; filename="soft-hub-accounts.xlsx"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Soft-Hub-Spreadsheet-Safe", "true")
        self.end_headers()
        self.wfile.write(body)

    def _technical_log_export(self, run_id: str) -> None:
        body = self.application.runs.technical_log(run_id)
        filename = f"soft-hub-run-{run_id}.log"
        self.send_response(200)
        self._security_headers()
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Soft-Hub-Redacted", "true")
        self.end_headers()
        self.wfile.write(body)

    def _presentation_asset(self, module_id: str, kind: str) -> None:
        module = self.application.plugins.get(module_id)
        if not module:
            raise ApiError("Модуль не найден", 404)
        presentation = module.get("manifest", {}).get("presentation")
        assets = presentation.get("assets") if isinstance(presentation, dict) else None
        relative_value = assets.get(kind) if isinstance(assets, dict) else None
        if not isinstance(relative_value, str) or not relative_value:
            raise ApiError("Изображение модуля не найдено", 404)
        relative = Path(relative_value)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or "\\" in relative_value
            or relative.parts[:1] != ("assets",)
        ):
            raise ApiError("Изображение модуля недоступно", 404)
        content_type = _PRESENTATION_CONTENT_TYPES.get(relative.suffix.lower())
        if content_type is None:
            raise ApiError("Формат изображения модуля не поддерживается", 415)
        active_value = module.get("active_path")
        if not isinstance(active_value, str) or not active_value:
            raise ApiError("Изображение модуля недоступно", 404)
        try:
            root = Path(active_value).resolve(strict=True)
            unresolved_target = root / relative
            if unresolved_target.is_symlink():
                raise ApiError("Изображение модуля недоступно", 404)
            target = unresolved_target.resolve(strict=True)
            target.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            raise ApiError("Изображение модуля недоступно", 404) from None
        if not target.is_file():
            raise ApiError("Изображение модуля не найдено", 404)
        limit = _PRESENTATION_ASSET_LIMITS[kind]
        try:
            descriptor = os.open(
                target,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            with os.fdopen(descriptor, "rb") as stream:
                body = stream.read(limit + 1)
        except OSError:
            raise ApiError("Изображение модуля недоступно", 404) from None
        if len(body) > limit:
            raise ApiError("Изображение модуля превышает лимит", 413)
        if not _valid_presentation_signature(body, relative.suffix.lower()):
            raise ApiError("Изображение модуля повреждено", 415)
        self.send_response(200)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _install_archive(self) -> None:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type not in {"application/zip", "application/octet-stream"}:
            raise ApiError("Ожидается ZIP archive", 415)
        length = self._content_length(MAX_ARCHIVE_BYTES)
        _local_plugin_filename(
            self.headers.get("X-Soft-Hub-Filename", "plugin.softhub.zip")
        )
        temporary = self.application.paths.imports / f"{uuid.uuid4()}.softhub.zip"
        remaining = length
        try:
            with temporary.open("xb") as output:
                try:
                    temporary.chmod(0o600)
                except OSError:
                    pass
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ApiError("Архив передан не полностью")
                    output.write(chunk)
                    remaining -= len(chunk)
            module = self.application.plugins.install(temporary)
            self._json(_public_module(module), status=201)
        finally:
            temporary.unlink(missing_ok=True)

    def _read_json(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type != "application/json":
            raise ApiError("Ожидается application/json", 415)
        length = self._content_length(MAX_JSON_BYTES)
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ApiError("Некорректный JSON") from error
        if not isinstance(body, dict):
            raise ApiError("JSON body должен быть объектом")
        return body

    def _content_length(self, maximum: int) -> int:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError as error:
            raise ApiError("Некорректный Content-Length", 411) from error
        if length <= 0:
            raise ApiError("Пустой request body")
        if length > maximum:
            raise ApiError("Request body слишком большой", 413)
        return length

    @staticmethod
    def _query_int(query: dict[str, list[str]], key: str, default: int) -> int:
        try:
            return int(query.get(key, [str(default)])[0])
        except ValueError:
            return default

    @staticmethod
    def _query_text(query: dict[str, list[str]], key: str) -> str | None:
        values = query.get(key)
        return values[0] if values else None

    def _require_token(self) -> None:
        supplied = self.headers.get("X-Soft-Hub-Token", "")
        if not secrets.compare_digest(supplied, self.api_token):
            raise ApiError("Не авторизовано", 401)

    def _require_unlocked_projection(self) -> None:
        """Deny history projections once an existing Vault is locked.

        Run summaries, errors, events and results are plugin-controlled and can
        contain account identifiers or metadata even when their nominal schema
        is secret-free.  Treat the complete projection as protected instead of
        attempting a brittle field-by-field redaction while locked.
        """
        vault = self.application.vault
        if vault.exists and not vault.unlocked:
            raise ApiError("Vault заблокирован", HTTPStatus.LOCKED)

    def _validate_host(self) -> None:
        raw_host = self.headers.get("Host", "").strip().lower()
        try:
            parsed = urlparse("//" + raw_host)
            host = parsed.hostname
            port = parsed.port
        except ValueError as error:
            raise ApiError("Недопустимый Host", 400) from error
        server_port = int(self.server.server_address[1])
        if (
            host not in {"127.0.0.1", "localhost"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or port not in {None, server_port}
        ):
            raise ApiError("Недопустимый Host", 400)
        self._request_host = host

    def _validate_origin(self) -> None:
        origin = self.headers.get("Origin")
        if not origin:
            return
        parsed = urlparse(origin)
        server_port = int(self.server.server_address[1])
        try:
            origin_port = parsed.port
        except ValueError as error:
            raise ApiError("Недопустимый Origin", 403) from error
        if (
            parsed.scheme != "http"
            or parsed.hostname != getattr(self, "_request_host", None)
            or origin_port != server_port
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise ApiError("Недопустимый Origin", 403)

    def _serve_static(self, path: str) -> None:
        aliases = {"/": "index.html", "/index.html": "index.html"}
        relative = aliases.get(path, path.lstrip("/"))
        if not relative or ".." in Path(relative).parts or "\\" in relative:
            raise ApiError("Файл не найден", 404)
        target = (self.static_root / relative).resolve()
        if target.parent != self.static_root.resolve() or not target.is_file():
            raise ApiError("Файл не найден", 404)
        body = target.read_bytes()
        mime = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(200)
        self._security_headers()
        self.send_header("Content-Type", f"{mime}; charset=utf-8" if mime.startswith("text/") else mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
            "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'",
        )

    def _handle_error(self, error: BaseException) -> None:
        if isinstance(error, ApiError):
            status = error.status
            message = str(error)
        elif isinstance(error, (VaultError, PluginError, RunError, TypeError)):
            status = (
                HTTPStatus.CONFLICT
                if isinstance(error, ReferralRevisionConflict)
                else HTTPStatus.LOCKED
                if isinstance(error, VaultError) and str(error) == "Vault заблокирован"
                else HTTPStatus.BAD_REQUEST
            )
            message = str(error)
        else:
            status = 500
            message = "Внутренняя ошибка Soft Hub"
        try:
            self._json({"error": message}, status=status)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format: str, *args: Any) -> None:
        # Avoid echoing query parameters or request bodies into terminal logs.
        return


def create_server(
    application: HubApplication,
    token: str | None = None,
    port: int = 0,
) -> tuple[ThreadingHTTPServer, str]:
    api_token = token or secrets.token_urlsafe(32)

    class BoundHandler(HubRequestHandler):
        pass

    BoundHandler.application = application
    BoundHandler.api_token = api_token
    class ApplicationServer(ThreadingHTTPServer):
        def server_close(self) -> None:
            try:
                super().server_close()
            finally:
                application.close()

    server = ApplicationServer(("127.0.0.1", port), BoundHandler)
    server.daemon_threads = True
    return server, api_token
