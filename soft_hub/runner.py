from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from decimal import Decimal, InvalidOperation
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from .config import HubPaths, project_root
from .database import Database, utc_now
from .plugins import PluginError, PluginManager, catalog_sections
from .sdk import ACCOUNT_STATE_STATUSES
from .vault import Vault, VaultError

_KEY_RE = re.compile(r"(?i)(?:0x)?[0-9a-f]{64}")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?")
_PROXY_RE = re.compile(
    r"(?i)(?:https?://)?(?:[^\s:@/]+:[^\s@/]+@)?(?:[A-Za-z0-9.-]+|\[[0-9a-f:]+\]):\d{1,5}(?::[^\s:]+:[^\s]+)?"
)
_EMAIL_RE = re.compile(
    r"(?i)(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+"
)
_AUTHORIZATION_RE = re.compile(
    r"(?i)\b(?P<name>(?:proxy[-_ ]?)?authorization)\s*[:=]\s*"
    r"(?:(?:basic|bearer)\s+)?[^\s,;]+"
)
_COOKIE_HEADER_RE = re.compile(
    r"(?im)\b(?P<name>set[-_ ]?cookie|cookie)\s*[:=]\s*[^\r\n]+"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r'''(?ix)
    (?P<prefix>
        ["']?
        (?:
            password|passwd|pwd|passphrase|secret|client[-_ ]?secret|
            private[-_ ]?key|privkey|mnemonic|seed(?:[-_ ]?phrase)?|
            api[-_ ]?key|apikey|access[-_ ]?token|refresh[-_ ]?token|token|
            session(?:[-_ ]?(?:id|key|token))?|credential(?:s)?|
            proxy|email(?:[-_ ]?password)?
        )
        ["']?\s*[:=]\s*
    )
    (?P<value>
        "(?:\\.|[^"\\])*"|
        '(?:\\.|[^'\\])*'|
        [^\s,;}&]+
    )
    ''',
)
_KNOWN_TOKEN_RE = re.compile(
    r"(?i)\b(?:github_pat_|gh[pousr]_|xox[baprs]-|sk-(?:proj-)?|cap[-_])"
    r"[A-Za-z0-9._=-]{12,}\b"
)
_HIGH_ENTROPY_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?=[A-Za-z0-9_./+=-]{32,}(?![A-Za-z0-9]))"
    r"(?=[A-Za-z0-9_./+=-]*[a-z])(?=[A-Za-z0-9_./+=-]*[A-Z])"
    r"(?=[A-Za-z0-9_./+=-]*\d)[A-Za-z0-9_./+=-]+"
)
_SECRET_FIELD_RE = re.compile(
    r"(?:^|_)(?:password|passwd|pwd|passphrase|secret|secrets|client_secret|"
    r"private_key|privkey|mnemonic|seed|seed_phrase|api_key|apikey|token|"
    r"access_token|refresh_token|auth|authorization|bearer|cookie|cookies|"
    r"set_cookie|session|session_id|session_key|session_token|credential|"
    r"credentials|proxy|email|email_password|referral_code|referrer_code|"
    r"external_referrer_code)(?:$|_)"
)
_ALLOWED_LEVELS = {"debug", "info", "success", "warning", "error"}
_ALLOWED_EVENTS = {
    "started",
    "log",
    "progress",
    "metric",
    "warning",
    "result",
    "account_state",
    "heartbeat",
    "completed",
    "failed",
    "cancelled",
}
_TERMINAL_EVENTS = {"completed", "failed", "cancelled"}
_ACCOUNT_ACTIVE_STATUSES = {"queued", "running"}
_ACCOUNT_TERMINAL_STATUSES = (ACCOUNT_STATE_STATUSES | {"unknown"}) - _ACCOUNT_ACTIVE_STATUSES
_ACCOUNT_PRESERVE_PROGRESS_STATUSES = {
    "failed",
    "skipped",
    "blocked",
    "needs_attention",
    "cancelled",
}
_LEGACY_ACCOUNT_SUMMARY_STATUSES = {
    "succeeded",
    "partial",
    "failed",
    "skipped",
    "blocked",
    "needs_attention",
}
_LEGACY_ACCOUNT_SUMMARY_STAGES = {
    "succeeded": "completed",
    "partial": "partially_completed",
    "failed": "action_failed",
    "skipped": "skipped",
    "blocked": "blocked",
    "needs_attention": "external_state_unknown",
}
_LEGACY_ACCOUNT_SUMMARY_BRIDGE = {
    ("io.sprintray.checkpoint-testnet", "1.0.0"): frozenset(
        {"inspect", "daily_farm", "deposit", "full_cycle", "create_sell"}
    ),
    ("io.sprintray.sekai-testnet", "1.0.0"): frozenset({"inspect", "run_cycle"}),
    ("io.sprintray.umia-testnet", "1.0.0"): frozenset({"inspect", "run_activities"}),
}
_ACCOUNT_STAGE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_MAX_PROTOCOL_LINE = 64 * 1024
_MAX_RUN_OUTPUT_LINES = 50_000
_MAX_LOG_EXPORT_BYTES = 16 * 1024 * 1024
_MAX_LOG_EXPORT_DATA_CHARS = 256 * 1024
_MAX_LOG_EXPORT_LINE_BYTES = 512 * 1024
_OVERSIZE_LINE = "[SOFT_HUB_OVERSIZE_LINE]"
_MAX_BATCH_RUNS = 100
_MAX_ACCOUNT_CONCURRENCY = 20
_ACCOUNT_CONCURRENCY_OPTION = "account_concurrency"
_OUTPUT_MODE = "account_table"
_OUTPUT_TYPES = {"string", "integer", "number", "decimal_string", "boolean"}
_OUTPUT_NUMERIC_TYPES = {"integer", "number", "decimal_string"}
_OUTPUT_AGGREGATES = {"sum", "avg", "min", "max"}
_OUTPUT_RESULT_STATUSES = {
    "succeeded",
    "partial",
    "failed",
    "skipped",
    "blocked",
    "needs_attention",
}
_OUTPUT_COLUMN_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_OUTPUT_KIND_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
_DECIMAL_STRING_RE = re.compile(r"^-?\d+(?:\.\d+)?$")
_MAX_OUTPUT_COLUMNS = 12
_MAX_OUTPUT_AGGREGATES = 4
_JS_SAFE_INTEGER = 9_007_199_254_740_991
_MAX_REPORT_ROWS = 2_000
_MAX_REPORTS = 500
_REPORT_ACCOUNT_STATUSES = (
    "queued",
    "running",
    "succeeded",
    "partial",
    "failed",
    "skipped",
    "blocked",
    "needs_attention",
    "cancelled",
    "unknown",
)
_EXTERNAL_WRITE_LEASE_SCOPE = 0
_REFERRAL_PARENT_LEASE_SCOPE = -1
_ACTIVE_RUN_STATUSES = ("queued", "starting", "running", "cancelling")
_OPERATIONAL_RUN_STATUSES = _ACTIVE_RUN_STATUSES
_BATCH_SPEC_FIELDS = {
    "module_id",
    "action_id",
    "account_ids",
    "options",
    "acknowledgement",
}


class RunError(ValueError):
    pass


class IdempotencyConflictError(RunError):
    pass


FORCE_STOP_ACKNOWLEDGEMENT = "FORCE STOP"


def _catalog_snapshot(value: Any) -> list[str]:
    try:
        sections = json.loads(value) if isinstance(value, str) else value
    except (TypeError, json.JSONDecodeError):
        return ["general"]
    return catalog_sections({"catalog": {"sections": sections}})


def _normalize_idempotency_key(value: Any) -> str:
    if not isinstance(value, str):
        raise RunError("idempotency_key должен быть UUID")
    try:
        normalized = str(uuid.UUID(value))
    except (ValueError, AttributeError) as error:
        raise RunError("idempotency_key должен быть UUID") from error
    if value.lower() != normalized:
        raise RunError("idempotency_key должен быть UUID в canonical формате")
    return normalized


def _normalize_batch_specs(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_BATCH_RUNS:
        raise RunError(f"runs должен содержать от 1 до {_MAX_BATCH_RUNS} запусков")
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(value, start=1):
        if not isinstance(raw, dict):
            raise RunError(f"runs[{index}] должен быть объектом")
        unknown = sorted(set(raw) - _BATCH_SPEC_FIELDS)
        if unknown:
            raise RunError(f"runs[{index}] содержит неизвестное поле: {unknown[0]}")
        module_id = raw.get("module_id")
        action_id = raw.get("action_id")
        account_ids = raw.get("account_ids", [])
        options = raw.get("options", {})
        acknowledgement = raw.get("acknowledgement", "")
        if not isinstance(module_id, str) or not module_id:
            raise RunError(f"runs[{index}].module_id должен быть строкой")
        if not isinstance(action_id, str) or not action_id:
            raise RunError(f"runs[{index}].action_id должен быть строкой")
        if not isinstance(account_ids, list) or any(
            not isinstance(account_id, str) or not account_id for account_id in account_ids
        ):
            raise RunError(f"runs[{index}].account_ids должен быть списком строк")
        if not isinstance(options, dict) or any(not isinstance(key, str) for key in options):
            raise RunError(f"runs[{index}].options должен быть JSON-объектом")
        if not isinstance(acknowledgement, str):
            raise RunError(f"runs[{index}].acknowledgement должен быть строкой")
        normalized.append(
            {
                "module_id": module_id,
                "action_id": action_id,
                "account_ids": list(dict.fromkeys(account_ids)),
                "options": dict(options),
                "acknowledgement": acknowledgement,
            }
        )
    return normalized


def _batch_request_hash(runs: list[dict[str, Any]]) -> str:
    try:
        canonical = json.dumps(
            {"schema": 1, "runs": runs},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise RunError("runs содержит данные, которые нельзя представить как JSON") from error
    return hashlib.sha256(canonical).hexdigest()


def _action_secret_permissions(
    manifest: dict[str, Any], action: dict[str, Any]
) -> list[str]:
    """Resolve the exact action grant, falling back only for legacy manifests."""
    if "permissions" in action:
        action_permissions = action.get("permissions")
        if not isinstance(action_permissions, dict) or not isinstance(
            action_permissions.get("secrets"), list
        ):
            raise RunError("action.permissions.secrets имеет некорректный формат")
        return list(action_permissions["secrets"])
    legacy_permissions = manifest.get("permissions", {})
    legacy_secrets = legacy_permissions.get("secrets")
    if not isinstance(legacy_secrets, list):
        raise RunError("permissions.secrets имеет некорректный формат")
    return list(legacy_secrets)


def _action_resource_requirements(
    action: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """Resolve declarative preflight requirements; absence is the legacy fallback."""
    resources = action.get("resources")
    if resources is None:
        return [], []
    if not isinstance(resources, dict):
        raise RunError("action.resources имеет некорректный формат")
    account = resources.get("account")
    settings = resources.get("settings")
    if (
        not isinstance(account, list)
        or any(not isinstance(item, str) for item in account)
        or not isinstance(settings, list)
        or any(not isinstance(item, str) for item in settings)
    ):
        raise RunError("action.resources имеет некорректный формат")
    return list(account), list(settings)


def _action_referral_requirements(
    action: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[str], list[str]]:
    referral = action.get("referral")
    if referral is None:
        return None, [], []
    if not isinstance(referral, dict) or referral.get("mode") != "project_runtime":
        raise RunError("action.referral имеет некорректный формат")
    permissions = referral.get("permissions", {})
    resources = referral.get("resources", {})
    secrets = permissions.get("secrets") if isinstance(permissions, dict) else None
    account = resources.get("account") if isinstance(resources, dict) else None
    if not isinstance(secrets, list) or not isinstance(account, list):
        raise RunError("action.referral grants/resources имеют некорректный формат")
    return referral, list(secrets), list(account)


def _strict_json_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    return type(left) is type(right) and left == right


def _finite_schema_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        numeric = float(value)
    except (OverflowError, ValueError):
        return None
    return numeric if math.isfinite(numeric) else None


def validate_run_options(schema: Any, options: Any) -> dict[str, Any]:
    """Validate the closed, primitive JSON-schema subset rendered by the Hub UI."""
    if not isinstance(schema, dict) or schema.get("type", "object") != "object":
        raise RunError("Схема options плагина некорректна")
    if not isinstance(options, dict) or any(not isinstance(key, str) for key in options):
        raise RunError("options должен быть JSON-объектом со строковыми ключами")
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if (
        not isinstance(properties, dict)
        or any(not isinstance(key, str) or not isinstance(field, dict) for key, field in properties.items())
        or not isinstance(required, list)
        or any(not isinstance(key, str) for key in required)
        or len(required) != len(set(required))
        or any(key not in properties for key in required)
    ):
        raise RunError("Схема options плагина некорректна")

    unknown = sorted(set(options) - set(properties))
    if unknown:
        raise RunError(f"options содержит неизвестное поле: {unknown[0]}")
    missing = [key for key in required if key not in options]
    if missing:
        raise RunError(f"Не заполнено обязательное поле options: {missing[0]}")

    for key, value in options.items():
        field = properties[key]
        field_type = field.get("type", "string")
        if field_type == "boolean":
            valid_type = isinstance(value, bool)
        elif field_type == "integer":
            valid_type = (
                isinstance(value, int)
                and not isinstance(value, bool)
                and _finite_schema_number(value) is not None
            )
        elif field_type == "number":
            valid_type = _finite_schema_number(value) is not None
        elif field_type == "string":
            valid_type = isinstance(value, str)
        elif field_type == "null":
            valid_type = value is None
        else:
            raise RunError("Схема options плагина содержит неподдерживаемый type")
        if not valid_type:
            raise RunError(f"Поле options.{key} имеет неверный тип")

        if "enum" in field:
            choices = field["enum"]
            if not isinstance(choices, list) or not choices:
                raise RunError("Схема options плагина содержит некорректный enum")
            if not any(_strict_json_equal(value, choice) for choice in choices):
                raise RunError(f"Поле options.{key} содержит недопустимое значение")

        if field_type in {"integer", "number"}:
            numeric = Decimal(str(value))
            for boundary_key, comparison, label in (
                ("minimum", lambda item: numeric < item, "меньше minimum"),
                ("maximum", lambda item: numeric > item, "больше maximum"),
            ):
                if boundary_key not in field:
                    continue
                boundary = field[boundary_key]
                if _finite_schema_number(boundary) is None:
                    raise RunError("Схема options плагина содержит некорректную границу")
                if comparison(Decimal(str(boundary))):
                    raise RunError(f"Поле options.{key} {label}")
            if "multipleOf" in field:
                multiple = _finite_schema_number(field["multipleOf"])
                if multiple is None or multiple <= 0:
                    raise RunError("Схема options плагина содержит некорректный multipleOf")
                try:
                    quotient = Decimal(str(value)) / Decimal(str(field["multipleOf"]))
                except (InvalidOperation, ZeroDivisionError):
                    raise RunError("Схема options плагина содержит некорректный multipleOf")
                if quotient != quotient.to_integral_value():
                    raise RunError(f"Поле options.{key} не кратно multipleOf")

        if field_type == "string":
            for boundary_key, comparison, label in (
                ("minLength", lambda length, boundary: length < boundary, "короче minLength"),
                ("maxLength", lambda length, boundary: length > boundary, "длиннее maxLength"),
            ):
                if boundary_key not in field:
                    continue
                boundary = field[boundary_key]
                if (
                    not isinstance(boundary, int)
                    or isinstance(boundary, bool)
                    or not 0 <= boundary <= 16_000
                ):
                    raise RunError("Схема options плагина содержит некорректную длину")
                if comparison(len(value), boundary):
                    raise RunError(f"Поле options.{key} {label}")

    range_members: dict[str, list[tuple[str, str]]] = {}
    for key, field in properties.items():
        ui = field.get("x-ui")
        if not isinstance(ui, dict) or ui.get("control") != "dual_range":
            continue
        descriptor = ui.get("range")
        if (
            not isinstance(descriptor, dict)
            or not isinstance(descriptor.get("id"), str)
            or descriptor.get("role") not in {"from", "to"}
        ):
            raise RunError("Схема options плагина содержит некорректный dual_range")
        range_members.setdefault(descriptor["id"], []).append((descriptor["role"], key))
    for range_id, members in range_members.items():
        if len(members) != 2 or {role for role, _ in members} != {"from", "to"}:
            raise RunError(f"Схема options плагина содержит неполный dual_range {range_id}")
        from_key = next(key for role, key in members if role == "from")
        to_key = next(key for role, key in members if role == "to")
        supplied = {key for key in (from_key, to_key) if key in options}
        if supplied and supplied != {from_key, to_key}:
            raise RunError(f"Диапазон options.{range_id} требует значения from и to")
        if supplied and Decimal(str(options[from_key])) > Decimal(str(options[to_key])):
            raise RunError(f"Диапазон options.{range_id}: from больше to")

    return dict(options)


def _output_contract(value: Any) -> dict[str, Any] | None:
    """Decode and defensively re-check a snapshotted renderer contract."""
    if isinstance(value, str):
        try:
            value = json.loads(value or "{}")
        except (TypeError, json.JSONDecodeError):
            return None
    if not isinstance(value, dict) or not value:
        return None
    if set(value) != {"mode", "title", "primary_kind", "columns"}:
        return None
    title = value.get("title")
    primary_kind = value.get("primary_kind")
    columns = value.get("columns")
    if (
        value.get("mode") != _OUTPUT_MODE
        or not isinstance(title, str)
        or title != title.strip()
        or not 1 <= len(title) <= 120
        or not isinstance(primary_kind, str)
        or not _OUTPUT_KIND_RE.fullmatch(primary_kind)
        or not isinstance(columns, list)
        or not 1 <= len(columns) <= _MAX_OUTPUT_COLUMNS
    ):
        return None
    keys: set[str] = set()
    aggregate_count = 0
    for column in columns:
        if (
            not isinstance(column, dict)
            or not {"key", "title", "type"}.issubset(column)
            or not set(column).issubset({"key", "title", "type", "aggregate"})
        ):
            return None
        key = column.get("key")
        column_title = column.get("title")
        column_type = column.get("type")
        aggregate = column.get("aggregate")
        if (
            not isinstance(key, str)
            or not _OUTPUT_COLUMN_RE.fullmatch(key)
            or key in keys
            or not isinstance(column_title, str)
            or column_title != column_title.strip()
            or not 1 <= len(column_title) <= 100
            or column_type not in _OUTPUT_TYPES
        ):
            return None
        keys.add(key)
        if "aggregate" in column:
            if aggregate not in _OUTPUT_AGGREGATES or column_type not in _OUTPUT_NUMERIC_TYPES:
                return None
            aggregate_count += 1
    if aggregate_count > _MAX_OUTPUT_AGGREGATES:
        return None
    return json.loads(json.dumps(value, ensure_ascii=False))


def _validate_primary_output_result(
    output: dict[str, Any],
    data: dict[str, Any],
    *,
    account_id: str | None,
    title: str,
) -> dict[str, Any]:
    if account_id is None:
        raise ValueError("declared account_table result requires account_id")
    if not title.strip():
        raise ValueError("declared account_table result requires title")
    status = data.get("status", "succeeded")
    if status not in _OUTPUT_RESULT_STATUSES:
        raise ValueError("invalid declared account_table result status")
    payload = data.get("payload", {})
    if not isinstance(payload, dict):
        raise ValueError("declared account_table result payload must be an object")
    for column in output["columns"]:
        key = column["key"]
        if key not in payload or payload[key] is None:
            continue
        value = payload[key]
        column_type = column["type"]
        if not _output_value_has_type(value, column_type):
            raise ValueError(
                f"invalid declared account_table value for column {key}"
            )
    return payload


def _output_value_has_type(value: Any, column_type: str) -> bool:
    if column_type == "string":
        return isinstance(value, str) and len(value) <= 4_096
    if column_type == "boolean":
        return isinstance(value, bool)
    if column_type == "integer":
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and abs(value) <= _JS_SAFE_INTEGER
        )
    if column_type == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return False
        try:
            return math.isfinite(float(value))
        except (OverflowError, ValueError):
            return False
    if column_type == "decimal_string":
        if (
            not isinstance(value, str)
            or len(value) > 128
            or _DECIMAL_STRING_RE.fullmatch(value) is None
        ):
            return False
        try:
            return Decimal(value).is_finite()
        except InvalidOperation:
            return False
    return False


class Redactor:
    def __init__(self, secrets: Iterable[str] = ()):
        self._secrets = sorted(
            {secret for secret in secrets if isinstance(secret, str) and len(secret) >= 4},
            key=len,
            reverse=True,
        )

    def register(self, secret: str) -> None:
        if not isinstance(secret, str) or not 4 <= len(secret) <= 4096:
            raise ValueError("invalid runtime secret guard")
        if secret not in self._secrets:
            self._secrets.append(secret)
            self._secrets.sort(key=len, reverse=True)

    def text(self, value: Any) -> str:
        clean = str(value)
        for secret in self._secrets:
            clean = clean.replace(secret, "[REDACTED]")
        clean = _COOKIE_HEADER_RE.sub(
            lambda match: f"{match.group('name')}: [REDACTED_COOKIE]", clean
        )
        clean = _AUTHORIZATION_RE.sub(
            lambda match: f"{match.group('name')}: [REDACTED_AUTHORIZATION]", clean
        )
        clean = _KEY_RE.sub("[REDACTED_KEY]", clean)
        clean = _JWT_RE.sub("[REDACTED_TOKEN]", clean)
        clean = _KNOWN_TOKEN_RE.sub("[REDACTED_TOKEN]", clean)
        clean = _PROXY_RE.sub("[REDACTED_PROXY]", clean)
        clean = _EMAIL_RE.sub("[REDACTED_EMAIL]", clean)
        clean = _HIGH_ENTROPY_TOKEN_RE.sub("[REDACTED_TOKEN]", clean)

        def redact_assignment(match: re.Match[str]) -> str:
            value = match.group("value")
            if value.strip('"\'').startswith("[REDACTED"):
                return match.group(0)
            quote = value[0] if value[:1] in {'"', "'"} else ""
            return f"{match.group('prefix')}{quote}[REDACTED]{quote}"

        clean = _SECRET_ASSIGNMENT_RE.sub(redact_assignment, clean)
        return clean[:16_000]

    def value(self, value: Any, depth: int = 0) -> Any:
        if depth > 8:
            return "[TRUNCATED]"
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            clean: dict[str, Any] = {}
            for key, item in list(value.items())[:200]:
                safe_key = self.text(key)
                normalized_key = re.sub(
                    r"[^a-z0-9]+",
                    "_",
                    re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", safe_key).lower(),
                ).strip("_")
                secret_field = _SECRET_FIELD_RE.search(normalized_key) is not None
                clean[safe_key] = (
                    "[REDACTED]"
                    if secret_field and item is not None and not isinstance(item, bool)
                    else self.value(item, depth + 1)
                )
            return clean
        if isinstance(value, list):
            return [self.value(item, depth + 1) for item in value[:500]]
        if isinstance(value, float) and not math.isfinite(value):
            return "[NON_FINITE_NUMBER]"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return self.text(value)


def _collect_secret_values(
    accounts: list[dict[str, Any]],
    settings: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
) -> list[str]:
    public = {
        "id",
        "label",
        "evm_address",
        "referrer_account_id",
        "referral_depth",
    }
    values = [
        value
        for account in accounts
        for key, value in account.items()
        if key not in public and isinstance(value, str)
    ]
    values.extend(
        value for value in (settings or {}).values() if isinstance(value, str)
    )
    # Options are normally non-secret and /3 rejects manually supplied referral
    # codes. Keep this defense for compatible legacy manifests and any other
    # secret-named flat string option without exposing or persisting options.
    for key, value in (options or {}).items():
        normalized_key = re.sub(
            r"[^a-z0-9]+",
            "_",
            re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(key)).lower(),
        ).strip("_")
        if (
            isinstance(value, str)
            and _SECRET_FIELD_RE.search(normalized_key) is not None
        ):
            values.append(value)
    return values


class RunManager:
    def __init__(
        self,
        database: Database,
        paths: HubPaths,
        plugins: PluginManager,
        vault: Vault,
        max_concurrent: int = 4,
    ):
        self.database = database
        self.paths = paths
        self.plugins = plugins
        self.vault = vault
        self._slots = threading.BoundedSemaphore(max(1, max_concurrent))
        self._processes: dict[str, subprocess.Popen[str]] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._manifests: dict[str, dict[str, Any]] = {}
        self._cancel_requests: set[str] = set()
        self._force_stop_requests: set[str] = set()
        self._force_killed: set[str] = set()
        self._shutdown_requests: set[str] = set()
        self._shutting_down = False
        self._lock = threading.RLock()
        self._recover_orphans()

    def _recover_orphans(self) -> None:
        now = utc_now()
        with self.database.transaction() as connection:
            # `needs_attention` used to retain account leases until an operator
            # completed a separate confirmation flow.  It is a historical
            # terminal outcome now: preserve its events/error/account stage,
            # but make the run retryable immediately.
            connection.execute(
                "INSERT INTO run_events(run_id,created_at,level,event_type,message,data_json) "
                "SELECT id,?,'info','attention_released',"
                "'Старая защитная блокировка снята; журнал и результаты сохранены',"
                "'{\"original_status\":\"needs_attention\"}' FROM runs "
                "WHERE status='needs_attention'",
                (now,),
            )
            connection.execute(
                "UPDATE run_account_states SET status='failed',updated_at=? "
                "WHERE status='needs_attention'",
                (now,),
            )
            connection.execute(
                "UPDATE runs SET status='failed',finished_at=COALESCE(finished_at,?),"
                "error=COALESCE(error,'external_state_unknown'),pid=NULL "
                "WHERE status='needs_attention'",
                (now,),
            )
            connection.execute(
                "UPDATE runs SET status='failed',finished_at=?,"
                "error='Hub was restarted during this run',pid=NULL "
                "WHERE status IN ('queued','starting','running','cancelling')",
                (now,),
            )
            connection.execute(
                "UPDATE run_account_states SET status='failed',stage='hub_restarted',"
                "last_message='Hub был перезапущен во время выполнения',updated_at=? "
                "WHERE status IN ('queued','running')",
                (now,),
            )
            connection.execute(
                "DELETE FROM account_leases"
            )
            connection.execute(
                "DELETE FROM run_account_pins"
            )

    def start(
        self,
        plugin_id: str,
        action_id: str,
        account_ids: list[str],
        options: dict[str, Any] | None = None,
        acknowledgement: str = "",
    ) -> dict[str, Any]:
        with self._lock:
            if self._shutting_down:
                raise RunError("Soft Hub завершает работу и не принимает новые запуски")
        module = self.plugins.get(plugin_id)
        account_ids = list(dict.fromkeys(str(item) for item in account_ids))
        prepared = self._preflight_run(
            module,
            action_id,
            account_ids,
            options,
            acknowledgement,
            batch=False,
        )
        self._initialize_run(prepared)

        with self._lock, self.plugins.admission_guard():
            if self._shutting_down:
                raise RunError("Soft Hub завершает работу и не принимает новые запуски")
            current_module = self.plugins.get(plugin_id)
            if not self._same_module_snapshot(module, current_module):
                raise RunError("Плагин был изменён или удалён во время подготовки запуска")
            with self.database.transaction() as connection:
                self._insert_prepared_run(connection, prepared)
            self._register_and_start([prepared])
        return self.get(prepared["run_id"]) or {}

    def start_batch(
        self, idempotency_key: Any, run_requests: Any
    ) -> dict[str, Any]:
        normalized_key = _normalize_idempotency_key(idempotency_key)
        normalized_requests = _normalize_batch_specs(run_requests)
        request_sha256 = _batch_request_hash(normalized_requests)

        with self._lock:
            if self._shutting_down:
                raise RunError("Soft Hub завершает работу и не принимает новые запуски")
            replay = self._load_batch(normalized_key, request_sha256)
            if replay is not None:
                return {"runs": self._runs_by_ids(replay), "replayed": True}

            with self.plugins.admission_guard():
                prepared_runs: list[dict[str, Any]] = []
                for request in normalized_requests:
                    module = self.plugins.get(request["module_id"])
                    prepared = self._preflight_run(
                        module,
                        request["action_id"],
                        request["account_ids"],
                        request["options"],
                        request["acknowledgement"],
                        batch=True,
                    )
                    self._initialize_run(prepared)
                    prepared_runs.append(prepared)

                replayed_ids: list[str] | None = None
                with self.database.transaction() as connection:
                    existing = connection.execute(
                        "SELECT request_sha256 FROM run_batches WHERE idempotency_key=?",
                        (normalized_key,),
                    ).fetchone()
                    if existing:
                        if not hmac.compare_digest(existing["request_sha256"], request_sha256):
                            raise IdempotencyConflictError(
                                "idempotency_key уже использован для другой пачки"
                            )
                        replayed_ids = [
                            row["run_id"]
                            for row in connection.execute(
                                "SELECT run_id FROM run_batch_items WHERE idempotency_key=? "
                                "ORDER BY ordinal",
                                (normalized_key,),
                            ).fetchall()
                        ]
                    else:
                        for prepared in prepared_runs:
                            self._insert_prepared_run(connection, prepared)
                        connection.execute(
                            "INSERT INTO run_batches(idempotency_key,request_sha256,created_at) "
                            "VALUES (?,?,?)",
                            (normalized_key, request_sha256, utc_now()),
                        )
                        connection.executemany(
                            "INSERT INTO run_batch_items(idempotency_key,ordinal,run_id) "
                            "VALUES (?,?,?)",
                            [
                                (normalized_key, ordinal, prepared["run_id"])
                                for ordinal, prepared in enumerate(prepared_runs)
                            ],
                        )

                if replayed_ids is not None:
                    if not replayed_ids:
                        raise RunError("Идемпотентная запись пачки повреждена")
                    return {"runs": self._runs_by_ids(replayed_ids), "replayed": True}

                # No worker can observe a run until every run and every write lease
                # has committed successfully as one batch admission transaction.
                self._register_and_start(prepared_runs)
                return {
                    "runs": self._runs_by_ids(
                        [prepared["run_id"] for prepared in prepared_runs]
                    ),
                    "replayed": False,
                }

    def _preflight_run(
        self,
        module: dict[str, Any] | None,
        action_id: str,
        account_ids: list[str],
        options: dict[str, Any] | None,
        acknowledgement: str,
        *,
        batch: bool,
    ) -> dict[str, Any]:
        if not module or not module["enabled"]:
            raise RunError("Плагин не найден или выключен")
        if module["health"] != "ready":
            raise RunError("Сначала подготовьте окружение плагина")
        manifest = module["manifest"]
        requirements = manifest["runtime"].get("requirements")
        python = Path(sys.executable)
        if requirements:
            plugin_path = Path(module["active_path"])
            plugin_python = self.plugins.python_for(plugin_path, requirements)
            if plugin_python is None:
                self.plugins.mark_runtime_needs_setup(
                    str(module["id"]), str(module["active_path"])
                )
                raise RunError("Сначала подготовьте окружение плагина")
            python = plugin_python
        action = next((item for item in manifest["actions"] if item["id"] == action_id), None)
        if not action:
            raise RunError("Действие не объявлено плагином")
        if batch and action["risk"] == "mainnet_write":
            raise RunError("Mainnet-действия нельзя запускать пачкой")
        if action["account_mode"] == "one_or_more" and not account_ids:
            raise RunError("Выберите минимум один аккаунт")
        if action["account_mode"] == "none" and account_ids:
            raise RunError("Это действие не принимает аккаунты")
        phrase = str(action.get("confirmation_phrase", ""))
        if phrase and acknowledgement != phrase:
            raise RunError("Не введена обязательная фраза подтверждения")
        if action["risk"] == "testnet_write" and acknowledgement != "TESTNET":
            raise RunError("Для testnet-действия требуется подтверждение TESTNET")

        if options is not None and not isinstance(options, dict):
            raise RunError("options должен быть JSON-объектом")
        run_options = dict(options or {})
        option_properties = action.get("options", {}).get("properties", {})
        concurrency_field = option_properties.get(_ACCOUNT_CONCURRENCY_OPTION)
        if isinstance(concurrency_field, dict) and _ACCOUNT_CONCURRENCY_OPTION not in run_options:
            run_options[_ACCOUNT_CONCURRENCY_OPTION] = concurrency_field.get("default", 1)
        testnet_acknowledgement = option_properties.get("acknowledge_testnet_transactions")
        if (
            action["risk"] == "testnet_write"
            and isinstance(testnet_acknowledgement, dict)
            and testnet_acknowledgement.get("type") == "boolean"
        ):
            # The Hub confirmation is the single trusted testnet gate. Legacy
            # adapters still consume this option, so derive it server-side only
            # after the acknowledgement above has been validated.
            run_options["acknowledge_testnet_transactions"] = True
        run_options = validate_run_options(action.get("options", {}), run_options)
        account_concurrency = 1
        if action["account_mode"] == "one_or_more" and isinstance(concurrency_field, dict):
            raw_concurrency = run_options.get(_ACCOUNT_CONCURRENCY_OPTION, 1)
            if (
                not isinstance(raw_concurrency, int)
                or isinstance(raw_concurrency, bool)
                or not 1 <= raw_concurrency <= _MAX_ACCOUNT_CONCURRENCY
            ):
                raise RunError("account_concurrency должен быть целым числом 1..20")
            account_concurrency = min(raw_concurrency, max(1, len(account_ids)))
            run_options[_ACCOUNT_CONCURRENCY_OPTION] = account_concurrency
        secret_permissions = _action_secret_permissions(manifest, action)
        if {"referral_code", "referrer_code"} & set(secret_permissions):
            raise RunError(
                "Плагин использует устаревший referral contract 0.6.4; "
                "установите версию с action.referral project_runtime"
            )
        account_resources, setting_resources = _action_resource_requirements(action)
        referral_config, parent_secret_permissions, parent_account_resources = (
            _action_referral_requirements(action)
        )
        self.vault.validate_runner_access(
            account_ids,
            secret_permissions,
            account_resources,
            setting_resources,
        )
        referral_plan: dict[str, Any] | None = None
        if referral_config is not None:
            referral_plan = self.vault.referral_plan(
                account_ids,
                parent_required=bool(referral_config.get("parent_required")),
            )
            self.vault.validate_runner_access(
                referral_plan["parent_ids"],
                parent_secret_permissions,
                parent_account_resources,
                (),
            )
        return {
            "module": module,
            "action": action,
            "python": python,
            "account_ids": list(account_ids),
            "secret_permissions": secret_permissions,
            "account_resources": account_resources,
            "setting_resources": setting_resources,
            "options": run_options,
            "account_concurrency": account_concurrency,
            "referral_config": referral_config,
            "referral_plan": referral_plan,
            "parent_secret_permissions": parent_secret_permissions,
            "parent_account_resources": parent_account_resources,
        }

    def _initialize_run(self, prepared: dict[str, Any]) -> None:
        run_id = str(uuid.uuid4())
        prepared["run_id"] = run_id
        prepared["requested_at"] = utc_now()
        prepared["thread"] = threading.Thread(
            target=self._execute,
            name=f"soft-hub-run-{run_id[:8]}",
            args=(
                run_id,
                prepared["module"],
                prepared["action"],
                prepared["python"],
                prepared["account_ids"],
                prepared["secret_permissions"],
                prepared["account_resources"],
                prepared["setting_resources"],
                prepared["options"],
                prepared["account_concurrency"],
                prepared["referral_config"],
                prepared["referral_plan"],
                prepared["parent_secret_permissions"],
                prepared["parent_account_resources"],
            ),
            daemon=True,
        )

    @staticmethod
    def _same_module_snapshot(
        expected: dict[str, Any] | None, current: dict[str, Any] | None
    ) -> bool:
        return bool(
            expected
            and current
            and current["enabled"]
            and current["health"] == "ready"
            and current["version"] == expected["version"]
            and current["active_path"] == expected["active_path"]
        )

    def _insert_prepared_run(self, connection: Any, prepared: dict[str, Any]) -> None:
        module = prepared["module"]
        action = prepared["action"]
        run_id = prepared["run_id"]
        output = _output_contract(action.get("output")) or {}
        connection.execute(
            "INSERT INTO runs(id,module_id,module_version,action_id,status,progress,account_count,"
            "account_concurrency,requested_at,output_schema_json,catalog_sections_json) "
            "VALUES (?,?,?,?, 'queued',0,?,?,?,?,?)",
            (
                run_id,
                module["id"],
                module["version"],
                action["id"],
                len(prepared["account_ids"]),
                prepared["account_concurrency"],
                prepared["requested_at"],
                json.dumps(output, ensure_ascii=False, separators=(",", ":")),
                json.dumps(
                    catalog_sections(module["manifest"]),
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            ),
        )
        for account_id in prepared["account_ids"]:
            account = connection.execute(
                "SELECT label,evm_address FROM accounts WHERE id=?",
                (account_id,),
            ).fetchone()
            if not account:
                raise RunError("Один из выбранных аккаунтов больше не существует")
            connection.execute(
                "INSERT INTO run_account_states("
                "run_id,account_id,account_label,account_address,status,stage,progress,"
                "last_message,updated_at"
                ") VALUES (?,?,?,?,'queued','queued',0,'Ожидает запуска',?)",
                (
                    run_id,
                    account_id,
                    account["label"],
                    account["evm_address"],
                    prepared["requested_at"],
                ),
            )
            connection.execute(
                "INSERT INTO run_account_pins(run_id,account_id,role) VALUES (?,?,?)",
                (run_id, account_id, "target"),
            )
        referral_plan = prepared.get("referral_plan") or {}
        for parent_id in referral_plan.get("parent_ids", []):
            connection.execute(
                "INSERT INTO run_account_pins(run_id,account_id,role) VALUES (?,?,?)",
                (run_id, parent_id, "referral_parent"),
            )
        if action["risk"] != "read":
            lease_scopes = list(module["manifest"]["permissions"]["chains"])
            if action["risk"] == "external_write":
                # Non-financial services have no chain ID, but they still need
                # per-account serialization and ambiguity holds. Scope zero is
                # internal-only; manifest chain IDs remain strictly positive.
                lease_scopes = [_EXTERNAL_WRITE_LEASE_SCOPE]
            self._acquire_leases(
                connection,
                run_id,
                prepared["account_ids"],
                lease_scopes,
            )
        referral_config = prepared.get("referral_config") or {}
        if referral_config.get("parent_access") == "exclusive":
            self._acquire_leases(
                connection,
                run_id,
                list(referral_plan.get("parent_ids", [])),
                [_REFERRAL_PARENT_LEASE_SCOPE],
            )

    def _register_and_start(self, prepared_runs: list[dict[str, Any]]) -> None:
        for prepared in prepared_runs:
            run_id = prepared["run_id"]
            module = prepared["module"]
            action = prepared["action"]
            self._manifests[run_id] = {
                "manifest": module["manifest"],
                "action": action,
            }
            self._threads[run_id] = prepared["thread"]
        for prepared in prepared_runs:
            prepared["thread"].start()

    def _load_batch(self, idempotency_key: str, request_sha256: str) -> list[str] | None:
        row = self.database.one(
            "SELECT request_sha256 FROM run_batches WHERE idempotency_key=?",
            (idempotency_key,),
        )
        if not row:
            return None
        if not hmac.compare_digest(row["request_sha256"], request_sha256):
            raise IdempotencyConflictError(
                "idempotency_key уже использован для другой пачки"
            )
        run_ids = [
            item["run_id"]
            for item in self.database.all(
                "SELECT run_id FROM run_batch_items WHERE idempotency_key=? ORDER BY ordinal",
                (idempotency_key,),
            )
        ]
        if not run_ids:
            raise RunError("Идемпотентная запись пачки повреждена")
        return run_ids

    def _runs_by_ids(self, run_ids: list[str]) -> list[dict[str, Any]]:
        runs: list[dict[str, Any]] = []
        for run_id in run_ids:
            run = self.get(run_id)
            if not run:
                raise RunError("Идемпотентная запись пачки повреждена")
            runs.append(run)
        return runs

    def _acquire_leases(
        self,
        connection: Any,
        run_id: str,
        account_ids: list[str],
        chains: list[int],
    ) -> None:
        now = datetime.now(UTC)
        connection.execute("DELETE FROM account_leases WHERE expires_at < ?", (now.isoformat(),))
        expires = (now + timedelta(minutes=30)).isoformat()
        for chain_id in chains:
            for account_id in account_ids:
                try:
                    connection.execute(
                        "INSERT INTO account_leases(chain_id,account_id,run_id,acquired_at,expires_at) "
                        "VALUES (?,?,?,?,?)",
                        (chain_id, account_id, run_id, now.isoformat(), expires),
                    )
                except Exception as error:
                    scope = (
                        "external service"
                        if chain_id == _EXTERNAL_WRITE_LEASE_SCOPE
                        else "referral parent service"
                        if chain_id == _REFERRAL_PARENT_LEASE_SCOPE
                        else f"chainId={chain_id}"
                    )
                    raise RunError(
                        f"Аккаунт уже занят другой задачей ({scope})"
                    ) from error

    def _touch_leases(self, run_id: str) -> None:
        expires = (datetime.now(UTC) + timedelta(minutes=30)).isoformat()
        self.database.execute("UPDATE account_leases SET expires_at=? WHERE run_id=?", (expires, run_id))

    def _release_leases(self, run_id: str) -> None:
        self.database.execute("DELETE FROM account_leases WHERE run_id=?", (run_id,))

    def _release_pins(self, run_id: str) -> None:
        self.database.execute("DELETE FROM run_account_pins WHERE run_id=?", (run_id,))

    def _finish_run(
        self,
        run_id: str,
        *,
        status: str,
        progress: float,
        summary: dict[str, Any] | None,
        error: str | None,
    ) -> None:
        """Commit a terminal run state and its unresolved account projections."""
        now = utc_now()
        with self.database.transaction() as connection:
            self._recover_legacy_account_summaries(connection, run_id, now)
            account_progress = connection.execute(
                "SELECT COUNT(*) AS count,AVG(progress) AS progress "
                "FROM run_account_states WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if account_progress and int(account_progress["count"]):
                # For account runs the persisted aggregate remains authoritative
                # at the terminal boundary too. A normal process exit must not
                # turn an early per-account failure into a cosmetic 100%.
                progress = float(account_progress["progress"] or 0.0)
            account_requires_attention = connection.execute(
                "SELECT 1 FROM run_account_states "
                "WHERE run_id=? AND status='needs_attention' LIMIT 1",
                (run_id,),
            ).fetchone()
            if status == "needs_attention" or account_requires_attention:
                # Keep the adapter's exact event/data as evidence, but do not
                # turn uncertainty into a persistent operational lock.
                status = "failed"
                error = error or "external_state_unknown"
                connection.execute(
                    "UPDATE run_account_states SET status='failed',updated_at=? "
                    "WHERE run_id=? AND status='needs_attention'",
                    (now, run_id),
                )
            if status == "cancelled":
                account_status = "cancelled"
                stage = "cancelled"
                message = "Запуск остановлен до получения итогового account_state"
            else:
                account_status = "unknown"
                stage = "unreported"
                message = (
                    "Плагин завершился без итогового account_state"
                    if status == "succeeded"
                    else "Запуск завершился с ошибкой без итогового account_state"
                )
            connection.execute(
                "UPDATE runs SET status=?,progress=?,finished_at=?,summary_json=?,error=?,pid=NULL "
                "WHERE id=?",
                (
                    status,
                    progress,
                    now,
                    json.dumps(summary or {}, ensure_ascii=False),
                    error,
                    run_id,
                ),
            )
            connection.execute(
                "UPDATE run_account_states SET status=?,stage=?,"
                "last_message=CASE WHEN status='queued' OR last_message='' "
                "THEN ? ELSE last_message END,updated_at=? "
                "WHERE run_id=? AND status IN ('queued','running')",
                (account_status, stage, message, now, run_id),
            )
            # A terminal status and lease release are one database boundary.
            # The UI may offer an immediate retry as soon as it observes the
            # status, so there must never be a visible terminal-but-leased gap.
            connection.execute("DELETE FROM account_leases WHERE run_id=?", (run_id,))

    def _recover_legacy_account_summaries(
        self,
        connection: Any,
        run_id: str,
        now: str,
    ) -> None:
        """Recover old adapters that emitted a typed final result but no lifecycle event.

        This compatibility path deliberately ignores log wording. Only exact
        legacy first-party adapter versions whose code contract is known are eligible,
        and exactly one account-scoped `account_summary` must exist. New software
        must still emit an explicit terminal `account_state`.
        """
        run = connection.execute(
            "SELECT module_id,module_version,action_id FROM runs WHERE id=?",
            (run_id,),
        ).fetchone()
        if not run:
            return
        bridged_actions = _LEGACY_ACCOUNT_SUMMARY_BRIDGE.get(
            (str(run["module_id"]), str(run["module_version"]))
        )
        if not bridged_actions or str(run["action_id"]) not in bridged_actions:
            return
        placeholders = ",".join("?" for _ in _LEGACY_ACCOUNT_SUMMARY_STATUSES)
        rows = connection.execute(
            "SELECT s.account_id,MIN(x.status) AS status FROM run_account_states s "
            "JOIN results x ON x.run_id=s.run_id AND x.account_id=s.account_id "
            "WHERE s.run_id=? AND s.status IN ('queued','running') "
            "AND x.kind='account_summary' "
            "GROUP BY s.account_id HAVING COUNT(*)=1 "
            f"AND MIN(x.status) IN ({placeholders})",
            (run_id, *sorted(_LEGACY_ACCOUNT_SUMMARY_STATUSES)),
        ).fetchall()
        for row in rows:
            account_id = str(row["account_id"])
            status = str(row["status"])
            stage = _LEGACY_ACCOUNT_SUMMARY_STAGES[status]
            progress = None if status == "needs_attention" else 1.0
            stored_status = "failed" if status == "needs_attention" else status
            connection.execute(
                "UPDATE run_account_states SET status=?,stage=?,"
                "progress=CASE WHEN ? IS NULL THEN progress ELSE MAX(progress,?) END,"
                "last_message=CASE WHEN last_message='' THEN "
                "'Итог восстановлен из структурированного account_summary' "
                "ELSE last_message END,updated_at=? "
                "WHERE run_id=? AND account_id=? AND status IN ('queued','running')",
                (stored_status, stage, progress, progress, now, run_id, account_id),
            )
            self._insert_event(
                connection,
                run_id,
                now,
                "success" if stored_status == "succeeded" else "warning",
                "account_state",
                "Hub восстановил итог старого адаптера из структурированного account_summary",
                account_id,
                {
                    "status": stored_status,
                    "stage": stage,
                    "source": "legacy_account_summary",
                    **({"reported_status": status} if stored_status != status else {}),
                    **({"progress": progress} if progress is not None else {}),
                },
            )

    def _execute(
        self,
        run_id: str,
        module: dict[str, Any],
        action: dict[str, Any],
        python: Path,
        account_ids: list[str],
        secret_permissions: list[str],
        account_resources: list[str],
        setting_resources: list[str],
        options: dict[str, Any],
        account_concurrency: int,
        referral_config: dict[str, Any] | None,
        referral_plan: dict[str, Any] | None,
        parent_secret_permissions: list[str],
        parent_account_resources: list[str],
    ) -> None:
        terminal: str | None = None
        terminal_data: dict[str, Any] = {}
        accounts: list[dict[str, Any]] = []
        referral_parents: list[dict[str, Any]] = []
        settings: dict[str, str] = {}
        redactor = Redactor()
        process: subprocess.Popen[str] | None = None
        slot_acquired = False
        try:
            # A blocking acquire made queued runs deaf to Stop while every slot
            # was occupied. Poll with a short timeout so cancellation can finish
            # before secrets are decrypted or a plugin process can cause a side
            # effect. A write cancelled at this boundary is unambiguous and its
            # lease is safe to release.
            while not slot_acquired:
                if self._cancelled_before_process_start(run_id):
                    return
                slot_acquired = self._slots.acquire(timeout=0.1)
            if self._cancelled_before_process_start(run_id):
                return
            settings = self.vault.settings_for_runner(
                secret_permissions, setting_resources
            )
            if account_ids:
                # Queued workers retain only public account identifiers. Secret
                # payloads enter memory only after this worker owns an execution slot.
                accounts = self.vault.bundles_for_runner(
                    account_ids, secret_permissions, account_resources
                )
            if referral_plan and referral_plan.get("parent_ids"):
                referral_parents = self.vault.bundles_for_runner(
                    list(referral_plan["parent_ids"]),
                    parent_secret_permissions,
                    parent_account_resources,
                )
            if referral_plan is not None:
                links_by_child = {
                    str(link["child_account_id"]): link
                    for link in referral_plan.get("links", [])
                }
                for account in accounts:
                    link = links_by_child.get(str(account["id"]))
                    if link is None:
                        raise RunError(
                            "Referral plan не содержит выбранный target-аккаунт"
                        )
                    account["referrer_account_id"] = link.get("parent_account_id")
                    account["referral_depth"] = int(link.get("depth", 0))
            redactor = Redactor(
                _collect_secret_values(
                    [*accounts, *referral_parents], settings, options
                )
            )
            if self._cancelled_before_process_start(run_id):
                return
            plugin_path = Path(module["active_path"])
            manifest = module["manifest"]
            if manifest["runtime"].get("requirements") and not python.is_file():
                self.plugins.mark_runtime_needs_setup(
                    str(module["id"]), str(module["active_path"])
                )
                raise RunError("Окружение плагина больше не готово; подготовьте его заново")
            scratch = self.paths.runs / run_id / "scratch"
            scratch.mkdir(parents=True, exist_ok=False, mode=0o700)
            context = {
                "run_id": run_id,
                "plugin_id": module["id"],
                "plugin_version": module["version"],
                "action_id": action["id"],
                "options": options,
                "accounts": accounts,
                "settings": settings,
                "account_concurrency": account_concurrency,
                "referral_mode": (
                    str(referral_config.get("mode")) if referral_config else "none"
                ),
                "referrals": {
                    "mode": str(referral_config.get("mode")) if referral_config else "none",
                    "revision": str(referral_plan.get("revision", ""))
                    if referral_plan
                    else "",
                    "links": list(referral_plan.get("links", []))
                    if referral_plan
                    else [],
                    "parents": referral_parents,
                },
                "plugin_root": str(plugin_path),
                "scratch_dir": str(scratch),
            }
            command = [
                str(python),
                "-u",
                str(project_root() / "soft_hub" / "runtime" / "bootstrap.py"),
                str(plugin_path),
                manifest["runtime"]["entrypoint"],
            ]
            environment = self._safe_environment()
            popen_options: dict[str, Any] = {}
            if os.name == "nt":
                popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
            else:
                popen_options["start_new_session"] = True
            cancelled_before_spawn = False
            with self._lock:
                if run_id in self._cancel_requests:
                    cancelled_before_spawn = True
                else:
                    # Spawn and publication share the cancellation lock. Stop is
                    # therefore linearized either before process creation (safe
                    # cancelled) or after a real process exists (signal/ambiguity).
                    process = subprocess.Popen(
                        command,
                        cwd=scratch,
                        env=environment,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        bufsize=1,
                        shell=False,
                        **popen_options,
                    )
                    self._processes[run_id] = process
            if cancelled_before_spawn:
                self._cancelled_before_process_start(run_id)
                return
            assert process is not None
            self.database.execute(
                "UPDATE runs SET status=CASE WHEN status='cancelling' THEN 'cancelling' ELSE 'running' END,"
                "started_at=?,pid=? WHERE id=?",
                (utc_now(), process.pid, run_id),
            )
            assert process.stdin and process.stdout and process.stderr
            serialized = json.dumps(context, ensure_ascii=False, separators=(",", ":"))
            process.stdin.write(serialized + "\n")
            process.stdin.flush()
            process.stdin.close()
            context.clear()
            accounts.clear()
            referral_parents.clear()
            settings.clear()
            serialized = ""

            lines: queue.Queue[tuple[str, str | None]] = queue.Queue(maxsize=2_000)
            stdout_thread = threading.Thread(
                target=self._read_stream, args=("stdout", process.stdout, lines), daemon=True
            )
            stderr_thread = threading.Thread(
                target=self._read_stream, args=("stderr", process.stderr, lines), daemon=True
            )
            stdout_thread.start()
            stderr_thread.start()
            closed: set[str] = set()
            malformed = 0
            protected_secret_count = 0
            protected_secret_chars = 0
            output_lines = 0
            output_limited = False
            last_touch = time.monotonic()
            leader_exited_at: float | None = None
            pipes_forced = False
            while len(closed) < 2 or process.poll() is None:
                tick = time.monotonic()
                if tick - last_touch > 60:
                    self._touch_leases(run_id)
                    last_touch = tick
                if process.poll() is not None and len(closed) < 2:
                    if leader_exited_at is None:
                        leader_exited_at = tick
                    elif tick - leader_exited_at > 2 and not pipes_forced:
                        pipes_forced = True
                        self._signal_process(process, force=True)
                    elif tick - leader_exited_at > 4:
                        for stream in (process.stdout, process.stderr):
                            if stream is not None and not stream.closed:
                                try:
                                    stream.close()
                                except (OSError, ValueError):
                                    pass
                        break
                try:
                    source, line = lines.get(timeout=1)
                except queue.Empty:
                    continue
                if line is None:
                    closed.add(source)
                    continue
                output_lines += 1
                if output_lines > _MAX_RUN_OUTPUT_LINES:
                    if not output_limited:
                        output_limited = True
                        terminal = "failed"
                        terminal_data = {"reason": "output_limit_exceeded"}
                        self._event(
                            run_id,
                            "error",
                            "host",
                            "Плагин превысил лимит строк вывода и был остановлен",
                        )
                        if process.poll() is None:
                            self._signal_process(process, force=True)
                    continue
                if source == "stderr":
                    if line == _OVERSIZE_LINE:
                        self._event(
                            run_id,
                            "warning",
                            "stderr",
                            "Строка stderr превысила лимит 64 KB и была отброшена",
                        )
                        continue
                    if line.strip():
                        self._event(run_id, "warning", "stderr", redactor.text(line.strip()))
                    continue
                try:
                    if line == _OVERSIZE_LINE:
                        raise ValueError("oversize frame")
                    frame = json.loads(line)
                    if (
                        isinstance(frame, dict)
                        and frame.get("protocol") == "soft-hub-jsonl/1"
                        and frame.get("type") == "protect_secret"
                    ):
                        guard_data = frame.get("data")
                        if not isinstance(guard_data, dict) or set(guard_data) != {"value"}:
                            raise ValueError("invalid runtime secret guard")
                        guard_value = guard_data.get("value")
                        if not isinstance(guard_value, str) or not 4 <= len(guard_value) <= 4096:
                            raise ValueError("invalid runtime secret guard")
                        protected_secret_count += 1
                        protected_secret_chars += len(guard_value)
                        if protected_secret_count > 10_000 or protected_secret_chars > 2_000_000:
                            raise ValueError("runtime secret guard limit exceeded")
                        redactor.register(guard_value)
                        continue
                    if (
                        not isinstance(frame, dict)
                        or frame.get("protocol") != "soft-hub-jsonl/1"
                        or frame.get("type") not in _ALLOWED_EVENTS
                        or not isinstance(frame.get("data", {}), dict)
                    ):
                        raise ValueError("invalid frame")
                    terminal_candidate = self._handle_frame(run_id, module["id"], frame, redactor)
                    if terminal_candidate:
                        terminal = terminal_candidate
                        terminal_data = redactor.value(frame.get("data", {}))
                except (json.JSONDecodeError, ValueError, TypeError):
                    malformed += 1
                    self._event(run_id, "warning", "protocol", "Плагин отправил некорректный protocol frame")
                    if malformed >= 3 and process.poll() is None:
                        self._signal_process(process, force=True)
                        terminal = "failed"
                        terminal_data = {"reason": "protocol_error"}

            exit_code = process.wait(timeout=10)
            with self._lock:
                cancellation_requested = run_id in self._cancel_requests
                force_killed = run_id in self._force_killed
            if force_killed:
                status = "cancelled"
                progress = self._current_progress(run_id)
                error = "process_force_killed"
            elif terminal == "completed" and exit_code == 0:
                status = "succeeded"
                progress = 1.0
                error = None
            elif terminal == "cancelled" or exit_code == 130:
                status = "cancelled"
                progress = self._current_progress(run_id)
                error = None
            else:
                status = (
                    "cancelled"
                    if cancellation_requested
                    else "failed"
                )
                progress = self._current_progress(run_id)
                error = redactor.text(
                    "process_force_killed"
                    if force_killed
                    else terminal_data.get("reason")
                    or "Плагин завершился без успешного terminal event"
                )
            self._finish_run(
                run_id,
                status=status,
                progress=progress,
                summary=terminal_data.get("summary", {}),
                error=error,
            )
        except BaseException as error:
            message = redactor.text(error)
            self._event(run_id, "error", "host", message)
            with self._lock:
                cancellation_requested = run_id in self._cancel_requests
                force_killed = run_id in self._force_killed
            failure_status = (
                "cancelled"
                if cancellation_requested
                else "failed"
            )
            failure_error = (
                "process_force_killed"
                if force_killed
                else None
                if cancellation_requested
                else message
            )
            self._finish_run(
                run_id,
                status=failure_status,
                progress=self._current_progress(run_id),
                summary={},
                error=failure_error,
            )
            if process and process.poll() is None:
                self._signal_process(process, force=True)
        finally:
            accounts.clear()
            referral_parents.clear()
            settings.clear()
            if process is not None:
                if process.poll() is None:
                    with self._lock:
                        self._force_killed.add(run_id)
                    self._signal_process(process, force=True)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        try:
                            stream.close()
                        except (OSError, ValueError):
                            pass
                if os.name != "nt":
                    self._signal_process(process, force=True)
            with self._lock:
                self._processes.pop(run_id, None)
            try:
                self._release_leases(run_id)
            finally:
                self._release_pins(run_id)
                if slot_acquired:
                    self._slots.release()
                # Absence from _threads is the public completion boundary used
                # by shutdown/tests. Publish it only after leases and capacity
                # are finalized so callers cannot tear down the database early.
                with self._lock:
                    self._threads.pop(run_id, None)
                    self._manifests.pop(run_id, None)
                    self._cancel_requests.discard(run_id)
                    self._force_stop_requests.discard(run_id)
                    self._force_killed.discard(run_id)
                    self._shutdown_requests.discard(run_id)

    def _cancelled_before_process_start(self, run_id: str) -> bool:
        with self._lock:
            cancelled = run_id in self._cancel_requests
        if not cancelled:
            return False
        self._event(run_id, "info", "cancelled", "Запуск отменён до старта процесса")
        self._finish_run(
            run_id,
            status="cancelled",
            progress=self._current_progress(run_id),
            summary={},
            error=None,
        )
        return True

    @staticmethod
    def _read_stream(source: str, stream: Any, output: queue.Queue[tuple[str, str | None]]) -> None:
        try:
            while True:
                line = stream.readline(_MAX_PROTOCOL_LINE + 1)
                if not line:
                    break
                oversized = len(line) > _MAX_PROTOCOL_LINE
                if oversized:
                    while line and not line.endswith(("\n", "\r")):
                        line = stream.readline(_MAX_PROTOCOL_LINE + 1)
                    output.put((source, _OVERSIZE_LINE))
                else:
                    output.put((source, line.rstrip("\r\n")))
        except (OSError, ValueError):
            pass
        finally:
            output.put((source, None))

    @staticmethod
    def _safe_environment() -> dict[str, str]:
        allowed = (
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        )
        environment = {key: os.environ[key] for key in allowed if key in os.environ}
        environment.update(
            {
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUTF8": "1",
                "PYTHONUNBUFFERED": "1",
            }
        )
        return environment

    def _run_output_contract(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            runtime_snapshot = self._manifests.get(run_id)
            action = runtime_snapshot.get("action") if runtime_snapshot else None
            in_memory = action.get("output") if isinstance(action, dict) else None
        output = _output_contract(in_memory)
        if output is not None:
            return output
        row = self.database.one(
            "SELECT output_schema_json FROM runs WHERE id=?",
            (run_id,),
        )
        return _output_contract(row["output_schema_json"]) if row else None

    def _handle_frame(
        self, run_id: str, module_id: str, frame: dict[str, Any], redactor: Redactor
    ) -> str | None:
        event_type = str(frame["type"])
        level = str(frame.get("level", "info"))
        if level not in _ALLOWED_LEVELS:
            level = "info"
        message = redactor.text(frame.get("message", ""))
        account_id = frame.get("account_id")
        if account_id is not None and (
            not isinstance(account_id, str) or not account_id or len(account_id) > 128
        ):
            raise ValueError("invalid account_id")
        if event_type == "account_state" and account_id is None:
            raise ValueError("account_state requires account_id")
        if event_type in _TERMINAL_EVENTS | {"started"} and account_id is not None:
            raise ValueError("run lifecycle events cannot be account-scoped")
        data = redactor.value(frame.get("data", {}))
        if not isinstance(data, dict):
            raise ValueError("event data must be an object")
        output = self._run_output_contract(run_id) if event_type == "result" else None
        declared_primary = bool(
            output is not None
            and isinstance(data.get("kind"), str)
            and data["kind"] == output["primary_kind"]
        )
        if declared_primary:
            assert output is not None
            _validate_primary_output_result(
                output,
                data,
                account_id=account_id,
                title=message,
            )
        account_state = (
            self._normalize_account_state(data) if event_type == "account_state" else None
        )
        now = utc_now()
        with self.database.transaction() as connection:
            current_account_state = None
            if account_id is not None:
                current_account_state = connection.execute(
                    "SELECT status,stage,progress,last_message FROM run_account_states "
                    "WHERE run_id=? AND account_id=?",
                    (run_id, account_id),
                ).fetchone()
                if not current_account_state:
                    # account_id is deliberately not echoed or persisted here: a
                    # malicious adapter could otherwise use this plaintext field
                    # to exfiltrate a secret into run_events/results.
                    raise ValueError("account_id is not selected for this run")

            if declared_primary:
                duplicate = connection.execute(
                    "SELECT 1 FROM results WHERE run_id=? AND account_id=? AND kind=? LIMIT 1",
                    (run_id, account_id, output["primary_kind"]),
                ).fetchone()
                if duplicate:
                    raise ValueError(
                        "declared account_table result already exists for this account"
                    )

            self._insert_event(
                connection,
                run_id,
                now,
                level,
                event_type,
                message,
                account_id,
                data,
            )

            progress_value: float | None = None
            if event_type == "progress":
                value = data.get("value")
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not math.isfinite(float(value))
                    or not 0 <= float(value) <= 1
                ):
                    raise ValueError("invalid progress")
                progress_value = float(value)
                if account_id is None:
                    account_projection = connection.execute(
                        "SELECT 1 FROM run_account_states WHERE run_id=? LIMIT 1",
                        (run_id,),
                    ).fetchone()
                    if not account_projection:
                        current_run = connection.execute(
                            "SELECT progress FROM runs WHERE id=?", (run_id,)
                        ).fetchone()
                        if current_run and progress_value < float(current_run["progress"]):
                            raise ValueError("run progress cannot move backwards")
                        connection.execute(
                            "UPDATE runs SET progress=? WHERE id=?",
                            (progress_value, run_id),
                        )
            elif event_type == "result":
                connection.execute(
                    "INSERT INTO results("
                    "id,run_id,module_id,account_id,kind,status,title,data_json,created_at"
                    ") VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        str(uuid.uuid4()),
                        run_id,
                        module_id,
                        account_id,
                        str(data.get("kind", "summary"))[:80],
                        str(data.get("status", "succeeded"))[:40],
                        message[:300],
                        json.dumps(data.get("payload", {}), ensure_ascii=False),
                        now,
                    ),
                )
            if account_state is not None:
                assert account_id is not None and current_account_state is not None
                self._apply_account_state(
                    connection,
                    run_id,
                    account_id,
                    current_account_state,
                    account_state,
                    message,
                    now,
                )
                self._update_run_progress_from_accounts(connection, run_id)
            elif account_id is not None:
                self._touch_account_activity(
                    connection,
                    run_id,
                    account_id,
                    message,
                    progress_value,
                    now,
                )
                if progress_value is not None:
                    self._update_run_progress_from_accounts(connection, run_id)
        return event_type if event_type in _TERMINAL_EVENTS else None

    @staticmethod
    def _normalize_account_state(data: dict[str, Any]) -> dict[str, Any]:
        status = data.get("status")
        stage = data.get("stage")
        progress = data.get("progress")
        if not isinstance(status, str) or status not in ACCOUNT_STATE_STATUSES:
            raise ValueError("invalid account status")
        if not isinstance(stage, str) or not _ACCOUNT_STAGE_RE.fullmatch(stage):
            raise ValueError("invalid account stage")
        if progress is not None and (
            isinstance(progress, bool)
            or not isinstance(progress, (int, float))
            or not math.isfinite(float(progress))
            or not 0 <= float(progress) <= 1
        ):
            raise ValueError("invalid account progress")
        return {
            "status": status,
            "stage": stage,
            "progress": None if progress is None else float(progress),
        }

    @staticmethod
    def _apply_account_state(
        connection: Any,
        run_id: str,
        account_id: str,
        current: Any,
        state: dict[str, Any],
        message: str,
        now: str,
    ) -> None:
        current_status = str(current["status"])
        next_status = str(state["status"])
        if current_status in _ACCOUNT_TERMINAL_STATUSES:
            raise ValueError("account state is already terminal")
        if current_status == "running" and next_status == "queued":
            raise ValueError("account state cannot move back to queued")
        progress = state["progress"]
        if next_status == "succeeded":
            progress = 1.0
        elif next_status in _ACCOUNT_PRESERVE_PROGRESS_STATUSES:
            # A terminal error is an outcome, not evidence that unfinished
            # work suddenly completed. Preserve the last accepted milestone
            # even if a legacy adapter sends a cosmetic terminal percentage.
            progress = None
        if progress is not None and progress < float(current["progress"]):
            raise ValueError("account progress cannot move backwards")
        connection.execute(
            "UPDATE run_account_states SET status=?,stage=?,"
            "progress=CASE WHEN ? IS NULL THEN progress ELSE MAX(progress,?) END,"
            "last_message=CASE WHEN ?='' THEN last_message ELSE ? END,updated_at=? "
            "WHERE run_id=? AND account_id=?",
            (
                next_status,
                state["stage"],
                progress,
                progress,
                message,
                message[:1000],
                now,
                run_id,
                account_id,
            ),
        )

    @staticmethod
    def _touch_account_activity(
        connection: Any,
        run_id: str,
        account_id: str,
        message: str,
        progress: float | None,
        now: str,
    ) -> None:
        current = connection.execute(
            "SELECT progress FROM run_account_states WHERE run_id=? AND account_id=?",
            (run_id, account_id),
        ).fetchone()
        if progress is not None and current and progress < float(current["progress"]):
            raise ValueError("account progress cannot move backwards")
        connection.execute(
            "UPDATE run_account_states SET status='running',"
            "stage=CASE WHEN stage='queued' THEN 'running' ELSE stage END,"
            "progress=CASE WHEN ? IS NULL THEN progress ELSE MAX(progress,?) END,"
            "last_message=CASE WHEN ?='' THEN last_message ELSE ? END,updated_at=? "
            "WHERE run_id=? AND account_id=? AND status IN ('queued','running')",
            (
                progress,
                progress,
                message,
                message[:1000],
                now,
                run_id,
                account_id,
            ),
        )

    @staticmethod
    def _update_run_progress_from_accounts(connection: Any, run_id: str) -> None:
        connection.execute(
            "UPDATE runs SET progress=MAX(progress,COALESCE(("
            "SELECT AVG(progress) FROM run_account_states WHERE run_id=?"
            "),0)) WHERE id=?",
            (run_id, run_id),
        )

    @staticmethod
    def _insert_event(
        connection: Any,
        run_id: str,
        created_at: str,
        level: str,
        event_type: str,
        message: str,
        account_id: str | None,
        data: dict[str, Any],
    ) -> None:
        connection.execute(
            "INSERT INTO run_events(run_id,created_at,level,event_type,message,account_id,data_json) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                run_id,
                created_at,
                level,
                event_type,
                message,
                account_id,
                json.dumps(data, ensure_ascii=False),
            ),
        )

    def _event(
        self,
        run_id: str,
        level: str,
        event_type: str,
        message: str,
        account_id: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        with self.database.transaction() as connection:
            self._insert_event(
                connection,
                run_id,
                utc_now(),
                level,
                event_type,
                message,
                account_id,
                data or {},
            )

    def stop(self, run_id: str) -> dict[str, Any]:
        run = self.get(run_id)
        if not run:
            raise RunError("Запуск не найден")
        if run["status"] not in {"queued", "starting", "running", "cancelling"}:
            return run
        with self._lock:
            meta = self._manifests.get(run_id, {})
            manifest = meta.get("manifest", {})
            if manifest.get("runtime", {}).get("safe_stop") is not True:
                raise RunError("Плагин не объявил безопасную остановку; требуется recovery-действие")
            self._cancel_requests.add(run_id)
            process = self._processes.get(run_id)
        self.database.execute("UPDATE runs SET status='cancelling' WHERE id=?", (run_id,))
        if process and process.poll() is None:
            self._signal_process(process, force=False)
            threading.Thread(
                target=self._force_after_grace,
                args=(run_id, process, 10),
                daemon=True,
            ).start()
        return self.get(run_id) or run

    def force_stop(self, run_id: str, acknowledgement: str) -> dict[str, Any]:
        """Immediately kill a run, bypassing the plugin's safe-stop declaration."""
        run = self.get(run_id)
        if not run:
            raise RunError("Запуск не найден")
        active_statuses = {"queued", "starting", "running", "cancelling"}
        if run["status"] not in active_statuses:
            return run
        if acknowledgement != FORCE_STOP_ACKNOWLEDGEMENT:
            raise RunError(f"Для принудительной остановки введите {FORCE_STOP_ACKNOWLEDGEMENT}")

        with self._lock:
            changed = self.database.execute(
                "UPDATE runs SET status='cancelling' WHERE id=? "
                "AND status IN ('queued','starting','running','cancelling')",
                (run_id,),
            )
            if not changed:
                return self.get(run_id) or run
            self._cancel_requests.add(run_id)
            self._force_stop_requests.add(run_id)
            process = self._processes.get(run_id)
            if process is not None and process.poll() is None:
                self._force_killed.add(run_id)

        self._event(
            run_id,
            "warning",
            "host",
            "Оператор запросил принудительную остановку процесса",
        )
        if process is not None and process.poll() is None:
            self._signal_process(process, force=True)
        return self.get(run_id) or run

    def uninstall_module(self, plugin_id: str) -> dict[str, Any]:
        """Serialize uninstall against starts and in-memory worker finalization."""
        with self._lock:
            if self._shutting_down:
                raise RunError("Soft Hub завершает работу; удаление плагина недоступно")
            for run_id, meta in self._manifests.items():
                manifest = meta.get("manifest", {})
                if manifest.get("id") == plugin_id and run_id in self._threads:
                    raise RunError(
                        "Нельзя удалить плагин, пока его запуск или финализация не завершены"
                    )
            try:
                return self.plugins.uninstall(plugin_id)
            except PluginError as error:
                raise RunError(str(error)) from error

    def review_failure(self, run_id: str) -> dict[str, Any]:
        """Close a known failure notification without claiming reconciliation.

        A known issue can be represented either by a failed run or by a
        terminal per-account failed/partial/blocked/unknown state.  The latter
        matters for adapters that completed their process cleanly after one
        account failed.  Reviewing only changes the run's operational
        projection and appends an audit event; account states, results and the
        original error text are not rewritten.  This is only notification
        housekeeping: terminal account leases are always released separately.
        """
        now = utc_now()
        with self.database.transaction() as connection:
            run = connection.execute(
                "SELECT r.*,m.name AS module_name,v.manifest_json AS run_manifest_json "
                "FROM runs r JOIN modules m ON m.id=r.module_id "
                "LEFT JOIN module_versions v ON v.module_id=r.module_id "
                "AND v.version=r.module_version WHERE r.id=?",
                (run_id,),
            ).fetchone()
            if not run:
                raise RunError("Запуск не найден")
            original_status = str(run["status"])
            if original_status == "reviewed":
                return self._present_run(dict(run))
            if original_status in _ACTIVE_RUN_STATUSES:
                raise RunError("Запуск ещё не завершён")
            if original_status == "reconciled":
                return self._present_run(dict(run))

            account_issue = connection.execute(
                "SELECT COUNT(*) AS count FROM run_account_states WHERE run_id=? AND ("
                "status IN ('partial','failed','blocked','needs_attention') OR "
                "(status='unknown' AND stage NOT IN ('historical','reconciled')))",
                (run_id,),
            ).fetchone()
            issue_count = int(account_issue["count"] if account_issue else 0)
            if original_status not in {"failed", "needs_attention"} and issue_count == 0:
                raise RunError("У запуска нет активного уведомления об известной ошибке")
            # Defensive cleanup for databases created by older Hub versions.
            connection.execute("DELETE FROM account_leases WHERE run_id=?", (run_id,))
            connection.execute(
                "UPDATE runs SET status='reviewed',finished_at=COALESCE(finished_at,?) "
                "WHERE id=? AND status=?",
                (now, run_id, original_status),
            )
            connection.execute(
                "INSERT INTO run_events(run_id,created_at,level,event_type,message,data_json) "
                "VALUES (?,?,?,?,?,?)",
                (
                    run_id,
                    now,
                    "info",
                    "failure_reviewed",
                    "Уведомление об ошибке скрыто; журнал и результаты сохранены",
                    json.dumps(
                        {
                            "original_status": original_status,
                            "account_issue_count": issue_count,
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
        return self.get(run_id) or {}

    def _force_after_grace(self, run_id: str, process: subprocess.Popen[str], seconds: int) -> None:
        try:
            process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            self._event(run_id, "warning", "host", "Плагин не остановился вовремя; процесс завершён принудительно")
            with self._lock:
                self._force_killed.add(run_id)
            self._signal_process(process, force=True)
        else:
            if os.name != "nt":
                self._signal_process(process, force=True)

    @staticmethod
    def _signal_process(process: subprocess.Popen[str], force: bool) -> None:
        try:
            if os.name == "nt":
                if process.poll() is not None:
                    return
                if force:
                    completed = subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                        check=False,
                    )
                    if completed.returncode != 0 and process.poll() is None:
                        process.kill()
                else:
                    process.terminate()
            else:
                os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
        except (OSError, ProcessLookupError, subprocess.SubprocessError):
            if force and process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
            return

    def shutdown(self, grace_seconds: float = 8.0) -> None:
        with self._lock:
            if self._shutting_down:
                threads = list(self._threads.values())
            else:
                self._shutting_down = True
                run_ids = set(self._manifests)
                self._shutdown_requests.update(run_ids)
                self._cancel_requests.update(run_ids)
                processes = list(self._processes.items())
                threads = list(self._threads.values())
                for run_id in run_ids:
                    self.database.execute(
                        "UPDATE runs SET status='cancelling' "
                        "WHERE id=? AND status IN ('queued','starting','running')",
                        (run_id,),
                    )
                for _run_id, process in processes:
                    self._signal_process(process, force=False)

        deadline = time.monotonic() + max(0.0, grace_seconds)
        for thread in threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(timeout=remaining)

        with self._lock:
            remaining_processes = list(self._processes.items())
            remaining_threads = list(self._threads.values())
            for run_id, process in remaining_processes:
                self._force_killed.add(run_id)
                self._signal_process(process, force=True)
        for thread in remaining_threads:
            thread.join(timeout=2)

        now = utc_now()
        with self.database.transaction() as connection:
            connection.execute(
                "UPDATE runs SET status='cancelled',finished_at=COALESCE(finished_at,?),"
                "error=COALESCE(error,'Hub shutdown interrupted this run'),pid=NULL "
                "WHERE status IN ('queued','starting','running','cancelling')",
                (now,),
            )
            connection.execute(
                "DELETE FROM account_leases"
            )
            connection.execute(
                "UPDATE run_account_states SET status='cancelled',"
                "stage='hub_shutdown',last_message='Hub завершил работу во время выполнения',"
                "updated_at=? WHERE status IN ('queued','running')",
                (now,),
            )
            connection.execute("DELETE FROM run_account_pins")

    def _current_progress(self, run_id: str) -> float:
        row = self.database.one("SELECT progress FROM runs WHERE id=?", (run_id,))
        return float(row["progress"]) if row else 0.0

    def get(self, run_id: str) -> dict[str, Any] | None:
        row = self.database.one(
            "SELECT r.*,m.name AS module_name,v.manifest_json AS run_manifest_json "
            "FROM runs r JOIN modules m ON m.id=r.module_id "
            "LEFT JOIN module_versions v ON v.module_id=r.module_id AND v.version=r.module_version "
            "WHERE r.id=?",
            (run_id,),
        )
        return self._present_run(row) if row else None

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.database.all(
            "SELECT r.*,m.name AS module_name,v.manifest_json AS run_manifest_json "
            "FROM runs r JOIN modules m ON m.id=r.module_id "
            "LEFT JOIN module_versions v ON v.module_id=r.module_id AND v.version=r.module_version "
            "ORDER BY r.requested_at DESC LIMIT ?",
            (max(1, min(200, limit)),),
        )
        return [self._present_run(row) for row in rows]

    def bootstrap_runs(
        self, operational_limit: int = 500, terminal_limit: int = 30
    ) -> dict[str, Any]:
        """Keep every relevant operation visible without an unbounded bootstrap."""
        operational_cap = max(1, min(500, operational_limit))
        terminal_cap = max(0, min(200, terminal_limit))
        select = (
            "SELECT r.*,m.name AS module_name,v.manifest_json AS run_manifest_json "
            "FROM runs r JOIN modules m ON m.id=r.module_id "
            "LEFT JOIN module_versions v ON v.module_id=r.module_id AND v.version=r.module_version "
        )
        placeholders = ",".join("?" for _ in _OPERATIONAL_RUN_STATUSES)
        active_placeholders = ",".join("?" for _ in _ACTIVE_RUN_STATUSES)
        operational_rows = self.database.all(
            select
            + f"WHERE r.status IN ({placeholders}) "
            + f"ORDER BY CASE WHEN r.status IN ({active_placeholders}) THEN 0 ELSE 1 END,"
            "r.requested_at DESC,r.id DESC LIMIT ?",
            (*_OPERATIONAL_RUN_STATUSES, *_ACTIVE_RUN_STATUSES, operational_cap + 1),
        )
        truncated = len(operational_rows) > operational_cap
        operational_rows = operational_rows[:operational_cap]
        terminal_rows = (
            self.database.all(
                select
                + f"WHERE r.status NOT IN ({placeholders}) "
                "ORDER BY r.requested_at DESC,r.id DESC LIMIT ?",
                (*_OPERATIONAL_RUN_STATUSES, terminal_cap),
            )
            if terminal_cap
            else []
        )
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in [*operational_rows, *terminal_rows]:
            run_id = str(row["id"])
            if run_id in seen:
                continue
            seen.add(run_id)
            rows.append(self._present_run(row))
        return {"runs": rows, "truncated": truncated}

    def status_counts(self) -> dict[str, int]:
        row = self.database.one(
            "SELECT "
            "SUM(CASE WHEN status IN ('queued','starting','running','cancelling') "
            "THEN 1 ELSE 0 END) AS active_runs,"
            "0 AS needs_attention,"
            "(SELECT COUNT(*) FROM runs attention_run WHERE "
            "attention_run.status NOT IN ('reconciled','reviewed') AND ("
            "attention_run.status IN ('failed','needs_attention') OR EXISTS ("
            "SELECT 1 FROM run_account_states attention_account "
            "WHERE attention_account.run_id=attention_run.id AND ("
            "attention_account.status IN ('partial','failed','blocked','needs_attention') "
            "OR (attention_account.status='unknown' AND "
            "attention_account.stage NOT IN ('historical','reconciled'))"
            ")))) AS attention_runs "
            "FROM runs"
        ) or {}
        return {
            "active_runs": int(row.get("active_runs") or 0),
            "needs_attention": int(row.get("needs_attention") or 0),
            "attention_runs": int(row.get("attention_runs") or 0),
        }

    @staticmethod
    def _present_run(row: dict[str, Any]) -> dict[str, Any]:
        row["summary"] = json.loads(row.pop("summary_json") or "{}")
        row["catalog_sections"] = _catalog_snapshot(
            row.pop("catalog_sections_json", None)
        )
        manifest_json = row.pop("run_manifest_json", None)
        if manifest_json:
            try:
                row["safe_stop"] = json.loads(manifest_json).get("runtime", {}).get("safe_stop") is True
            except (TypeError, json.JSONDecodeError):
                row["safe_stop"] = False
        else:
            row["safe_stop"] = False
        return row

    def events(self, run_id: str, after: int = 0, limit: int = 500) -> list[dict[str, Any]]:
        rows = self.database.all(
            "SELECT e.*,s.account_label FROM run_events e "
            "LEFT JOIN run_account_states s "
            "ON s.run_id=e.run_id AND s.account_id=e.account_id "
            "WHERE e.run_id=? AND e.id>? ORDER BY e.id LIMIT ?",
            (run_id, max(0, after), max(1, min(1000, limit))),
        )
        redactor = Redactor()
        for row in rows:
            row["message"] = redactor.text(row.get("message", ""))
            try:
                raw_data = json.loads(row.pop("data_json") or "{}")
            except (TypeError, json.JSONDecodeError):
                raw_data = {"redaction": "Некорректные сохранённые данные события скрыты"}
            row["data"] = redactor.value(raw_data)
        return rows

    def technical_log(self, run_id: str) -> bytes:
        """Build a bounded UTF-8 JSONL log without manifest, options, or raw secrets."""
        run = self.database.one(
            "SELECT r.id,r.module_id,r.module_version,r.action_id,r.status,r.progress,"
            "r.account_count,r.account_concurrency,r.requested_at,r.started_at,r.finished_at,"
            "substr(COALESCE(r.error,''),1,16000) AS error,m.name AS module_name "
            "FROM runs r JOIN modules m ON m.id=r.module_id WHERE r.id=?",
            (run_id,),
        )
        if not run:
            raise RunError("Запуск не найден")

        total_row = self.database.one(
            "SELECT COUNT(*) AS count FROM run_events WHERE run_id=?", (run_id,)
        ) or {"count": 0}
        total_events = int(total_row["count"])
        redactor = Redactor()
        output = bytearray()
        footer_reserve = 1024

        def encode_record(value: dict[str, Any]) -> bytes:
            return (
                json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
            ).encode("utf-8")

        header = {
            "record": "soft_hub_technical_log",
            "format_version": 1,
            "scope": "full_run_all_accounts",
            "privacy": "Секретные значения повторно скрыты при экспорте",
            "event_count": total_events,
            "run": redactor.value(run),
        }
        output.extend(encode_record(header))

        exported_events = 0
        truncated = False
        connection = self.database.connect()
        try:
            cursor = connection.execute(
                "SELECT e.id,e.created_at,e.level,e.event_type,"
                "substr(COALESCE(e.message,''),1,16000) AS message,"
                "CASE WHEN length(COALESCE(e.message,''))>16000 THEN 1 ELSE 0 END "
                "AS message_truncated,e.account_id,s.account_label,"
                "CASE WHEN length(COALESCE(e.data_json,''))<=? THEN e.data_json ELSE NULL END "
                "AS data_json,"
                "CASE WHEN length(COALESCE(e.data_json,''))>? THEN 1 ELSE 0 END "
                "AS data_truncated FROM run_events e LEFT JOIN run_account_states s "
                "ON s.run_id=e.run_id AND s.account_id=e.account_id "
                "WHERE e.run_id=? ORDER BY e.id",
                (_MAX_LOG_EXPORT_DATA_CHARS, _MAX_LOG_EXPORT_DATA_CHARS, run_id),
            )
            while True:
                rows = cursor.fetchmany(500)
                if not rows:
                    break
                for raw_row in rows:
                    row = dict(raw_row)
                    raw_data = row.pop("data_json", None)
                    data_truncated = bool(row.pop("data_truncated", 0))
                    message_truncated = bool(row.pop("message_truncated", 0))
                    if data_truncated:
                        data: Any = {
                            "redaction": "Слишком большие данные события скрыты при экспорте"
                        }
                    else:
                        try:
                            data = json.loads(raw_data or "{}")
                        except (TypeError, json.JSONDecodeError):
                            data = {
                                "redaction": "Некорректные сохранённые данные события скрыты"
                            }
                    event = redactor.value(
                        {
                            "record": "event",
                            **row,
                            "message": row.get("message", ""),
                            "data": data,
                        }
                    )
                    if message_truncated:
                        event["message_truncated"] = True
                    encoded = encode_record(event)
                    if len(encoded) > _MAX_LOG_EXPORT_LINE_BYTES:
                        event["data"] = {
                            "redaction": "Данные события сокращены до безопасного размера"
                        }
                        encoded = encode_record(event)
                    if len(output) + len(encoded) + footer_reserve > _MAX_LOG_EXPORT_BYTES:
                        truncated = True
                        break
                    output.extend(encoded)
                    exported_events += 1
                if truncated:
                    break
        finally:
            connection.close()

        output.extend(
            encode_record(
                {
                    "record": "end",
                    "exported_events": exported_events,
                    "omitted_events": total_events - exported_events,
                    "truncated": truncated,
                }
            )
        )
        return bytes(output)

    def account_states(
        self,
        run_id: str | None = None,
        limit: int = 500,
        *,
        scope: str = "historical",
    ) -> list[dict[str, Any]]:
        """Return the compact, secret-free run-by-account lifecycle projection."""
        capped_limit = max(1, min(2_000, limit))
        return self._query_account_states(run_id, capped_limit, scope)

    def account_state_page(
        self, *, scope: str = "historical", limit: int = 500
    ) -> dict[str, Any]:
        """Return a bounded global projection and disclose server truncation."""
        capped_limit = max(1, min(2_000, limit))
        rows = self._query_account_states(None, capped_limit + 1, scope)
        return {
            "accounts": rows[:capped_limit],
            "truncated": len(rows) > capped_limit,
        }

    def _query_account_states(
        self, run_id: str | None, limit: int, scope: str
    ) -> list[dict[str, Any]]:
        if scope not in {"historical", "active", "attention", "operations"}:
            raise RunError("Неизвестный scope lifecycle-проекции")
        if run_id is not None and scope != "historical":
            raise RunError("Operations scope доступен только для общей проекции")
        select = (
            "SELECT s.run_id,s.account_id,s.account_label,s.status,s.stage,s.progress,"
            "s.last_message,s.updated_at,r.module_id,m.name AS module_name,"
            "r.module_version,r.action_id,r.account_concurrency,"
            "r.status AS run_status,r.requested_at,"
            "r.started_at,r.finished_at FROM run_account_states s "
            "JOIN runs r ON r.id=s.run_id JOIN modules m ON m.id=r.module_id "
        )
        if run_id is not None:
            return self.database.all(
                select
                + "WHERE s.run_id=? ORDER BY s.account_label COLLATE NOCASE,s.account_id LIMIT ?",
                (run_id, limit),
            )
        if scope in {"active", "attention", "operations"}:
            active_predicate = "r.status IN ('queued','starting','running','cancelling')"
            attention_predicate = (
                "(r.status NOT IN ('reconciled','reviewed') AND ("
                "r.status IN ('failed','needs_attention') "
                "OR s.status IN ('partial','failed','blocked','needs_attention') "
                "OR (s.status='unknown' AND s.stage NOT IN ('historical','reconciled'))))"
            )
            predicate = (
                active_predicate
                if scope == "active"
                else attention_predicate
                if scope == "attention"
                else f"({active_predicate} OR {attention_predicate})"
            )
            ordering = (
                "CASE WHEN r.status IN ('queued','starting','running','cancelling') "
                "THEN 0 ELSE 1 END,"
                if scope == "operations"
                else ""
            )
            return self.database.all(
                select
                + f"WHERE {predicate} ORDER BY {ordering}"
                "s.updated_at DESC,s.run_id DESC,s.account_id LIMIT ?",
                (limit,),
            )
        return self.database.all(
            select + "ORDER BY s.updated_at DESC,s.run_id DESC,s.account_id LIMIT ?",
            (limit,),
        )

    @staticmethod
    def _report_filter(value: str | None, *, name: str, maximum: int) -> str | None:
        if value is None:
            return None
        if (
            not isinstance(value, str)
            or not value
            or len(value) > maximum
            or any(ord(character) < 32 for character in value)
        ):
            raise RunError(f"Некорректный фильтр {name}")
        return value

    @staticmethod
    def _present_report_metadata(row: dict[str, Any]) -> dict[str, Any] | None:
        output = _output_contract(row.pop("output_schema_json", None))
        if output is None:
            return None
        counts = {
            status: int(row.pop(f"count_{status}", 0) or 0)
            for status in _REPORT_ACCOUNT_STATUSES
        }
        return {
            "run_id": row["run_id"],
            "module_id": row["module_id"],
            "module_name": row["module_name"],
            "catalog_sections": _catalog_snapshot(
                row.get("catalog_sections_json")
            ),
            "action_id": row["action_id"],
            "requested_at": row["requested_at"],
            "finished_at": row["finished_at"],
            "run_status": row["run_status"],
            "output": output,
            "total": int(row.get("total") or 0),
            "counts": counts,
        }

    def result_reports(
        self,
        *,
        run_id: str | None = None,
        module_id: str | None = None,
        action_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        run_id = self._report_filter(run_id, name="run_id", maximum=128)
        module_id = self._report_filter(module_id, name="module_id", maximum=96)
        action_id = self._report_filter(action_id, name="action_id", maximum=96)
        capped_limit = max(1, min(_MAX_REPORTS, limit))
        predicates = ["r.output_schema_json <> '{}' "]
        params: list[Any] = []
        for column, value in (
            ("r.id", run_id),
            ("r.module_id", module_id),
            ("r.action_id", action_id),
        ):
            if value is not None:
                predicates.append(f"{column}=?")
                params.append(value)
        count_columns = ",".join(
            f"SUM(CASE WHEN s.status='{status}' THEN 1 ELSE 0 END) AS count_{status}"
            for status in _REPORT_ACCOUNT_STATUSES
        )
        rows = self.database.all(
            "SELECT r.id AS run_id,r.module_id,m.name AS module_name,r.action_id,"
            "r.requested_at,r.finished_at,r.status AS run_status,r.output_schema_json,"
            "r.catalog_sections_json,"
            f"COUNT(s.account_id) AS total,{count_columns} "
            "FROM runs r JOIN modules m ON m.id=r.module_id "
            "LEFT JOIN run_account_states s ON s.run_id=r.id "
            f"WHERE {' AND '.join(predicates)} "
            "GROUP BY r.id,r.module_id,m.name,r.action_id,r.requested_at,r.finished_at,"
            "r.status,r.output_schema_json,r.catalog_sections_json "
            "ORDER BY r.requested_at DESC,r.id DESC LIMIT ?",
            (*params, capped_limit),
        )
        reports: list[dict[str, Any]] = []
        for row in rows:
            report = self._present_report_metadata(row)
            if report is not None:
                reports.append(report)
        return reports

    def _result_report_aggregates(
        self, run_id: str, output: dict[str, Any]
    ) -> dict[str, dict[str, Any]]:
        aggregate_columns = [
            column for column in output["columns"] if "aggregate" in column
        ]
        if not aggregate_columns:
            return {}
        raw_rows = self.database.all(
            "SELECT CASE WHEN length(COALESCE(x.data_json,''))<=? "
            "THEN x.data_json ELSE NULL END AS data_json "
            "FROM run_account_states s JOIN results x ON x.id=("
            "SELECT candidate.id FROM results candidate "
            "WHERE candidate.run_id=s.run_id AND candidate.account_id=s.account_id "
            "AND candidate.kind=? ORDER BY candidate.created_at DESC,candidate.id DESC LIMIT 1"
            ") WHERE s.run_id=?",
            (_MAX_PROTOCOL_LINE, output["primary_kind"], run_id),
        )
        values: dict[str, list[Decimal]] = {
            column["key"]: [] for column in aggregate_columns
        }
        for raw_row in raw_rows:
            try:
                data = json.loads(raw_row.get("data_json") or "{}")
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            for column in aggregate_columns:
                key = column["key"]
                value = data.get(key)
                try:
                    if column["type"] == "integer":
                        if (
                            not isinstance(value, int)
                            or isinstance(value, bool)
                            or abs(value) > _JS_SAFE_INTEGER
                        ):
                            continue
                        numeric = Decimal(value)
                    elif column["type"] == "number":
                        if not isinstance(value, (int, float)) or isinstance(value, bool):
                            continue
                        if not math.isfinite(float(value)):
                            continue
                        numeric = Decimal(str(value))
                    else:
                        if (
                            not isinstance(value, str)
                            or len(value) > 128
                            or _DECIMAL_STRING_RE.fullmatch(value) is None
                        ):
                            continue
                        numeric = Decimal(value)
                    if numeric.is_finite():
                        values[key].append(numeric)
                except (InvalidOperation, OverflowError, ValueError):
                    continue

        aggregates: dict[str, dict[str, Any]] = {}
        for column in aggregate_columns:
            key = column["key"]
            operation = column["aggregate"]
            column_values = values[key]
            aggregate_value: Decimal | None = None
            if column_values:
                if operation == "sum":
                    aggregate_value = sum(column_values, Decimal(0))
                elif operation == "avg":
                    aggregate_value = sum(column_values, Decimal(0)) / len(column_values)
                elif operation == "min":
                    aggregate_value = min(column_values)
                else:
                    aggregate_value = max(column_values)
            presented: Any = None
            if aggregate_value is not None:
                if column["type"] == "decimal_string" or (
                    operation == "avg" and column["type"] == "integer"
                ):
                    presented = format(aggregate_value, "f")
                elif column["type"] == "integer":
                    integer_value = int(aggregate_value)
                    presented = (
                        integer_value
                        if abs(integer_value) <= _JS_SAFE_INTEGER
                        else format(aggregate_value, "f")
                    )
                else:
                    numeric = float(aggregate_value)
                    presented = numeric if math.isfinite(numeric) else None
            aggregates[key] = {
                "aggregate": operation,
                "value": presented,
                "count": len(column_values),
            }
        return aggregates

    def result_report(self, run_id: str, *, limit: int = _MAX_REPORT_ROWS) -> dict[str, Any]:
        reports = self.result_reports(run_id=run_id, limit=1)
        if not reports:
            raise RunError("Отчёт запуска не найден")
        report = reports[0]
        output = report["output"]
        capped_limit = max(1, min(_MAX_REPORT_ROWS, limit))
        primary_kind = output["primary_kind"]
        rows = self.database.all(
            "SELECT s.account_id,s.account_label,s.account_address,s.status,s.stage,s.progress,"
            "x.status AS result_status,x.title,"
            "CASE WHEN length(COALESCE(x.data_json,''))<=? THEN x.data_json ELSE NULL END "
            "AS data_json,x.created_at "
            "FROM run_account_states s LEFT JOIN results x ON x.id=("
            "SELECT candidate.id FROM results candidate "
            "WHERE candidate.run_id=s.run_id AND candidate.account_id=s.account_id "
            "AND candidate.kind=? ORDER BY candidate.created_at DESC,candidate.id DESC LIMIT 1"
            ") WHERE s.run_id=? "
            "ORDER BY s.account_label COLLATE NOCASE,s.account_id LIMIT ?",
            (_MAX_PROTOCOL_LINE, primary_kind, run_id, capped_limit + 1),
        )
        redactor = Redactor()
        projected: list[dict[str, Any]] = []
        for row in rows[:capped_limit]:
            raw_data = row.pop("data_json", None)
            try:
                decoded = json.loads(raw_data or "{}")
            except (TypeError, json.JSONDecodeError):
                decoded = {}
            if not isinstance(decoded, dict):
                decoded = {}
            row["title"] = (
                redactor.text(row["title"])
                if isinstance(row.get("title"), str)
                else None
            )
            safe_data: dict[str, Any] = {}
            for column in output["columns"]:
                key = column["key"]
                if key not in decoded:
                    continue
                value = decoded[key]
                if value is None or _output_value_has_type(value, column["type"]):
                    safe_data[key] = value
            row["data"] = redactor.value(safe_data)
            projected.append(row)
        result_count_row = self.database.one(
            "SELECT COUNT(DISTINCT account_id) AS count FROM results "
            "WHERE run_id=? AND kind=? AND account_id IS NOT NULL",
            (run_id, primary_kind),
        ) or {"count": 0}
        return {
            "report": report,
            "rows": projected,
            "total": report["total"],
            "result_count": int(result_count_row["count"] or 0),
            "truncated": len(rows) > capped_limit,
            "aggregates": self._result_report_aggregates(run_id, output),
        }

    def results(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.database.all(
            "SELECT x.*,m.name AS module_name,a.label AS account_label,"
            "r.catalog_sections_json FROM results x "
            "JOIN runs r ON r.id=x.run_id JOIN modules m ON m.id=x.module_id "
            "LEFT JOIN accounts a ON a.id=x.account_id "
            "ORDER BY x.created_at DESC LIMIT ?",
            (max(1, min(500, limit)),),
        )
        for row in rows:
            row["data"] = json.loads(row.pop("data_json") or "{}")
            row["catalog_sections"] = _catalog_snapshot(
                row.pop("catalog_sections_json", None)
            )
        return rows
