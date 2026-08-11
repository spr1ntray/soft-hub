from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import unicodedata
import uuid
import venv
import zipfile
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from .config import (
    APP_VERSION,
    MAX_ARCHIVE_BYTES,
    MAX_ARCHIVE_FILES,
    MAX_JSON_BYTES,
    MAX_UNPACKED_BYTES,
    PLUGIN_SCHEMA_VERSION,
    HubPaths,
    bundled_pip_wheel,
    runtime_fingerprint,
)
from .database import Database, utc_now
from .github_install import GitHubPackage
from .versions import compare_version_strings

_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
_ENTRYPOINT_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*$"
)
_ACTION_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
_ALLOWED_SECRETS = {
    "evm_private_key",
    "proxy",
    "email",
    "email_password",
    "twitter",
    "adspower_profile",
    "capsolver_api_key",
    "adspower_api_key",
}
_ACCOUNT_RESOURCE_PERMISSIONS = {
    "private_key": "evm_private_key",
    "proxy": "proxy",
    "email": "email",
    "email_password": "email_password",
    "twitter": "twitter",
    "adspower_profile": "adspower_profile",
}
_SETTING_RESOURCE_PERMISSIONS = {
    "capsolver": "capsolver_api_key",
    "adspower_api": "adspower_api_key",
}
_GLOBAL_SECRET_NAMES = {"capsolver_api_key", "adspower_api_key"}
_LEGACY_REFERRAL_SECRET_NAMES = {"referral_code", "referrer_code"}
_PRESENTATION_ASSET_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".avif", ".ico"}
_MAX_PRESENTATION_ASSET_BYTES = {"icon": 2 * 1024 * 1024, "image": 16 * 1024 * 1024}
_ALLOWED_RISKS = {"none", "testnet", "mainnet"}
_ALLOWED_ACTION_RISKS = {
    "read",
    "external_write",
    "testnet_write",
    "mainnet_write",
}
_ALLOWED_STATE_MODELS = {"stateless", "resumable", "externally_reconciled"}
LEGACY_STRICT_CONTRACT_VERSION = "SH-SOFTWARE-0.6/2"
STRICT_CONTRACT_VERSION = "SH-SOFTWARE-0.6/3"
_STRICT_CONTRACT_VERSIONS = {
    LEGACY_STRICT_CONTRACT_VERSION,
    STRICT_CONTRACT_VERSION,
}
_ACCOUNT_CONCURRENCY_OPTION = "account_concurrency"
_ACCOUNT_CONCURRENCY_MAX = 20
_BROWSER_ACCOUNT_CONCURRENCY_MAX = 5
_OPTION_TYPES = {"boolean", "string", "integer", "number"}
_OPTION_FIELD_KEYS = {
    "type",
    "title",
    "description",
    "default",
    "enum",
    "minimum",
    "maximum",
    "multipleOf",
    "minLength",
    "maxLength",
    "pattern",
    "x-ui",
}
_OPTION_UI_KEYS = {
    "group",
    "order",
    "control",
    "placeholder",
    "unit",
    "advanced",
    "enum_labels",
    "range",
}
_OUTPUT_MODE = "account_table"
_OUTPUT_TYPES = {"string", "integer", "number", "decimal_string", "boolean"}
_OUTPUT_NUMERIC_TYPES = {"integer", "number", "decimal_string"}
_OUTPUT_AGGREGATES = {"sum", "avg", "min", "max"}
_OUTPUT_COLUMN_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_OUTPUT_KIND_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
_MAX_OUTPUT_COLUMNS = 12
_MAX_OUTPUT_AGGREGATES = 4
_WINDOWS_DEVICE_RE = re.compile(
    r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.IGNORECASE
)
_DENIED_SECRET_BASENAMES = {
    "accounts.csv",
    "accounts.tsv",
    "accounts.xlsx",
    "auth.json",
    "capsolver_api_key.txt",
    "cookies.json",
    "cookies.txt",
    "credentials.json",
    "email_passwords.txt",
    "emails.txt",
    "id_ed25519",
    "id_rsa",
    "mnemonic.txt",
    "private_key.txt",
    "private_keys.txt",
    "proxies.txt",
    "proxy.txt",
    "seed.txt",
    "secrets.json",
    "telegram.txt",
    "twitter.txt",
    "wallets.json",
    "wallets.txt",
}
_DENIED_SECRET_SUFFIXES = {
    ".db",
    ".har",
    ".key",
    ".kdbx",
    ".p12",
    ".pfx",
    ".sqlite",
    ".sqlite3",
}


class PluginError(ValueError):
    pass


def _reject_unknown(mapping: dict[str, Any], allowed: set[str], scope: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise PluginError(f"{scope} содержит неизвестные поля: {', '.join(unknown)}")


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        numeric = float(value)
    except (OverflowError, ValueError):
        return None
    return numeric if math.isfinite(numeric) else None


def _option_value_has_type(value: Any, field_type: str) -> bool:
    if field_type == "boolean":
        return isinstance(value, bool)
    if field_type == "string":
        return isinstance(value, str)
    if field_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if field_type == "number":
        return _finite_number(value) is not None
    return False


def _validate_option_ui(
    raw: Any,
    *,
    scope: str,
    field_type: str,
    choices: list[Any] | None,
    strict: bool = False,
) -> None:
    if not isinstance(raw, dict):
        raise PluginError(f"{scope}.x-ui должен быть объектом")
    _reject_unknown(raw, _OPTION_UI_KEYS, f"{scope}.x-ui")
    if strict and not {"group", "order"}.issubset(raw):
        raise PluginError(
            f"{scope}.x-ui строгого контракта требует group и order"
        )
    for key, maximum in (("group", 80), ("placeholder", 160), ("unit", 24)):
        if key in raw and (
            not isinstance(raw[key], str)
            or not raw[key].strip()
            or len(raw[key]) > maximum
        ):
            raise PluginError(f"{scope}.x-ui.{key} должен быть непустой строкой")
    if "order" in raw and (
        not isinstance(raw["order"], int)
        or isinstance(raw["order"], bool)
        or not 0 <= raw["order"] <= 1000
    ):
        raise PluginError(f"{scope}.x-ui.order должен быть integer 0..1000")
    if "advanced" in raw and not isinstance(raw["advanced"], bool):
        raise PluginError(f"{scope}.x-ui.advanced должен быть boolean")
    if "unit" in raw and field_type not in {"integer", "number"}:
        raise PluginError(f"{scope}.x-ui.unit разрешён только числовому полю")
    if "control" in raw:
        if raw["control"] not in {"input", "textarea", "slider", "dual_range"}:
            raise PluginError(f"{scope}.x-ui.control неизвестен")
        if raw["control"] == "textarea" and (field_type != "string" or choices):
            raise PluginError(f"{scope}: textarea разрешён только для свободной строки")
        if raw["control"] in {"slider", "dual_range"} and (
            field_type not in {"integer", "number"} or choices is not None
        ):
            raise PluginError(f"{scope}: slider разрешён только числовому полю")
    range_descriptor = raw.get("range")
    if range_descriptor is not None:
        if raw.get("control") != "dual_range" or not isinstance(range_descriptor, dict):
            raise PluginError(f"{scope}.x-ui.range разрешён только для dual_range")
        _reject_unknown(range_descriptor, {"id", "role"}, f"{scope}.x-ui.range")
        range_id = range_descriptor.get("id")
        if (
            not isinstance(range_id, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", range_id)
        ):
            raise PluginError(f"{scope}.x-ui.range.id должен быть snake_case")
        if range_descriptor.get("role") not in {"from", "to"}:
            raise PluginError(f"{scope}.x-ui.range.role должен быть from или to")
        if set(range_descriptor) != {"id", "role"}:
            raise PluginError(f"{scope}.x-ui.range требует id и role")
    elif raw.get("control") == "dual_range":
        raise PluginError(f"{scope}.x-ui.dual_range требует range")
    if "enum_labels" in raw:
        labels = raw["enum_labels"]
        if not isinstance(labels, dict) or choices is None:
            raise PluginError(f"{scope}.x-ui.enum_labels требует string enum")
        choice_keys = {str(choice) for choice in choices}
        if set(labels) != choice_keys or any(
            not isinstance(label, str) or not label.strip() or len(label) > 120
            for label in labels.values()
        ):
            raise PluginError(
                f"{scope}.x-ui.enum_labels должен подписывать каждое enum-значение"
            )
    elif strict and choices is not None:
        raise PluginError(f"{scope}.x-ui.enum_labels обязателен для enum")


def _validate_slider_field(field: dict[str, Any], *, scope: str) -> None:
    field_type = field.get("type")
    if field_type not in {"integer", "number"}:
        raise PluginError(f"{scope}: slider разрешён только числовому полю")
    if "default" not in field:
        raise PluginError(f"{scope}: slider требует безопасный default")
    if not {"minimum", "maximum"}.issubset(field) or field["minimum"] >= field["maximum"]:
        raise PluginError(f"{scope}: slider требует minimum меньше maximum")
    if field_type == "number" and "multipleOf" not in field:
        raise PluginError(f"{scope}: number slider требует multipleOf")
    step = field.get("multipleOf", 1)
    if field_type == "integer" and (
        not isinstance(step, int) or isinstance(step, bool) or step < 1
    ):
        raise PluginError(f"{scope}: integer slider требует целый multipleOf")
    try:
        minimum = Decimal(str(field["minimum"]))
        maximum = Decimal(str(field["maximum"]))
        default = Decimal(str(field["default"]))
        decimal_step = Decimal(str(step))
        ticks = (maximum - minimum) / decimal_step
    except (InvalidOperation, ZeroDivisionError):
        raise PluginError(f"{scope}: slider имеет некорректную числовую сетку") from None
    if ticks != ticks.to_integral_value() or not 1 <= ticks <= 1000:
        raise PluginError(f"{scope}: slider допускает от 1 до 1000 шагов")
    for label, value in (("minimum", minimum), ("maximum", maximum), ("default", default)):
        quotient = value / decimal_step
        if quotient != quotient.to_integral_value():
            raise PluginError(f"{scope}.{label} не кратен multipleOf")
    if field_type == "integer" and any(
        not isinstance(field[name], int)
        or isinstance(field[name], bool)
        or not -(2**53 - 1) <= field[name] <= 2**53 - 1
        for name in ("minimum", "maximum", "default")
    ):
        raise PluginError(f"{scope}: integer slider требует безопасные integer-значения")


def _validate_options_schema(raw: Any, *, strict: bool, scope: str) -> None:
    if not isinstance(raw, dict):
        raise PluginError(f"{scope} должен быть объектом")
    if not raw and not strict:
        return
    _reject_unknown(raw, {"type", "properties", "required", "additionalProperties"}, scope)
    if raw.get("type", "object") != "object":
        raise PluginError(f"{scope}.type должен быть object")
    if "additionalProperties" in raw and raw["additionalProperties"] is not False:
        raise PluginError(f"{scope}.additionalProperties должен быть false")
    properties = raw.get("properties", {})
    required = raw.get("required", [])
    if not isinstance(properties, dict) or any(
        not isinstance(key, str)
        or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key)
        or not isinstance(field, dict)
        for key, field in properties.items()
    ):
        raise PluginError(f"{scope}.properties требует snake_case primitive-поля")
    if len(properties) > 40:
        raise PluginError(f"{scope}.properties содержит слишком много полей")
    if (
        not isinstance(required, list)
        or any(not isinstance(key, str) for key in required)
        or len(required) != len(set(required))
        or any(key not in properties for key in required)
    ):
        raise PluginError(f"{scope}.required некорректен")
    if strict and set(raw) != {"type", "properties", "required", "additionalProperties"}:
        raise PluginError(
            f"{scope} строгого контракта требует type, properties, required и additionalProperties"
        )

    primary_count = 0
    ui_orders: set[int] = set()
    group_modes: dict[str, bool] = {}
    range_fields: dict[str, list[tuple[str, dict[str, Any], dict[str, Any]]]] = {}
    for key, field in properties.items():
        field_scope = f"{scope}.properties.{key}"
        _reject_unknown(field, _OPTION_FIELD_KEYS, field_scope)
        field_type = field.get("type", "string")
        if field_type not in _OPTION_TYPES:
            raise PluginError(f"{field_scope}.type не поддерживается")
        if strict and "type" not in field:
            raise PluginError(f"{field_scope}.type обязателен")
        for text_key, maximum in (("title", 100), ("description", 500)):
            if text_key in field and (
                not isinstance(field[text_key], str)
                or not field[text_key].strip()
                or len(field[text_key]) > maximum
            ):
                raise PluginError(f"{field_scope}.{text_key} должен быть непустой строкой")
            if strict and text_key not in field:
                raise PluginError(f"{field_scope}.{text_key} обязателен")

        choices = field.get("enum")
        if choices is not None:
            if (
                field_type != "string"
                or not isinstance(choices, list)
                or not choices
                or any(not isinstance(choice, str) or not choice for choice in choices)
                or len(choices) != len(set(choices))
            ):
                raise PluginError(f"{field_scope}.enum должен быть непустым string enum")
        if "default" in field:
            default = field["default"]
            if not _option_value_has_type(default, field_type):
                raise PluginError(f"{field_scope}.default имеет неверный тип")
            if choices is not None and default not in choices:
                raise PluginError(f"{field_scope}.default отсутствует в enum")
        elif strict and key not in required:
            raise PluginError(f"{field_scope}.default обязателен для необязательного поля")

        if field_type in {"integer", "number"}:
            for boundary in ("minimum", "maximum"):
                if boundary in field and _finite_number(field[boundary]) is None:
                    raise PluginError(f"{field_scope}.{boundary} должен быть конечным числом")
            if strict and not {"minimum", "maximum"}.issubset(field):
                raise PluginError(f"{field_scope} требует minimum и maximum")
            if "minimum" in field and "maximum" in field and field["minimum"] > field["maximum"]:
                raise PluginError(f"{field_scope}: minimum больше maximum")
            if "multipleOf" in field and (
                _finite_number(field["multipleOf"]) is None or field["multipleOf"] <= 0
            ):
                raise PluginError(f"{field_scope}.multipleOf должен быть положительным")
            if "default" in field:
                default_number = float(field["default"])
                if "minimum" in field and default_number < float(field["minimum"]):
                    raise PluginError(f"{field_scope}.default меньше minimum")
                if "maximum" in field and default_number > float(field["maximum"]):
                    raise PluginError(f"{field_scope}.default больше maximum")
                if "multipleOf" in field:
                    multiple = float(field["multipleOf"])
                    quotient = default_number / multiple
                    if not math.isclose(quotient, round(quotient), rel_tol=1e-9, abs_tol=1e-9):
                        raise PluginError(f"{field_scope}.default не кратен multipleOf")
        elif any(name in field for name in ("minimum", "maximum", "multipleOf")):
            raise PluginError(f"{field_scope}: numeric keywords разрешены только числам")

        if field_type == "string":
            if "pattern" in field and (
                not isinstance(field["pattern"], str)
                or not field["pattern"]
                or len(field["pattern"]) > 500
            ):
                raise PluginError(f"{field_scope}.pattern должен быть непустой строкой")
            if strict and "pattern" in field:
                raise PluginError(
                    f"{field_scope}.pattern не исполняется Hub; валидируйте строку в entrypoint"
                )
            for boundary in ("minLength", "maxLength"):
                if boundary in field and (
                    not isinstance(field[boundary], int)
                    or isinstance(field[boundary], bool)
                    or field[boundary] < 0
                    or field[boundary] > 16_000
                ):
                    raise PluginError(f"{field_scope}.{boundary} некорректен")
            if "minLength" in field and "maxLength" in field and field["minLength"] > field["maxLength"]:
                raise PluginError(f"{field_scope}: minLength больше maxLength")
            if strict and choices is None and "maxLength" not in field:
                raise PluginError(f"{field_scope}.maxLength обязателен для свободной строки")
            if "default" in field:
                default_length = len(field["default"])
                if "minLength" in field and default_length < field["minLength"]:
                    raise PluginError(f"{field_scope}.default короче minLength")
                if "maxLength" in field and default_length > field["maxLength"]:
                    raise PluginError(f"{field_scope}.default длиннее maxLength")
        elif any(name in field for name in ("minLength", "maxLength")):
            raise PluginError(f"{field_scope}: length keywords разрешены только строкам")

        if strict and "x-ui" not in field:
            raise PluginError(f"{field_scope}.x-ui обязателен для дружелюбного UI")
        if "x-ui" in field:
            _validate_option_ui(
                field["x-ui"],
                scope=field_scope,
                field_type=field_type,
                choices=choices,
                strict=strict,
            )
            if strict:
                ui = field["x-ui"]
                if ui.get("control") in {"slider", "dual_range"}:
                    _validate_slider_field(field, scope=field_scope)
                if ui.get("control") == "dual_range":
                    range_fields.setdefault(ui["range"]["id"], []).append((key, field, ui))
                order = ui["order"]
                if order in ui_orders:
                    raise PluginError(f"{field_scope}.x-ui.order должен быть уникальным")
                ui_orders.add(order)
                group = ui["group"].strip()
                advanced = bool(ui.get("advanced", False))
                if group in group_modes and group_modes[group] != advanced:
                    raise PluginError(
                        f"{field_scope}.x-ui.group не может смешивать основные и расширенные поля"
                    )
                group_modes[group] = advanced
                if not advanced:
                    primary_count += 1

    for range_id, members in range_fields.items():
        if len(members) != 2 or {member[2]["range"]["role"] for member in members} != {"from", "to"}:
            raise PluginError(f"{scope}.x-ui.range {range_id} требует ровно одну пару from/to")
        from_key, from_field, from_ui = next(
            member for member in members if member[2]["range"]["role"] == "from"
        )
        to_key, to_field, to_ui = next(
            member for member in members if member[2]["range"]["role"] == "to"
        )
        for attribute in ("type", "title", "description", "minimum", "maximum", "multipleOf"):
            if from_field.get(attribute) != to_field.get(attribute):
                raise PluginError(f"{scope}.x-ui.range {range_id}: {attribute} должен совпадать")
        for attribute in ("group", "advanced", "unit"):
            if from_ui.get(attribute) != to_ui.get(attribute):
                raise PluginError(f"{scope}.x-ui.range {range_id}: x-ui.{attribute} должен совпадать")
        if (from_key in required) != (to_key in required):
            raise PluginError(f"{scope}.x-ui.range {range_id}: оба поля должны быть одинаково required")
        if Decimal(str(from_field["default"])) > Decimal(str(to_field["default"])):
            raise PluginError(f"{scope}.x-ui.range {range_id}: default from больше default to")
        if not bool(from_ui.get("advanced", False)):
            primary_count -= 1

    if strict and primary_count > 7:
        raise PluginError(f"{scope} допускает не более 7 основных параметров")


def _validate_account_concurrency_option(
    action: dict[str, Any],
    *,
    browser: bool,
    required: bool,
    minimum_hub: tuple[int, int, int],
) -> None:
    options = action.get("options", {})
    properties = options.get("properties", {}) if isinstance(options, dict) else {}
    field = properties.get(_ACCOUNT_CONCURRENCY_OPTION) if isinstance(properties, dict) else None
    if action.get("account_mode") == "none":
        if field is not None:
            raise PluginError(
                "account_concurrency запрещён для action.account_mode=none"
            )
        return
    if field is None:
        if required:
            raise PluginError(
                f"{STRICT_CONTRACT_VERSION} требует option account_concurrency "
                "у каждого account-action"
            )
        return
    if minimum_hub < (0, 6, 5):
        raise PluginError("account_concurrency требует compatibility.hub >=0.6.5")
    hard_maximum = (
        _BROWSER_ACCOUNT_CONCURRENCY_MAX if browser else _ACCOUNT_CONCURRENCY_MAX
    )
    expected_keys = {
        "type",
        "title",
        "description",
        "default",
        "minimum",
        "maximum",
        "multipleOf",
        "x-ui",
    }
    if not isinstance(field, dict) or set(field) != expected_keys:
        raise PluginError(
            "account_concurrency должен полностью объявлять type/title/description/"
            "default/minimum/maximum/multipleOf/x-ui"
        )
    default = field.get("default")
    declared_maximum = field.get("maximum")
    if (
        field.get("type") != "integer"
        or field.get("minimum") != 1
        or field.get("multipleOf") != 1
        or not isinstance(default, int)
        or isinstance(default, bool)
        or not isinstance(declared_maximum, int)
        or isinstance(declared_maximum, bool)
        or not 1 <= default <= declared_maximum <= hard_maximum
    ):
        kind = "browser" if browser else "HTTP/API"
        raise PluginError(
            f"account_concurrency для {kind} должен быть integer 1..{hard_maximum} "
            "с целым default внутри диапазона"
        )
    if _ACCOUNT_CONCURRENCY_OPTION in options.get("required", []):
        raise PluginError(
            "account_concurrency не включается в required: безопасный default обязателен"
        )
    ui = field.get("x-ui")
    if not isinstance(ui, dict) or ui.get("group") != "Выполнение":
        raise PluginError(
            'account_concurrency.x-ui.group должен быть "Выполнение"'
        )


def _manual_referral_code_options(action: dict[str, Any]) -> set[str]:
    option_names = set(action.get("options", {}).get("properties", {}))
    return {
        name
        for name in option_names
        if re.search(
            r"(?:referr|referral|invite).*(?:code)|(?:code).*(?:referr|invite)",
            name,
        )
    }


def _validate_referral_contract(
    action: dict[str, Any],
    *,
    minimum_hub: tuple[int, int, int],
) -> set[str]:
    referral = action.get("referral")
    if referral is None:
        return set()
    # Referral parents are a separate least-privilege grant.  Never let a
    # compatible non-strict manifest fall back to the plugin-wide permission
    # set here: that would expose parent-only credentials to target accounts.
    if "permissions" not in action or "resources" not in action:
        raise PluginError(
            "action.referral требует explicit action.permissions.secrets "
            "и action.resources для разделения target/parent grants"
        )
    if minimum_hub < (0, 6, 5):
        raise PluginError("action.referral требует compatibility.hub >=0.6.5")
    if action.get("account_mode") != "one_or_more":
        raise PluginError("action.referral требует account_mode=one_or_more")
    if not isinstance(referral, dict) or set(referral) != {
        "mode",
        "parent_required",
        "parent_access",
        "permissions",
        "resources",
    }:
        raise PluginError(
            "action.referral требует mode, parent_required, parent_access, "
            "permissions и resources"
        )
    if referral.get("mode") != "project_runtime":
        raise PluginError("action.referral.mode поддерживает только project_runtime")
    if not isinstance(referral.get("parent_required"), bool):
        raise PluginError("action.referral.parent_required должен быть boolean")
    if referral.get("parent_access") not in {"shared_read", "exclusive"}:
        raise PluginError(
            "action.referral.parent_access должен быть shared_read или exclusive"
        )
    permissions = referral.get("permissions")
    resources = referral.get("resources")
    if not isinstance(permissions, dict) or set(permissions) != {"secrets"}:
        raise PluginError("action.referral.permissions требует только secrets")
    parent_secrets = permissions.get("secrets")
    account_scoped = _ALLOWED_SECRETS - _GLOBAL_SECRET_NAMES - _LEGACY_REFERRAL_SECRET_NAMES
    if (
        not isinstance(parent_secrets, list)
        or any(secret not in account_scoped for secret in parent_secrets)
        or len(parent_secrets) != len(set(parent_secrets))
    ):
        raise PluginError(
            "action.referral.permissions.secrets содержит неизвестное account-право"
        )
    if not isinstance(resources, dict) or set(resources) != {"account"}:
        raise PluginError("action.referral.resources требует только account")
    parent_resources = resources.get("account")
    allowed_resources = {
        name
        for name, permission in _ACCOUNT_RESOURCE_PERMISSIONS.items()
        if permission in account_scoped
    }
    if (
        not isinstance(parent_resources, list)
        or any(resource not in allowed_resources for resource in parent_resources)
        or len(parent_resources) != len(set(parent_resources))
    ):
        raise PluginError("action.referral.resources.account содержит неизвестный ресурс")
    required_parent_secrets = {
        _ACCOUNT_RESOURCE_PERMISSIONS[resource] for resource in parent_resources
    }
    if required_parent_secrets != set(parent_secrets):
        raise PluginError(
            "action.referral resources должны точно соответствовать parent permissions"
        )
    if (
        "adspower_profile" in parent_secrets
        and referral["parent_access"] != "exclusive"
    ):
        raise PluginError(
            "Referral parent с AdsPower profile требует parent_access=exclusive"
        )
    forbidden = _manual_referral_code_options(action)
    if forbidden:
        raise PluginError(
            "Referral-aware action не принимает ручной referral/invite code через options"
        )
    return set(parent_secrets)


def _validate_output_contract(
    action: dict[str, Any], *, scope: str, minimum_hub: tuple[int, int, int]
) -> None:
    output = action.get("output")
    if output is None:
        return
    if minimum_hub < (0, 6, 8):
        raise PluginError("action.output требует compatibility.hub >=0.6.8")
    if action.get("account_mode") != "one_or_more":
        raise PluginError(f"{scope} требует account_mode=one_or_more")
    if not isinstance(output, dict):
        raise PluginError(f"{scope} должен быть объектом")
    required = {"mode", "title", "primary_kind", "columns"}
    _reject_unknown(output, required, scope)
    if set(output) != required:
        raise PluginError(
            f"{scope} требует mode, title, primary_kind и columns"
        )
    if output.get("mode") != _OUTPUT_MODE:
        raise PluginError(f"{scope}.mode поддерживает только {_OUTPUT_MODE}")
    title = output.get("title")
    if (
        not isinstance(title, str)
        or title != title.strip()
        or not 1 <= len(title) <= 120
        or any(ord(character) < 32 for character in title)
    ):
        raise PluginError(f"{scope}.title должен быть строкой длиной 1..120")
    primary_kind = output.get("primary_kind")
    if not isinstance(primary_kind, str) or not _OUTPUT_KIND_RE.fullmatch(primary_kind):
        raise PluginError(f"{scope}.primary_kind имеет некорректный формат")
    columns = output.get("columns")
    if not isinstance(columns, list) or not 1 <= len(columns) <= _MAX_OUTPUT_COLUMNS:
        raise PluginError(
            f"{scope}.columns должен содержать 1..{_MAX_OUTPUT_COLUMNS} колонок"
        )
    keys: set[str] = set()
    aggregate_count = 0
    for index, column in enumerate(columns):
        column_scope = f"{scope}.columns[{index}]"
        if not isinstance(column, dict):
            raise PluginError(f"{column_scope} должен быть объектом")
        required_column = {"key", "title", "type"}
        _reject_unknown(column, required_column | {"aggregate"}, column_scope)
        if not required_column.issubset(column):
            raise PluginError(f"{column_scope} требует key, title и type")
        key = column.get("key")
        if not isinstance(key, str) or not _OUTPUT_COLUMN_RE.fullmatch(key):
            raise PluginError(f"{column_scope}.key имеет некорректный формат")
        if key in keys:
            raise PluginError(f"{scope}.columns содержит повтор key={key}")
        keys.add(key)
        column_title = column.get("title")
        if (
            not isinstance(column_title, str)
            or column_title != column_title.strip()
            or not 1 <= len(column_title) <= 100
            or any(ord(character) < 32 for character in column_title)
        ):
            raise PluginError(f"{column_scope}.title должен быть строкой длиной 1..100")
        column_type = column.get("type")
        if column_type not in _OUTPUT_TYPES:
            raise PluginError(f"{column_scope}.type не поддерживается")
        if "aggregate" in column:
            aggregate = column["aggregate"]
            if aggregate not in _OUTPUT_AGGREGATES:
                raise PluginError(f"{column_scope}.aggregate не поддерживается")
            if column_type not in _OUTPUT_NUMERIC_TYPES:
                raise PluginError(
                    f"{column_scope}.aggregate разрешён только числовой колонке"
                )
            aggregate_count += 1
    if aggregate_count > _MAX_OUTPUT_AGGREGATES:
        raise PluginError(
            f"{scope} допускает не более {_MAX_OUTPUT_AGGREGATES} агрегатов"
        )


def _version_tuple(value: str) -> tuple[int, int, int]:
    base = value.split("-", 1)[0]
    return tuple(int(part) for part in base.split("."))  # type: ignore[return-value]


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(value: str, field: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\\" in value:
        raise PluginError(f"{field} должен быть безопасным относительным путём")
    return value


def _presentation_asset_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 240:
        raise PluginError(f"{field} должен быть непустой строкой")
    _safe_relative(value, field)
    path = PurePosixPath(value)
    if (
        path.as_posix() != value
        or len(path.parts) < 2
        or path.parts[0] != "assets"
        or any(part in {"", ".", ".."} or part.startswith(".") for part in path.parts)
        or any(
            part.endswith((".", " "))
            or ":" in part
            or _WINDOWS_DEVICE_RE.fullmatch(part.rstrip(". "))
            for part in path.parts
        )
        or path.suffix.lower() not in _PRESENTATION_ASSET_SUFFIXES
    ):
        raise PluginError(
            f"{field} должен указывать на локальное изображение внутри assets/"
        )
    return value


def _validate_presentation_payload(payload: bytes, path: str, kind: str) -> None:
    if len(payload) > _MAX_PRESENTATION_ASSET_BYTES[kind]:
        raise PluginError(f"presentation.assets.{kind} превышает допустимый размер")
    suffix = PurePosixPath(path).suffix.lower()
    signatures = {
        ".png": payload.startswith(b"\x89PNG\r\n\x1a\n"),
        ".jpg": payload.startswith(b"\xff\xd8\xff"),
        ".jpeg": payload.startswith(b"\xff\xd8\xff"),
        ".gif": payload.startswith((b"GIF87a", b"GIF89a")),
        ".webp": len(payload) >= 12 and payload[:4] == b"RIFF" and payload[8:12] == b"WEBP",
        ".avif": len(payload) >= 12 and payload[4:8] == b"ftyp" and payload[8:12] in {b"avif", b"avis", b"mif1"},
        ".ico": payload.startswith(b"\x00\x00\x01\x00"),
    }
    if not signatures.get(suffix, False):
        raise PluginError(f"presentation.assets.{kind} не соответствует формату файла")


def secret_material_reason(path: PurePosixPath | Path) -> str | None:
    """Identify credential-like files that must never be shipped in a patch."""
    basename = path.name.casefold()
    if basename == ".env" or (
        basename.startswith(".env.")
        and not basename.endswith((".example", ".sample", ".template"))
    ):
        return "environment-файл"
    if basename in _DENIED_SECRET_BASENAMES:
        return "файл расходников/учётных данных"
    if any(basename.endswith(suffix) for suffix in _DENIED_SECRET_SUFFIXES):
        return "секрет, сессия или локальная база"
    if basename.startswith(("private_keys.", "mnemonic.", "seed_phrase.")):
        return "ключевой материал кошелька"
    return None


def secret_payload_reason(payload: bytes) -> str | None:
    """Detect private-key containers without rejecting ordinary public certificates."""
    prefix = payload[:128 * 1024].upper()
    private_markers = (
        b"-----BEGIN PRIVATE KEY-----",  # gitleaks:allow -- detector signature
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----",  # gitleaks:allow -- detector signature
        b"-----BEGIN RSA PRIVATE KEY-----",  # gitleaks:allow -- detector signature
        b"-----BEGIN EC PRIVATE KEY-----",  # gitleaks:allow -- detector signature
        b"-----BEGIN OPENSSH PRIVATE KEY-----",  # gitleaks:allow -- detector signature
        b"-----BEGIN PGP PRIVATE KEY BLOCK-----",  # gitleaks:allow -- detector signature
    )
    return "private-key payload" if any(marker in prefix for marker in private_markers) else None


def validate_manifest(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PluginError("hub.plugin.json должен содержать JSON-объект")
    required = {
        "schema_version",
        "id",
        "name",
        "version",
        "description",
        "runtime",
        "permissions",
        "actions",
    }
    missing = sorted(required - raw.keys())
    if missing:
        raise PluginError("В манифесте отсутствуют поля: " + ", ".join(missing))
    if raw["schema_version"] != PLUGIN_SCHEMA_VERSION:
        raise PluginError("Версия схемы плагина не поддерживается")
    _reject_unknown(
        raw,
        required | {"$schema", "contract_version", "author", "compatibility", "presentation", "ui"},
        "Манифест",
    )
    contract_version = raw.get("contract_version")
    if contract_version is not None and contract_version not in _STRICT_CONTRACT_VERSIONS:
        raise PluginError("Неизвестная contract_version плагина")
    strict_contract = contract_version in _STRICT_CONTRACT_VERSIONS
    latest_contract = contract_version == STRICT_CONTRACT_VERSION
    if strict_contract:
        strict_top_level = {"author", "compatibility", "presentation"}
        strict_missing = sorted(strict_top_level - raw.keys())
        if strict_missing:
            raise PluginError(
                f"{STRICT_CONTRACT_VERSION} требует поля: {', '.join(strict_missing)}"
            )
    if "$schema" in raw and (
        not isinstance(raw["$schema"], str) or len(raw["$schema"]) > 500
    ):
        raise PluginError("$schema должен быть строкой")
    plugin_id = raw["id"]
    if not isinstance(plugin_id, str) or len(plugin_id) > 96 or not _ID_RE.fullmatch(plugin_id):
        raise PluginError("Некорректный id плагина")
    version = raw["version"]
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        raise PluginError("version должен быть SemVer вида 1.2.3")
    if not isinstance(raw["name"], str) or not 1 <= len(raw["name"].strip()) <= 80:
        raise PluginError("Некорректное имя плагина")
    if (
        not isinstance(raw["description"], str)
        or (strict_contract and not raw["description"].strip())
        or len(raw["description"]) > 500
    ):
        raise PluginError("Описание плагина слишком длинное")
    if "author" in raw and (
        not isinstance(raw["author"], str)
        or not raw["author"].strip()
        or len(raw["author"]) > 120
    ):
        raise PluginError("Некорректный author плагина")

    presentation = raw.get("presentation")
    if presentation is not None:
        if not isinstance(presentation, dict):
            raise PluginError("presentation должен быть объектом")
        _reject_unknown(
            presentation,
            {"display_name", "description", "assets"},
            "presentation",
        )
        if set(presentation) != {"display_name", "description", "assets"}:
            raise PluginError(
                "presentation требует display_name, description и assets"
            )
        display_name = presentation["display_name"]
        full_description = presentation["description"]
        if (
            not isinstance(display_name, str)
            or not 1 <= len(display_name.strip()) <= 120
        ):
            raise PluginError("presentation.display_name должен быть непустой строкой")
        if (
            not isinstance(full_description, str)
            or not 1 <= len(full_description.strip()) <= 4000
        ):
            raise PluginError("presentation.description должен быть непустой строкой")
        assets = presentation["assets"]
        if not isinstance(assets, dict):
            raise PluginError("presentation.assets должен быть объектом")
        _reject_unknown(assets, {"icon", "image"}, "presentation.assets")
        if set(assets) != {"icon", "image"}:
            raise PluginError("presentation.assets требует icon и image")
        _presentation_asset_path(assets["icon"], "presentation.assets.icon")
        _presentation_asset_path(assets["image"], "presentation.assets.image")

    compatibility = raw.get("compatibility", {})
    if not isinstance(compatibility, dict):
        raise PluginError("compatibility должен быть объектом")
    _reject_unknown(compatibility, {"hub", "python", "os"}, "compatibility")
    hub_constraint = compatibility.get("hub", ">=0.1.0")
    if not isinstance(hub_constraint, str) or not hub_constraint.startswith(">="):
        raise PluginError("Сейчас поддерживается compatibility.hub только в формате >=x.y.z")
    minimum = hub_constraint[2:]
    if not _VERSION_RE.fullmatch(minimum) or _version_tuple(APP_VERSION) < _version_tuple(minimum):
        raise PluginError(f"Плагину требуется Soft Hub {hub_constraint}")
    contract_minimum = (0, 6, 5) if latest_contract else (0, 6, 3)
    if strict_contract and _version_tuple(minimum) < contract_minimum:
        raise PluginError(
            f"{contract_version} требует compatibility.hub "
            f">={'.'.join(str(part) for part in contract_minimum)}"
        )
    if "python" in compatibility and (
        not isinstance(compatibility["python"], str)
        or not compatibility["python"].strip()
        or len(compatibility["python"]) > 80
    ):
        raise PluginError("compatibility.python должен быть непустой строкой")
    systems = compatibility.get("os", ["darwin", "win32", "linux"])
    if not isinstance(systems, list) or not systems or any(
        item not in {"darwin", "win32", "linux"} for item in systems
    ):
        raise PluginError("compatibility.os содержит неизвестную платформу")
    if len(systems) != len(set(systems)):
        raise PluginError("compatibility.os содержит повторы")
    if strict_contract and set(compatibility) != {"hub", "python", "os"}:
        raise PluginError(
            f"{STRICT_CONTRACT_VERSION} требует compatibility.hub, python и os"
        )

    runtime = raw["runtime"]
    if not isinstance(runtime, dict) or runtime.get("type") != "python":
        raise PluginError("MVP поддерживает только runtime.type=python")
    _reject_unknown(
        runtime,
        {
            "type",
            "entrypoint",
            "protocol",
            "state_model",
            "requirements",
            "safe_stop",
            "heartbeat_seconds",
        },
        "runtime",
    )
    if runtime.get("protocol") != "soft-hub-jsonl/1":
        raise PluginError("Плагин должен использовать protocol soft-hub-jsonl/1")
    entrypoint = runtime.get("entrypoint")
    if not isinstance(entrypoint, str) or not _ENTRYPOINT_RE.fullmatch(entrypoint):
        raise PluginError("runtime.entrypoint должен иметь вид package.module:function")
    if runtime.get("state_model") not in _ALLOWED_STATE_MODELS:
        raise PluginError("Неизвестная runtime.state_model")
    heartbeat = runtime.get("heartbeat_seconds", 15)
    if not isinstance(heartbeat, int) or not 5 <= heartbeat <= 300:
        raise PluginError("runtime.heartbeat_seconds должен быть в диапазоне 5..300")
    if "safe_stop" in runtime and not isinstance(runtime["safe_stop"], bool):
        raise PluginError("runtime.safe_stop должен быть boolean")
    if strict_contract and not {"safe_stop", "heartbeat_seconds"}.issubset(runtime):
        raise PluginError(
            f"{STRICT_CONTRACT_VERSION} требует runtime.safe_stop и heartbeat_seconds"
        )
    if "requirements" in runtime:
        requirements = runtime["requirements"]
        if not isinstance(requirements, str) or not requirements:
            raise PluginError("runtime.requirements должен быть строкой")
        _safe_relative(requirements, "runtime.requirements")

    permissions = raw["permissions"]
    if not isinstance(permissions, dict):
        raise PluginError("permissions должен быть объектом")
    _reject_unknown(
        permissions,
        {"secrets", "network", "chains", "financial_risk", "browser", "local_services"},
        "permissions",
    )
    secrets = permissions.get("secrets")
    network = permissions.get("network")
    chains = permissions.get("chains")
    if not isinstance(secrets, list) or any(
        not isinstance(secret, str) or secret not in _ALLOWED_SECRETS
        for secret in secrets
    ):
        raise PluginError("permissions.secrets содержит неизвестное право")
    if len(secrets) != len(set(secrets)):
        raise PluginError("permissions.secrets содержит повторы")
    if not isinstance(network, list) or any(not isinstance(host, str) or not host for host in network):
        raise PluginError("permissions.network должен быть списком доменов")
    if len(network) != len(set(network)):
        raise PluginError("permissions.network содержит повторы")
    if any(
        len(host) > 253
        or host != host.strip()
        or any(ord(char) < 33 for char in host)
        or "://" in host
        or "/" in host
        for host in network
    ):
        raise PluginError("permissions.network содержит некорректный домен")
    if not isinstance(chains, list) or any(
        not isinstance(chain, int) or isinstance(chain, bool) or chain <= 0 for chain in chains
    ):
        raise PluginError("permissions.chains должен быть списком chain id")
    if len(chains) != len(set(chains)):
        raise PluginError("permissions.chains содержит повторы")
    if permissions.get("financial_risk") not in _ALLOWED_RISKS:
        raise PluginError("permissions.financial_risk неизвестен")
    if "browser" in permissions and not isinstance(permissions["browser"], bool):
        raise PluginError("permissions.browser должен быть boolean")
    local_services = permissions.get("local_services", [])
    if not isinstance(local_services, list) or any(
        not isinstance(service, str)
        or not service.strip()
        or len(service) > 120
        or any(ord(char) < 32 for char in service)
        for service in local_services
    ):
        raise PluginError("permissions.local_services должен быть списком")
    if len(local_services) != len(set(local_services)):
        raise PluginError("permissions.local_services содержит повторы")
    if {"adspower_profile", "adspower_api_key"} & set(secrets):
        if permissions.get("browser") is not True:
            raise PluginError(
                "AdsPower permissions требуют permissions.browser=true"
            )
        if "adspower" not in local_services:
            raise PluginError(
                'AdsPower permissions требуют permissions.local_services=["adspower"]'
            )

    actions = raw["actions"]
    if not isinstance(actions, list) or not actions:
        raise PluginError("Манифест должен объявить минимум одно действие")
    action_ids: set[str] = set()
    action_secret_sets: list[set[str] | None] = []
    for action in actions:
        if not isinstance(action, dict):
            raise PluginError("Каждое действие должно быть объектом")
        _reject_unknown(
            action,
            {
                "id",
                "name",
                "description",
                "risk",
                "account_mode",
                "confirmation_phrase",
                "permissions",
                "resources",
                "options",
                "referral",
                "output",
            },
            "action",
        )
        action_id = action.get("id")
        if not isinstance(action_id, str) or not _ACTION_RE.fullmatch(action_id):
            raise PluginError("Некорректный id действия")
        if action_id in action_ids:
            raise PluginError("id действий должны быть уникальными")
        action_ids.add(action_id)
        if (
            not isinstance(action.get("name"), str)
            or not action["name"].strip()
            or len(action["name"]) > 80
        ):
            raise PluginError("У действия отсутствует name")
        if (
            not isinstance(action.get("description"), str)
            or (strict_contract and not action["description"].strip())
            or len(action["description"]) > 300
        ):
            raise PluginError("У действия некорректное description")
        if action.get("risk") not in _ALLOWED_ACTION_RISKS:
            raise PluginError("Некорректный risk действия")
        if action.get("account_mode") not in {"none", "one_or_more"}:
            raise PluginError("Некорректный account_mode действия")
        _validate_output_contract(
            action,
            scope=f"actions[{action_id}].output",
            minimum_hub=_version_tuple(minimum),
        )
        if action["risk"] == "mainnet_write" and not action.get("confirmation_phrase"):
            raise PluginError("Mainnet-действию обязательна confirmation_phrase")
        if "confirmation_phrase" in action and (
            not isinstance(action["confirmation_phrase"], str)
            or not action["confirmation_phrase"].strip()
            or len(action["confirmation_phrase"]) > 120
        ):
            raise PluginError("Некорректная confirmation_phrase")
        if action["risk"] != "mainnet_write" and "confirmation_phrase" in action:
            raise PluginError("confirmation_phrase разрешена только для mainnet-действия")
        if action["risk"] == "mainnet_write" and permissions["financial_risk"] != "mainnet":
            raise PluginError("Mainnet action требует permissions.financial_risk=mainnet")
        if action["risk"] == "testnet_write" and permissions["financial_risk"] == "none":
            raise PluginError("Testnet action не может объявлять financial_risk=none")
        if "permissions" not in action:
            if strict_contract:
                raise PluginError(
                    f"{STRICT_CONTRACT_VERSION} требует action.permissions у каждого action"
                )
            action_secret_sets.append(None)
            effective_action_secrets = set(secrets)
        else:
            action_permissions = action["permissions"]
            if not isinstance(action_permissions, dict):
                raise PluginError("action.permissions должен быть объектом")
            _reject_unknown(action_permissions, {"secrets"}, "action.permissions")
            action_secrets = action_permissions.get("secrets")
            if not isinstance(action_secrets, list) or any(
                not isinstance(secret, str) or secret not in _ALLOWED_SECRETS
                for secret in action_secrets
            ):
                raise PluginError("action.permissions.secrets содержит неизвестное право")
            if len(action_secrets) != len(set(action_secrets)):
                raise PluginError("action.permissions.secrets содержит повторы")
            action_secret_set = set(action_secrets)
            if not action_secret_set.issubset(set(secrets)):
                raise PluginError(
                    "action.permissions.secrets должен быть подмножеством permissions.secrets"
                )
            action_secret_sets.append(action_secret_set)
            effective_action_secrets = action_secret_set
        resources = action.get("resources")
        if strict_contract and resources is None:
            raise PluginError(
                f"{STRICT_CONTRACT_VERSION} требует action.resources у каждого action"
            )
        referral_action_permissions = {
            "referral_code",
            "referrer_code",
        } & effective_action_secrets
        if referral_action_permissions and resources is None:
            raise PluginError(
                "Referral permissions требуют соответствующие action.resources"
            )
        if resources is not None:
            if not isinstance(resources, dict):
                raise PluginError("action.resources должен быть объектом")
            _reject_unknown(resources, {"account", "settings"}, "action.resources")
            if set(resources) != {"account", "settings"}:
                raise PluginError("action.resources требует account и settings")
            account_resources = resources["account"]
            setting_resources = resources["settings"]
            if not isinstance(account_resources, list) or any(
                not isinstance(resource, str)
                or resource not in _ACCOUNT_RESOURCE_PERMISSIONS
                for resource in account_resources
            ):
                raise PluginError("action.resources.account содержит неизвестный ресурс")
            if len(account_resources) != len(set(account_resources)):
                raise PluginError("action.resources.account содержит повторы")
            if not isinstance(setting_resources, list) or any(
                not isinstance(resource, str)
                or resource not in _SETTING_RESOURCE_PERMISSIONS
                for resource in setting_resources
            ):
                raise PluginError("action.resources.settings содержит неизвестный ресурс")
            if len(setting_resources) != len(set(setting_resources)):
                raise PluginError("action.resources.settings содержит повторы")
            if account_resources and action["account_mode"] != "one_or_more":
                raise PluginError(
                    "action.resources.account требует account_mode=one_or_more"
                )
            required_permissions = {
                _ACCOUNT_RESOURCE_PERMISSIONS[resource]
                for resource in account_resources
            } | {
                _SETTING_RESOURCE_PERMISSIONS[resource]
                for resource in setting_resources
            }
            if strict_contract and required_permissions != effective_action_secrets:
                raise PluginError(
                    "action.resources должны точно соответствовать action.permissions.secrets"
                )
            if not strict_contract and not required_permissions.issubset(effective_action_secrets):
                raise PluginError(
                    "action.resources должны иметь точные action.permissions.secrets"
                )
            if referral_action_permissions != required_permissions & {
                "referral_code",
                "referrer_code",
            }:
                raise PluginError(
                    "Referral permissions должны точно соответствовать action.resources"
                )
        options = action.get("options", {})
        if "$ref" in json.dumps(options, ensure_ascii=False):
            raise PluginError("Remote/local $ref в action.options запрещены")
        if strict_contract and "options" not in action:
            raise PluginError(
                f"{STRICT_CONTRACT_VERSION} требует action.options у каждого action"
            )
        _validate_options_schema(
            options,
            strict=strict_contract,
            scope=f"actions[{action_id}].options",
        )
        _validate_account_concurrency_option(
            action,
            browser=permissions.get("browser") is True,
            required=latest_contract and action["account_mode"] == "one_or_more",
            minimum_hub=_version_tuple(minimum),
        )
        if latest_contract and _manual_referral_code_options(action):
            raise PluginError(
                "SH-SOFTWARE-0.6/3 не принимает ручной referral/invite code через options"
            )
        parent_secret_set = _validate_referral_contract(
            action,
            minimum_hub=_version_tuple(minimum),
        )
        if latest_contract and _LEGACY_REFERRAL_SECRET_NAMES & effective_action_secrets:
            raise PluginError(
                "SH-SOFTWARE-0.6/3 удалил referral_code/referrer_code: "
                "используйте action.referral project_runtime"
            )
        if action_secret_sets[-1] is not None:
            action_secret_sets[-1] = set(action_secret_sets[-1]) | parent_secret_set

    declared_action_secret_sets = [
        action_secrets for action_secrets in action_secret_sets if action_secrets is not None
    ]
    if declared_action_secret_sets and len(declared_action_secret_sets) != len(actions):
        raise PluginError(
            "action.permissions должен быть объявлен либо у всех actions, либо ни у одного"
        )
    if declared_action_secret_sets:
        declared_secret_union = set().union(*declared_action_secret_sets)
        if declared_secret_union != set(secrets):
            raise PluginError(
                "Объединение action.permissions.secrets должно совпадать с permissions.secrets"
            )

    if latest_contract and _LEGACY_REFERRAL_SECRET_NAMES & set(secrets):
        raise PluginError(
            "SH-SOFTWARE-0.6/3 не поддерживает legacy referral secret grants"
        )

    if {"referral_code", "referrer_code"} & set(secrets) and _version_tuple(
        minimum
    ) < (0, 6, 4):
        raise PluginError(
            "Referral grants/resources требуют compatibility.hub >=0.6.4"
        )

    action_risks = {action["risk"] for action in actions}
    expected_financial_risk = (
        "mainnet"
        if "mainnet_write" in action_risks
        else "testnet"
        if "testnet_write" in action_risks
        else "none"
    )
    if permissions["financial_risk"] != expected_financial_risk:
        raise PluginError("permissions.financial_risk не соответствует максимальному риску actions")
    if action_risks & {"testnet_write", "mainnet_write"} and not chains:
        raise PluginError("Chain write-действию нужен минимум один permissions.chains")
    if any(
        action["risk"] != "read" and action["account_mode"] != "one_or_more"
        for action in actions
    ):
        raise PluginError("Write-действие должно использовать account_mode=one_or_more")

    ui = raw.get("ui", {})
    if not isinstance(ui, dict):
        raise PluginError("ui должен быть объектом")
    _reject_unknown(ui, {"accent", "monogram"}, "ui")
    if "accent" in ui and (
        not isinstance(ui["accent"], str) or not re.fullmatch(r"#[0-9A-Fa-f]{6}", ui["accent"])
    ):
        raise PluginError("ui.accent должен быть hex-цветом")
    if "monogram" in ui and (
        not isinstance(ui["monogram"], str) or not 1 <= len(ui["monogram"]) <= 3
    ):
        raise PluginError("ui.monogram должен содержать 1..3 символа")

    return json.loads(json.dumps(raw, ensure_ascii=False))


def _validate_archive_member(info: zipfile.ZipInfo) -> PurePosixPath:
    name = info.filename
    if "\x00" in name or "\\" in name:
        raise PluginError("Архив содержит недопустимый путь")
    if unicodedata.normalize("NFC", name) != name:
        raise PluginError("Архив содержит Unicode-путь не в NFC")
    path = PurePosixPath(name)
    canonical = path.as_posix() + ("/" if info.is_dir() else "")
    if canonical != name:
        raise PluginError("Архив содержит неканонический путь")
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise PluginError("Архив пытается выйти за каталог установки")
    if any(_WINDOWS_DEVICE_RE.fullmatch(part.rstrip(". ")) for part in path.parts):
        raise PluginError("Архив содержит имя, зарезервированное Windows")
    if any(part.casefold() == ".venv" for part in path.parts):
        raise PluginError("Готовую .venv нельзя включать в пакет")
    if any(part.endswith((".", " ")) or ":" in part for part in path.parts):
        raise PluginError("Архив содержит непереносимый путь")
    unix_mode = info.external_attr >> 16
    if stat.S_ISLNK(unix_mode):
        raise PluginError("Символические ссылки в плагинах запрещены")
    if info.create_system == 3 and unix_mode and not info.is_dir() and not stat.S_ISREG(unix_mode):
        raise PluginError("Архив содержит специальный файл")
    if not info.is_dir() and (reason := secret_material_reason(path)):
        raise PluginError(
            f"Патч содержит запрещённый {reason}: {path.as_posix()}. "
            "Передавайте такие значения только через Vault."
        )
    return path


def _missing_package_contract_message(names: set[str]) -> str:
    root_manifest = "hub.plugin.json" in names
    root_checksums = "hub.checksums.json" in names
    if root_manifest and not root_checksums:
        return (
            "Патч не собран: в корне нет hub.checksums.json. "
            "Возьмите готовый .softhub.zip в GitHub Releases → Assets."
        )

    manifest_paths = [
        PurePosixPath(name)
        for name in names
        if PurePosixPath(name).name == "hub.plugin.json"
    ]
    for manifest_path in manifest_paths:
        parent = manifest_path.parent
        if parent == PurePosixPath("."):
            continue
        sibling = (parent / "hub.checksums.json").as_posix()
        if sibling in names:
            return (
                "Патч запакован с лишней общей папкой. Нужен .softhub.zip, "
                "где hub.plugin.json и hub.checksums.json лежат сразу в корне."
            )
    if manifest_paths:
        return (
            "Похоже, выбран GitHub Source code ZIP, а не готовый патч. "
            "В Releases откройте Assets и выберите файл .softhub.zip."
        )
    return (
        "Это не готовый пакет Soft Hub. Выберите в GitHub Releases → Assets "
        "файл с окончанием .softhub.zip, а не Source code (zip)."
    )


class PluginManager:
    def __init__(self, database: Database, paths: HubPaths):
        self.database = database
        self.paths = paths
        self._mutation_lock = threading.RLock()

    @contextmanager
    def admission_guard(self) -> Iterator[None]:
        """Keep a validated module snapshot stable through run admission."""
        with self._mutation_lock:
            yield

    def inspect_archive(self, archive: Path | str) -> dict[str, Any]:
        archive_path = Path(archive).resolve()
        if not archive_path.is_file():
            raise PluginError("Архив не найден")
        if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise PluginError("Архив превышает лимит 256 MB")
        try:
            with zipfile.ZipFile(archive_path) as bundle:
                infos = bundle.infolist()
                if len(infos) > MAX_ARCHIVE_FILES:
                    raise PluginError("В архиве слишком много файлов")
                total = 0
                names: set[str] = set()
                entry_kinds: dict[str, bool] = {}
                for info in infos:
                    relative = _validate_archive_member(info)
                    normalized = relative.as_posix().rstrip("/")
                    folded = normalized.casefold()
                    if not normalized or folded in entry_kinds:
                        raise PluginError("Архив содержит дублирующийся или конфликтующий путь")
                    ancestors = list(PurePosixPath(normalized).parents)[:-1]
                    if any(
                        ancestor.as_posix().casefold() in entry_kinds
                        and entry_kinds[ancestor.as_posix().casefold()] is False
                        for ancestor in ancestors
                    ):
                        raise PluginError("Файл архива используется как родительский каталог")
                    if any(existing.startswith(folded + "/") for existing in entry_kinds):
                        raise PluginError("Путь архива конфликтует с уже объявленным каталогом")
                    entry_kinds[folded] = info.is_dir()
                    if info.is_dir():
                        continue
                    total += info.file_size
                    if total > MAX_UNPACKED_BYTES:
                        raise PluginError("Распакованный плагин превышает лимит 512 MB")
                    if normalized in names:
                        raise PluginError("Архив содержит дублирующийся путь")
                    if (
                        info.file_size > 1024 * 1024
                        and info.compress_size > 0
                        and info.file_size / info.compress_size > 100
                    ):
                        raise PluginError("Архив содержит подозрительно сильно сжатый файл")
                    names.add(normalized)
                required = {"hub.plugin.json", "hub.checksums.json"}
                if not required.issubset(names):
                    raise PluginError(_missing_package_contract_message(names))
                sizes = {info.filename.rstrip("/"): info.file_size for info in infos if not info.is_dir()}
                if sizes["hub.plugin.json"] > MAX_JSON_BYTES or sizes["hub.checksums.json"] > MAX_JSON_BYTES:
                    raise PluginError("Манифест или checksums превышает лимит 2 MB")
                manifest = validate_manifest(json.loads(bundle.read("hub.plugin.json")))
                checksums_payload = bundle.read("hub.checksums.json")
                checksums = json.loads(checksums_payload)
                if not isinstance(checksums, dict) or not checksums:
                    raise PluginError("hub.checksums.json должен содержать контрольные суммы")
                expected_files = names - {"hub.checksums.json"}
                if set(checksums) != expected_files:
                    raise PluginError("Список контрольных сумм не совпадает с файлами архива")
                for name, expected in checksums.items():
                    _safe_relative(name, "checksum path")
                    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                        raise PluginError("Некорректная SHA-256 сумма")
                    payload = bundle.read(name)
                    if reason := secret_payload_reason(payload):
                        raise PluginError(
                            f"Патч содержит запрещённый {reason}: {name}. "
                            "Передавайте ключевой материал только через Vault."
                        )
                    actual = hashlib.sha256(payload).hexdigest()
                    if not hmac.compare_digest(actual, expected):
                        raise PluginError(f"Контрольная сумма не совпала: {name}")
                presentation = manifest.get("presentation")
                if presentation:
                    for kind, asset_path in presentation["assets"].items():
                        if asset_path not in names:
                            raise PluginError(
                                f"presentation.assets.{kind} отсутствует в архиве"
                            )
                        _validate_presentation_payload(
                            bundle.read(asset_path), asset_path, kind
                        )
                requirements = manifest["runtime"].get("requirements")
                if requirements and requirements not in names:
                    raise PluginError("Файл runtime.requirements отсутствует в архиве")
                module_name = manifest["runtime"]["entrypoint"].split(":", 1)[0]
                module_file = module_name.replace(".", "/") + ".py"
                package_file = module_name.replace(".", "/") + "/__init__.py"
                if module_file not in names and package_file not in names:
                    raise PluginError("Python entrypoint отсутствует в архиве")
                return {
                    "manifest": manifest,
                    "archive_sha256": _file_sha256(archive_path),
                    "checksums": checksums,
                    "checksums_sha256": hashlib.sha256(checksums_payload).hexdigest(),
                    "file_count": len(expected_files),
                    "unpacked_bytes": total,
                }
        except zipfile.BadZipFile as error:
            raise PluginError("Файл не является корректным ZIP-архивом") from error
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PluginError("Манифест или checksums содержит некорректный JSON") from error
        except RuntimeError as error:
            raise PluginError("Зашифрованные ZIP entry не поддерживаются") from error

    def install(self, archive: Path | str) -> dict[str, Any]:
        with self._mutation_lock:
            return self._install(archive)

    def install_github(
        self,
        archive: Path | str,
        source: GitHubPackage,
    ) -> dict[str, Any]:
        """Install an inspected GitHub package and bind its repository identity.

        The source object is created by the trusted downloader, never from renderer
        metadata. Package versions remain immutable; reinstalling the exact active
        version is idempotent only when its archive digest also matches.
        """

        if not isinstance(source, GitHubPackage):
            raise PluginError("Некорректная GitHub source identity")
        with self._mutation_lock:
            archive_path = Path(archive).resolve()
            inspection = self.inspect_archive(archive_path)
            manifest = inspection["manifest"]
            plugin_id = manifest["id"]
            version = manifest["version"]
            owner = source.owner.casefold()
            repository = source.repository.casefold()

            repository_sources = self.database.all(
                "SELECT module_id,version FROM github_module_sources "
                "WHERE owner=? COLLATE NOCASE AND repository=? COLLATE NOCASE",
                (owner, repository),
            )
            if any(row["module_id"] != plugin_id for row in repository_sources):
                raise PluginError(
                    "GitHub repository уже привязан к другому id софта; установка остановлена"
                )
            module_sources = self.database.all(
                "SELECT owner,repository FROM github_module_sources WHERE module_id=?",
                (plugin_id,),
            )
            if any(
                row["owner"].casefold() != owner
                or row["repository"].casefold() != repository
                for row in module_sources
            ):
                raise PluginError(
                    "Этот id софта уже привязан к другому GitHub repository; "
                    "установка остановлена"
                )

            current = self.database.one(
                "SELECT version FROM modules WHERE id=? AND health!='removed'",
                (plugin_id,),
            )
            if current:
                precedence = (
                    0
                    if version == current["version"]
                    else compare_version_strings(version, current["version"])
                )
                if precedence is None:
                    raise PluginError(
                        "Версии GitHub-пакета и установленного софта нельзя безопасно сравнить"
                    )
                if precedence < 0:
                    raise PluginError(
                        f"Установлена более новая версия {current['version']}; "
                        f"понижение до {version} остановлено"
                    )

            existing = self.database.one(
                "SELECT path,manifest_json,archive_sha256,active FROM module_versions "
                "WHERE module_id=? AND version=?",
                (plugin_id, version),
            )
            if existing:
                if not hmac.compare_digest(
                    str(existing["archive_sha256"]), inspection["archive_sha256"]
                ):
                    raise PluginError(
                        f"GitHub asset повторно использует версию {version} с другим содержимым"
                    )
                if (
                    current is None
                    or current["version"] != version
                    or not bool(existing["active"])
                ):
                    raise PluginError(
                        f"Версия {version} уже была установлена и не может быть активирована "
                        "повторно; выпустите новую SemVer-версию"
                    )
                self._bind_existing_current_github_version(
                    manifest,
                    existing,
                    inspection["archive_sha256"],
                    source,
                )
                return self.get(plugin_id) or {}

            return self._install(
                archive_path,
                inspection=inspection,
                github_source=source,
            )

    def _install(
        self,
        archive: Path | str,
        *,
        inspection: dict[str, Any] | None = None,
        github_source: GitHubPackage | None = None,
    ) -> dict[str, Any]:
        archive_path = Path(archive).resolve()
        inspection = inspection or self.inspect_archive(archive_path)
        manifest = inspection["manifest"]
        plugin_id = manifest["id"]
        version = manifest["version"]
        current = self.database.one(
            "SELECT version FROM modules WHERE id=? AND health!='removed'",
            (plugin_id,),
        )
        if current and version != current["version"]:
            precedence = compare_version_strings(version, current["version"])
            if precedence is None:
                raise PluginError(
                    "Версии пакета и установленного софта нельзя безопасно сравнить"
                )
            if precedence < 0:
                raise PluginError(
                    f"Установлена более новая версия {current['version']}; "
                    f"понижение до {version} остановлено"
                )
        existing_version = self.database.one(
            "SELECT version FROM module_versions WHERE module_id=? AND version=?",
            (plugin_id, version),
        )
        if existing_version:
            raise PluginError(f"Версия {version} уже установлена")

        stage = self.paths.staging / str(uuid.uuid4())
        target_parent = self.paths.plugins / plugin_id
        target = target_parent / version
        activated_target = False
        stage.mkdir(parents=True, mode=0o700)
        try:
            with zipfile.ZipFile(archive_path) as bundle:
                for info in bundle.infolist():
                    relative = _validate_archive_member(info)
                    destination = stage.joinpath(*relative.parts)
                    if info.is_dir():
                        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                        continue
                    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    digest = hashlib.sha256()
                    with bundle.open(info) as source, destination.open("wb") as output:
                        for chunk in iter(lambda: source.read(1024 * 1024), b""):
                            digest.update(chunk)
                            output.write(chunk)
                    destination.chmod(0o600)
                    normalized = relative.as_posix()
                    if normalized == "hub.checksums.json":
                        expected = inspection["checksums_sha256"]
                    else:
                        expected = inspection["checksums"].get(normalized)
                    if expected is None or not hmac.compare_digest(digest.hexdigest(), expected):
                        raise PluginError(f"Архив изменился во время установки: {normalized}")
            if not hmac.compare_digest(_file_sha256(archive_path), inspection["archive_sha256"]):
                raise PluginError("Архив изменился во время установки")
            validate_manifest(json.loads((stage / "hub.plugin.json").read_text(encoding="utf-8")))
            if target.exists():
                raise PluginError("Целевой каталог версии уже существует")
            target_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.replace(stage, target)
            activated_target = True
            now = utc_now()
            manifest_json = json.dumps(manifest, ensure_ascii=False, separators=(",", ":"))
            with self.database.transaction() as connection:
                connection.execute(
                    "INSERT INTO modules(id,name,version,description,active_path,manifest_json,enabled,"
                    "trust_status,health,installed_at,updated_at) VALUES (?,?,?,?,?,?,1,'local_unsigned',?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET name=excluded.name,version=excluded.version,"
                    "description=excluded.description,active_path=excluded.active_path,"
                    "manifest_json=excluded.manifest_json,"
                    "enabled=CASE WHEN modules.health='removed' THEN 1 ELSE modules.enabled END,"
                    "trust_status=excluded.trust_status,health=excluded.health,"
                    "installed_at=CASE WHEN modules.health='removed' "
                    "THEN excluded.installed_at ELSE modules.installed_at END,"
                    "updated_at=excluded.updated_at",
                    (
                        plugin_id,
                        manifest["name"],
                        version,
                        manifest["description"],
                        str(target),
                        manifest_json,
                        self._health(manifest, target),
                        now,
                        now,
                    ),
                )
                connection.execute(
                    "UPDATE module_versions SET active=0 WHERE module_id=?", (plugin_id,)
                )
                connection.execute(
                    "INSERT INTO module_versions(module_id,version,path,manifest_json,archive_sha256,installed_at,active) "
                    "VALUES (?,?,?,?,?,?,1)",
                    (
                        plugin_id,
                        version,
                        str(target),
                        manifest_json,
                        inspection["archive_sha256"],
                        now,
                    ),
                )
                if github_source is not None:
                    self._insert_github_source(
                        connection,
                        plugin_id=plugin_id,
                        version=version,
                        archive_sha256=inspection["archive_sha256"],
                        source=github_source,
                        installed_at=now,
                    )
        except BaseException:
            if stage.exists():
                shutil.rmtree(stage)
            if activated_target and target.exists() and not self.database.one(
                "SELECT version FROM module_versions WHERE module_id=? AND version=?",
                (plugin_id, version),
            ):
                shutil.rmtree(target)
            raise
        return self.get(plugin_id) or {}

    @staticmethod
    def _insert_github_source(
        connection: Any,
        *,
        plugin_id: str,
        version: str,
        archive_sha256: str,
        source: GitHubPackage,
        installed_at: str,
    ) -> None:
        connection.execute(
            "INSERT INTO github_module_sources("
            "module_id,version,owner,repository,release_tag,asset_name,asset_url,"
            "archive_sha256,installed_at) VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(module_id,version) DO UPDATE SET "
            "owner=excluded.owner,repository=excluded.repository,"
            "release_tag=excluded.release_tag,asset_name=excluded.asset_name,"
            "asset_url=excluded.asset_url,archive_sha256=excluded.archive_sha256",
            (
                plugin_id,
                version,
                source.owner.casefold(),
                source.repository.casefold(),
                source.release,
                source.filename,
                source.download_url,
                archive_sha256,
                installed_at,
            ),
        )

    def _bind_existing_current_github_version(
        self,
        manifest: dict[str, Any],
        existing: dict[str, Any],
        archive_sha256: str,
        source: GitHubPackage,
    ) -> None:
        plugin_id = manifest["id"]
        version = manifest["version"]
        target = self.paths.plugins / plugin_id / version
        if target.is_symlink() or Path(existing["path"]).resolve() != target.resolve():
            raise PluginError("Путь ранее установленной версии повреждён")
        if not target.is_dir():
            raise PluginError("Каталог ранее установленной версии отсутствует")
        installed_manifest = validate_manifest(
            json.loads((target / "hub.plugin.json").read_text(encoding="utf-8"))
        )
        if installed_manifest["id"] != plugin_id or installed_manifest["version"] != version:
            raise PluginError("Identity ранее установленной версии повреждён")
        now = utc_now()
        with self.database.transaction() as connection:
            self._insert_github_source(
                connection,
                plugin_id=plugin_id,
                version=version,
                archive_sha256=archive_sha256,
                source=source,
                installed_at=now,
            )

    def github_sources(self) -> list[dict[str, Any]]:
        """Return the core-owned repository bindings used by Patch Radar."""

        with self._mutation_lock:
            return self.database.all(
                "SELECT s.module_id,s.version,s.owner,s.repository,s.release_tag,"
                "s.asset_name,s.asset_url,s.archive_sha256,m.version AS active_version "
                "FROM github_module_sources AS s "
                "JOIN modules AS m ON m.id=s.module_id AND m.health!='removed' "
                "ORDER BY s.owner,s.repository,s.module_id,s.installed_at DESC"
            )

    def _health(self, manifest: dict[str, Any], path: Path) -> str:
        requirements = manifest["runtime"].get("requirements")
        if not requirements:
            return "ready"
        content = (path / requirements).read_text(encoding="utf-8")
        has_dependencies = any(
            line.strip() and not line.lstrip().startswith("#") for line in content.splitlines()
        )
        if not has_dependencies:
            return "ready"
        return "ready" if self.python_for(path, requirements) else "needs_setup"

    @staticmethod
    def _venv_python(plugin_path: Path) -> Path:
        if sys.platform == "win32":
            return plugin_path / ".venv" / "Scripts" / "python.exe"
        return plugin_path / ".venv" / "bin" / "python"

    def python_for(self, plugin_path: Path, requirements: str | None = None) -> Path | None:
        if requirements is None:
            try:
                installed_manifest = json.loads(
                    (plugin_path / "hub.plugin.json").read_text(encoding="utf-8")
                )
                requirements = installed_manifest.get("runtime", {}).get("requirements")
            except (OSError, json.JSONDecodeError, AttributeError):
                return None
        if not requirements:
            return None
        requirement_path = plugin_path / requirements
        candidate = self._venv_python(plugin_path)
        marker = plugin_path / ".venv" / ".soft-hub-ready.json"
        if not candidate.is_file() or not marker.is_file() or not requirement_path.is_file():
            return None
        try:
            state = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        expected = hashlib.sha256(requirement_path.read_bytes()).hexdigest()
        configuration = marker.parent / "pyvenv.cfg"
        if not configuration.is_file():
            return None
        try:
            home = next(
                line.split("=", 1)[1].strip()
                for line in configuration.read_text(encoding="utf-8").splitlines()
                if line.partition("=")[0].strip().lower() == "home"
            )
        except (OSError, StopIteration):
            return None
        expected_home = Path(sys.executable).resolve().parent
        if Path(home).expanduser().resolve() != expected_home:
            return None
        return candidate if (
            state.get("requirements_sha256") == expected
            and state.get("runtime_id") == runtime_fingerprint()
        ) else None

    def prepare(self, plugin_id: str) -> dict[str, Any]:
        with self._mutation_lock:
            return self._prepare(plugin_id)

    def _prepare(self, plugin_id: str) -> dict[str, Any]:
        module = self.get(plugin_id)
        if not module:
            raise PluginError("Плагин не найден")
        path = Path(module["active_path"])
        requirements = module["manifest"]["runtime"].get("requirements")
        if not requirements:
            return module
        requirement_path = path / requirements
        if not requirement_path.is_file():
            raise PluginError("Файл зависимостей не найден")
        if self.database.one(
            "SELECT id FROM runs WHERE module_id=? "
            "AND status IN ('queued','starting','running','cancelling') LIMIT 1",
            (plugin_id,),
        ):
            raise PluginError("Нельзя перестраивать окружение во время активного запуска")
        environment = path / ".venv"
        current_python = self.python_for(path, requirements)
        if current_python is None and environment.exists():
            shutil.rmtree(environment)
        candidate = self._venv_python(path)
        if not candidate.is_file():
            venv.EnvBuilder(with_pip=True, clear=False).create(environment)
        python = self._venv_python(path)
        if not python.is_file():
            raise PluginError("Не удалось создать Python environment")
        marker = environment / ".soft-hub-ready.json"
        marker.unlink(missing_ok=True)
        self.database.execute(
            "UPDATE modules SET health='needs_setup',updated_at=? WHERE id=?",
            (utc_now(), plugin_id),
        )
        pip_wheel = bundled_pip_wheel()
        pip_requirement = str(pip_wheel) if pip_wheel else "pip>=26.1.2,<27"
        pip_command = [
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--upgrade",
        ]
        if pip_wheel:
            pip_command.append("--no-index")
        pip_command.append(pip_requirement)
        pip_upgrade = subprocess.run(
            pip_command,
            cwd=path,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if pip_upgrade.returncode != 0:
            raise PluginError("Не удалось подготовить безопасный pip для окружения плагина")
        completed = subprocess.run(
            [str(python), "-m", "pip", "install", "--disable-pip-version-check", "-r", str(requirement_path)],
            cwd=path,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        if completed.returncode != 0:
            raise PluginError("Не удалось установить зависимости плагина; подробности в журнале Hub")
        marker_temporary = environment / f".soft-hub-ready-{uuid.uuid4()}.tmp"
        marker_temporary.write_text(
            json.dumps(
                {
                    "requirements_sha256": hashlib.sha256(requirement_path.read_bytes()).hexdigest(),
                    "runtime_id": runtime_fingerprint(),
                    "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                    "prepared_at": utc_now(),
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        try:
            marker_temporary.chmod(0o600)
        except OSError:
            pass
        os.replace(marker_temporary, marker)
        self.database.execute("UPDATE modules SET health='ready',updated_at=? WHERE id=?", (utc_now(), plugin_id))
        return self.get(plugin_id) or {}

    def uninstall(self, plugin_id: str) -> dict[str, Any]:
        """Remove Hub-owned code while preserving historical run/result foreign keys."""
        if not isinstance(plugin_id, str) or not _ID_RE.fullmatch(plugin_id):
            raise PluginError("Плагин не найден")
        with self._mutation_lock:
            quarantine: Path | None = None
            plugin_root = self.paths.plugins / plugin_id
            try:
                with self.database.transaction() as connection:
                    module_row = connection.execute(
                        "SELECT * FROM modules WHERE id=? AND health!='removed'",
                        (plugin_id,),
                    ).fetchone()
                    if not module_row:
                        raise PluginError("Плагин не найден")
                    blocker = connection.execute(
                        "SELECT id,status FROM runs WHERE module_id=? "
                        "AND status IN ('queued','starting','running','cancelling','needs_attention') "
                        "ORDER BY requested_at DESC LIMIT 1",
                        (plugin_id,),
                    ).fetchone()
                    if blocker:
                        if blocker["status"] == "needs_attention":
                            raise PluginError(
                                "Нельзя удалить плагин: сначала выполните внешнюю сверку запуска needs_attention"
                            )
                        raise PluginError("Нельзя удалить плагин, пока у него есть активный запуск")

                    version_rows = connection.execute(
                        "SELECT version,path FROM module_versions WHERE module_id=?",
                        (plugin_id,),
                    ).fetchall()
                    self._validate_managed_install_paths(
                        plugin_id,
                        dict(module_row),
                        [dict(row) for row in version_rows],
                    )
                    if plugin_root.is_symlink():
                        raise PluginError("Каталог плагина повреждён; удаление остановлено")
                    if plugin_root.exists():
                        if not plugin_root.is_dir():
                            raise PluginError("Каталог плагина повреждён; удаление остановлено")
                        quarantine = self.paths.staging / f"uninstall-{uuid.uuid4()}"
                        os.replace(plugin_root, quarantine)

                    connection.execute(
                        "DELETE FROM module_versions WHERE module_id=?",
                        (plugin_id,),
                    )
                    connection.execute(
                        "UPDATE modules SET active_path='',enabled=0,health='removed',updated_at=? "
                        "WHERE id=?",
                        (utc_now(), plugin_id),
                    )
            except BaseException:
                if quarantine is not None and quarantine.exists() and not plugin_root.exists():
                    try:
                        os.replace(quarantine, plugin_root)
                    except OSError as restore_error:
                        raise PluginError(
                            "Удаление прервано, но каталог плагина не удалось восстановить"
                        ) from restore_error
                raise

            cleanup_pending = False
            if quarantine is not None:
                try:
                    shutil.rmtree(quarantine)
                except OSError:
                    # The quarantined tree is no longer executable or addressable by a
                    # module record. Report the residue explicitly instead of following
                    # an untrusted path or pretending cleanup completed.
                    cleanup_pending = True
            return {
                "id": plugin_id,
                "removed": True,
                "cleanup_pending": cleanup_pending,
            }

    def _validate_managed_install_paths(
        self,
        plugin_id: str,
        module: dict[str, Any],
        versions: list[dict[str, Any]],
    ) -> None:
        plugin_root = self.paths.plugins / plugin_id
        if self.paths.plugins.is_symlink():
            raise PluginError("Корневой каталог plugins повреждён; удаление остановлено")
        managed_root = self.paths.plugins.resolve()
        if plugin_root.parent.resolve() != managed_root or plugin_root.is_symlink():
            raise PluginError("Каталог плагина повреждён; удаление остановлено")

        expected_active = plugin_root / str(module["version"])
        candidates = [(str(module["version"]), module["active_path"])] + [
            (str(row["version"]), row["path"]) for row in versions
        ]
        for version, stored_path in candidates:
            if not _VERSION_RE.fullmatch(version) or not isinstance(stored_path, str):
                raise PluginError("Пути плагина повреждены; удаление остановлено")
            expected = plugin_root / version
            if expected.is_symlink() or Path(stored_path).resolve() != expected.resolve():
                raise PluginError("Пути плагина повреждены; удаление остановлено")
        if Path(module["active_path"]).resolve() != expected_active.resolve():
            raise PluginError("Пути плагина повреждены; удаление остановлено")

    def set_enabled(self, plugin_id: str, enabled: bool) -> dict[str, Any]:
        with self._mutation_lock:
            if not self.database.execute(
                "UPDATE modules SET enabled=?,updated_at=? WHERE id=? AND health!='removed'",
                (int(enabled), utc_now(), plugin_id),
            ):
                raise PluginError("Плагин не найден")
            return self.get(plugin_id) or {}

    def get(self, plugin_id: str) -> dict[str, Any] | None:
        with self._mutation_lock:
            row = self.database.one(
                "SELECT * FROM modules WHERE id=? AND health!='removed'", (plugin_id,)
            )
            if not row:
                return None
            return self._present(row)

    def list(self) -> list[dict[str, Any]]:
        with self._mutation_lock:
            return [
                self._present(row)
                for row in self.database.all(
                    "SELECT * FROM modules WHERE health!='removed' ORDER BY name"
                )
            ]

    def _present(self, row: dict[str, Any]) -> dict[str, Any]:
        row["enabled"] = bool(row["enabled"])
        row["manifest"] = json.loads(row.pop("manifest_json"))
        return row
