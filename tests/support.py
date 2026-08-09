from __future__ import annotations

import hashlib
import json
import stat
import time
import zipfile
from pathlib import Path
from typing import Any, Mapping


TEST_MASTER_PASSWORD = "Correct Horse 42!"
TEST_PRIVATE_KEY_A = "0x" + "11" * 32
TEST_PRIVATE_KEY_B = "0x" + "22" * 32
TEST_PRIVATE_KEY_C = "0x" + "33" * 32


def plugin_manifest(
    version: str = "1.0.0",
    *,
    plugin_id: str = "test.plugin",
    entrypoint: str = "plugin.main:run",
    requirements: str | None = None,
    action_risk: str = "read",
    account_mode: str = "none",
    secrets: list[str] | None = None,
    chains: list[int] | None = None,
    safe_stop: bool = True,
) -> dict[str, Any]:
    runtime: dict[str, Any] = {
        "type": "python",
        "entrypoint": entrypoint,
        "protocol": "soft-hub-jsonl/1",
        "state_model": "stateless",
        "safe_stop": safe_stop,
    }
    if requirements is not None:
        runtime["requirements"] = requirements
    action: dict[str, Any] = {
        "id": "run",
        "name": "Run",
        "description": "Deterministic test action",
        "risk": action_risk,
        "account_mode": account_mode,
    }
    if action_risk == "mainnet_write":
        action["confirmation_phrase"] = "CONFIRM TEST MAINNET"
    return {
        "schema_version": 1,
        "id": plugin_id,
        "name": "Test Plugin",
        "version": version,
        "description": "A deterministic plugin fixture",
        "compatibility": {"hub": ">=0.1.0", "os": ["darwin", "win32", "linux"]},
        "runtime": runtime,
        "permissions": {
            "secrets": list(secrets or []),
            "network": [],
            "chains": list(chains or []),
            "financial_risk": (
                "mainnet" if action_risk == "mainnet_write" else
                "testnet" if action_risk == "testnet_write" else
                "none"
            ),
        },
        "actions": [action],
        "ui": {"accent": "#123456", "monogram": "TST"},
    }


def regular_zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def directory_zip_info(name: str) -> zipfile.ZipInfo:
    normalized = name if name.endswith("/") else name + "/"
    info = zipfile.ZipInfo(normalized, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFDIR | 0o755) << 16
    return info


def symlink_zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    return info


def archive_payloads(
    manifest: Mapping[str, Any] | None = None,
    files: Mapping[str, bytes | str] | None = None,
) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {
        "hub.plugin.json": json.dumps(
            dict(manifest or plugin_manifest()),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8"),
        "plugin/__init__.py": b"",
        "plugin/main.py": b"def run(context):\n    return {'ok': True}\n",
    }
    for name, payload in (files or {}).items():
        payloads[name] = payload.encode("utf-8") if isinstance(payload, str) else payload
    return payloads


def write_plugin_archive(
    output: Path,
    manifest: Mapping[str, Any] | None = None,
    *,
    files: Mapping[str, bytes | str] | None = None,
    checksum_overrides: Mapping[str, str] | None = None,
    checksum_names: set[str] | None = None,
) -> Path:
    payloads = archive_payloads(manifest, files)
    names = set(payloads) if checksum_names is None else set(checksum_names)
    checksums = {
        name: hashlib.sha256(payloads[name]).hexdigest()
        for name in names
        if name in payloads
    }
    checksums.update(checksum_overrides or {})
    with zipfile.ZipFile(output, "w") as bundle:
        for name, payload in payloads.items():
            bundle.writestr(regular_zip_info(name), payload)
        bundle.writestr(
            regular_zip_info("hub.checksums.json"),
            json.dumps(checksums, sort_keys=True).encode("utf-8"),
        )
    return output


def wait_until(predicate: Any, timeout: float = 10.0, interval: float = 0.02) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError(f"Condition was not met within {timeout:.1f}s")
