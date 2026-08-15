#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from soft_hub.config import HubPaths
from soft_hub.database import Database
from soft_hub.plugins import (
    PluginManager,
    STRICT_CONTRACT_VERSION,
    secret_material_reason,
    secret_payload_reason,
    validate_manifest,
)

IGNORED_PARTS = {"__pycache__", ".venv", ".git", ".DS_Store"}


def files_for(source: Path) -> list[Path]:
    files: list[Path] = []
    for path in source.rglob("*"):
        relative = path.relative_to(source)
        if any(part in IGNORED_PARTS for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError(f"Symlink запрещён: {relative}")
        if path.is_file() and relative.as_posix() != "hub.checksums.json":
            if reason := secret_material_reason(relative):
                raise ValueError(
                    f"Патч содержит запрещённый {reason}: {relative}. "
                    "Передавайте такие значения только через Vault."
                )
            files.append(path)
    return sorted(files, key=lambda item: item.relative_to(source).as_posix())


def zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.create_system = 3
    return info


def build(source: Path, output: Path) -> Path:
    source = source.resolve()
    output = output.expanduser().resolve()
    if output == source or source in output.parents:
        raise ValueError("Выходной архив должен находиться вне source-каталога")
    manifest_path = source / "hub.plugin.json"
    if not manifest_path.is_file():
        raise ValueError("В source отсутствует hub.plugin.json")
    manifest = validate_manifest(
        json.loads(manifest_path.read_text(encoding="utf-8"))
    )
    if manifest.get("contract_version") != STRICT_CONTRACT_VERSION:
        raise ValueError(
            "Штатный builder выпускает только новые пакеты контракта "
            f"{STRICT_CONTRACT_VERSION}. Legacy-пакеты остаются совместимыми "
            "с установщиком, но не должны пересобираться как новый релиз."
        )
    files = files_for(source)
    checksums: dict[str, str] = {}
    payloads: dict[str, bytes] = {}
    for path in files:
        name = unicodedata.normalize(
            "NFC", PurePosixPath(path.relative_to(source)).as_posix()
        )
        if name in payloads:
            raise ValueError(f"Пути конфликтуют после Unicode NFC normalization: {name}")
        payload = path.read_bytes()
        if reason := secret_payload_reason(payload):
            raise ValueError(
                f"Патч содержит запрещённый {reason}: {name}. "
                "Передавайте ключевой материал только через Vault."
            )
        payloads[name] = payload
        checksums[name] = hashlib.sha256(payload).hexdigest()
    checksums_payload = (json.dumps(checksums, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with zipfile.ZipFile(temporary, "w") as archive:
        for name, payload in payloads.items():
            archive.writestr(zip_info(name), payload)
        archive.writestr(zip_info("hub.checksums.json"), checksums_payload)
    # The author must receive the same answer as the end-user installer. Run
    # the complete archive inspection before publishing the deterministic file.
    with tempfile.TemporaryDirectory(prefix="soft-hub-builder-inspection-") as root:
        paths = HubPaths.create(Path(root))
        PluginManager(Database(paths), paths).inspect_archive(temporary)
    os.replace(temporary, output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Build deterministic Soft Hub plugin package")
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    result = build(arguments.source, arguments.output)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
