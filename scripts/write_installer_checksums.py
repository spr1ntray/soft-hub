from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLERS_DIR = PROJECT_ROOT / "INSTALLERS"
_VERSION_PATTERN = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
RELEASE_ARTIFACT_RE = re.compile(
    rf"^Soft-Hub-(?P<version>{_VERSION_PATTERN})-"
    r"(?P<target>arm64\.dmg|x64\.exe)$"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(*, require_complete: bool = False) -> Path:
    package = json.loads((PROJECT_ROOT / "package.json").read_text(encoding="utf-8"))
    version = package.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise RuntimeError("package.json содержит некорректную версию")
    if not INSTALLERS_DIR.is_dir() or INSTALLERS_DIR.is_symlink():
        raise RuntimeError("INSTALLERS недоступен или является symlink")

    installers: list[Path] = []
    for path in sorted(INSTALLERS_DIR.iterdir(), key=lambda item: item.name):
        artifact = RELEASE_ARTIFACT_RE.fullmatch(path.name)
        if artifact and artifact.group("version") == version:
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(f"Release artifact недоступен или является symlink: {path.name}")
            if path.stat().st_size <= 0:
                raise RuntimeError(f"Release artifact пуст: {path.name}")
            installers.append(path)

    if not installers:
        raise RuntimeError(f"Установщики Soft Hub {version} не найдены")
    if require_complete:
        expected = {
            f"Soft-Hub-{version}-arm64.dmg",
            f"Soft-Hub-{version}-x64.exe",
        }
        actual = {path.name for path in installers}
        if actual != expected:
            missing = ", ".join(sorted(expected - actual)) or "—"
            raise RuntimeError(
                f"Неполный набор Soft Hub {version}; отсутствуют: {missing}"
            )

    destination = INSTALLERS_DIR / "SHA256SUMS"
    temporary = INSTALLERS_DIR / ".SHA256SUMS.tmp"
    payload = "".join(f"{_sha256(path)}  {path.name}\n" for path in installers)
    temporary.write_text(payload, encoding="utf-8", newline="\n")
    os.replace(temporary, destination)
    destination.chmod(0o644)
    print(f"checksums written: {destination.relative_to(PROJECT_ROOT)}")
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="require both macOS arm64 and Windows x64 installers",
    )
    arguments = parser.parse_args()
    write_checksums(require_complete=arguments.require_complete)
