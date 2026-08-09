from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLERS_DIR = PROJECT_ROOT / "INSTALLERS"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums() -> Path:
    package = json.loads((PROJECT_ROOT / "package.json").read_text(encoding="utf-8"))
    version = package.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise RuntimeError("package.json содержит некорректную версию")
    if not INSTALLERS_DIR.is_dir() or INSTALLERS_DIR.is_symlink():
        raise RuntimeError("INSTALLERS недоступен или является symlink")

    installers = sorted(
        path
        for path in INSTALLERS_DIR.iterdir()
        if path.is_file()
        and re.fullmatch(rf"Soft Hub-{re.escape(version)}-.+\.(?:dmg|exe)", path.name)
    )
    if not installers:
        raise RuntimeError(f"Установщики Soft Hub {version} не найдены")

    destination = INSTALLERS_DIR / "SHA256SUMS"
    temporary = INSTALLERS_DIR / ".SHA256SUMS.tmp"
    payload = "".join(f"{_sha256(path)}  {path.name}\n" for path in installers)
    temporary.write_text(payload, encoding="utf-8", newline="\n")
    os.replace(temporary, destination)
    destination.chmod(0o644)
    print(f"checksums written: {destination.relative_to(PROJECT_ROOT)}")
    return destination


if __name__ == "__main__":
    write_checksums()
