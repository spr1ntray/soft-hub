from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLERS_DIR = PROJECT_ROOT / "INSTALLERS"
STAGING_NAMES = {
    ".icon-icns",
    ".icon-ico",
    "mac",
    "mac-arm64",
    "mac-universal",
    "win-unpacked",
}
METADATA_NAMES = {
    "builder-debug.yml",
    "builder-effective-config.yaml",
    "latest-mac.yml",
    "latest.yml",
}
INSTALLER_RE = re.compile(r"^Soft Hub-(?P<version>\d+\.\d+\.\d+)-.+\.(?:dmg|exe)$")
SIDECAR_SUFFIXES = (".blockmap", ".sha256")


def _package_version() -> str:
    payload = json.loads((PROJECT_ROOT / "package.json").read_text(encoding="utf-8"))
    version = payload.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise RuntimeError("package.json содержит некорректную версию")
    return version


def _validate_installers_directory() -> None:
    project_root = PROJECT_ROOT.resolve()
    if not project_root.is_dir():
        raise RuntimeError(f"Корень проекта недоступен: {project_root}")
    if INSTALLERS_DIR.is_symlink():
        raise RuntimeError("Отказ от очистки: INSTALLERS не должен быть symlink")
    resolved = INSTALLERS_DIR.resolve()
    if resolved.parent != project_root:
        raise RuntimeError(f"Отказ от очистки вне корня проекта: {resolved}")
    if INSTALLERS_DIR.exists() and not INSTALLERS_DIR.is_dir():
        raise RuntimeError("Отказ от очистки: INSTALLERS не является каталогом")


def _remove(path: Path) -> None:
    resolved = path.resolve()
    if resolved.parent != INSTALLERS_DIR.resolve():
        raise RuntimeError(f"Отказ от удаления вне INSTALLERS: {resolved}")
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)
    print(f"removed {path.relative_to(PROJECT_ROOT)}")


def clean(*, before_build: bool, platform: str | None = None) -> None:
    _validate_installers_directory()
    INSTALLERS_DIR.mkdir(parents=True, exist_ok=True)
    current_version = _package_version()

    for path in sorted(INSTALLERS_DIR.iterdir(), key=lambda item: item.name):
        name = path.name

        if name.endswith(".softhub.zip"):
            _remove(path)
            continue
        if name in STAGING_NAMES or name in METADATA_NAMES:
            _remove(path)
            continue
        if name.endswith(SIDECAR_SUFFIXES):
            _remove(path)
            continue

        installer = INSTALLER_RE.fullmatch(name)
        if installer:
            stale_version = installer.group("version") != current_version
            target_platform = (
                platform == "mac" and name.endswith(".dmg")
            ) or (
                platform == "win" and name.endswith(".exe")
            )
            if stale_version or (before_build and target_platform):
                _remove(path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Remove stale Soft Hub installers and electron-builder staging output."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--before",
        action="store_true",
        help="remove stale installers and replace the selected platform",
    )
    mode.add_argument("--after", action="store_true", help="keep only installers for package.json version")
    parser.add_argument(
        "--platform",
        choices=("mac", "win"),
        help="installer family being replaced; required with --before",
    )
    args = parser.parse_args()
    if args.before and args.platform is None:
        parser.error("--before требует --platform mac или --platform win")
    clean(before_build=args.before, platform=args.platform)


if __name__ == "__main__":
    main()
