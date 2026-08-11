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
_VERSION_PATTERN = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
RELEASE_ARTIFACT_RE = re.compile(
    rf"^Soft-Hub-(?P<version>{_VERSION_PATTERN})-"
    r"(?P<target>arm64\.dmg|x64\.exe)$"
)
UNNEEDED_RELEASE_ARTIFACT_RE = re.compile(
    rf"^Soft-Hub-(?P<version>{_VERSION_PATTERN})-"
    r"(?:arm64|x64)\.(?:dmg|exe|zip)(?:\.blockmap)?$"
)
LEGACY_ARTIFACT_RE = re.compile(
    rf"^Soft(?: |\.)Hub-(?P<version>{_VERSION_PATTERN})-.+"
    r"\.(?:dmg|exe|zip)(?:\.blockmap)?$"
)
_CHECKSUM_LINE_RE = re.compile(
    r"^[0-9a-f]{64}  (?P<name>[A-Za-z0-9][A-Za-z0-9._-]{0,239})$"
)


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


def _artifact_platform(name: str) -> str | None:
    match = RELEASE_ARTIFACT_RE.fullmatch(name)
    if match:
        return "win" if match.group("target") == "x64.exe" else "mac"
    return None


def _checksums_are_current(path: Path, current_version: str) -> bool:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024:
        return False
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return False
    if not lines:
        return False
    installer_found = False
    seen_names: set[str] = set()
    for line in lines:
        match = _CHECKSUM_LINE_RE.fullmatch(line)
        if match is None:
            return False
        name = match.group("name")
        artifact = RELEASE_ARTIFACT_RE.fullmatch(name)
        installer = INSTALLERS_DIR / name
        if (
            artifact is None
            or artifact.group("version") != current_version
            or name.casefold() in seen_names
            or installer.is_symlink()
            or not installer.is_file()
        ):
            return False
        seen_names.add(name.casefold())
        installer_found = True
    return installer_found


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
        if name == "SHA256SUMS":
            if before_build or not _checksums_are_current(path, current_version):
                _remove(path)
            continue
        if LEGACY_ARTIFACT_RE.fullmatch(name):
            _remove(path)
            continue
        artifact = RELEASE_ARTIFACT_RE.fullmatch(name)
        if artifact:
            version = artifact.group("version")
            if version != current_version or (
                before_build and platform == _artifact_platform(name)
            ):
                _remove(path)
            continue
        if UNNEEDED_RELEASE_ARTIFACT_RE.fullmatch(name):
            _remove(path)
            continue
        if name.endswith((".blockmap", ".sha256")):
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
