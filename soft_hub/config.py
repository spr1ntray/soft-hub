from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path

APP_NAME = "Soft Hub"
APP_VERSION = "0.6.11"
PLUGIN_SCHEMA_VERSION = 1
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_UNPACKED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_FILES = 4_000
MAX_JSON_BYTES = 2 * 1024 * 1024


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def managed_runtime() -> tuple[Path, dict[str, object]] | None:
    executable = Path(sys.executable).resolve()
    candidates = [executable.parent, executable.parent.parent]
    for root in candidates:
        marker = root / "soft-hub-runtime.json"
        if not marker.is_file():
            continue
        try:
            state = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(state, dict):
            continue
        runtime_id = state.get("runtime_id")
        if isinstance(runtime_id, str) and runtime_id:
            return root, state
    return None


def runtime_fingerprint() -> str:
    """Stable plugin-ABI identity for the interpreter hosting Soft Hub."""
    managed = managed_runtime()
    if managed:
        return str(managed[1]["runtime_id"])
    executable = Path(sys.executable).resolve()
    executable_id = hashlib.sha256(str(executable).encode()).hexdigest()[:16]
    return (
        f"developer-python:{sys.version_info.major}.{sys.version_info.minor}."
        f"{sys.version_info.micro}:{platform.machine().lower()}:{executable_id}"
    )


def bundled_pip_wheel() -> Path | None:
    managed = managed_runtime()
    if not managed:
        return None
    root, state = managed
    relative = state.get("pip_wheel")
    if not isinstance(relative, str) or not relative:
        return None
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def default_data_dir() -> Path:
    override = os.environ.get("SOFT_HUB_DATA_DIR", "").strip()
    if override:
        return Path(override).expanduser().resolve()

    system = platform.system()
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    if system == "Windows":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return base / APP_NAME
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "soft-hub"


@dataclass(frozen=True, slots=True)
class HubPaths:
    data_dir: Path

    @classmethod
    def create(cls, data_dir: Path | str | None = None) -> "HubPaths":
        root = Path(data_dir).expanduser().resolve() if data_dir else default_data_dir()
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for child in ("plugins", "plugins/.staging", "imports", "logs", "runs"):
            (root / child).mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            root.chmod(0o700)
        except OSError:
            pass
        return cls(data_dir=root)

    @property
    def database(self) -> Path:
        return self.data_dir / "hub.sqlite3"

    @property
    def plugins(self) -> Path:
        return self.data_dir / "plugins"

    @property
    def staging(self) -> Path:
        return self.plugins / ".staging"

    @property
    def imports(self) -> Path:
        return self.data_dir / "imports"

    @property
    def runs(self) -> Path:
        return self.data_dir / "runs"
