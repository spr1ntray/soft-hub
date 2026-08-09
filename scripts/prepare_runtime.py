#!/usr/bin/env python3
from __future__ import annotations

import argparse
import email.parser
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUILD_ROOT = PROJECT_ROOT / "build"
RUNTIME_ROOT = BUILD_ROOT / "runtime"
CACHE_ROOT = BUILD_ROOT / "runtime-cache"
RUNTIME_LOCK = PROJECT_ROOT / "requirements-runtime.lock"
PIP_REQUIREMENT = "pip==26.2.1"


@dataclass(frozen=True, slots=True)
class RuntimeSpec:
    os_name: str
    arch: str
    python_version: str
    release: str
    filename: str
    sha256: str
    pip_platform: str

    @property
    def url(self) -> str:
        escaped = self.filename.replace("+", "%2B")
        return (
            "https://github.com/astral-sh/python-build-standalone/releases/download/"
            f"{self.release}/{escaped}"
        )

    @property
    def runtime_id(self) -> str:
        lock_hash = _file_sha256(RUNTIME_LOCK)[:16]
        return (
            f"python-build-standalone:{self.release}:cpython-{self.python_version}:"
            f"{self.os_name}-{self.arch}:{lock_hash}"
        )


SPECS = {
    ("darwin", "arm64"): RuntimeSpec(
        os_name="darwin",
        arch="arm64",
        python_version="3.12.13",
        release="20260805",
        filename=(
            "cpython-3.12.13+20260805-aarch64-apple-darwin-"
            "install_only_stripped.tar.gz"
        ),
        sha256="a4b36035915038104aabee94d6f02827161da444296881fe4493cb98f70304b2",
        pip_platform="macosx_11_0_arm64",
    ),
    ("darwin", "x64"): RuntimeSpec(
        os_name="darwin",
        arch="x64",
        python_version="3.12.13",
        release="20260805",
        filename=(
            "cpython-3.12.13+20260805-x86_64-apple-darwin-"
            "install_only_stripped.tar.gz"
        ),
        sha256="0d232711501680a619ea6113046603567d93be3218e326e4357557e771d1aec7",
        pip_platform="macosx_10_13_x86_64",
    ),
    ("win32", "x64"): RuntimeSpec(
        os_name="win32",
        arch="x64",
        python_version="3.12.13",
        release="20260805",
        filename=(
            "cpython-3.12.13+20260805-x86_64-pc-windows-msvc-"
            "install_only_stripped.tar.gz"
        ),
        sha256="b304536477587bbb729322b77ac1c59bdb95706651ab2ef38cae0fec77ede00f",
        pip_platform="win_amd64",
    ),
}

TARGET_ALIASES = {
    "darwin-arm64": ("darwin", "arm64"),
    "darwin-x64": ("darwin", "x64"),
    "mac-arm64": ("darwin", "arm64"),
    "mac-x64": ("darwin", "x64"),
    "win-x64": ("win32", "x64"),
    "win32-x64": ("win32", "x64"),
}
_REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)$")
_PE_AMD64 = 0x8664


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_sha256() -> str:
    digest = hashlib.sha256()
    roots = [PROJECT_ROOT / "soft_hub"]
    explicit = [
        PROJECT_ROOT / "pyproject.toml",
        RUNTIME_LOCK,
        Path(__file__).resolve(),
    ]
    files = [
        path
        for root in roots
        for path in root.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    ]
    files.extend(path for path in explicit if path.is_file())
    for path in sorted(files, key=lambda item: item.relative_to(PROJECT_ROOT).as_posix()):
        relative = path.relative_to(PROJECT_ROOT).as_posix().encode()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _host_key(*, required: bool = True) -> tuple[str, str] | None:
    os_name = {"Darwin": "darwin", "Windows": "win32"}.get(platform.system())
    machine = platform.machine().lower()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "x64" if machine in {
        "x86_64",
        "amd64",
    } else None
    if (not os_name or not arch) and required:
        raise SystemExit(f"Release runtime не поддерживает host {platform.system()} {machine}")
    return (os_name, arch) if os_name and arch else None


def _resolve_spec(target: str) -> RuntimeSpec:
    if target == "host":
        key = _host_key()
        assert key is not None
    else:
        key = TARGET_ALIASES.get(target)
        if key is None:
            raise SystemExit(f"Неизвестная цель runtime: {target}")
    spec = SPECS.get(key)
    if spec is None:
        raise SystemExit(f"Нет закреплённого runtime для {key[0]} {key[1]}")
    return spec


def _is_native_target(spec: RuntimeSpec) -> bool:
    return _host_key(required=False) == (spec.os_name, spec.arch)


def _python_path(root: Path, spec: RuntimeSpec) -> Path:
    return root / ("python.exe" if spec.os_name == "win32" else "bin/python3")


def _purelib_path(root: Path, spec: RuntimeSpec) -> Path:
    if spec.os_name == "win32":
        return root / "Lib" / "site-packages"
    return root / "lib" / f"python{'.'.join(spec.python_version.split('.')[:2])}" / "site-packages"


def _download(spec: RuntimeSpec) -> Path:
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    archive = CACHE_ROOT / spec.filename
    if archive.is_file() and _file_sha256(archive) == spec.sha256:
        return archive
    archive.unlink(missing_ok=True)
    temporary = archive.with_suffix(archive.suffix + ".part")
    temporary.unlink(missing_ok=True)
    request = urllib.request.Request(spec.url, headers={"User-Agent": "Soft-Hub-Builder/0.3"})
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                digest.update(chunk)
                output.write(chunk)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    actual = digest.hexdigest()
    if actual != spec.sha256:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(f"SHA-256 runtime не совпал: {actual}")
    os.replace(temporary, archive)
    return archive


def _clean_environment(runtime: Path, spec: RuntimeSpec) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV", "__PYVENV_LAUNCHER__"}
    }
    environment.update(
        {
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_CACHE_DIR": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
        }
    )
    bin_dir = runtime if spec.os_name == "win32" else runtime / "bin"
    environment["PATH"] = str(bin_dir) + os.pathsep + environment.get("PATH", "")
    return environment


def _builder_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV", "__PYVENV_LAUNCHER__"}
    }
    environment.update(
        {
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_CACHE_DIR": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
        }
    )
    return environment


def _run(command: list[str], *, environment: dict[str, str]) -> str:
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=900,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"Команда завершилась с code {completed.returncode}: {' '.join(command)}\n"
            + completed.stdout[-12_000:]
        )
    return completed.stdout


def _copy_core(runtime: Path, spec: RuntimeSpec) -> None:
    purelib = _purelib_path(runtime, spec)
    purelib.mkdir(parents=True, exist_ok=True)
    destination = purelib / "soft_hub"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(
        PROJECT_ROOT / "soft_hub",
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )


def _prune_dependency_test_suites(runtime: Path, spec: RuntimeSpec) -> None:
    """Remove dependency self-test fixtures (some contain published sample keys)."""
    purelib = _purelib_path(runtime, spec)
    relative_suites = (
        "Crypto/SelfTest",
        "cytoolz/tests",
        "parsimonious/tests",
        "regex/tests",
        "toolz/sandbox/tests",
        "toolz/tests",
    )
    for relative in relative_suites:
        candidate = purelib.joinpath(*relative.split("/"))
        if candidate.is_dir():
            shutil.rmtree(candidate)


def _cross_pip_install_command(spec: RuntimeSpec, destination: Path) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--no-compile",
        "--only-binary=:all:",
        "--platform",
        spec.pip_platform,
        "--implementation",
        "cp",
        "--python-version",
        ".".join(spec.python_version.split(".")[:2]),
        "--abi",
        "cp" + "".join(spec.python_version.split(".")[:2]),
        "--no-deps",
        "--upgrade",
        "--target",
        str(destination),
        "--requirement",
        str(RUNTIME_LOCK),
    ]


def _install_dependencies(runtime: Path, spec: RuntimeSpec) -> None:
    purelib = _purelib_path(runtime, spec)
    if not _is_native_target(spec) and purelib.exists():
        # Cross-target pip cannot uninstall packages from an interpreter it cannot
        # execute. Start from an empty site-packages instead of leaving the pip
        # bundled in the upstream archive next to the exact locked pip version.
        shutil.rmtree(purelib)
    purelib.mkdir(parents=True, exist_ok=True)
    if _is_native_target(spec):
        python = _python_path(runtime, spec)
        _run(
            [
                str(python),
                "-I",
                "-m",
                "pip",
                "install",
                "--no-cache-dir",
                "--requirement",
                str(RUNTIME_LOCK),
            ],
            environment=_clean_environment(runtime, spec),
        )
        return
    _run(
        _cross_pip_install_command(spec, purelib),
        environment=_builder_environment(),
    )


def _download_pip_wheel(runtime: Path, spec: RuntimeSpec) -> Path:
    wheel_dir = runtime / "soft-hub-wheels"
    wheel_dir.mkdir(mode=0o755)
    if _is_native_target(spec):
        command = [str(_python_path(runtime, spec)), "-I", "-m", "pip"]
        environment = _clean_environment(runtime, spec)
    else:
        command = [sys.executable, "-I", "-m", "pip"]
        environment = _builder_environment()
    _run(
        [
            *command,
            "download",
            "--no-deps",
            "--only-binary=:all:",
            "--dest",
            str(wheel_dir),
            PIP_REQUIREMENT,
        ],
        environment=environment,
    )
    pip_wheels = sorted(wheel_dir.glob("pip-*.whl"))
    if len(pip_wheels) != 1:
        raise RuntimeError("Не удалось закрепить offline pip wheel")
    return pip_wheels[0]


def _canonical_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _locked_distributions() -> dict[str, str]:
    locked: dict[str, str] = {}
    for line_number, raw in enumerate(RUNTIME_LOCK.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _REQUIREMENT_RE.fullmatch(line)
        if match is None:
            raise RuntimeError(
                f"requirements-runtime.lock:{line_number} должен содержать точный name==version"
            )
        name = _canonical_distribution_name(match.group(1))
        if name in locked:
            raise RuntimeError(f"Дублирующаяся runtime-зависимость: {name}")
        locked[name] = match.group(2)
    return locked


def _installed_distributions(purelib: Path) -> dict[str, str]:
    installed: dict[str, str] = {}
    parser = email.parser.Parser()
    for metadata_path in sorted(purelib.glob("*.dist-info/METADATA")):
        try:
            metadata = parser.parsestr(metadata_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError):
            continue
        name = metadata.get("Name")
        version = metadata.get("Version")
        if name and version:
            installed[_canonical_distribution_name(name)] = version
    return installed


def _pe_machine(path: Path) -> int:
    payload = path.read_bytes()
    if len(payload) < 64 or payload[:2] != b"MZ":
        raise RuntimeError(f"Windows runtime содержит не-PE файл: {path.name}")
    offset = int.from_bytes(payload[60:64], "little")
    if offset < 64 or offset + 6 > len(payload) or payload[offset : offset + 4] != b"PE\0\0":
        raise RuntimeError(f"Windows runtime содержит повреждённый PE: {path.name}")
    return int.from_bytes(payload[offset + 4 : offset + 6], "little")


def _validate_windows_layout(runtime: Path, spec: RuntimeSpec) -> None:
    if spec.arch != "x64":
        raise RuntimeError(f"Неизвестная Windows-архитектура runtime: {spec.arch}")
    required = [
        runtime / "python.exe",
        runtime / "python312.dll",
        runtime / "vcruntime140.dll",
        runtime / "vcruntime140_1.dll",
    ]
    if not all(path.is_file() for path in required):
        raise RuntimeError("Windows runtime не содержит Python/MSVC runtime DLL")
    native_extensions = sorted(runtime.rglob("*.pyd"))
    if not native_extensions:
        raise RuntimeError("Windows runtime не содержит закреплённых native wheels")
    for path in [*required, *native_extensions]:
        if _pe_machine(path) != _PE_AMD64:
            raise RuntimeError(f"Windows runtime содержит бинарник не x64: {path}")
    if (runtime / "bin" / "python3").exists() or any(runtime.rglob("*.dylib")):
        raise RuntimeError("Windows runtime смешан с Darwin runtime")


def _validate_static_layout(runtime: Path, spec: RuntimeSpec) -> None:
    python = _python_path(runtime, spec)
    purelib = _purelib_path(runtime, spec)
    if not python.is_file() or not (purelib / "soft_hub" / "__init__.py").is_file():
        raise RuntimeError("Runtime не содержит ожидаемый Python/core")
    installed = _installed_distributions(purelib)
    mismatches = [
        f"{name}=={version}"
        for name, version in _locked_distributions().items()
        if installed.get(name) != version
    ]
    if mismatches:
        raise RuntimeError("Runtime не содержит точные зависимости: " + ", ".join(mismatches))
    if spec.os_name == "win32":
        _validate_windows_layout(runtime, spec)


def _probe(runtime: Path, spec: RuntimeSpec, expected_source: str) -> bool:
    marker = runtime / "soft-hub-runtime.json"
    python = _python_path(runtime, spec)
    if not marker.is_file() or not python.is_file():
        return False
    try:
        state = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    pip_wheel = state.get("pip_wheel")
    if (
        state.get("runtime_id") != spec.runtime_id
        or state.get("source_sha256") != expected_source
        or not isinstance(pip_wheel, str)
        or not (runtime / pip_wheel).is_file()
    ):
        return False
    try:
        _validate_static_layout(runtime, spec)
        if not _is_native_target(spec):
            return True
        _run(
            [
                str(python),
                "-I",
                "-c",
                (
                    "import cryptography, eth_account, soft_hub; "
                    "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; "
                    "from eth_account import Account; "
                    "assert AESGCM.generate_key(bit_length=256); "
                    "assert Account.from_key(bytes.fromhex('11' * 32)).address"
                ),
            ],
            environment=_clean_environment(runtime, spec),
        )
    except (OSError, RuntimeError):
        return False
    return True


def prepare(target_name: str = "host") -> Path:
    spec = _resolve_spec(target_name)
    source_hash = _source_sha256()
    target = RUNTIME_ROOT / "python"
    if _probe(target, spec, source_hash):
        print(f"Managed runtime уже готов: {target}")
        return target

    archive = _download(spec)
    RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
    staging_parent = Path(tempfile.mkdtemp(prefix=".python-staging-", dir=RUNTIME_ROOT))
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            bundle.extractall(staging_parent, filter="data")
        staging = staging_parent / "python"
        python = _python_path(staging, spec)
        if not python.is_file():
            raise RuntimeError("Runtime archive не содержит ожидаемый Python")
        _install_dependencies(staging, spec)
        _prune_dependency_test_suites(staging, spec)
        pip_wheel = _download_pip_wheel(staging, spec)
        _copy_core(staging, spec)
        marker = {
            "runtime_id": spec.runtime_id,
            "python_version": spec.python_version,
            "release": spec.release,
            "os": spec.os_name,
            "arch": spec.arch,
            "archive_sha256": spec.sha256,
            "source_sha256": source_hash,
            "pip_wheel": pip_wheel.relative_to(staging).as_posix(),
            "validation": "executed-on-target" if _is_native_target(spec) else "static-cross-target",
        }
        (staging / "soft-hub-runtime.json").write_text(
            json.dumps(marker, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _validate_static_layout(staging, spec)
        if not _probe(staging, spec, source_hash):
            raise RuntimeError("Managed runtime не прошёл self-check")

        previous = RUNTIME_ROOT / ".python-previous"
        if previous.exists():
            shutil.rmtree(previous)
        if target.exists():
            target.rename(previous)
        staging.rename(target)
        if previous.exists():
            shutil.rmtree(previous)
    finally:
        if staging_parent.exists():
            shutil.rmtree(staging_parent)
    print(f"Managed runtime подготовлен: {target}")
    return target


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Prepare the pinned managed Python runtime for an explicit desktop target."
    )
    parser.add_argument(
        "--target",
        default="host",
        choices=("host", *sorted(TARGET_ALIASES)),
        help="target OS/architecture; release scripts must never rely on host inference",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the already prepared runtime without downloading or replacing it",
    )
    arguments = parser.parse_args()
    if arguments.check:
        selected = _resolve_spec(arguments.target)
        selected_source = _source_sha256()
        selected_runtime = RUNTIME_ROOT / "python"
        if not _probe(selected_runtime, selected, selected_source):
            raise SystemExit(
                f"Managed runtime не соответствует target {selected.os_name}-{selected.arch}"
            )
        print(f"Managed runtime проверен: {selected.os_name}-{selected.arch}")
    else:
        prepare(arguments.target)
