#!/usr/bin/env python3
from __future__ import annotations

import ast
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE_ROOTS = (
    PROJECT_ROOT / "soft_hub",
    PROJECT_ROOT / "tests",
    PROJECT_ROOT / "scripts",
)


def python_files() -> list[Path]:
    return sorted(
        (
            path
            for root in SOURCE_ROOTS
            for path in root.rglob("*.py")
            if "__pycache__" not in path.parts
        ),
        key=lambda path: path.relative_to(PROJECT_ROOT).as_posix(),
    )


def main() -> None:
    failures: list[str] = []
    for path in python_files():
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeError) as error:
            failures.append(f"{path.relative_to(PROJECT_ROOT)}: {error}")
    if failures:
        raise SystemExit("Python syntax check failed:\n" + "\n".join(failures))


if __name__ == "__main__":
    main()
