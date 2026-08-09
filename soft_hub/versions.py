from __future__ import annotations

import re
from dataclasses import dataclass


_SEMVER_RE = re.compile(
    r"^(?:[vV])?"
    r"(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


@dataclass(frozen=True, slots=True)
class SemanticVersion:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] | None = None

    @property
    def canonical(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return base if self.prerelease is None else base + "-" + ".".join(self.prerelease)


def parse_semantic_version(value: object, *, allow_v_prefix: bool = False) -> SemanticVersion | None:
    """Parse strict SemVer without ever guessing malformed versions.

    Build metadata is deliberately ignored for precedence. A leading ``v`` is only
    accepted for release tags and asset names, never for manifest versions.
    """

    if not isinstance(value, str) or not value or len(value) > 180:
        return None
    if value[:1] in {"v", "V"} and not allow_v_prefix:
        return None
    match = _SEMVER_RE.fullmatch(value)
    if match is None:
        return None
    prerelease = match.group("prerelease")
    identifiers = tuple(prerelease.split(".")) if prerelease is not None else None
    if identifiers is not None and any(
        identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0")
        for identifier in identifiers
    ):
        return None
    return SemanticVersion(
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        identifiers,
    )


def compare_semantic_versions(left: SemanticVersion, right: SemanticVersion) -> int:
    left_core = (left.major, left.minor, left.patch)
    right_core = (right.major, right.minor, right.patch)
    if left_core != right_core:
        return 1 if left_core > right_core else -1
    if left.prerelease is None or right.prerelease is None:
        if left.prerelease is right.prerelease:
            return 0
        return 1 if left.prerelease is None else -1
    for left_identifier, right_identifier in zip(left.prerelease, right.prerelease):
        if left_identifier == right_identifier:
            continue
        left_numeric = left_identifier.isdigit()
        right_numeric = right_identifier.isdigit()
        if left_numeric and right_numeric:
            return 1 if int(left_identifier) > int(right_identifier) else -1
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return 1 if left_identifier > right_identifier else -1
    if len(left.prerelease) == len(right.prerelease):
        return 0
    return 1 if len(left.prerelease) > len(right.prerelease) else -1


def compare_version_strings(left: object, right: object) -> int | None:
    """Return SemVer precedence or ``None`` when either side is not trustworthy."""

    parsed_left = parse_semantic_version(left)
    parsed_right = parse_semantic_version(right)
    if parsed_left is None or parsed_right is None:
        return None
    return compare_semantic_versions(parsed_left, parsed_right)
