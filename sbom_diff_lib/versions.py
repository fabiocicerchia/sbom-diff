"""Version arithmetic: how big a change is, and which direction it went."""

import re
from itertools import zip_longest

from sbom_diff_lib.types import Component


def split_version(version: str) -> tuple[list[int | str], str]:
    """Split a version into its core segments and its pre-release, if any.

    The pre-release has to come off before the dots: a suffix makes a version
    *older* than the same version without one, the opposite of how the core
    segments compare. Build metadata (+sha) carries no precedence, a
    pre-release (-rc1) does.
    """
    text = str(version).lstrip("v")
    marker = re.search(r"[-+]", text)
    core = text[: marker.start()] if marker else text
    pre = ""
    if marker and text[marker.start()] == "-":
        pre = text[marker.start() + 1 :].split("+")[0]
    return [int(p) if p.isdigit() else p for p in core.split(".")], pre


def _compare_core(left: list[int | str], right: list[int | str]) -> int:
    """Order the dotted core segments; 0 when they are the same version."""
    # A missing segment is zero, so 1.2 and 1.2.0 are the same version.
    for a, b in zip_longest(left, right, fillvalue=0):
        if a == b:
            continue
        if isinstance(a, int) and isinstance(b, int):
            return -1 if a < b else 1
        return -1 if str(a) < str(b) else 1
    return 0


def _compare_prerelease(left_pre: str, right_pre: str) -> int:
    """Order two pre-release suffixes; having none sorts above having one."""
    if left_pre == right_pre:
        return 0
    if not left_pre:
        return 1
    if not right_pre:
        return -1
    return -1 if left_pre < right_pre else 1


def compare_versions(old: str, new: str) -> int:
    """Order two versions: -1 if old < new, 1 if old > new, 0 if equal.

    Enough of semver to tell an upgrade from a downgrade, falling back to a
    string compare for anything not numeric-dotted. semver_jump says how big a
    change is; this says which direction it went.
    """
    left, left_pre = split_version(old)
    right, right_pre = split_version(new)
    return _compare_core(left, right) or _compare_prerelease(left_pre, right_pre)


def semver_jump(old: str, new: str) -> str:
    """Classify a version bump: major / minor / patch / other."""
    try:
        o = [int(x) for x in old.lstrip("v").split(".")[:3]]
        n = [int(x) for x in new.lstrip("v").split(".")[:3]]
        o += [0] * (3 - len(o))
        n += [0] * (3 - len(n))
    except ValueError:
        return "other"
    if n[0] != o[0]:
        return "major"
    if n[1] != o[1]:
        return "minor"
    return "patch" if n[2] != o[2] else "other"


def is_downgrade(old: Component, new: Component) -> bool:
    # compare_versions returns 1 when the first argument is the higher one, so
    # a downgrade is the old version sorting *above* the new one.
    return compare_versions(old["version"], new["version"]) > 0
