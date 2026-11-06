"""What docs/ tells a reader holds against the code: flags, choices, modules, signals, links."""

from __future__ import annotations

import re
from pathlib import Path

from sbom_diff_lib.cli import build_parser
from sbom_diff_lib.signals import SIGNALS
from sbom_diff_lib.tiers import TIER_IDS

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
GETTING_STARTED = (DOCS / "getting-started.md").read_text(encoding="utf-8")
ARCHITECTURE = (DOCS / "architecture.md").read_text(encoding="utf-8")


def test_every_flag_in_getting_started_exists() -> None:
    # Only sbom-diff command lines and `--flag` in prose: the CI section also shows `docker run --rm`.
    commands = "\n".join(line for line in GETTING_STARTED.splitlines() if line.startswith("sbom-diff "))
    documented = set(re.findall(r"(?<![\w-])--[a-z][a-z-]*", commands))
    documented |= set(re.findall(r"`(--[a-z][a-z-]*)`", GETTING_STARTED))
    assert {"--fail-on", "--review", "--cache-dir"} <= documented
    known = set(re.findall(r"(?<![\w-])--[a-z][a-z-]*", build_parser().format_help()))
    assert documented - known == set()


def test_documented_choices_match_the_parser() -> None:
    assert "any | major | license" in GETTING_STARTED
    assert "{any,major,license}" in build_parser().format_usage()
    assert "read this / glance / routine" in GETTING_STARTED
    assert list(TIER_IDS) == ["read", "glance", "routine"]
    assert "{read,glance,routine}" in build_parser().format_usage()


def test_every_module_in_architecture_exists() -> None:
    listed = re.findall(r"\*\*`(\w+)\.py`\*\*", ARCHITECTURE)
    assert {"cli", "review"} <= set(listed)
    missing = [m for m in listed if not (ROOT / "sbom_diff_lib" / f"{m}.py").is_file()]
    assert missing == []


def test_ten_signals_as_documented() -> None:
    assert "ten signals" in ARCHITECTURE
    assert "ten independent signals" in GETTING_STARTED
    assert len(SIGNALS) == 10
    assert len({s.id for s in SIGNALS}) == 10


def test_relative_links_in_docs_resolve() -> None:
    broken: list[str] = []
    for page in DOCS.glob("*.md"):
        for target in re.findall(r"\]\(([^)#\s]+)\)", page.read_text(encoding="utf-8")):
            if "://" not in target and not (page.parent / target).exists():
                broken.append(f"{page.name} -> {target}")
    assert broken == []
