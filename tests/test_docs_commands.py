"""Every sbom-diff command line in getting-started.md, run for real against examples/review."""

from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / "examples" / "review"
GETTING_STARTED = (ROOT / "docs" / "getting-started.md").read_text(encoding="utf-8")


def documented_commands() -> list[list[str]]:
    commands: list[list[str]] = []
    for line in GETTING_STARTED.splitlines():
        if line.startswith("sbom-diff "):
            argv = shlex.split(line, comments=True)[1:]
            # The suite opens no sockets: --review runs scored from the SBOMs alone.
            if "--review" in argv and "--offline" not in argv:
                argv.append("--offline")
            commands.append(argv)
    return commands


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603  # nosec B603 — runs this repo's own CLI
        [sys.executable, str(ROOT / "sbom_diff.py"), *argv],
        capture_output=True,
        text=True,
        cwd=REVIEW,
        check=False,
    )


def test_every_documented_command_runs_on_the_review_example() -> None:
    commands = documented_commands()
    assert len(commands) >= 9
    outcomes = {}
    for argv in commands:
        result = run(argv)
        assert "Traceback" not in result.stderr, argv
        assert result.stdout, argv
        outcomes[shlex.join(argv)] = result.returncode
    # internal-toolkit changes licence and chalk jumps majors; nothing lands in "read this".
    assert outcomes == {
        "old.json new.json": 0,
        "old.json new.json --json": 0,
        "old.json new.json --fail-on license": 1,
        "old.json new.json --max-added 25 --max-added-transitive 10": 0,
        "old.json new.json --fail-on-downgrade --fail-on-license-change": 1,
        "old.json new.json --deny-licenses AGPL-3.0,GPL-3.0": 0,
        "old.json new.json --review --offline": 0,
        "old.json new.json --review --fail-on-tier read --offline": 0,
        "--list-signals": 0,
        "old.json new.json --review --disable-signal scorecard,fanout --offline": 0,
    }
