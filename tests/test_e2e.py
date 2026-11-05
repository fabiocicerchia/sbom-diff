"""The documented journey, end to end: the script run on examples/basic as a user would."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASIC = ROOT / "examples" / "basic"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "sbom_diff.py"), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )


def test_basic_example_prints_the_report_and_passes() -> None:
    result = run(str(BASIC / "old.json"), str(BASIC / "new.json"))
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    report = result.stdout
    assert report.startswith("# SBOM diff\n")
    for name in ("openssl", "libfoo", "oldpkg", "newpkg"):
        assert name in report
    assert "Apache-2.0" in report and "GPL-3.0" in report
    # Major jumps are the headline, so they come before the patch update.
    assert report.index("openssl") < report.index("libfoo")


def test_basic_example_trips_the_major_gate_and_json_matches_stdout() -> None:
    gated = run(str(BASIC / "old.json"), str(BASIC / "new.json"), "--fail-on", "major")
    assert gated.returncode == 1

    as_json = run(str(BASIC / "old.json"), str(BASIC / "new.json"), "--json")
    assert as_json.returncode == 0, as_json.stderr
    payload = json.loads(as_json.stdout)
    assert payload["counts"]["added"] == 1
    assert payload["markdown"] + "\n" == gated.stdout


def test_missing_sbom_exits_with_a_message_not_a_traceback() -> None:
    result = run(str(BASIC / "absent.json"), str(BASIC / "new.json"))
    assert result.returncode == 66
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert result.stderr.strip().endswith("absent.json: no such file")
