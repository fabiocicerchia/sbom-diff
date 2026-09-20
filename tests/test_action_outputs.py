"""Every declared action output has to be one the run: block actually writes."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ACTION = yaml.safe_load((Path(__file__).resolve().parents[1] / "action.yml").read_text())


def _written_by(step_id: str) -> set[str]:
    script = "\n".join(
        step["run"] for step in ACTION["runs"]["steps"] if step.get("id") == step_id
    )
    return set(re.findall(r'^\s*echo "([a-z0-9-]+)=', script, re.MULTILINE))


def test_declared_outputs_are_written() -> None:
    written = _written_by("diff")
    for name, spec in ACTION["outputs"].items():
        step_output = re.fullmatch(r"\$\{\{ steps\.diff\.outputs\.([a-z0-9-]+) \}\}", spec["value"])
        assert step_output, f"{name} does not read a step output"
        assert step_output.group(1) in written, f"{name} is declared but never written"
