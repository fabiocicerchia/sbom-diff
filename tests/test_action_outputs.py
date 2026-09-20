"""Every declared action output has to be one the run: block actually writes."""

from __future__ import annotations

import re
from pathlib import Path

# Read as text, not YAML: this tool is stdlib-only and a parser is not worth a
# dependency for two regexes.
ACTION = (Path(__file__).resolve().parents[1] / "action.yml").read_text()
OUTPUTS = ACTION.split("\noutputs:\n", 1)[1].split("\nruns:\n", 1)[0]


def test_declared_outputs_are_written() -> None:
    written = set(re.findall(r'^\s*echo "([a-z0-9-]+)=', ACTION, re.MULTILINE))
    declared = re.findall(r"^  ([a-z0-9-]+):\n(?:    .+\n)*?    value: (.+)$", OUTPUTS, re.MULTILINE)
    assert len(declared) == OUTPUTS.count("\n    value: "), "an output failed to parse"
    for name, value in declared:
        step_output = re.fullmatch(r"\$\{\{ steps\.diff\.outputs\.([a-z0-9-]+) \}\}", value)
        assert step_output, f"{name} does not read a step output"
        assert step_output.group(1) in written, f"{name} is declared but never written"
