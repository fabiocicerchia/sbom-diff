"""The shapes this package passes between its modules.

They are plain dicts on purpose: the whole tool is a pipeline from JSON to
Markdown, and the only place a shape becomes a class is `Counts`, which callers
read out of `--json` in a fixed field order.
"""

from typing import Any

# A CycloneDX or SPDX document, as json.load hands it over.
Json = dict[str, Any]

# One normalised component: {name, version, licenses, direct, purl}.
Component = dict[str, Any]
# Components keyed by PURL identity where there is one, by name otherwise --
# which is what makes a rename visible as a rename rather than an add + remove.
Components = dict[str, Component]

# One vulnerability's VEX state: {state, severity}.
Vulnerability = dict[str, Any]
Vulnerabilities = dict[str, Vulnerability]

# A pair of (old, new) for something present in both documents.
Pair = tuple[Component, Component]
Pairs = dict[str, Pair]

# What diff_vulnerabilities returns: the vulnerabilities added, the ones gone,
# and the VEX state changes for the ones present in both, keyed by id.
VulnDiff = tuple[Vulnerabilities, Vulnerabilities, dict[str, tuple[str, str]]]

# One version change, ready to render: (name, old version, new version, note).
Jump = tuple[str, str, str, str]
# Version changes bucketed by semver jump size ("major", "minor", ...).
Jumps = dict[str, list[Jump]]
