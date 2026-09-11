"""The dependency graph an SBOM carries, and what a component drags in.

`normalize.py` reads the graph for one question -- is this component a direct
dependency of the root -- and throws the rest away. The fan-out signal needs
the rest: how many packages a single dependency pulls in behind it, on each
side of the diff. A document without a graph gets `None`, which the signal
reports as not checkable rather than as zero.
"""

import json
from collections import deque
from pathlib import Path
from typing import cast

from sbom_diff_lib.purl import purl_identity
from sbom_diff_lib.types import Json

# Edges keyed the way components are: purl identity, or the name without one.
Graph = dict[str, frozenset[str]]


def read_graph(path: str) -> Graph | None:
    """The dependency graph of the SBOM at `path`, or None when it has none.

    Every failure is None: by the time this runs the file has already been
    parsed once by `read_sbom`, so an error here is not the place to report a
    bad input -- it is the place to say the fan-out is not checkable.
    """
    try:
        parsed: object = json.loads(Path(path).read_text())
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(parsed, dict):
        return None
    doc = cast(Json, parsed)
    if isinstance(doc.get("dependencies"), list):
        return _cyclonedx_graph(doc)
    if isinstance(doc.get("relationships"), list):
        return _spdx_graph(doc)
    return None


def _component_key(name: object, purl: object) -> str:
    return purl_identity(purl) if isinstance(purl, str) and purl else str(name)


def _cyclonedx_graph(doc: Json) -> Graph | None:
    """CycloneDX `dependencies`: bom-refs resolved to component keys."""
    components: list[Json] = doc.get("components") or []
    by_ref = {c["bom-ref"]: _component_key(c.get("name"), c.get("purl")) for c in components if c.get("bom-ref")}
    edges: dict[str, set[str]] = {}
    dependencies: list[Json] = doc.get("dependencies") or []
    for entry in dependencies:
        key = by_ref.get(entry.get("ref"))
        if key is None:
            continue  # the root component, or a ref no component declares
        targets: list[str] = entry.get("dependsOn") or []
        edges.setdefault(key, set()).update(k for t in targets if (k := by_ref.get(t)) and k != key)
    return {k: frozenset(v) for k, v in edges.items()} if edges else None


def _spdx_graph(doc: Json) -> Graph | None:
    """SPDX `relationships`, read in both directions as `normalize.py` does."""
    packages: list[Json] = doc.get("packages") or []
    by_id = {p["SPDXID"]: _component_key(p.get("name"), _spdx_purl(p)) for p in packages if p.get("SPDXID")}
    edges: dict[str, set[str]] = {}
    relationships: list[Json] = doc.get("relationships") or []
    for rel in relationships:
        kind = rel.get("relationshipType")
        if kind == "DEPENDS_ON":
            source, target = rel.get("spdxElementId"), rel.get("relatedSpdxElement")
        elif kind == "DEPENDENCY_OF":
            source, target = rel.get("relatedSpdxElement"), rel.get("spdxElementId")
        else:
            continue
        from_key, to_key = by_id.get(source), by_id.get(target)
        if from_key and to_key and from_key != to_key:
            edges.setdefault(from_key, set()).add(to_key)
    return {k: frozenset(v) for k, v in edges.items()} if edges else None


def _spdx_purl(package: Json) -> str | None:
    refs: list[Json] = package.get("externalRefs", [])
    return next((r.get("referenceLocator") for r in refs if r.get("referenceType") == "purl"), None)


def fanout(graph: Graph | None, key: str) -> int | None:
    """How many distinct packages `key` reaches, directly or through others.

    Breadth-first with a visited set, so a dependency cycle -- which real
    lockfiles do contain -- is counted once instead of forever.
    """
    if graph is None or key not in graph:
        return None
    seen: set[str] = set()
    queue = deque(graph[key])
    while queue:
        current = queue.popleft()
        if current in seen or current == key:
            continue
        seen.add(current)
        queue.extend(graph.get(current, ()))
    return len(seen)
