"""CycloneDX and SPDX documents normalized into one {key: component} shape."""

from sbom_diff_lib.purl import ecosystem, purl_identity
from sbom_diff_lib.types import Component, Components, Json
from sbom_diff_lib.versions import compare_versions

# What an SBOM writes when it has no value for a field we still have to show.
MISSING_FIELD = "?"

# CycloneDX's default component type, and the only one SPDX packages can be.
DEFAULT_COMPONENT_TYPE = "library"

# SPDX's two ways of saying "no licence stated"; neither is a licence.
SPDX_NO_LICENSE = ("NOASSERTION", "NONE")


def _insert(comps: Components, key: str, comp: Component) -> None:
    """Keep one entry per identity, preferring the higher version.

    A component catalogued twice at the same version is the same component; at
    two different versions the higher one wins, so the diff does not report a
    change that is really two copies coexisting. `direct` is sticky — listed as
    a direct dependency once is enough.
    """
    seen = comps.get(key)
    if seen is None:
        comps[key] = comp
    elif compare_versions(seen["version"], comp["version"]) < 0:
        comp["direct"] = comp["direct"] or seen["direct"]
        comps[key] = comp
    elif comp["direct"]:
        seen["direct"] = True


def _cyclonedx_direct_refs(doc: Json, root_ref: str | None) -> set[str]:
    """bom-refs the root component depends on, or an empty set without a graph.

    The dependency graph, when present, is how "direct" is known. Without it
    every component reports as transitive — the honest default, since claiming
    a dependency is direct without evidence is worse than not saying.
    """
    if not root_ref:
        return set()
    entry = next((d for d in doc.get("dependencies") or [] if d.get("ref") == root_ref), None)
    return set(entry.get("dependsOn") or []) if entry else set()


def _cyclonedx_licenses(component: Json) -> list[str]:
    """SPDX ids, free-text names and expressions all flattened to a sorted list."""
    ids = [
        lic.get("license", {}).get("id") or lic.get("license", {}).get("name") or lic.get("expression")
        for lic in component.get("licenses", [])
    ]
    return sorted(filter(None, ids))


def load_cyclonedx(doc: Json) -> Components:
    """Normalize a CycloneDX document into {key: component}."""
    root = (doc.get("metadata") or {}).get("component") or {}
    root_ref, root_name = root.get("bom-ref"), root.get("name")
    direct_refs = _cyclonedx_direct_refs(doc, root_ref)

    comps = {}
    for c in doc.get("components", []):
        # The project is not one of its own dependencies. syft catalogues it
        # under a different bom-ref from metadata.component when scanning a
        # directory, so the name is checked too.
        if root_ref and c.get("bom-ref") == root_ref:
            continue
        if root_name and c.get("name") == root_name:
            continue
        name = c.get("name", MISSING_FIELD)
        purl = c.get("purl")
        _insert(
            comps,
            purl_identity(purl) if purl else name,
            {
                "name": name,
                "version": c.get("version", MISSING_FIELD),
                "type": c.get("type", DEFAULT_COMPONENT_TYPE),
                "ecosystem": ecosystem(purl),
                "licenses": _cyclonedx_licenses(c),
                "purl": purl,
                "direct": c.get("bom-ref") in direct_refs,
            },
        )
    return comps


def _spdx_direct_refs(doc: Json, root_ref: str | None) -> set[str]:
    """SPDXIDs the root package depends on.

    SPDX states the relationship in either direction depending on which tool
    produced the document, so both are read.
    """
    if not root_ref:
        return set()
    direct_refs = set()
    for rel in doc.get("relationships") or []:
        relationship = rel.get("relationshipType")
        if relationship == "DEPENDS_ON" and rel.get("spdxElementId") == root_ref:
            direct_refs.add(rel.get("relatedSpdxElement"))
        if relationship == "DEPENDENCY_OF" and rel.get("relatedSpdxElement") == root_ref:
            direct_refs.add(rel.get("spdxElementId"))
    return direct_refs


def _spdx_purl(package: Json) -> str | None:
    """The package's purl from its externalRefs, or None when it carries none."""
    return next(
        (ref.get("referenceLocator") for ref in package.get("externalRefs", []) if ref.get("referenceType") == "purl"),
        None,
    )


def _spdx_root(doc: Json) -> tuple[str | None, str | None]:
    """(SPDXID, name) of the package the document is about, either possibly None."""
    root_ref = next(iter(doc.get("documentDescribes") or []), None)
    root_name = next(
        (p.get("name") for p in doc.get("packages", []) if p.get("SPDXID") == root_ref),
        doc.get("name"),
    )
    return root_ref, root_name


def _spdx_component(pkg: Json, direct_refs: set[str]) -> Component:
    """One SPDX package as the normalized component record."""
    lic = pkg.get("licenseConcluded") or pkg.get("licenseDeclared")
    purl = _spdx_purl(pkg)
    return {
        "name": pkg.get("name", MISSING_FIELD),
        "version": pkg.get("versionInfo", MISSING_FIELD),
        "type": DEFAULT_COMPONENT_TYPE,
        "ecosystem": ecosystem(purl),
        "licenses": [lic] if lic and lic not in SPDX_NO_LICENSE else [],
        "purl": purl,
        "direct": pkg.get("SPDXID") in direct_refs,
    }


def load_spdx(doc: Json) -> Components:
    """Normalize an SPDX document into {key: component}."""
    root_ref, root_name = _spdx_root(doc)
    direct_refs = _spdx_direct_refs(doc, root_ref)

    comps = {}
    for pkg in doc.get("packages", []):
        if pkg.get("SPDXID") == root_ref:
            continue  # skip the document/root package
        if root_name and pkg.get("name") == root_name:
            continue
        comp = _spdx_component(pkg, direct_refs)
        purl = comp["purl"]
        _insert(comps, purl_identity(purl) if purl else comp["name"], comp)
    return comps
