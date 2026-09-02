#!/usr/bin/env python3
"""sbom-diff — diff two SBOMs, explain the changes in plain language.

Supports CycloneDX JSON and SPDX JSON (as produced by syft, trivy, etc.):

  syft -o cyclonedx-json myapp:1.0 > old.json
  syft -o cyclonedx-json myapp:1.1 > new.json
  sbom-diff old.json new.json
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass

# Every purl starts with this scheme; the type follows it directly.
PURL_PREFIX = "pkg:"

# What an SBOM writes when it has no value for a field we still have to show.
MISSING_FIELD = "?"

# CycloneDX's default component type, and the only one SPDX packages can be.
DEFAULT_COMPONENT_TYPE = "library"

# SPDX's two ways of saying "no licence stated"; neither is a licence.
SPDX_NO_LICENSE = ("NOASSERTION", "NONE")

# Exit codes, following sysexits(3). 0 and 1 are the documented gate contract
# and keep their meanings; the rest separate "this input is unusable" from
# "a gate tripped", which both used to surface as an uncaught traceback.
EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_DATAERR = 65  # EX_DATAERR: not JSON, or JSON that is not an SBOM
EXIT_NOINPUT = 66  # EX_NOINPUT: the file is not there
EXIT_IOERR = 74  # EX_IOERR: it is there but cannot be read
EXIT_NOPERM = 77  # EX_NOPERM: permission denied

# purl identity: everything up to the first version/qualifier/subpath marker,
# e.g. "pkg:pypi/requests@2.31.0" -> "pkg:pypi/requests". Two components with
# the same identity are the same package even if their SBOM "name" differs.
_PURL_IDENTITY_RE = re.compile(r"[@?#]")


def purl_identity(purl):
    return _PURL_IDENTITY_RE.split(purl, 1)[0]


# purl type -> the ecosystem name people recognise. Unknown types pass through
# rather than being dropped: an SBOM full of "deb" components is still a diff
# worth reading, even if this tool has no opinion about apt.
ECOSYSTEM = {
    "npm": "npm",
    "pypi": "PyPI",
    "cargo": "Cargo",
    "gem": "RubyGems",
    "composer": "Composer",
    "golang": "Go",
    "maven": "Maven",
    "nuget": "NuGet",
    "deb": "deb",
    "rpm": "rpm",
    "apk": "apk",
    "github": "GitHub Actions",
}


def ecosystem(purl):
    if not purl or not purl.startswith(PURL_PREFIX):
        return "unknown"
    kind = purl[len(PURL_PREFIX) :].split("/", 1)[0].lower()
    return ECOSYSTEM.get(kind, kind)


def split_version(version):
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


def compare_versions(old, new):
    """Order two versions: -1 if old < new, 1 if old > new, 0 if equal.

    Enough of semver to tell an upgrade from a downgrade, falling back to a
    string compare for anything not numeric-dotted. semver_jump says how big a
    change is; this says which direction it went.
    """
    left, left_pre = split_version(old)
    right, right_pre = split_version(new)

    for i in range(max(len(left), len(right))):
        # A missing segment is zero, so 1.2 and 1.2.0 are the same version.
        a = left[i] if i < len(left) else 0
        b = right[i] if i < len(right) else 0
        if a == b:
            continue
        if isinstance(a, int) and isinstance(b, int):
            return -1 if a < b else 1
        return -1 if str(a) < str(b) else 1

    if left_pre == right_pre:
        return 0
    if not left_pre:
        return 1
    if not right_pre:
        return -1
    return -1 if left_pre < right_pre else 1


def _insert(comps, key, comp):
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


def _cyclonedx_direct_refs(doc, root_ref):
    """bom-refs the root component depends on, or an empty set without a graph.

    The dependency graph, when present, is how "direct" is known. Without it
    every component reports as transitive — the honest default, since claiming
    a dependency is direct without evidence is worse than not saying.
    """
    if not root_ref:
        return set()
    entry = next((d for d in doc.get("dependencies") or [] if d.get("ref") == root_ref), None)
    return set(entry.get("dependsOn") or []) if entry else set()


def _cyclonedx_licenses(component):
    """SPDX ids, free-text names and expressions all flattened to a sorted list."""
    ids = [
        lic.get("license", {}).get("id")
        or lic.get("license", {}).get("name")
        or lic.get("expression")
        for lic in component.get("licenses", [])
    ]
    return sorted(filter(None, ids))


def _load_cyclonedx(doc):
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


def _spdx_direct_refs(doc, root_ref):
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


def _spdx_purl(package):
    """The package's purl from its externalRefs, or None when it carries none."""
    return next(
        (
            ref.get("referenceLocator")
            for ref in package.get("externalRefs", [])
            if ref.get("referenceType") == "purl"
        ),
        None,
    )


def _load_spdx(doc):
    """Normalize an SPDX document into {key: component}."""
    root_ref = next(iter(doc.get("documentDescribes") or []), None)
    root_name = next(
        (p.get("name") for p in doc.get("packages", []) if p.get("SPDXID") == root_ref),
        doc.get("name"),
    )
    direct_refs = _spdx_direct_refs(doc, root_ref)

    comps = {}
    for pkg in doc.get("packages", []):
        if pkg.get("SPDXID") == root_ref:
            continue  # skip the document/root package
        if root_name and pkg.get("name") == root_name:
            continue
        lic = pkg.get("licenseConcluded") or pkg.get("licenseDeclared")
        name = pkg.get("name", MISSING_FIELD)
        purl = _spdx_purl(pkg)
        _insert(
            comps,
            purl_identity(purl) if purl else name,
            {
                "name": name,
                "version": pkg.get("versionInfo", MISSING_FIELD),
                "type": DEFAULT_COMPONENT_TYPE,
                "ecosystem": ecosystem(purl),
                "licenses": [lic] if lic and lic not in SPDX_NO_LICENSE else [],
                "purl": purl,
                "direct": pkg.get("SPDXID") in direct_refs,
            },
        )
    return comps


def load_components(path):
    """Return {key: {name, version, ...}} plus license info from either format.

    Keyed by PURL identity when the component carries one (rename-aware: the
    same purl matches across a name change), falling back to name otherwise.
    """
    with open(path) as fh:
        doc = json.load(fh)

    if "components" in doc or doc.get("bomFormat") == "CycloneDX":
        return _load_cyclonedx(doc)
    if "spdxVersion" in doc:
        return _load_spdx(doc)
    raise ValueError(f"{path}: not a recognizable CycloneDX or SPDX JSON SBOM")


def load_vulnerabilities(path):
    """Return {id: {state, severity}} from a CycloneDX doc's embedded VEX data.

    No-op (empty dict) for SBOMs without a "vulnerabilities" array, e.g. SPDX
    or a CycloneDX SBOM that wasn't augmented with vulnerability/VEX info.
    """
    with open(path) as fh:
        doc = json.load(fh)

    vulns = {}
    for v in doc.get("vulnerabilities", []) or []:
        analysis = v.get("analysis") or {}
        vulns[v.get("id", MISSING_FIELD)] = {
            "state": analysis.get("state", "unknown"),
            "severity": next(
                (r.get("severity") for r in v.get("ratings", []) if r.get("severity")), None
            ),
        }
    return vulns


def _added_removed(old, new):
    return {k: new[k] for k in new.keys() - old.keys()}, {
        k: old[k] for k in old.keys() - new.keys()
    }


def diff_vulnerabilities(old, new):
    added, removed = _added_removed(old, new)
    changed = {
        k: (old[k]["state"], new[k]["state"])
        for k in old.keys() & new.keys()
        if old[k]["state"] != new[k]["state"]
    }
    return added, removed, changed


def semver_jump(old, new):
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


def diff(old, new):
    added, removed = _added_removed(old, new)
    common = old.keys() & new.keys()
    # Same purl identity but a different SBOM "name" -> a rename, reported
    # separately rather than as a version jump.
    renamed = {k: (old[k], new[k]) for k in common if old[k]["name"] != new[k]["name"]}
    changed = {
        k: (old[k], new[k])
        for k in common
        if old[k]["version"] != new[k]["version"] and old[k]["name"] == new[k]["name"]
    }
    license_changes = {
        k: (old[k], new[k])
        for k in common
        if old[k]["licenses"] != new[k]["licenses"] and (old[k]["licenses"] or new[k]["licenses"])
    }
    return added, removed, changed, license_changes, renamed


def is_downgrade(old, new):
    # compare_versions returns 1 when the first argument is the higher one, so
    # a downgrade is the old version sorting *above* the new one.
    return compare_versions(old["version"], new["version"]) > 0


def transitive_count(added):
    """How many added components the document does not name as direct.

    One definition, because three numbers have to agree: the headline summary,
    the "New dependencies" heading, and Counts.added_transitive in --json.
    """
    return sum(1 for c in added.values() if not c.get("direct"))


def downgrade_count(changed):
    """How many changed components moved to a lower version.

    Same reason as transitive_count: the summary line and
    Counts.downgrades are read side by side and must not disagree.
    """
    return sum(1 for o, n in changed.values() if is_downgrade(o, n))


@dataclass(frozen=True)
class Counts:
    """Headline numbers, including the direct/transitive split callers gate on.

    Field order is the key order of the --json "counts" object, which callers
    read; asdict() is the only place it turns back into a dict.
    """

    added: int
    added_direct: int
    added_transitive: int
    removed: int
    changed: int
    license_changed: int
    downgrades: int


def counts(added, removed, changed, license_changes):
    """Count the diff.

    The transitive count is the one nobody sees in a pull request diff and
    everybody cares about once it is put in front of them.
    """
    transitive = transitive_count(added)
    return Counts(
        added=len(added),
        added_direct=len(added) - transitive,
        added_transitive=transitive,
        removed=len(removed),
        changed=len(changed),
        license_changed=len(license_changes),
        downgrades=downgrade_count(changed),
    )


def policy_failures(added, license_changes, totals, policy):
    """Reasons the check should fail. Empty means pass.

    Every threshold is opt-in: a dependency review that fails by default is a
    dependency review that gets disabled by default.
    """
    fails = []
    max_added = policy.get("max_added")
    if max_added is not None and totals.added > max_added:
        fails.append(f"{totals.added} components added, over the limit of {max_added}")

    max_transitive = policy.get("max_added_transitive")
    if max_transitive is not None and totals.added_transitive > max_transitive:
        fails.append(
            f"{totals.added_transitive} transitive components added, "
            f"over the limit of {max_transitive}"
        )

    if policy.get("fail_on_downgrade") and totals.downgrades:
        fails.append(
            f"{totals.downgrades} component(s) downgraded — usually a lockfile "
            "conflict resolved the wrong way"
        )
    if policy.get("fail_on_license_change") and totals.license_changed:
        fails.append(f"{totals.license_changed} licence change(s)")

    denied = {lic.lower() for lic in policy.get("deny_licenses") or []}
    if denied:
        # Checked on what the change *introduces*: components added, and the
        # new side of a licence that changed under a dependency already there.
        candidates = list(added.values()) + [n for _o, n in license_changes.values()]
        hits = [
            f"{c['name']} ({lic})"
            for c in candidates
            for lic in c["licenses"]
            if lic.lower() in denied
        ]
        if hits:
            fails.append(f"denied licence(s): {', '.join(sorted(set(hits)))}")
    return fails


def classify_jumps(changed):
    """Bucket every version change by size, in name order, ready to render."""
    jumps = defaultdict(list)
    for o, n in sorted(changed.values(), key=lambda pair: pair[0]["name"]):
        # A downgrade is flagged wherever it lands: 2.0.0 -> 1.9.0 is classified
        # "major" like any other, and reads as an upgrade unless it is labelled.
        note = " *(downgrade)*" if is_downgrade(o, n) else ""
        jumps[semver_jump(o["version"], n["version"])].append(
            (o["name"], o["version"], n["version"], note)
        )
    return jumps


def _render_renamed(renamed):
    if not renamed:
        return []
    lines = [f"## Renamed ({len(renamed)})\n"]
    for _, (o, n) in sorted(renamed.items(), key=lambda kv: kv[1][0]["name"]):
        note = f" ({o['version']} → {n['version']})" if o["version"] != n["version"] else ""
        lines.append(f"- **{o['name']}** → **{n['name']}**{note}")
    return lines + [""]


def _render_jumps(jumps):
    """Major first and bolded, then the calmer buckets in decreasing size."""
    lines = []
    if jumps["major"]:
        lines.append("## ⚠ Major version jumps (review breaking changes)\n")
        lines += [f"- **{n}**: {o} → {v}{note}" for n, o, v, note in jumps["major"]]
        lines.append("")
    for label, key in (
        ("Minor updates", "minor"),
        ("Patch updates", "patch"),
        ("Other version changes", "other"),
    ):
        if jumps[key]:
            lines.append(f"## {label}\n")
            lines += [f"- {n}: {o} → {v}{note}" for n, o, v, note in jumps[key]]
            lines.append("")
    return lines


def _render_added(added):
    if not added:
        return []
    transitive = transitive_count(added)
    heading = f"## New dependencies ({len(added)}"
    heading += f", {transitive} transitive)\n" if transitive else ")\n"
    return (
        [heading]
        + [
            f"- {c['name']} {c['version']}" + ("" if c.get("direct") else " _(transitive)_")
            for c in sorted(added.values(), key=lambda c: c["name"])
        ]
        + [""]
    )


def _render_removed(removed):
    if not removed:
        return []
    return (
        [f"## Removed dependencies ({len(removed)})\n"]
        + [
            f"- {c['name']} {c['version']}"
            for c in sorted(removed.values(), key=lambda c: c["name"])
        ]
        + [""]
    )


def _render_license_changes(license_changes):
    if not license_changes:
        return []
    return (
        ["## ⚠ License changes\n"]
        + [
            f"- **{o['name']}**: {', '.join(o['licenses']) or '(none)'} → "
            f"{', '.join(n['licenses']) or '(none)'}"
            for o, n in sorted(license_changes.values(), key=lambda pair: pair[0]["name"])
        ]
        + [""]
    )


def _render_vulnerabilities(vulns):
    """The VEX delta: newly reported, gone, and state changes, in that order."""
    added_v, removed_v, changed_v = vulns or ({}, {}, {})
    if not (added_v or removed_v or changed_v):
        return []
    return (
        ["## Vulnerability changes (VEX)\n"]
        + [
            f"- ⚠ **{vid}** newly reported ({v['state']}{', ' + v['severity'] if v['severity'] else ''})"
            for vid, v in sorted(added_v.items())
        ]
        + [
            f"- ✅ **{vid}** no longer reported (was: {v['state']})"
            for vid, v in sorted(removed_v.items())
        ]
        + [
            f"- 🔄 **{vid}**: {old_state} → {new_state}"
            for vid, (old_state, new_state) in sorted(changed_v.items())
        ]
        + [""]
    )


def summarize(added, removed, changed, renamed, jumps):
    """The one-line headline that leads the report and the --json payload."""
    total = len(added) + len(removed) + len(changed)
    transitive = transitive_count(added)
    added_desc = f"{len(added)} added"
    if transitive:
        added_desc += f" ({len(added) - transitive} direct, {transitive} transitive)"
    summary = (
        f"{total} dependency change(s): {added_desc}, {len(removed)} removed, "
        f"{len(changed)} updated ({len(jumps['major'])} major)"
    )
    downgrades = downgrade_count(changed)
    if downgrades:
        summary += f", {downgrades} downgraded"
    if renamed:
        summary += f", {len(renamed)} renamed"
    return summary


def explain(added, removed, changed, license_changes, renamed=None, vulns=None):
    """Return (headline, markdown body); sections run most to least alarming."""
    renamed = renamed or {}
    jumps = classify_jumps(changed)
    lines = (
        _render_renamed(renamed)
        + _render_jumps(jumps)
        + _render_added(added)
        + _render_removed(removed)
        + _render_license_changes(license_changes)
        + _render_vulnerabilities(vulns)
    )
    summary = summarize(added, removed, changed, renamed, jumps)
    return summary, "\n".join(lines)


class SbomError(Exception):
    """An input the tool cannot use, carrying the exit code that reports it."""

    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def read_sbom(path):
    """Return (components, vulnerabilities) for one SBOM, or raise SbomError.

    Every expected failure becomes an SbomError so main can print one line and
    exit with a code that says which kind it was. Anything not listed here is a
    bug in this tool and keeps its traceback.
    """
    try:
        return load_components(path), load_vulnerabilities(path)
    except FileNotFoundError:
        raise SbomError(f"{path}: no such file", EXIT_NOINPUT) from None
    except PermissionError:
        raise SbomError(f"{path}: permission denied", EXIT_NOPERM) from None
    except OSError as exc:
        raise SbomError(f"{path}: {exc.strerror}", EXIT_IOERR) from None
    except json.JSONDecodeError as exc:
        raise SbomError(f"{path}: not valid JSON: {exc}", EXIT_DATAERR) from None
    except ValueError as exc:
        raise SbomError(str(exc), EXIT_DATAERR) from None


def build_parser():
    """The CLI surface. Every gate is opt-in and every one of them exits 1."""
    p = argparse.ArgumentParser(
        prog="sbom-diff", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("old", help="previous SBOM (CycloneDX or SPDX JSON)")
    p.add_argument("new", help="current SBOM")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument(
        "--fail-on",
        choices=["any", "major", "license"],
        help="exit 1 on: any change / major bumps / license changes",
    )
    p.add_argument("--max-added", type=int, help="exit 1 if more than N components are added")
    p.add_argument(
        "--max-added-transitive",
        type=int,
        help="exit 1 if more than N *transitive* components are added",
    )
    p.add_argument(
        "--fail-on-downgrade",
        action="store_true",
        help="exit 1 when a component moves to a lower version",
    )
    p.add_argument(
        "--fail-on-license-change",
        action="store_true",
        help="exit 1 when an existing component changes license",
    )
    p.add_argument(
        "--deny-licenses",
        default="",
        help="comma/newline separated license IDs that must not appear on an added component",
    )
    return p


def policy_from_args(args):
    """The gate settings, lifted out of argparse so policy_failures never sees it."""
    return {
        "max_added": args.max_added,
        "max_added_transitive": args.max_added_transitive,
        "fail_on_downgrade": args.fail_on_downgrade,
        "fail_on_license_change": args.fail_on_license_change,
        "deny_licenses": [s.strip() for s in re.split(r"[,\n]", args.deny_licenses) if s.strip()],
    }


def json_payload(report, summary, totals, changes, vulns):
    """The --json document. Its shape is a contract; callers read these keys."""
    added, removed, changed, licenses, renamed = changes
    vuln_added, vuln_removed, vuln_changed = vulns
    return {
        "summary": summary,
        # The rendered report travels with the numbers so a caller that wants
        # both does not have to run the diff twice.
        "markdown": report,
        "counts": asdict(totals),
        "added": added,
        "removed": removed,
        "changed": {k: {"old": o, "new": n} for k, (o, n) in changed.items()},
        "renamed": {k: {"old": o, "new": n} for k, (o, n) in renamed.items()},
        "license_changes": {k: {"old": o, "new": n} for k, (o, n) in licenses.items()},
        "vulnerabilities": {
            "added": vuln_added,
            "removed": vuln_removed,
            "changed": {vid: {"old": o, "new": n} for vid, (o, n) in vuln_changed.items()},
        },
    }


def fail_on_verdict(fail_on, added, removed, changed, license_changes):
    """True when --fail-on's chosen class of change is present."""
    if fail_on == "any":
        return bool(added or removed or changed)
    if fail_on == "major":
        return any(semver_jump(o["version"], n["version"]) == "major" for o, n in changed.values())
    if fail_on == "license":
        return bool(license_changes)
    return False


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        old_comps, old_vulns = read_sbom(args.old)
        new_comps, new_vulns = read_sbom(args.new)
    except SbomError as exc:
        print(f"sbom-diff: {exc}", file=sys.stderr)
        return exc.code

    changes = diff(old_comps, new_comps)
    added, removed, changed, licenses, renamed = changes
    vulns = diff_vulnerabilities(old_vulns, new_vulns)
    summary, body = explain(added, removed, changed, licenses, renamed, vulns)

    totals = counts(added, removed, changed, licenses)
    # One string, rendered once: --json carries the same markdown stdout prints.
    report = f"# SBOM diff\n\n{summary}\n\n{body}"

    if args.json:
        json.dump(json_payload(report, summary, totals, changes, vulns), sys.stdout, indent=2)
    else:
        print(report)

    fails = policy_failures(added, licenses, totals, policy_from_args(args))
    for reason in fails:
        print(f"sbom-diff: {reason}", file=sys.stderr)

    if fail_on_verdict(args.fail_on, added, removed, changed, licenses):
        return EXIT_GATE_FAILED
    return EXIT_GATE_FAILED if fails else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
