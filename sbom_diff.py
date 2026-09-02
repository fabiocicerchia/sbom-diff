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

# Every purl starts with this scheme; the type follows it directly.
PURL_PREFIX = "pkg:"

# What an SBOM writes when it has no value for a field we still have to show.
MISSING_FIELD = "?"

# CycloneDX's default component type, and the only one SPDX packages can be.
DEFAULT_COMPONENT_TYPE = "library"

# SPDX's two ways of saying "no licence stated"; neither is a licence.
SPDX_NO_LICENSE = ("NOASSERTION", "NONE")

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


def compare_versions(old, new):
    """Order two versions: -1 if old < new, 1 if old > new, 0 if equal.

    Enough of semver to tell an upgrade from a downgrade, falling back to a
    string compare for anything not numeric-dotted. semver_jump says how big a
    change is; this says which direction it went.
    """

    def split(v):
        # The pre-release has to come off before the dots: a suffix makes a
        # version *older* than the same version without one, the opposite of
        # how the core segments compare. Build metadata (+sha) carries no
        # precedence, a pre-release (-rc1) does.
        s = str(v).lstrip("v")
        marker = re.search(r"[-+]", s)
        core = s[: marker.start()] if marker else s
        pre = ""
        if marker and s[marker.start()] == "-":
            pre = s[marker.start() + 1 :].split("+")[0]
        return [int(p) if p.isdigit() else p for p in core.split(".")], pre

    left, left_pre = split(old)
    right, right_pre = split(new)

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


def load_components(path):
    """Return {key: {name, version, ...}} plus license info from either format.

    Keyed by PURL identity when the component carries one (rename-aware: the
    same purl matches across a name change), falling back to name otherwise.
    """
    with open(path) as fh:
        doc = json.load(fh)

    comps = {}
    if "components" in doc or doc.get("bomFormat") == "CycloneDX":
        root = (doc.get("metadata") or {}).get("component") or {}
        root_ref, root_name = root.get("bom-ref"), root.get("name")

        # The dependency graph, when present, is how "direct" is known. Without
        # it every component reports as transitive — the honest default, since
        # claiming a dependency is direct without evidence is worse than not
        # saying.
        direct_refs = set()
        if root_ref:
            entry = next(
                (d for d in doc.get("dependencies") or [] if d.get("ref") == root_ref), None
            )
            if entry:
                direct_refs = set(entry.get("dependsOn") or [])

        for c in doc.get("components", []):
            # The project is not one of its own dependencies. syft catalogues it
            # under a different bom-ref from metadata.component when scanning a
            # directory, so the name is checked too.
            if root_ref and c.get("bom-ref") == root_ref:
                continue
            if root_name and c.get("name") == root_name:
                continue
            licenses = [
                lic.get("license", {}).get("id")
                or lic.get("license", {}).get("name")
                or lic.get("expression")
                for lic in c.get("licenses", [])
            ]
            name = c.get("name", MISSING_FIELD)
            purl = c.get("purl")
            key = purl_identity(purl) if purl else name
            _insert(
                comps,
                key,
                {
                    "name": name,
                    "version": c.get("version", MISSING_FIELD),
                    "type": c.get("type", DEFAULT_COMPONENT_TYPE),
                    "ecosystem": ecosystem(purl),
                    "licenses": sorted(filter(None, licenses)),
                    "purl": purl,
                    "direct": c.get("bom-ref") in direct_refs,
                },
            )
    elif "spdxVersion" in doc:
        root_ref = next(iter(doc.get("documentDescribes") or []), None)
        root_name = next(
            (p.get("name") for p in doc.get("packages", []) if p.get("SPDXID") == root_ref),
            doc.get("name"),
        )

        # SPDX states the relationship in either direction depending on which
        # tool produced the document, so both are read.
        direct_refs = set()
        for rel in doc.get("relationships") or []:
            if not root_ref:
                break
            if rel.get("relationshipType") == "DEPENDS_ON" and rel.get("spdxElementId") == root_ref:
                direct_refs.add(rel.get("relatedSpdxElement"))
            if (
                rel.get("relationshipType") == "DEPENDENCY_OF"
                and rel.get("relatedSpdxElement") == root_ref
            ):
                direct_refs.add(rel.get("spdxElementId"))

        for pkg in doc.get("packages", []):
            if pkg.get("SPDXID") == root_ref:
                continue  # skip the document/root package
            if root_name and pkg.get("name") == root_name:
                continue
            lic = pkg.get("licenseConcluded") or pkg.get("licenseDeclared")
            name = pkg.get("name", MISSING_FIELD)
            purl = next(
                (
                    ref.get("referenceLocator")
                    for ref in pkg.get("externalRefs", [])
                    if ref.get("referenceType") == "purl"
                ),
                None,
            )
            key = purl_identity(purl) if purl else name
            _insert(
                comps,
                key,
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
    else:
        raise ValueError(f"{path}: not a recognizable CycloneDX or SPDX JSON SBOM")
    return comps


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
    the "New dependencies" heading, and counts["added_transitive"] in --json.
    """
    return sum(1 for c in added.values() if not c.get("direct"))


def downgrade_count(changed):
    """How many changed components moved to a lower version.

    Same reason as transitive_count: the summary line and
    counts["downgrades"] are read side by side and must not disagree.
    """
    return sum(1 for o, n in changed.values() if is_downgrade(o, n))


def counts(added, removed, changed, license_changes):
    """Headline numbers, including the direct/transitive split callers gate on.

    The transitive count is the one nobody sees in a pull request diff and
    everybody cares about once it is put in front of them.
    """
    transitive = transitive_count(added)
    return {
        "added": len(added),
        "added_direct": len(added) - transitive,
        "added_transitive": transitive,
        "removed": len(removed),
        "changed": len(changed),
        "license_changed": len(license_changes),
        "downgrades": downgrade_count(changed),
    }


def policy_failures(added, license_changes, totals, policy):
    """Reasons the check should fail. Empty means pass.

    Every threshold is opt-in: a dependency review that fails by default is a
    dependency review that gets disabled by default.
    """
    fails = []
    max_added = policy.get("max_added")
    if max_added is not None and totals["added"] > max_added:
        fails.append(f"{totals['added']} components added, over the limit of {max_added}")

    max_transitive = policy.get("max_added_transitive")
    if max_transitive is not None and totals["added_transitive"] > max_transitive:
        fails.append(
            f"{totals['added_transitive']} transitive components added, "
            f"over the limit of {max_transitive}"
        )

    if policy.get("fail_on_downgrade") and totals["downgrades"]:
        fails.append(
            f"{totals['downgrades']} component(s) downgraded — usually a lockfile "
            "conflict resolved the wrong way"
        )
    if policy.get("fail_on_license_change") and totals["license_changed"]:
        fails.append(f"{totals['license_changed']} licence change(s)")

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


def explain(added, removed, changed, license_changes, renamed=None, vulns=None):
    renamed = renamed or {}
    lines = []
    jumps = defaultdict(list)
    for o, n in sorted(changed.values(), key=lambda pair: pair[0]["name"]):
        # A downgrade is flagged wherever it lands: 2.0.0 -> 1.9.0 is classified
        # "major" like any other, and reads as an upgrade unless it is labelled.
        note = " *(downgrade)*" if is_downgrade(o, n) else ""
        jumps[semver_jump(o["version"], n["version"])].append(
            (o["name"], o["version"], n["version"], note)
        )

    if renamed:
        lines.append(f"## Renamed ({len(renamed)})\n")
        for _, (o, n) in sorted(renamed.items(), key=lambda kv: kv[1][0]["name"]):
            note = f" ({o['version']} → {n['version']})" if o["version"] != n["version"] else ""
            lines.append(f"- **{o['name']}** → **{n['name']}**{note}")
        lines.append("")

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
    if added:
        transitive = transitive_count(added)
        heading = f"## New dependencies ({len(added)}"
        heading += f", {transitive} transitive)\n" if transitive else ")\n"
        lines.append(heading)
        lines += [
            f"- {c['name']} {c['version']}" + ("" if c.get("direct") else " _(transitive)_")
            for c in sorted(added.values(), key=lambda c: c["name"])
        ]
        lines.append("")
    if removed:
        lines.append(f"## Removed dependencies ({len(removed)})\n")
        lines += [
            f"- {c['name']} {c['version']}"
            for c in sorted(removed.values(), key=lambda c: c["name"])
        ]
        lines.append("")
    if license_changes:
        lines.append("## ⚠ License changes\n")
        lines += [
            f"- **{o['name']}**: {', '.join(o['licenses']) or '(none)'} → "
            f"{', '.join(n['licenses']) or '(none)'}"
            for o, n in sorted(license_changes.values(), key=lambda pair: pair[0]["name"])
        ]
        lines.append("")

    added_v, removed_v, changed_v = vulns or ({}, {}, {})
    if added_v or removed_v or changed_v:
        lines.append("## Vulnerability changes (VEX)\n")
        lines += [
            f"- ⚠ **{vid}** newly reported ({v['state']}{', ' + v['severity'] if v['severity'] else ''})"
            for vid, v in sorted(added_v.items())
        ]
        lines += [
            f"- ✅ **{vid}** no longer reported (was: {v['state']})"
            for vid, v in sorted(removed_v.items())
        ]
        lines += [
            f"- 🔄 **{vid}**: {old_state} → {new_state}"
            for vid, (old_state, new_state) in sorted(changed_v.items())
        ]
        lines.append("")

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
    return summary, "\n".join(lines)


def main(argv=None):
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
    args = p.parse_args(argv)

    added, removed, changed, licenses, renamed = diff(
        load_components(args.old), load_components(args.new)
    )
    vuln_added, vuln_removed, vuln_changed = diff_vulnerabilities(
        load_vulnerabilities(args.old), load_vulnerabilities(args.new)
    )
    summary, body = explain(
        added, removed, changed, licenses, renamed, (vuln_added, vuln_removed, vuln_changed)
    )

    totals = counts(added, removed, changed, licenses)
    # One string, rendered once: --json carries the same markdown stdout prints.
    report = f"# SBOM diff\n\n{summary}\n\n{body}"

    if args.json:
        json.dump(
            {
                "summary": summary,
                # The rendered report travels with the numbers so a caller that
                # wants both does not have to run the diff twice.
                "markdown": report,
                "counts": totals,
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
            },
            sys.stdout,
            indent=2,
        )
    else:
        print(report)

    fails = policy_failures(
        added,
        licenses,
        totals,
        {
            "max_added": args.max_added,
            "max_added_transitive": args.max_added_transitive,
            "fail_on_downgrade": args.fail_on_downgrade,
            "fail_on_license_change": args.fail_on_license_change,
            "deny_licenses": [
                s.strip() for s in re.split(r"[,\n]", args.deny_licenses) if s.strip()
            ],
        },
    )
    for reason in fails:
        print(f"sbom-diff: {reason}", file=sys.stderr)

    if args.fail_on == "any" and (added or removed or changed):
        return 1
    if args.fail_on == "major" and any(
        semver_jump(o["version"], n["version"]) == "major" for o, n in changed.values()
    ):
        return 1
    if args.fail_on == "license" and licenses:
        return 1
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
