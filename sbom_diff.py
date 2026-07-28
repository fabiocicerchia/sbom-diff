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

# purl identity: everything up to the first version/qualifier/subpath marker,
# e.g. "pkg:pypi/requests@2.31.0" -> "pkg:pypi/requests". Two components with
# the same identity are the same package even if their SBOM "name" differs.
_PURL_IDENTITY_RE = re.compile(r"[@?#]")


def purl_identity(purl):
    return _PURL_IDENTITY_RE.split(purl, 1)[0]


def load_components(path):
    """Return {key: {name, version, ...}} plus license info from either format.

    Keyed by PURL identity when the component carries one (rename-aware: the
    same purl matches across a name change), falling back to name otherwise.
    """
    with open(path) as fh:
        doc = json.load(fh)

    comps = {}
    if "components" in doc or doc.get("bomFormat") == "CycloneDX":
        for c in doc.get("components", []):
            licenses = [
                lic.get("license", {}).get("id")
                or lic.get("license", {}).get("name")
                or lic.get("expression")
                for lic in c.get("licenses", [])
            ]
            name = c.get("name", "?")
            purl = c.get("purl")
            key = purl_identity(purl) if purl else name
            comps[key] = {
                "name": name,
                "version": c.get("version", "?"),
                "type": c.get("type", "library"),
                "licenses": sorted(filter(None, licenses)),
                "purl": purl,
            }
    elif "spdxVersion" in doc:
        for pkg in doc.get("packages", []):
            if pkg.get("name") == doc.get("name"):
                continue  # skip the document/root package
            lic = pkg.get("licenseConcluded") or pkg.get("licenseDeclared")
            name = pkg.get("name", "?")
            purl = next(
                (
                    ref.get("referenceLocator")
                    for ref in pkg.get("externalRefs", [])
                    if ref.get("referenceType") == "purl"
                ),
                None,
            )
            key = purl_identity(purl) if purl else name
            comps[key] = {
                "name": name,
                "version": pkg.get("versionInfo", "?"),
                "type": "library",
                "licenses": [lic] if lic and lic != "NOASSERTION" else [],
                "purl": purl,
            }
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
        vulns[v.get("id", "?")] = {
            "state": analysis.get("state", "unknown"),
            "severity": next(
                (r.get("severity") for r in v.get("ratings", []) if r.get("severity")), None
            ),
        }
    return vulns


def _added_removed(old, new):
    return {k: new[k] for k in new.keys() - old.keys()}, {k: old[k] for k in old.keys() - new.keys()}


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


def explain(added, removed, changed, license_changes, renamed=None, vulns=None):
    renamed = renamed or {}
    lines = []
    jumps = defaultdict(list)
    for o, n in sorted(changed.values(), key=lambda pair: pair[0]["name"]):
        jumps[semver_jump(o["version"], n["version"])].append(
            (o["name"], o["version"], n["version"])
        )

    if renamed:
        lines.append(f"## Renamed ({len(renamed)})\n")
        for _, (o, n) in sorted(renamed.items(), key=lambda kv: kv[1][0]["name"]):
            note = f" ({o['version']} → {n['version']})" if o["version"] != n["version"] else ""
            lines.append(f"- **{o['name']}** → **{n['name']}**{note}")
        lines.append("")

    if jumps["major"]:
        lines.append("## ⚠ Major version jumps (review breaking changes)\n")
        lines += [f"- **{n}**: {o} → {v}" for n, o, v in jumps["major"]]
        lines.append("")
    for label, key in (
        ("Minor updates", "minor"),
        ("Patch updates", "patch"),
        ("Other version changes", "other"),
    ):
        if jumps[key]:
            lines.append(f"## {label}\n")
            lines += [f"- {n}: {o} → {v}" for n, o, v in jumps[key]]
            lines.append("")
    if added:
        lines.append(f"## New dependencies ({len(added)})\n")
        lines += [
            f"- {c['name']} {c['version']}" for c in sorted(added.values(), key=lambda c: c["name"])
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
    summary = (
        f"{total} dependency change(s): {len(added)} added, {len(removed)} removed, "
        f"{len(changed)} updated ({len(jumps['major'])} major)"
    )
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

    if args.json:
        json.dump(
            {
                "summary": summary,
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
        print(f"# SBOM diff\n\n{summary}\n\n{body}")

    if args.fail_on == "any" and (added or removed or changed):
        return 1
    if args.fail_on == "major" and any(
        semver_jump(o["version"], n["version"]) == "major" for o, n in changed.values()
    ):
        return 1
    if args.fail_on == "license" and licenses:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
