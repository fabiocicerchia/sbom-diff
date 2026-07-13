#!/usr/bin/env python3
"""sbom-diff — diff two SBOMs, explain the changes in plain language.

Supports CycloneDX JSON and SPDX JSON (as produced by syft, trivy, etc.):

  syft -o cyclonedx-json myapp:1.0 > old.json
  syft -o cyclonedx-json myapp:1.1 > new.json
  sbom-diff old.json new.json
"""

import argparse
import json
import sys
from collections import defaultdict


def load_components(path):
    """Return {name: {version, ...}} plus license info from either format."""
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
            comps[c.get("name", "?")] = {
                "version": c.get("version", "?"),
                "type": c.get("type", "library"),
                "licenses": sorted(filter(None, licenses)),
            }
    elif "spdxVersion" in doc:
        for pkg in doc.get("packages", []):
            if pkg.get("name") == doc.get("name"):
                continue  # skip the document/root package
            lic = pkg.get("licenseConcluded") or pkg.get("licenseDeclared")
            comps[pkg.get("name", "?")] = {
                "version": pkg.get("versionInfo", "?"),
                "type": "library",
                "licenses": [lic] if lic and lic != "NOASSERTION" else [],
            }
    else:
        raise ValueError(f"{path}: not a recognizable CycloneDX or SPDX JSON SBOM")
    return comps


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
    added = {k: new[k] for k in new.keys() - old.keys()}
    removed = {k: old[k] for k in old.keys() - new.keys()}
    changed = {
        k: (old[k], new[k])
        for k in old.keys() & new.keys()
        if old[k]["version"] != new[k]["version"]
    }
    license_changes = {
        k: (old[k]["licenses"], new[k]["licenses"])
        for k in old.keys() & new.keys()
        if old[k]["licenses"] != new[k]["licenses"] and (old[k]["licenses"] or new[k]["licenses"])
    }
    return added, removed, changed, license_changes


def explain(added, removed, changed, license_changes):
    lines = []
    jumps = defaultdict(list)
    for name, (o, n) in sorted(changed.items()):
        jumps[semver_jump(o["version"], n["version"])].append((name, o["version"], n["version"]))

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
        lines += [f"- {n} {c['version']}" for n, c in sorted(added.items())]
        lines.append("")
    if removed:
        lines.append(f"## Removed dependencies ({len(removed)})\n")
        lines += [f"- {n} {c['version']}" for n, c in sorted(removed.items())]
        lines.append("")
    if license_changes:
        lines.append("## ⚠ License changes\n")
        lines += [
            f"- **{n}**: {', '.join(o) or '(none)'} → {', '.join(w) or '(none)'}"
            for n, (o, w) in sorted(license_changes.items())
        ]
        lines.append("")

    total = len(added) + len(removed) + len(changed)
    summary = (
        f"{total} dependency change(s): {len(added)} added, {len(removed)} removed, "
        f"{len(changed)} updated ({len(jumps['major'])} major)"
    )
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

    added, removed, changed, licenses = diff(load_components(args.old), load_components(args.new))
    summary, body = explain(added, removed, changed, licenses)

    if args.json:
        json.dump(
            {
                "summary": summary,
                "added": added,
                "removed": removed,
                "changed": {k: {"old": o, "new": n} for k, (o, n) in changed.items()},
                "license_changes": {k: {"old": o, "new": n} for k, (o, n) in licenses.items()},
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
