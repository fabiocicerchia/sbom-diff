"""The markdown report: one section per kind of change, most alarming first."""

from collections import defaultdict
from dataclasses import asdict

from sbom_diff_lib.compare import Counts, downgrade_count, transitive_count
from sbom_diff_lib.types import Components, Json, Pairs, Vulnerabilities
from sbom_diff_lib.versions import is_downgrade, semver_jump


def classify_jumps(changed: Pairs) -> dict[str, list[str]]:
    """Bucket every version change by size, in name order, ready to render."""
    jumps = defaultdict(list)
    for o, n in sorted(changed.values(), key=lambda pair: pair[0]["name"]):
        # A downgrade is flagged wherever it lands: 2.0.0 -> 1.9.0 is classified
        # "major" like any other, and reads as an upgrade unless it is labelled.
        note = " *(downgrade)*" if is_downgrade(o, n) else ""
        jumps[semver_jump(o["version"], n["version"])].append((o["name"], o["version"], n["version"], note))
    return jumps


def _render_renamed(renamed: Pairs) -> list[str]:
    if not renamed:
        return []
    lines = [f"## Renamed ({len(renamed)})\n"]
    for _, (o, n) in sorted(renamed.items(), key=lambda kv: kv[1][0]["name"]):
        note = f" ({o['version']} → {n['version']})" if o["version"] != n["version"] else ""
        lines.append(f"- **{o['name']}** → **{n['name']}**{note}")
    return [*lines, ""]


def _render_jumps(jumps: dict[str, list[str]]) -> list[str]:
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


def _render_added(added: Components) -> list[str]:
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


def _render_removed(removed: Components) -> list[str]:
    if not removed:
        return []
    return (
        [f"## Removed dependencies ({len(removed)})\n"]
        + [f"- {c['name']} {c['version']}" for c in sorted(removed.values(), key=lambda c: c["name"])]
        + [""]
    )


def _render_license_changes(license_changes: Pairs) -> list[str]:
    if not license_changes:
        return []
    return (
        ["## ⚠ License changes\n"]
        + [
            f"- **{o['name']}**: {', '.join(o['licenses']) or '(none)'} → {', '.join(n['licenses']) or '(none)'}"
            for o, n in sorted(license_changes.values(), key=lambda pair: pair[0]["name"])
        ]
        + [""]
    )


def _render_vulnerabilities(vulns: Vulnerabilities) -> list[str]:
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
        + [f"- ✅ **{vid}** no longer reported (was: {v['state']})" for vid, v in sorted(removed_v.items())]
        + [f"- 🔄 **{vid}**: {old_state} → {new_state}" for vid, (old_state, new_state) in sorted(changed_v.items())]
        + [""]
    )


def summarize(
    added: Components, removed: Components, changed: Pairs, renamed: Pairs, jumps: dict[str, list[str]]
) -> str:
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


def explain(  # noqa: PLR0913 — the five collections diff() returns, plus vulns
    added: Components,
    removed: Components,
    changed: Pairs,
    license_changes: Pairs,
    *,
    renamed: Pairs | None = None,
    vulns: Vulnerabilities | None = None,
) -> tuple[str, str]:
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


def json_payload(
    report: str,
    summary: str,
    totals: Counts,
    changes: tuple[Components, Components, Pairs, Pairs, Pairs],
    vulns: Vulnerabilities | None,
) -> Json:
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
