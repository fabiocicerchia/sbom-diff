"""The CI gates: which changes count as a failure, and why."""

from sbom_diff_lib.compare import Counts
from sbom_diff_lib.types import Components, Json, Pairs
from sbom_diff_lib.versions import semver_jump


def _threshold_failures(totals: Counts, policy: Json) -> list[str]:
    """The count gates, in the order the report lists them."""
    fails = []
    max_added = policy.get("max_added")
    if max_added is not None and totals.added > max_added:
        fails.append(f"{totals.added} components added, over the limit of {max_added}")

    max_transitive = policy.get("max_added_transitive")
    if max_transitive is not None and totals.added_transitive > max_transitive:
        fails.append(f"{totals.added_transitive} transitive components added, over the limit of {max_transitive}")

    if policy.get("fail_on_downgrade") and totals.downgrades:
        fails.append(
            f"{totals.downgrades} component(s) downgraded — usually a lockfile conflict resolved the wrong way"
        )
    if policy.get("fail_on_license_change") and totals.license_changed:
        fails.append(f"{totals.license_changed} licence change(s)")
    return fails


def _denied_license_hits(added: Components, license_changes: Pairs, deny_licenses: list[str]) -> list[str]:
    """ "name (licence)" for every denied licence the change introduces, sorted.

    Checked on what the change *introduces*: components added, and the new side
    of a licence that changed under a dependency already there.
    """
    denied = {lic.lower() for lic in deny_licenses or []}
    if not denied:
        return []
    candidates = list(added.values()) + [n for _o, n in license_changes.values()]
    return sorted({f"{c['name']} ({lic})" for c in candidates for lic in c["licenses"] if lic.lower() in denied})


def policy_failures(added: Components, license_changes: Pairs, totals: Counts, policy: Json) -> list[str]:
    """Reasons the check should fail. Empty means pass.

    Every threshold is opt-in: a dependency review that fails by default is a
    dependency review that gets disabled by default.
    """
    fails = _threshold_failures(totals, policy)
    hits = _denied_license_hits(added, license_changes, policy.get("deny_licenses"))
    if hits:
        fails.append(f"denied licence(s): {', '.join(hits)}")
    return fails


def fail_on_verdict(
    fail_on: str, added: Components, removed: Components, changed: Pairs, license_changes: Pairs
) -> bool:
    """True when --fail-on's chosen class of change is present."""
    if fail_on == "any":
        return bool(added or removed or changed)
    if fail_on == "major":
        return any(semver_jump(o["version"], n["version"]) == "major" for o, n in changed.values())
    if fail_on == "license":
        return bool(license_changes)
    return False
