"""What changed between two component maps, and the headline numbers for it."""

from dataclasses import dataclass

from sbom_diff_lib.versions import is_downgrade


def _added_removed(old, new):
    return {k: new[k] for k in new.keys() - old.keys()}, {
        k: old[k] for k in old.keys() - new.keys()
    }


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


def diff_vulnerabilities(old, new):
    added, removed = _added_removed(old, new)
    changed = {
        k: (old[k]["state"], new[k]["state"])
        for k in old.keys() & new.keys()
        if old[k]["state"] != new[k]["state"]
    }
    return added, removed, changed


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
