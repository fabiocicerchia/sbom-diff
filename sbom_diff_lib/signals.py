"""The signals: ten questions asked of every added or updated component.

Each signal is a small function from a `Subject` -- one component, both sides
of the change, and whatever its sources said -- to an `Outcome`. An outcome is
one of four things, and the difference between the last two is the point of
the exercise:

  hit            the thing happened, here is what to look at
  clear          it was checked and it did not happen
  not applicable there is no previous version to compare against
  not checkable  nobody could answer, and the report says so

Points are attached to the signal, not computed inside it, so the whole
ranking rule is one table a reader can look at and disagree with.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from sbom_diff_lib.depsdev import Scorecard
from sbom_diff_lib.osv import Advisories
from sbom_diff_lib.registries import VersionFacts
from sbom_diff_lib.types import Component

# How many advisory ids one line names before it starts counting instead.
NAMED_ADVISORIES = 3

HIT = "hit"
CLEAR = "clear"
NOT_APPLICABLE = "not-applicable"
NOT_CHECKABLE = "not-checkable"

# The source keys a signal can ask for, which is also what review.py fetches.
SBOM = "sbom"
# The dependency graph is in the SBOMs too, but parsing it is work the other
# signals do not need, so it is asked for separately.
GRAPH = "graph"
REGISTRY = "registry"
OSV = "osv"
DEPSDEV = "deps.dev"


@dataclass(frozen=True)
class Options:
    """The thresholds the signals compare against, all of them CLI flags."""

    young_days: int = 14
    fanout_threshold: int = 5
    scorecard_drop: float = 1.0


@dataclass(frozen=True)
class Subject:
    """One component under review, with everything its sources returned."""

    key: str
    name: str
    ecosystem: str
    new: Component
    old: Component | None = None
    new_facts: VersionFacts = field(default_factory=VersionFacts)
    old_facts: VersionFacts = field(default_factory=VersionFacts)
    new_advisories: Advisories = field(default_factory=Advisories)
    old_advisories: Advisories = field(default_factory=Advisories)
    new_scorecard: Scorecard = field(default_factory=Scorecard)
    old_scorecard: Scorecard = field(default_factory=Scorecard)
    new_fanout: int | None = None
    old_fanout: int | None = None
    # Where a human goes to read the package; known even when nothing was
    # fetched, so a report built offline still links out.
    link: str | None = None
    options: Options = field(default_factory=Options)
    now: datetime = field(default_factory=lambda: datetime.now().astimezone())

    @property
    def new_version(self) -> str:
        return str(self.new["version"])

    @property
    def old_version(self) -> str | None:
        return str(self.old["version"]) if self.old else None


@dataclass(frozen=True)
class Outcome:
    """What one signal concluded about one component."""

    signal: str
    status: str
    detail: str
    link: str | None = None

    @property
    def is_hit(self) -> bool:
        return self.status == HIT


@dataclass(frozen=True)
class Signal:
    """One question, its weight, and where the answer comes from."""

    id: str
    title: str
    source: str
    points: int
    check: Callable[[Subject], Outcome]
    needs: frozenset[str] = frozenset({SBOM})
    compares_versions: bool = False

    @property
    def offline(self) -> bool:
        """True when the two files on disk can answer it."""
        return not (self.needs - {SBOM, GRAPH})


def _outcome(signal: str, status: str, detail: str, link: str | None = None) -> Outcome:
    return Outcome(signal=signal, status=status, detail=detail, link=link)


def _no_previous(signal: str) -> Outcome:
    return _outcome(signal, NOT_APPLICABLE, "no previous version to compare against")


def new_package(s: Subject) -> Outcome:
    if s.old is None:
        return _outcome("new-package", HIT, "not in the base SBOM at all — nobody has reviewed it before", s.link)
    return _outcome("new-package", CLEAR, f"already present at {s.old_version}")


def major_skip(s: Subject) -> Outcome:
    if s.old is None:
        return _no_previous("major-skip")
    old_major, new_major = _major(s.old_version), _major(s.new_version)
    if old_major is None or new_major is None:
        return _outcome("major-skip", NOT_CHECKABLE, f"{s.old_version} → {s.new_version} is not a numbered major")
    skipped = new_major - old_major
    if skipped > 1:
        return _outcome(
            "major-skip",
            HIT,
            f"jumped {skipped} majors at once ({old_major}.x → {new_major}.x) — "
            f"{skipped - 1} release(s) of breaking changes went unread",
            s.link,
        )
    return _outcome("major-skip", CLEAR, f"{old_major}.x → {new_major}.x")


def _major(version: str | None) -> int | None:
    head = str(version or "").lstrip("v").split(".")[0]
    return int(head) if head.isdigit() else None


def new_advisories(s: Subject) -> Outcome:
    if s.new_advisories.records is None:
        return _outcome("advisories", NOT_CHECKABLE, s.new_advisories.note or "OSV was not asked")
    fresh = [a for a in s.new_advisories.records if a.id not in s.old_advisories.ids]
    if not fresh:
        known = len(s.new_advisories.records)
        settled = f"{known} advisory(ies), all of them already on {s.old_version}" if known else "no advisories"
        return _outcome("advisories", CLEAR, f"OSV reports {settled}")
    listed = ", ".join(f"{a.id}{f' ({a.severity})' if a.severity else ''}" for a in fresh[:NAMED_ADVISORIES])
    more = f" and {len(fresh) - NAMED_ADVISORIES} more" if len(fresh) > NAMED_ADVISORIES else ""
    return _outcome(
        "advisories", HIT, f"OSV reports {len(fresh)} advisory(ies) new to this version: {listed}{more}", fresh[0].link
    )


def install_scripts(s: Subject) -> Outcome:
    if s.new_facts.scripts is None:
        return _outcome(
            "install-scripts", NOT_CHECKABLE, s.new_facts.notes.get("scripts", "the registry was not asked")
        )
    if not s.new_facts.scripts:
        return _outcome("install-scripts", CLEAR, "no install or lifecycle scripts")
    previous = s.old_facts.scripts if s.old and s.old_facts.scripts is not None else {}
    changed = sorted(k for k, v in s.new_facts.scripts.items() if previous.get(k) != v)
    if not changed:
        return _outcome(
            "install-scripts", CLEAR, f"{', '.join(sorted(s.new_facts.scripts))} unchanged from {s.old_version}"
        )
    verb = "added" if s.old is None or not previous else "added or changed"
    unverified = (
        "" if s.old is None or s.old_facts.scripts is not None else " (the previous version could not be checked)"
    )
    return _outcome(
        "install-scripts",
        HIT,
        f"{', '.join(changed)} {verb} — this runs on `install`, read it{unverified}",
        s.link,
    )


def maintainers_changed(s: Subject) -> Outcome:
    if s.old is None:
        return _no_previous("maintainers")
    if s.new_facts.maintainers is None or s.old_facts.maintainers is None:
        missing = s.new_facts.notes.get("maintainers") or s.old_facts.notes.get("maintainers")
        return _outcome("maintainers", NOT_CHECKABLE, missing or "the registry was not asked")
    gained = sorted(s.new_facts.maintainers - s.old_facts.maintainers)
    lost = sorted(s.old_facts.maintainers - s.new_facts.maintainers)
    if not gained and not lost:
        return _outcome("maintainers", CLEAR, f"same {len(s.new_facts.maintainers)} maintainer(s) as {s.old_version}")
    moves = ", ".join([*(f"+{m}" for m in gained), *(f"-{m}" for m in lost)])
    return _outcome("maintainers", HIT, f"the people who can publish it changed: {moves}", s.link)


def young_package(s: Subject) -> Outcome:
    if s.new_facts.published is None:
        return _outcome(
            "young-package", NOT_CHECKABLE, s.new_facts.notes.get("published", "the registry was not asked")
        )
    age = (s.now - s.new_facts.published).days
    when = s.new_facts.published.date().isoformat()
    if age < s.options.young_days:
        return _outcome(
            "young-package",
            HIT,
            f"published {age} day(s) ago ({when}) — younger than the {s.options.young_days}-day floor, "
            "so a bad release has had little time to be noticed",
            s.link,
        )
    return _outcome("young-package", CLEAR, f"published {age} day(s) ago ({when})")


def license_changed(s: Subject) -> Outcome:
    if s.old is None:
        return _no_previous("license")
    old_licenses, new_licenses = list(s.old["licenses"]), list(s.new["licenses"])
    if old_licenses == new_licenses or not (old_licenses or new_licenses):
        return _outcome("license", CLEAR, f"still {', '.join(new_licenses) or '(none stated)'}")
    return _outcome(
        "license",
        HIT,
        f"{', '.join(old_licenses) or '(none stated)'} → {', '.join(new_licenses) or '(none stated)'}",
        s.link,
    )


def provenance_lost(s: Subject) -> Outcome:
    if s.old is None:
        return _no_previous("provenance")
    if s.new_facts.provenance is None or s.old_facts.provenance is None:
        missing = s.new_facts.notes.get("provenance") or s.old_facts.notes.get("provenance")
        return _outcome("provenance", NOT_CHECKABLE, missing or "the registry was not asked")
    if s.old_facts.provenance and not s.new_facts.provenance:
        return _outcome(
            "provenance",
            HIT,
            f"{s.old_version} shipped with published provenance and {s.new_version} does not — "
            "nothing now ties the published artifact to a build",
            s.link,
        )
    return _outcome("provenance", CLEAR, "published provenance" if s.new_facts.provenance else "none either side")


def fanout_grew(s: Subject) -> Outcome:
    if s.new_fanout is None:
        return _outcome("fanout", NOT_CHECKABLE, "the new SBOM has no dependency graph for it")
    if s.old is not None and s.old_fanout is None:
        return _outcome("fanout", NOT_CHECKABLE, "the base SBOM has no dependency graph for it")
    # A new dependency is measured from zero: everything behind it is new too.
    before = s.old_fanout or 0
    growth = s.new_fanout - before
    if growth > s.options.fanout_threshold:
        arrived = f"{growth} more than before" if s.old else "all of them new"
        return _outcome("fanout", HIT, f"pulls in {s.new_fanout} package(s), {arrived}", s.link)
    return _outcome("fanout", CLEAR, f"pulls in {s.new_fanout} package(s) ({growth:+d})")


def scorecard_drop(s: Subject) -> Outcome:
    if s.old is None:
        return _no_previous("scorecard")
    if s.new_scorecard.score is None or s.old_scorecard.score is None:
        missing = s.new_scorecard.note or s.old_scorecard.note
        return _outcome("scorecard", NOT_CHECKABLE, missing or "deps.dev was not asked")
    drop = s.old_scorecard.score - s.new_scorecard.score
    if drop > s.options.scorecard_drop:
        moved = (
            ""
            if s.old_scorecard.project == s.new_scorecard.project
            else f", and the source project moved to {s.new_scorecard.project}"
        )
        return _outcome(
            "scorecard",
            HIT,
            f"OpenSSF Scorecard {s.old_scorecard.score:.1f} → {s.new_scorecard.score:.1f}{moved}",
            s.new_scorecard.link,
        )
    return _outcome("scorecard", CLEAR, f"OpenSSF Scorecard {s.new_scorecard.score:.1f} ({-drop:+.1f})")


# The ranking rule, in one place: every signal, what it is worth, and who
# answers it. `--list-signals` prints this table and the report links to it.
SIGNALS: tuple[Signal, ...] = (
    Signal("advisories", "New advisories", "OSV API", 5, new_advisories, frozenset({OSV}), compares_versions=True),
    Signal(
        "install-scripts",
        "Install scripts added or changed",
        "npm registry (other ecosystems: not checkable)",
        5,
        install_scripts,
        frozenset({REGISTRY}),
        compares_versions=True,
    ),
    Signal(
        "provenance",
        "Provenance or attestation lost",
        "npm registry (other ecosystems: not checkable)",
        4,
        provenance_lost,
        frozenset({REGISTRY}),
        compares_versions=True,
    ),
    Signal(
        "maintainers",
        "Maintainer set changed",
        "npm and PyPI registries (other ecosystems: not checkable)",
        3,
        maintainers_changed,
        frozenset({REGISTRY}),
        compares_versions=True,
    ),
    Signal("major-skip", "More than one major skipped", "the two SBOMs", 3, major_skip),
    Signal("new-package", "Package is new to the tree", "the two SBOMs", 2, new_package),
    Signal(
        "young-package",
        "Release younger than the floor",
        "npm and PyPI registries (other ecosystems: not checkable)",
        2,
        young_package,
        frozenset({REGISTRY}),
    ),
    Signal("license", "License changed", "the two SBOMs", 2, license_changed),
    Signal(
        "scorecard",
        "OpenSSF Scorecard dropped",
        "deps.dev",
        2,
        scorecard_drop,
        frozenset({DEPSDEV}),
        compares_versions=True,
    ),
    Signal(
        "fanout",
        "Dependency fan-out grew",
        "the two SBOMs' dependency graphs",
        1,
        fanout_grew,
        frozenset({SBOM, GRAPH}),
    ),
)

SIGNALS_BY_ID = {s.id: s for s in SIGNALS}


def select(disabled: list[str] | None = None, *, offline: bool = False) -> tuple[list[Signal], list[tuple[str, str]]]:
    """The signals to run, and the ones left out with the reason why.

    Offline drops every signal that would need somebody else's API; naming one
    with `--disable-signal` drops it whatever the mode. Both endings are
    reported, because a signal nobody ran is not a signal that passed.
    """
    turned_off = set(disabled or [])
    unknown = sorted(turned_off - SIGNALS_BY_ID.keys())
    if unknown:
        raise ValueError(f"unknown signal(s): {', '.join(unknown)} (known: {', '.join(SIGNALS_BY_ID)})")

    run: list[Signal] = []
    skipped: list[tuple[str, str]] = []
    for signal in SIGNALS:
        if signal.id in turned_off:
            skipped.append((signal.id, "disabled on the command line"))
        elif offline and not signal.offline:
            skipped.append((signal.id, f"offline: needs {signal.source}"))
        else:
            run.append(signal)
    return run, skipped
