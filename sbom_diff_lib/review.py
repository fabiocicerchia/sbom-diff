"""The judgement layer: gather each component's signals, score it, rank it.

`compare.py` says what changed. This says which of it a human should read,
which is the part `cyclonedx-cli diff` and `sbomdiff` leave to the reviewer.
The order of operations matters for politeness: the signals to run are chosen
first, and only the sources those signals actually need are ever fetched.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sbom_diff_lib.depsdev import Scorecard, scorecard
from sbom_diff_lib.fetch import Fetcher
from sbom_diff_lib.graph import Graph, fanout
from sbom_diff_lib.osv import Advisories, advisories
from sbom_diff_lib.purl import purl_name
from sbom_diff_lib.registries import VersionFacts, package_link, version_facts
from sbom_diff_lib.signals import DEPSDEV, NOT_CHECKABLE, OSV, REGISTRY, Options, Outcome, Signal, Subject
from sbom_diff_lib.tiers import TIER_IDS, tier_for
from sbom_diff_lib.types import Changes, Component

NOT_ASKED = "not needed: every signal that reads it is turned off"


@dataclass(frozen=True)
class Plan:
    """Everything decided before the first request goes out."""

    signals: list[Signal]
    skipped: list[tuple[str, str]] = field(default_factory=list)
    options: Options = field(default_factory=Options)
    offline: bool = False

    @property
    def sources(self) -> frozenset[str]:
        """The union of what the enabled signals need, and nothing else."""
        sources: frozenset[str] = frozenset()
        return sources.union(*(s.needs for s in self.signals))

    @property
    def compares_versions(self) -> bool:
        """True when some enabled signal looks at the previous version too."""
        return any(s.compares_versions for s in self.signals)


@dataclass(frozen=True)
class GraphPair:
    """The two dependency graphs, either of which may be absent."""

    old: Graph | None = None
    new: Graph | None = None


@dataclass(frozen=True)
class Finding:
    """One component, everything its signals said, and where that lands it."""

    key: str
    name: str
    ecosystem: str
    new_version: str
    old_version: str | None
    purl: str | None
    link: str | None
    outcomes: tuple[Outcome, ...]
    score: int
    tier: str

    @property
    def hits(self) -> tuple[Outcome, ...]:
        return tuple(o for o in self.outcomes if o.is_hit)

    @property
    def unchecked(self) -> tuple[Outcome, ...]:
        return tuple(o for o in self.outcomes if o.status == NOT_CHECKABLE)


@dataclass(frozen=True)
class Review:
    """The ranked findings plus what it cost and what was not asked."""

    findings: tuple[Finding, ...]
    plan: Plan
    requests: int = 0
    cache_hits: int = 0
    budget_spent: bool = False

    def by_tier(self, tier_id: str) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.tier == tier_id)


def review(changes: Changes, graphs: GraphPair, fetcher: Fetcher, plan: Plan, now: datetime | None = None) -> Review:
    """Score every added and version-changed component, worst first."""
    moment = now or datetime.now(timezone.utc)
    findings = [_score(_subject(pair, graphs, fetcher, plan, moment), plan) for pair in _subjects(changes)]
    # Loudest tier first, then by score, then by name so two runs of the same
    # diff produce the same document.
    findings.sort(key=lambda f: (_tier_rank(f.tier), -f.score, f.name.lower()))
    return Review(
        findings=tuple(findings),
        plan=plan,
        requests=fetcher.requests_made,
        cache_hits=fetcher.cache.hits,
        budget_spent=fetcher.budget_spent,
    )


def _tier_rank(tier_id: str) -> int:
    return TIER_IDS.index(tier_id)


def _subjects(changes: Changes) -> list[tuple[str, Component | None, Component]]:
    """(key, old, new) for everything worth judging: added and version-changed.

    A rename is included when the version moved with it -- the package is still
    a different build of itself -- and skipped when only the label changed.
    """
    added, _removed, changed, _licenses, renamed = changes
    subjects: list[tuple[str, Component | None, Component]] = [(k, None, c) for k, c in added.items()]
    subjects += [(k, o, n) for k, (o, n) in changed.items()]
    subjects += [(k, o, n) for k, (o, n) in renamed.items() if o["version"] != n["version"]]
    return subjects


def _registry_name(component: Component) -> str:
    """The name the registry answers to: the purl's, falling back to the SBOM's."""
    return purl_name(component.get("purl")) or str(component["name"])


def _subject(
    entry: tuple[str, Component | None, Component], graphs: GraphPair, fetcher: Fetcher, plan: Plan, now: datetime
) -> Subject:
    """Fetch what the enabled signals need for one component, and nothing more."""
    key, old, new = entry
    ecosystem = str(new.get("ecosystem", "unknown"))
    name, version = _registry_name(new), str(new["version"])
    sources = plan.sources
    look_back = old is not None and plan.compares_versions
    old_name = _registry_name(old) if old else name
    old_version = str(old["version"]) if old else version

    return Subject(
        key=key,
        name=str(new["name"]),
        ecosystem=ecosystem,
        new=new,
        old=old,
        link=package_link(ecosystem, name, version),
        new_facts=_facts(fetcher, sources, ecosystem, name, version),
        old_facts=_facts(fetcher, sources, ecosystem, old_name, old_version) if look_back else VersionFacts(),
        new_advisories=_advisories(fetcher, sources, ecosystem, name, version),
        old_advisories=_advisories(fetcher, sources, ecosystem, old_name, old_version) if look_back else Advisories(),
        new_scorecard=_scorecard(fetcher, sources, ecosystem, name, version),
        old_scorecard=_scorecard(fetcher, sources, ecosystem, old_name, old_version) if look_back else Scorecard(),
        new_fanout=fanout(graphs.new, key),
        old_fanout=fanout(graphs.old, key) if old else None,
        options=plan.options,
        now=now,
    )


def _facts(fetcher: Fetcher, sources: frozenset[str], ecosystem: str, name: str, version: str) -> VersionFacts:
    if REGISTRY not in sources:
        return VersionFacts(notes=dict.fromkeys(("scripts", "maintainers", "published", "provenance"), NOT_ASKED))
    return version_facts(fetcher, ecosystem, name, version)


def _advisories(fetcher: Fetcher, sources: frozenset[str], ecosystem: str, name: str, version: str) -> Advisories:
    return advisories(fetcher, ecosystem, name, version) if OSV in sources else Advisories(note=NOT_ASKED)


def _scorecard(fetcher: Fetcher, sources: frozenset[str], ecosystem: str, name: str, version: str) -> Scorecard:
    return scorecard(fetcher, ecosystem, name, version) if DEPSDEV in sources else Scorecard(note=NOT_ASKED)


def _score(subject: Subject, plan: Plan) -> Finding:
    """Run the enabled signals over one subject and add up what fired."""
    outcomes = tuple(signal.check(subject) for signal in plan.signals)
    fired = {o.signal for o in outcomes if o.is_hit}
    score = sum(s.points for s in plan.signals if s.id in fired)
    return Finding(
        key=subject.key,
        name=subject.name,
        ecosystem=subject.ecosystem,
        new_version=subject.new_version,
        old_version=subject.old_version,
        purl=subject.new.get("purl"),
        link=subject.link,
        outcomes=outcomes,
        score=score,
        tier=tier_for(score).id,
    )
