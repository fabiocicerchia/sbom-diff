"""The review section: tiers, the specific thing to look at, and the rule.

Two renderings of one `Review`: markdown for the pull request comment, and a
JSON object for whatever reads the `--json` output. Both carry the ranking
rule, because a ranking a reader cannot audit is a ranking a reader will
either obey blindly or ignore entirely.
"""

from dataclasses import asdict

from sbom_diff_lib.review import Finding, Review
from sbom_diff_lib.tiers import TIERS, meets, rule_markdown
from sbom_diff_lib.types import Json

# Routine entries are one line each: the interesting thing about them is that
# there is nothing interesting about them.
DETAILED_TIERS = ("read", "glance")

# How many components a gate failure names before it starts counting instead.
NAMED_IN_FAILURE = 5


def render_review(review: Review) -> list[str]:
    """The whole review section, ready to append to the diff report."""
    if not review.findings:
        return []
    lines = [f"## What to review ({len(review.findings)} scored)\n", _headline(review), ""]
    if review.budget_spent:
        lines += [
            "> ⚠ The request budget was spent before every component was checked; "
            "the signals below it are marked not checkable, not clean. Raise `--max-requests` or re-run "
            "with a warm cache.",
            "",
        ]
    for tier in TIERS:
        lines += _render_tier(tier.id, tier.label, review.by_tier(tier.id))
    return [*lines, *_rule_block(review)]


def _headline(review: Review) -> str:
    counted = ", ".join(f"{len(review.by_tier(t.id))} {t.label.lower()}" for t in TIERS)
    scored_from = "the SBOMs alone (offline)" if review.plan.offline else f"{len(review.plan.signals)} signal(s)"
    return f"Added and updated components, scored from {scored_from}: {counted}."


def _render_tier(tier_id: str, label: str, findings: tuple[Finding, ...]) -> list[str]:
    if not findings:
        return []
    marker = "⚠ " if tier_id == "read" else ""
    lines = [f"### {marker}{label} ({len(findings)})\n"]
    for finding in findings:
        lines += _render_finding(finding, detailed=tier_id in DETAILED_TIERS)
    return [*lines, ""]


def _render_finding(finding: Finding, *, detailed: bool) -> list[str]:
    """One component: its heading line, then what fired under it."""
    if not detailed:
        fired = ", ".join(o.signal for o in finding.hits) or "no signal fired"
        return [f"- {finding.name} {_movement(finding)} · score {finding.score} · {fired}"]
    # "unknown" is what an ecosystem-less purl normalizes to; it is a fact
    # about the SBOM, not something to put in a heading.
    where = f" · {finding.ecosystem}" if finding.ecosystem != "unknown" else ""
    lines = [f"- **{finding.name}** {_movement(finding)}{where} · score {finding.score}"]
    lines += [f"  - {o.detail}{_link(o.link or finding.link)}" for o in finding.hits]
    if finding.unchecked:
        unchecked = ", ".join(f"`{o.signal}` ({o.detail})" for o in finding.unchecked)
        lines.append(f"  - _not checkable: {unchecked}_")
    return lines


def _movement(finding: Finding) -> str:
    return f"{finding.old_version} → {finding.new_version}" if finding.old_version else f"{finding.new_version} (new)"


def _link(url: str | None) -> str:
    return f" — [look]({url})" if url else ""


def _rule_block(review: Review) -> list[str]:
    """The ranking rule, folded away but present in every report."""
    cost = (
        "Nothing was fetched: this run was offline."
        if review.plan.offline
        else f"{review.requests} request(s) made, {review.cache_hits} answer(s) served from cache."
    )
    return [
        "<details>",
        "<summary>How this was ranked</summary>",
        "",
        *rule_markdown(review.plan.signals, review.plan.skipped),
        "",
        cost,
        "</details>",
        "",
    ]


def review_payload(review: Review) -> Json:
    """The `review` object in `--json`. Its shape is a contract; callers read these keys."""
    return {
        "offline": review.plan.offline,
        "thresholds": asdict(review.plan.options),
        "tiers": [
            {"id": t.id, "label": t.label, "min_score": t.minimum, "count": len(review.by_tier(t.id))} for t in TIERS
        ],
        "signals": [
            {"id": s.id, "title": s.title, "points": s.points, "source": s.source, "offline": s.offline}
            for s in review.plan.signals
        ],
        "skipped_signals": [{"signal": sid, "reason": why} for sid, why in review.plan.skipped],
        "findings": [_finding_payload(f) for f in review.findings],
        "requests": review.requests,
        "cache_hits": review.cache_hits,
        "budget_spent": review.budget_spent,
    }


def _finding_payload(finding: Finding) -> Json:
    return {
        "key": finding.key,
        "name": finding.name,
        "ecosystem": finding.ecosystem,
        "old_version": finding.old_version,
        "new_version": finding.new_version,
        "purl": finding.purl,
        "link": finding.link,
        "score": finding.score,
        "tier": finding.tier,
        "signals": [
            {"signal": o.signal, "status": o.status, "detail": o.detail, "link": o.link} for o in finding.outcomes
        ],
    }


def tier_failures(review: Review, threshold: str | None) -> list[str]:
    """Why `--fail-on-tier` should fail the run. Empty means pass."""
    if not threshold:
        return []
    loud = [f for f in review.findings if meets(f.tier, threshold)]
    if not loud:
        return []
    names = ", ".join(f"{f.name} ({f.tier}, score {f.score})" for f in loud[:NAMED_IN_FAILURE])
    more = f" and {len(loud) - NAMED_IN_FAILURE} more" if len(loud) > NAMED_IN_FAILURE else ""
    label = next(t.label for t in TIERS if t.id == threshold)
    return [f"{len(loud)} component(s) at or above “{label}”: {names}{more}"]
