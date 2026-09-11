"""The ranking rule: points to a tier, and the tier table that goes in the report.

The rule is deliberately arithmetic and deliberately printed. A reviewer who
thinks a maintainer change is worth more than a young release, or that
fan-out is worth nothing at all, can see the number, disagree with it, and
turn the signal off -- which is the only reason to trust a ranking somebody
else wrote.
"""

from dataclasses import dataclass

from sbom_diff_lib.signals import Signal


@dataclass(frozen=True)
class Tier:
    """One band of the ranking: its id, its heading, and the score that reaches it."""

    id: str
    label: str
    minimum: int
    blurb: str


# Ordered strongest first; the first tier a score reaches is the one it lands in.
TIERS: tuple[Tier, ...] = (
    Tier("read", "Read this", 5, "something specific happened here — open the link before approving"),
    Tier("glance", "Glance", 2, "worth ten seconds of eyes; nothing here is on fire by itself"),
    Tier("routine", "Routine", 0, "ordinary dependency movement"),
)

TIER_IDS = tuple(t.id for t in TIERS)


def tier_for(score: int) -> Tier:
    """The tier a score lands in. The last tier has a floor of zero, so this always returns."""
    return next(t for t in TIERS if score >= t.minimum)


def meets(tier_id: str, threshold: str) -> bool:
    """True when `tier_id` is at least as loud as `threshold`."""
    return TIER_IDS.index(tier_id) <= TIER_IDS.index(threshold)


def rule_markdown(signals: list[Signal], skipped: list[tuple[str, str]]) -> list[str]:
    """The ranking rule as markdown: the tiers, the points, and what was not run."""
    lines = [
        "Every signal below that fires adds its points; the total picks the tier.",
        "",
        "| Tier | Score | Means |",
        "| --- | --- | --- |",
    ]
    lines += [f"| {t.label} | {_band(i)} | {t.blurb} |" for i, t in enumerate(TIERS)]
    lines += ["", "| Signal | Points | Source |", "| --- | --- | --- |"]
    lines += [f"| `{s.id}` — {s.title} | {s.points} | {s.source} |" for s in signals]
    if skipped:
        lines += ["", "Not run on this diff:", ""]
        lines += [f"- `{sid}` — {why}" for sid, why in skipped]
    lines += [
        "",
        "Disagree with a weighting? Every signal is independent: "
        "`--disable-signal maintainers` drops it and rescores without it.",
    ]
    return lines


def _band(index: int) -> str:
    """The score range of a tier, written the way the table reads it."""
    tier = TIERS[index]
    if index == 0:
        return f"{tier.minimum} or more"
    return f"{tier.minimum}-{TIERS[index - 1].minimum - 1}" if tier.minimum else f"under {TIERS[index - 1].minimum}"
