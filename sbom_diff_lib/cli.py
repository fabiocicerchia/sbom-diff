"""sbom-diff — diff two SBOMs, explain the changes in plain language.

Supports CycloneDX JSON and SPDX JSON (as produced by syft, trivy, etc.):

  syft -o cyclonedx-json myapp:1.0 > old.json
  syft -o cyclonedx-json myapp:1.1 > new.json
  sbom-diff old.json new.json

`--review` adds the judgement layer on top of the diff: every added or
updated component is scored against ten signals and ranked into tiers, so a
reviewer knows which three of ninety changes to actually read.
"""

import argparse
import json
import re
import sys
from pathlib import Path

from sbom_diff_lib.cache import DEFAULT_TTL_SECONDS, Cache, default_cache_dir
from sbom_diff_lib.compare import counts, diff, diff_vulnerabilities
from sbom_diff_lib.exits import EXIT_GATE_FAILED, EXIT_OK, SbomError
from sbom_diff_lib.fetch import DEFAULT_MAX_REQUESTS, Fetcher
from sbom_diff_lib.graph import read_graph
from sbom_diff_lib.load import read_sbom
from sbom_diff_lib.policy import fail_on_verdict, policy_failures
from sbom_diff_lib.render import explain, json_payload
from sbom_diff_lib.render_review import render_review, review_payload, tier_failures
from sbom_diff_lib.review import GraphPair, Plan, Review, review
from sbom_diff_lib.signals import GRAPH, SIGNALS, Options, select
from sbom_diff_lib.tiers import TIER_IDS, TIERS
from sbom_diff_lib.types import Changes, Json


def build_parser() -> argparse.ArgumentParser:
    """The CLI surface. Every gate is opt-in and every one of them exits 1."""
    p = argparse.ArgumentParser(
        prog="sbom-diff", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    # Optional so `--list-signals` is a complete command line; main checks.
    p.add_argument("old", nargs="?", help="previous SBOM (CycloneDX or SPDX JSON)")
    p.add_argument("new", nargs="?", help="current SBOM")
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
    _add_review_arguments(p)
    return p


def _add_review_arguments(p: argparse.ArgumentParser) -> None:
    """The judgement layer: what to score, how hard to look, what to fail on."""
    group = p.add_argument_group("review", "score added and updated components, and rank what to read first")
    group.add_argument(
        "--review",
        action="store_true",
        help="gather signals for added/updated components and rank them into tiers",
    )
    group.add_argument(
        "--offline",
        action="store_true",
        help="score only from the SBOMs; report every signal that needed a network source as skipped",
    )
    group.add_argument(
        "--disable-signal",
        action="append",
        default=[],
        metavar="ID",
        help="turn one signal off (repeatable, comma separated); --list-signals prints the ids",
    )
    group.add_argument("--list-signals", action="store_true", help="print every signal, its points and its source")
    group.add_argument(
        "--fail-on-tier",
        choices=list(TIER_IDS),
        help="exit 1 when any component lands in this tier or a louder one",
    )
    group.add_argument(
        "--young-days",
        type=int,
        default=Options.young_days,
        metavar="N",
        help=f"flag releases published less than N days ago (default {Options.young_days})",
    )
    group.add_argument(
        "--fanout-threshold",
        type=int,
        default=Options.fanout_threshold,
        metavar="N",
        help=f"flag a component whose transitive count grew by more than N (default {Options.fanout_threshold})",
    )
    group.add_argument(
        "--scorecard-drop",
        type=float,
        default=Options.scorecard_drop,
        metavar="POINTS",
        help=f"flag an OpenSSF Scorecard fall larger than this (default {Options.scorecard_drop})",
    )
    group.add_argument(
        "--cache-dir", metavar="PATH", help=f"where responses are cached (default {default_cache_dir()})"
    )
    group.add_argument(
        "--cache-ttl",
        type=int,
        default=DEFAULT_TTL_SECONDS,
        metavar="SECONDS",
        help=f"how long a cached response stays fresh (default {DEFAULT_TTL_SECONDS})",
    )
    group.add_argument("--no-cache", action="store_true", help="do not read or write the response cache")
    group.add_argument(
        "--max-requests",
        type=int,
        default=DEFAULT_MAX_REQUESTS,
        metavar="N",
        help=f"stop asking after N requests in one run (default {DEFAULT_MAX_REQUESTS}, 0 for no limit)",
    )


def policy_from_args(args: argparse.Namespace) -> Json:
    """The gate settings, lifted out of argparse so policy_failures never sees it."""
    return {
        "max_added": args.max_added,
        "max_added_transitive": args.max_added_transitive,
        "fail_on_downgrade": args.fail_on_downgrade,
        "fail_on_license_change": args.fail_on_license_change,
        "deny_licenses": [s.strip() for s in re.split(r"[,\n]", args.deny_licenses) if s.strip()],
    }


def signal_listing() -> str:
    """`--list-signals`: the whole ranking rule, without running anything."""
    lines = ["Signals — each one independent, each one turn-off-able with --disable-signal <id>.", ""]
    lines += [
        f"  {s.id:<16} {s.points:>2} point{'s' if s.points != 1 else ''}  {s.title}"
        f"\n  {'':<16}         source: {s.source}"
        for s in SIGNALS
    ]
    lines += ["", "Tiers — a component's points add up, and the first band it reaches is its tier.", ""]
    lines += [f"  {t.label:<10} score >= {t.minimum:<3} {t.blurb}" for t in TIERS]
    return "\n".join(lines)


def disabled_signals(args: argparse.Namespace) -> list[str]:
    """--disable-signal, repeated and/or comma separated, flattened."""
    return [s.strip() for entry in args.disable_signal for s in entry.split(",") if s.strip()]


def run_review(args: argparse.Namespace, changes: Changes) -> Review:
    """Build the plan, fetch only what it needs, and score the changes."""
    signals, skipped = select(disabled_signals(args), offline=args.offline)
    plan = Plan(
        signals=signals,
        skipped=skipped,
        options=Options(
            young_days=args.young_days,
            fanout_threshold=args.fanout_threshold,
            scorecard_drop=args.scorecard_drop,
        ),
        offline=args.offline,
    )
    cache = Cache(None if args.no_cache else Path(args.cache_dir or default_cache_dir()), args.cache_ttl)
    fetcher = Fetcher(cache, offline=args.offline, max_requests=args.max_requests)
    # Parsing the graph is only worth it when a signal reads it.
    graphs = GraphPair(read_graph(args.old), read_graph(args.new)) if GRAPH in plan.sources else GraphPair()
    return review(changes, graphs, fetcher, plan)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_signals:
        print(signal_listing())  # noqa: T201 — the tool's output
        return EXIT_OK
    if not args.old or not args.new:
        parser.error("the old and new SBOM paths are both required")
    # A tier gate is a request for the review that produces the tiers.
    wants_review = args.review or bool(args.fail_on_tier)

    try:
        old_comps, old_vulns = read_sbom(args.old)
        new_comps, new_vulns = read_sbom(args.new)
    except SbomError as exc:
        print(f"sbom-diff: {exc}", file=sys.stderr)  # noqa: T201 — the tool's output
        return exc.code

    changes = diff(old_comps, new_comps)
    added, removed, changed, licenses, renamed = changes
    vulns = diff_vulnerabilities(old_vulns, new_vulns)
    summary, body = explain(added, removed, changed, licenses, renamed=renamed, vulns=vulns)

    try:
        judgement = run_review(args, changes) if wants_review else None
    except ValueError as exc:
        parser.error(str(exc))

    totals = counts(added, removed, changed, licenses)
    if judgement is not None:
        body = f"{body}\n" + "\n".join(render_review(judgement))
    # One string, rendered once: --json carries the same markdown stdout prints.
    report = f"# SBOM diff\n\n{summary}\n\n{body}"

    if args.json:
        payload = json_payload(report, summary, totals, changes, vulns)
        if judgement is not None:
            payload["review"] = review_payload(judgement)
        json.dump(payload, sys.stdout, indent=2)
    else:
        print(report)  # noqa: T201 — the tool's output

    fails = policy_failures(added, licenses, totals, policy_from_args(args))
    if judgement is not None:
        fails += tier_failures(judgement, args.fail_on_tier)
    for reason in fails:
        print(f"sbom-diff: {reason}", file=sys.stderr)  # noqa: T201 — the tool's output

    if fail_on_verdict(args.fail_on, added, removed, changed, licenses):
        return EXIT_GATE_FAILED
    return EXIT_GATE_FAILED if fails else EXIT_OK
