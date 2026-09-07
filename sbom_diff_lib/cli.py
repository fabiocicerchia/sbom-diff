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

from sbom_diff_lib.compare import counts, diff, diff_vulnerabilities
from sbom_diff_lib.exits import EXIT_GATE_FAILED, EXIT_OK, SbomError
from sbom_diff_lib.load import read_sbom
from sbom_diff_lib.policy import fail_on_verdict, policy_failures
from sbom_diff_lib.render import explain, json_payload
from sbom_diff_lib.types import Json


def build_parser() -> argparse.ArgumentParser:
    """The CLI surface. Every gate is opt-in and every one of them exits 1."""
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
    return p


def policy_from_args(args: argparse.Namespace) -> Json:
    """The gate settings, lifted out of argparse so policy_failures never sees it."""
    return {
        "max_added": args.max_added,
        "max_added_transitive": args.max_added_transitive,
        "fail_on_downgrade": args.fail_on_downgrade,
        "fail_on_license_change": args.fail_on_license_change,
        "deny_licenses": [s.strip() for s in re.split(r"[,\n]", args.deny_licenses) if s.strip()],
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

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

    totals = counts(added, removed, changed, licenses)
    # One string, rendered once: --json carries the same markdown stdout prints.
    report = f"# SBOM diff\n\n{summary}\n\n{body}"

    if args.json:
        json.dump(json_payload(report, summary, totals, changes, vulns), sys.stdout, indent=2)
    else:
        print(report)  # noqa: T201 — the tool's output

    fails = policy_failures(added, licenses, totals, policy_from_args(args))
    for reason in fails:
        print(f"sbom-diff: {reason}", file=sys.stderr)  # noqa: T201 — the tool's output

    if fail_on_verdict(args.fail_on, added, removed, changed, licenses):
        return EXIT_GATE_FAILED
    return EXIT_GATE_FAILED if fails else EXIT_OK
