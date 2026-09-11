"""The judgement layer: one fixture SBOM pair per signal, and recorded HTTP."""

import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import pytest
from conftest import RecordedTransport

from sbom_diff import main
from sbom_diff_lib.cache import Cache
from sbom_diff_lib.compare import diff
from sbom_diff_lib.fetch import Fetcher, RawResponse, Request
from sbom_diff_lib.graph import read_graph
from sbom_diff_lib.load import load_components
from sbom_diff_lib.osv import Advisories, Advisory
from sbom_diff_lib.registries import VersionFacts
from sbom_diff_lib.review import Finding, GraphPair, Plan, review
from sbom_diff_lib.signals import GRAPH, HIT, NOT_CHECKABLE, SIGNALS, Options, Subject, new_advisories, select
from sbom_diff_lib.tiers import tier_for

Pair = Callable[[str], tuple[str, str]]

# A fixed "now" so "published N days ago" is the same assertion next year.
NOW = datetime(2024, 6, 13, 12, tzinfo=timezone.utc)


def score_one(  # noqa: PLR0913 — the knobs a per-signal test needs, all of them optional
    pair: Pair,
    fixture: str,
    signal_id: str,
    *,
    transport: RecordedTransport | None = None,
    options: Options | None = None,
    now: datetime = NOW,
    name: str | None = None,
) -> Finding:
    """Run a single signal over one fixture pair and return the only finding."""
    old, new = pair(fixture)
    changes = diff(load_components(old), load_components(new))
    signals, skipped = select([s.id for s in SIGNALS if s.id != signal_id])
    plan = Plan(signals=signals, skipped=skipped, options=options or Options())
    fetcher = Fetcher(Cache(None), transport=transport, offline=transport is None, sleep=lambda _: None)
    graphs = GraphPair(read_graph(old), read_graph(new)) if GRAPH in plan.sources else GraphPair()
    findings = review(changes, graphs, fetcher, plan, now=now).findings
    chosen = [f for f in findings if name is None or f.name == name]
    assert len(chosen) == 1
    return chosen[0]


def only_outcome(finding: Finding) -> tuple[str, str]:
    assert len(finding.outcomes) == 1
    return finding.outcomes[0].status, finding.outcomes[0].detail


# ----------------------------------------------------- signals from the SBOMs


def test_new_package_fires_only_for_something_that_was_not_there(sbom_pair: Pair) -> None:
    finding = score_one(sbom_pair, "new-package", "new-package")
    status, detail = only_outcome(finding)
    assert status == HIT
    assert "not in the base SBOM" in detail
    assert finding.name == "brand-new"
    assert finding.old_version is None


def test_major_skip_counts_the_releases_that_went_unread(sbom_pair: Pair) -> None:
    status, detail = only_outcome(score_one(sbom_pair, "major-skip", "major-skip"))
    assert status == HIT
    assert "jumped 3 majors" in detail
    assert "2 release(s) of breaking changes" in detail


def test_a_single_major_is_not_a_skip(sbom_pair: Pair) -> None:
    status, _ = only_outcome(score_one(sbom_pair, "license", "major-skip"))
    assert status != HIT


def test_license_change_is_read_from_the_sboms(sbom_pair: Pair) -> None:
    status, detail = only_outcome(score_one(sbom_pair, "license", "license"))
    assert status == HIT
    assert detail == "MIT → GPL-3.0"


def test_fanout_growth_comes_from_the_dependency_graph(sbom_pair: Pair) -> None:
    status, detail = only_outcome(score_one(sbom_pair, "fanout", "fanout", name="hub"))
    assert status == HIT
    assert "pulls in 9 package(s), 7 more than before" in detail


def test_fanout_below_the_threshold_is_clear(sbom_pair: Pair) -> None:
    finding = score_one(sbom_pair, "fanout", "fanout", options=Options(fanout_threshold=10), name="hub")
    assert only_outcome(finding)[0] != HIT


# ------------------------------------------------ signals from the registries


def test_install_script_added_is_reported_with_somewhere_to_read_it(
    sbom_pair: Pair, recorded: RecordedTransport
) -> None:
    finding = score_one(sbom_pair, "install-scripts", "install-scripts", transport=recorded)
    outcome = finding.outcomes[0]
    assert outcome.status == HIT
    assert "postinstall added" in outcome.detail
    assert "read it" in outcome.detail
    assert finding.link == "https://www.npmjs.com/package/build-helper/v/2.0.0"
    assert recorded.calls == ["GET https://registry.npmjs.org/build-helper "]


def test_npm_maintainer_change_names_who_arrived(sbom_pair: Pair, recorded: RecordedTransport) -> None:
    status, detail = only_outcome(score_one(sbom_pair, "maintainers-npm", "maintainers", transport=recorded))
    assert status == HIT
    assert "+mallory" in detail


def test_pypi_maintainer_change_is_checkable_too(sbom_pair: Pair, recorded: RecordedTransport) -> None:
    status, detail = only_outcome(score_one(sbom_pair, "maintainers-pypi", "maintainers", transport=recorded))
    assert status == HIT
    assert "+Mallory" in detail
    assert "-Alice" in detail


def test_provenance_present_before_and_absent_now(sbom_pair: Pair, recorded: RecordedTransport) -> None:
    status, detail = only_outcome(score_one(sbom_pair, "provenance", "provenance", transport=recorded))
    assert status == HIT
    assert "nothing now ties the published artifact to a build" in detail


def test_a_release_younger_than_the_floor_is_flagged(sbom_pair: Pair, recorded: RecordedTransport) -> None:
    status, detail = only_outcome(score_one(sbom_pair, "young-package", "young-package", transport=recorded))
    assert status == HIT
    assert "published 3 day(s) ago (2024-06-10)" in detail


def test_the_young_floor_is_configurable(sbom_pair: Pair, recorded: RecordedTransport) -> None:
    finding = score_one(sbom_pair, "young-package", "young-package", transport=recorded, options=Options(young_days=1))
    assert only_outcome(finding)[0] != HIT


def test_install_scripts_are_not_checkable_outside_npm(sbom_pair: Pair, recorded: RecordedTransport) -> None:
    status, detail = only_outcome(score_one(sbom_pair, "not-checkable", "install-scripts", transport=recorded))
    assert status == NOT_CHECKABLE
    assert "deb" in detail
    assert recorded.calls == []


# ---------------------------------------------------------- OSV and deps.dev


def test_advisories_new_to_the_version_are_the_ones_reported(sbom_pair: Pair, recorded: RecordedTransport) -> None:
    status, detail = only_outcome(score_one(sbom_pair, "advisories", "advisories", transport=recorded))
    assert status == HIT
    assert "GHSA-1234-5678-9abc (high)" in detail
    # Both versions are queried, which is what makes "new to this version" true.
    assert len(recorded.calls) == 2


def test_an_advisory_the_old_version_already_had_is_not_news() -> None:
    known = Advisory("GHSA-1111-2222-3333", "old news", "low")
    subject = Subject(
        key="k",
        name="pkg",
        ecosystem="npm",
        new={"version": "2.0.0", "licenses": []},
        old={"version": "1.0.0", "licenses": []},
        new_advisories=Advisories(records=(known,)),
        old_advisories=Advisories(records=(known,)),
    )
    outcome = new_advisories(subject)
    assert outcome.status != HIT
    assert "already on 1.0.0" in outcome.detail


def test_scorecard_drop_names_the_project_it_moved_to(sbom_pair: Pair, recorded: RecordedTransport) -> None:
    status, detail = only_outcome(score_one(sbom_pair, "scorecard", "scorecard", transport=recorded))
    assert status == HIT
    assert "8.1 → 3.2" in detail
    assert "github.com/new/slipping" in detail


def test_osv_is_not_queried_for_ecosystems_it_does_not_index(sbom_pair: Pair, recorded: RecordedTransport) -> None:
    status, detail = only_outcome(score_one(sbom_pair, "not-checkable", "advisories", transport=recorded))
    assert status == NOT_CHECKABLE
    assert "not queried for deb" in detail
    assert recorded.calls == []


# ------------------------------------------------------------ scoring and CLI


def test_score_adds_up_and_picks_the_tier(sbom_pair: Pair, recorded: RecordedTransport) -> None:
    old, new = sbom_pair("advisories")
    changes = diff(load_components(old), load_components(new))
    signals, skipped = select(["fanout", "scorecard", "install-scripts", "provenance", "maintainers", "young-package"])
    fetcher = Fetcher(Cache(None), transport=recorded, sleep=lambda _: None)
    finding = review(changes, GraphPair(), fetcher, Plan(signals=signals, skipped=skipped), now=NOW).findings[0]
    # advisories (5) only: new-package, major-skip and license all stay quiet.
    assert finding.score == 5
    assert finding.tier == "read"
    assert tier_for(finding.score).label == "Read this"


def test_offline_scores_from_the_sboms_and_says_what_it_skipped(
    sbom_pair: Pair, capsys: pytest.CaptureFixture[str]
) -> None:
    old, new = sbom_pair("major-skip")
    assert main([old, new, "--review", "--offline"]) == 0
    out = capsys.readouterr().out
    assert "## What to review" in out
    assert "scored from the SBOMs alone (offline)" in out
    assert "`advisories` — offline: needs OSV API" in out
    assert "Nothing was fetched" in out


def test_the_ranking_rule_is_in_the_report(sbom_pair: Pair, capsys: pytest.CaptureFixture[str]) -> None:
    old, new = sbom_pair("license")
    main([old, new, "--review", "--offline"])
    out = capsys.readouterr().out
    assert "How this was ranked" in out
    assert "| `license` — License changed | 2 |" in out
    assert "--disable-signal maintainers" in out


def test_a_disabled_signal_does_not_score(sbom_pair: Pair, capsys: pytest.CaptureFixture[str]) -> None:
    old, new = sbom_pair("license")
    main([old, new, "--review", "--offline", "--disable-signal", "license,fanout"])
    out = capsys.readouterr().out
    assert "MIT → GPL-3.0" not in out.split("## What to review")[1]
    assert "`license` — disabled on the command line" in out


def test_fail_on_tier_is_the_gate(sbom_pair: Pair, capsys: pytest.CaptureFixture[str]) -> None:
    old, new = sbom_pair("major-skip")
    # major-skip (3) lands in "glance": a glance gate trips, a read gate does not.
    assert main([old, new, "--review", "--offline", "--fail-on-tier", "glance"]) == 1
    assert "at or above" in capsys.readouterr().err
    assert main([old, new, "--review", "--offline", "--fail-on-tier", "read"]) == 0


def test_a_tier_gate_implies_the_review(sbom_pair: Pair, capsys: pytest.CaptureFixture[str]) -> None:
    old, new = sbom_pair("major-skip")
    main([old, new, "--offline", "--fail-on-tier", "read"])
    assert "## What to review" in capsys.readouterr().out


def test_json_carries_the_findings_and_the_rule(
    sbom_pair: Pair, recorded: RecordedTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    old, new = sbom_pair("install-scripts")
    assert main([old, new, "--json", "--review", "--no-cache", "--disable-signal", "advisories,scorecard"]) == 0
    payload = json.loads(capsys.readouterr().out)
    finding = payload["review"]["findings"][0]
    assert finding["name"] == "build-helper"
    assert finding["tier"] == "read"
    assert {s["signal"] for s in finding["signals"] if s["status"] == "hit"} == {"install-scripts"}
    assert next(s["id"] for s in payload["review"]["signals"]) == "install-scripts"
    assert payload["review"]["thresholds"]["young_days"] == 14
    assert payload["review"]["requests"] == 1


def test_unknown_signal_is_a_usage_error(sbom_pair: Pair, capsys: pytest.CaptureFixture[str]) -> None:
    old, new = sbom_pair("license")
    with pytest.raises(SystemExit) as exit_info:
        main([old, new, "--review", "--offline", "--disable-signal", "nonsense"])
    assert exit_info.value.code == 2
    assert "unknown signal(s): nonsense" in capsys.readouterr().err


def test_list_signals_prints_the_rule_without_running_anything(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--list-signals"]) == 0
    out = capsys.readouterr().out
    assert "install-scripts" in out
    assert "Read this  score >= 5" in out


def test_a_diff_without_the_review_flag_is_unchanged(sbom_pair: Pair, capsys: pytest.CaptureFixture[str]) -> None:
    old, new = sbom_pair("license")
    assert main([old, new]) == 0
    assert "What to review" not in capsys.readouterr().out


# ------------------------------------------------------- cache and politeness


def test_the_cache_answers_the_second_run(tmp_path: Path, sbom_pair: Pair, recorded: RecordedTransport) -> None:
    old, new = sbom_pair("install-scripts")
    args = [old, new, "--review", "--cache-dir", str(tmp_path), "--disable-signal", "advisories,scorecard"]
    main(args)
    assert len(recorded.calls) == 1
    main(args)
    assert len(recorded.calls) == 1  # the second run asked the disk, not npm


def test_a_rate_limited_source_is_retried_after_the_delay_it_asked_for() -> None:
    slept: list[float] = []
    answers = [RawResponse(429, b"", retry_after=1.5), RawResponse(200, b'{"ok": true}')]

    def transport(_request: Request) -> RawResponse:
        return answers.pop(0)

    fetcher = Fetcher(Cache(None), transport=transport, sleep=slept.append)
    assert fetcher.get("https://api.osv.dev/v1/x").data == {"ok": True}
    # The delay it asked for, then the gap this tool leaves between requests.
    assert slept[0] == 1.5


def test_the_request_budget_stops_the_run_and_says_so() -> None:
    def transport(_request: Request) -> RawResponse:
        return RawResponse(200, b"{}")

    fetcher = Fetcher(Cache(None), transport=transport, max_requests=1, sleep=lambda _: None)
    assert fetcher.get("https://registry.npmjs.org/a").ok
    spent = fetcher.get("https://registry.npmjs.org/b")
    assert not spent.ok
    assert "budget of 1 spent" in spent.note
    assert fetcher.budget_spent


def test_offline_never_reaches_the_transport() -> None:
    def transport(_request: Request) -> RawResponse:
        raise AssertionError("offline must not send anything")

    fetched = Fetcher(Cache(None), transport=transport, offline=True).get("https://registry.npmjs.org/a")
    assert fetched.note == "offline: not fetched"


def test_a_registry_404_is_an_answer_not_a_crash(sbom_pair: Pair) -> None:
    def transport(_request: Request) -> RawResponse:
        return RawResponse(404, b'{"error": "Not found"}')

    finding = score_one(sbom_pair, "maintainers-npm", "maintainers", transport=transport)  # type: ignore[arg-type]
    status, detail = only_outcome(finding)
    assert status == NOT_CHECKABLE
    assert "no record of this package version" in detail


def test_unreadable_facts_are_never_mistaken_for_clean() -> None:
    facts = VersionFacts(notes={"scripts": "PyPI does not expose it"})
    assert facts.scripts is None
