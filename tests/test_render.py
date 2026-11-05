from sbom_diff_lib.render import explain
from sbom_diff_lib.types import Component


def comp(name: str, version: str, *, licenses: tuple[str, ...] = (), direct: bool = False) -> Component:
    return {"name": name, "version": version, "licenses": list(licenses), "direct": direct}


def test_explain_renders_every_section_most_alarming_first() -> None:
    openssl = (comp("openssl", "3.0.1", licenses=("Apache-2.0",)), comp("openssl", "4.0.0", licenses=("GPL-3.0",)))
    summary, body = explain(
        {"requests": comp("requests", "2.31.0", direct=True), "idna": comp("idna", "3.6")},
        {"left-pad": comp("left-pad", "1.0.0")},
        {"openssl": openssl, "six": (comp("six", "2.0.0"), comp("six", "1.9.0"))},
        {"openssl": openssl},
        renamed={"pkg:pypi/dateutil": (comp("python-dateutil", "2.8.0"), comp("dateutil", "2.8.0"))},
        vulns=(
            {"CVE-1": {"state": "affected", "severity": "high"}},
            {"CVE-2": {"state": "exploitable", "severity": None}},
            {"CVE-3": ("in_triage", "not_affected")},
        ),
    )
    assert summary == (
        "5 dependency change(s): 2 added (1 direct, 1 transitive), 1 removed, "
        "2 updated (2 major), 1 downgraded, 1 renamed"
    )
    assert body == "\n".join(
        [
            "## Renamed (1)\n",
            "- **python-dateutil** → **dateutil**",
            "",
            "## ⚠ Major version jumps (review breaking changes)\n",
            "- **openssl**: 3.0.1 → 4.0.0",
            "- **six**: 2.0.0 → 1.9.0 *(downgrade)*",
            "",
            "## New dependencies (2, 1 transitive)\n",
            "- idna 3.6 _(transitive)_",
            "- requests 2.31.0",
            "",
            "## Removed dependencies (1)\n",
            "- left-pad 1.0.0",
            "",
            "## ⚠ License changes\n",
            "- **openssl**: Apache-2.0 → GPL-3.0",
            "",
            "## Vulnerability changes (VEX)\n",
            "- ⚠ **CVE-1** newly reported (affected, high)",
            "- ✅ **CVE-2** no longer reported (was: exploitable)",
            "- 🔄 **CVE-3**: in_triage → not_affected",
            "",
        ]
    )


def test_explain_buckets_smaller_jumps_below_major_in_decreasing_size() -> None:
    _, body = explain(
        {},
        {},
        {
            "c": (comp("c", "abc"), comp("c", "def")),
            "b": (comp("b", "1.0.0"), comp("b", "1.0.1")),
            "a": (comp("a", "1.0.0"), comp("a", "1.1.0")),
        },
        {},
    )
    assert body == "\n".join(
        [
            "## Minor updates\n",
            "- a: 1.0.0 → 1.1.0",
            "",
            "## Patch updates\n",
            "- b: 1.0.0 → 1.0.1",
            "",
            "## Other version changes\n",
            "- c: abc → def",
            "",
        ]
    )


def test_explain_with_no_changes_is_a_headline_and_an_empty_body() -> None:
    assert explain({}, {}, {}, {}) == ("0 dependency change(s): 0 added, 0 removed, 0 updated (0 major)", "")
