import json

import pytest

from sbom_diff import (
    compare_versions,
    counts,
    diff,
    diff_vulnerabilities,
    ecosystem,
    load_components,
    load_vulnerabilities,
    main,
    policy_failures,
    purl_identity,
    semver_jump,
)


def cyclonedx(components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}


def write(tmp_path, name, doc):
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return str(p)


@pytest.fixture
def sboms(tmp_path):
    old = cyclonedx(
        [
            {
                "name": "openssl",
                "version": "3.0.1",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            {"name": "left-pad", "version": "1.0.0"},
        ]
    )
    new = cyclonedx(
        [
            {"name": "openssl", "version": "4.0.0", "licenses": [{"license": {"id": "GPL-3.0"}}]},
            {"name": "requests", "version": "2.31.0"},
        ]
    )
    return write(tmp_path, "old.json", old), write(tmp_path, "new.json", new)


def test_semver_classification():
    assert semver_jump("1.2.3", "2.0.0") == "major"
    assert semver_jump("1.2.3", "1.3.0") == "minor"
    assert semver_jump("v1.2.3", "v1.2.4") == "patch"
    assert semver_jump("abc", "def") == "other"


def test_diff_finds_all_change_kinds(sboms):
    old, new = sboms
    added, removed, changed, licenses, renamed = diff(load_components(old), load_components(new))
    assert "requests" in added and "left-pad" in removed
    assert changed["openssl"][1]["version"] == "4.0.0"
    assert licenses["openssl"][0]["licenses"] == ["Apache-2.0"]
    assert licenses["openssl"][1]["licenses"] == ["GPL-3.0"]
    assert renamed == {}


def test_purl_identity():
    assert purl_identity("pkg:pypi/requests@2.31.0") == "pkg:pypi/requests"
    assert purl_identity("pkg:pypi/requests@2.31.0?extra=x") == "pkg:pypi/requests"
    assert purl_identity("pkg:pypi/requests") == "pkg:pypi/requests"


def test_purl_matching_is_rename_aware(tmp_path):
    # Same purl, different "name" field between scans -> matched as a rename,
    # not add+remove.
    old = cyclonedx(
        [{"name": "python-requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}]
    )
    new = cyclonedx([{"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}])
    old_path, new_path = write(tmp_path, "old.json", old), write(tmp_path, "new.json", new)

    added, removed, changed, _licenses, renamed = diff(
        load_components(old_path), load_components(new_path)
    )
    assert not added and not removed and not changed
    assert len(renamed) == 1
    o, n = next(iter(renamed.values()))
    assert o["name"] == "python-requests" and n["name"] == "requests"


def test_vulnerability_delta():
    added, removed, changed = diff_vulnerabilities(
        {
            "CVE-2023-1111": {"state": "affected", "severity": "high"},
            "CVE-2023-2222": {"state": "affected", "severity": None},
        },
        {
            "CVE-2023-2222": {"state": "not_affected", "severity": None},
            "CVE-2023-3333": {"state": "affected", "severity": None},
        },
    )
    assert "CVE-2023-3333" in added
    assert "CVE-2023-1111" in removed
    assert changed["CVE-2023-2222"] == ("affected", "not_affected")


def test_load_vulnerabilities(tmp_path):
    doc = cyclonedx([])
    doc["vulnerabilities"] = [
        {
            "id": "CVE-2023-1111",
            "analysis": {"state": "affected"},
            "ratings": [{"severity": "high"}],
        }
    ]
    path = write(tmp_path, "sbom.json", doc)
    assert load_vulnerabilities(path) == {
        "CVE-2023-1111": {"state": "affected", "severity": "high"}
    }


def test_load_vulnerabilities_absent(sboms):
    old, _ = sboms
    assert load_vulnerabilities(old) == {}


def test_fail_on_major(sboms):
    old, new = sboms
    assert main([old, new, "--fail-on", "major"]) == 1
    assert main([old, old, "--fail-on", "any"]) == 0


def test_unrecognized_format(tmp_path):
    bad = write(tmp_path, "bad.json", {"hello": "world"})
    with pytest.raises(ValueError):
        load_components(bad)


def test_compare_versions_orders_and_handles_prereleases():
    assert compare_versions("1.2.3", "2.0.0") == -1
    assert compare_versions("2.0.0", "1.9.9") == 1
    # A missing segment is zero.
    assert compare_versions("1.2", "1.2.0") == 0
    assert compare_versions("v1.0.0", "1.0.0") == 0
    # A pre-release is older than the release; build metadata is not.
    assert compare_versions("1.0.0-rc1", "1.0.0") == -1
    assert compare_versions("1.0.0", "1.0.0+abc123") == 0
    assert compare_versions("1.0.0-alpha", "1.0.0-beta") == -1


def test_ecosystem_from_purl():
    assert ecosystem("pkg:pypi/requests@2.31.0") == "PyPI"
    assert ecosystem("pkg:npm/%40scope/pkg@1.0.0") == "npm"
    # Unknown types pass through rather than being dropped.
    assert ecosystem("pkg:conan/zlib@1.3") == "conan"
    assert ecosystem(None) == "unknown"


def test_direct_vs_transitive_from_dependency_graph(tmp_path):
    doc = cyclonedx(
        [
            {"bom-ref": "a", "name": "direct-dep", "version": "1.0.0", "purl": "pkg:npm/a@1.0.0"},
            {"bom-ref": "b", "name": "deep-dep", "version": "1.0.0", "purl": "pkg:npm/b@1.0.0"},
        ]
    )
    doc["metadata"] = {"component": {"bom-ref": "root", "name": "my-app"}}
    doc["dependencies"] = [{"ref": "root", "dependsOn": ["a"]}, {"ref": "a", "dependsOn": ["b"]}]
    comps = load_components(write(tmp_path, "sbom.json", doc))

    assert comps["pkg:npm/a"]["direct"] is True
    assert comps["pkg:npm/b"]["direct"] is False


def test_no_dependency_graph_means_everything_is_transitive(tmp_path):
    doc = cyclonedx([{"name": "x", "version": "1.0.0", "purl": "pkg:npm/x@1.0.0"}])
    comps = load_components(write(tmp_path, "sbom.json", doc))
    assert comps["pkg:npm/x"]["direct"] is False


def test_root_component_is_not_its_own_dependency(tmp_path):
    # syft catalogues the scanned project alongside its dependencies, under a
    # different bom-ref from metadata.component — hence the name check too.
    doc = cyclonedx(
        [
            {"bom-ref": "self", "name": "my-app", "version": "1.0.0", "purl": "pkg:npm/my-app@1"},
            {"bom-ref": "d", "name": "dep", "version": "1.0.0", "purl": "pkg:npm/dep@1.0.0"},
        ]
    )
    doc["metadata"] = {"component": {"bom-ref": "root", "name": "my-app"}}
    comps = load_components(write(tmp_path, "sbom.json", doc))
    assert list(comps) == ["pkg:npm/dep"]


def test_duplicate_component_keeps_the_higher_version(tmp_path):
    # Two copies coexisting in one tree is not a version change.
    doc = cyclonedx(
        [
            {"bom-ref": "lo", "name": "dup", "version": "1.0.0", "purl": "pkg:npm/dup@1.0.0"},
            {"bom-ref": "hi", "name": "dup", "version": "2.0.0", "purl": "pkg:npm/dup@2.0.0"},
        ]
    )
    doc["metadata"] = {"component": {"bom-ref": "root", "name": "my-app"}}
    doc["dependencies"] = [{"ref": "root", "dependsOn": ["lo"]}]
    comps = load_components(write(tmp_path, "sbom.json", doc))

    assert comps["pkg:npm/dup"]["version"] == "2.0.0"
    # direct is sticky: the copy the root depends on was the lower one.
    assert comps["pkg:npm/dup"]["direct"] is True


def test_spdx_direct_from_relationships_both_directions(tmp_path):
    doc = {
        "spdxVersion": "SPDX-2.3",
        "name": "my-app",
        "documentDescribes": ["SPDXRef-root"],
        "packages": [
            {"SPDXID": "SPDXRef-root", "name": "my-app", "versionInfo": "1.0.0"},
            {
                "SPDXID": "SPDXRef-a",
                "name": "a",
                "versionInfo": "1.0.0",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/a@1.0.0"}],
            },
            {
                "SPDXID": "SPDXRef-b",
                "name": "b",
                "versionInfo": "1.0.0",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/b@1.0.0"}],
            },
            {
                "SPDXID": "SPDXRef-c",
                "name": "c",
                "versionInfo": "1.0.0",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/c@1.0.0"}],
            },
        ],
        "relationships": [
            {
                "relationshipType": "DEPENDS_ON",
                "spdxElementId": "SPDXRef-root",
                "relatedSpdxElement": "SPDXRef-a",
            },
            {
                "relationshipType": "DEPENDENCY_OF",
                "spdxElementId": "SPDXRef-b",
                "relatedSpdxElement": "SPDXRef-root",
            },
        ],
    }
    comps = load_components(write(tmp_path, "sbom.json", doc))

    assert comps["pkg:npm/a"]["direct"] is True
    assert comps["pkg:npm/b"]["direct"] is True
    assert comps["pkg:npm/c"]["direct"] is False
    assert "my-app" not in comps


def test_counts_split_added_by_depth_and_spot_downgrades(sboms):
    old, new = sboms
    added, removed, changed, licenses, _renamed = diff(load_components(old), load_components(new))
    totals = counts(added, removed, changed, licenses)
    assert totals["added"] == 1 and totals["added_transitive"] == 1
    assert totals["removed"] == 1 and totals["changed"] == 1
    assert totals["license_changed"] == 1
    # openssl 3.0.1 -> 4.0.0 is an upgrade.
    assert totals["downgrades"] == 0


def test_downgrade_detection(tmp_path):
    old = cyclonedx([{"name": "x", "version": "2.0.0", "purl": "pkg:npm/x@2.0.0"}])
    new = cyclonedx([{"name": "x", "version": "1.9.0", "purl": "pkg:npm/x@1.9.0"}])
    old_p, new_p = write(tmp_path, "o.json", old), write(tmp_path, "n.json", new)

    added, removed, changed, licenses, _ = diff(load_components(old_p), load_components(new_p))
    assert counts(added, removed, changed, licenses)["downgrades"] == 1
    assert main([old_p, new_p, "--fail-on-downgrade"]) == 1
    assert main([old_p, new_p]) == 0


def test_policy_thresholds_are_opt_in():
    totals = {
        "added": 5,
        "added_direct": 2,
        "added_transitive": 3,
        "removed": 0,
        "changed": 0,
        "license_changed": 1,
        "downgrades": 1,
    }
    assert policy_failures({}, {}, totals, {}) == []

    fails = policy_failures(
        {},
        {},
        totals,
        {
            "max_added": 4,
            "max_added_transitive": 2,
            "fail_on_downgrade": True,
            "fail_on_license_change": True,
        },
    )
    assert len(fails) == 4


def test_deny_licenses_matches_added_and_newly_changed():
    added = {"a": {"name": "a", "licenses": ["GPL-3.0"]}}
    license_changes = {
        "b": ({"name": "b", "licenses": ["MIT"]}, {"name": "b", "licenses": ["AGPL-3.0"]})
    }
    totals = counts(added, {}, {}, license_changes)

    fails = policy_failures(added, license_changes, totals, {"deny_licenses": ["gpl-3.0"]})
    assert len(fails) == 1 and "a (GPL-3.0)" in fails[0]
    # The pre-change licence must not trigger it; only what the change introduces.
    assert policy_failures(added, license_changes, totals, {"deny_licenses": ["MIT"]}) == []


def test_json_output_carries_counts_and_markdown(sboms, capsys):
    old, new = sboms
    main([old, new, "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["added"] == 1
    assert payload["markdown"].startswith("# SBOM diff")
    assert payload["summary"] in payload["markdown"]
