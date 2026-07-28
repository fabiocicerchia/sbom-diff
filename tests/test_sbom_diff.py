import json

import pytest

from sbom_diff import (
    diff,
    diff_vulnerabilities,
    load_components,
    load_vulnerabilities,
    main,
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
