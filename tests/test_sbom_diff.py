import json

import pytest

from sbom_diff import diff, load_components, main, semver_jump


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
    added, removed, changed, licenses = diff(load_components(old), load_components(new))
    assert "requests" in added and "left-pad" in removed
    assert changed["openssl"][1]["version"] == "4.0.0"
    assert licenses["openssl"] == (["Apache-2.0"], ["GPL-3.0"])


def test_fail_on_major(sboms):
    old, new = sboms
    assert main([old, new, "--fail-on", "major"]) == 1
    assert main([old, old, "--fail-on", "any"]) == 0


def test_unrecognized_format(tmp_path):
    bad = write(tmp_path, "bad.json", {"hello": "world"})
    with pytest.raises(ValueError):
        load_components(bad)
