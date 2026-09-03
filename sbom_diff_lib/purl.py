"""Package URLs: the identity two SBOMs are matched on, and the ecosystem name."""

import re

# Every purl starts with this scheme; the type follows it directly.
PURL_PREFIX = "pkg:"

# purl identity: everything up to the first version/qualifier/subpath marker,
# e.g. "pkg:pypi/requests@2.31.0" -> "pkg:pypi/requests". Two components with
# the same identity are the same package even if their SBOM "name" differs.
_PURL_IDENTITY_RE = re.compile(r"[@?#]")

# purl type -> the ecosystem name people recognise. Unknown types pass through
# rather than being dropped: an SBOM full of "deb" components is still a diff
# worth reading, even if this tool has no opinion about apt.
ECOSYSTEM = {
    "npm": "npm",
    "pypi": "PyPI",
    "cargo": "Cargo",
    "gem": "RubyGems",
    "composer": "Composer",
    "golang": "Go",
    "maven": "Maven",
    "nuget": "NuGet",
    "deb": "deb",
    "rpm": "rpm",
    "apk": "apk",
    "github": "GitHub Actions",
}


def purl_identity(purl):
    return _PURL_IDENTITY_RE.split(purl, 1)[0]


def ecosystem(purl):
    if not purl or not purl.startswith(PURL_PREFIX):
        return "unknown"
    kind = purl[len(PURL_PREFIX) :].split("/", 1)[0].lower()
    return ECOSYSTEM.get(kind, kind)
