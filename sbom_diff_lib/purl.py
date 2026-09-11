"""Package URLs: the identity two SBOMs are matched on, and the ecosystem name."""

import re
from urllib.parse import unquote

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


def purl_identity(purl: str) -> str:
    return _PURL_IDENTITY_RE.split(purl, 1)[0]


def ecosystem(purl: str | None) -> str:
    """The package ecosystem a purl names, or "unknown".

    Takes None because a component without a purl is the common case in an
    SBOM, and "unknown" is the honest answer for one.
    """
    if not purl or not purl.startswith(PURL_PREFIX):
        return "unknown"
    kind = purl[len(PURL_PREFIX) :].split("/", 1)[0].lower()
    return ECOSYSTEM.get(kind, kind)


def purl_name(purl: str | None) -> str | None:
    """The package name a purl carries, namespace included, or None.

    This is the name a registry answers to, which is not always the SBOM's
    `name` field: npm scoped packages are `@scope/name` there and
    `%40scope/name` here. Both spellings are accepted, because producers write
    both, and the version/qualifier tail comes off either way.
    """
    if not purl or not purl.startswith(PURL_PREFIX):
        return None
    path = purl[len(PURL_PREFIX) :].split("?", 1)[0].split("#", 1)[0]
    if "/" not in path:
        return None
    name = unquote(path.split("/", 1)[1])
    # The version marker is the *last* @: an unencoded scoped name starts with
    # one, and "@babel/core" is a name, not an empty name at version "babel".
    at = name.rfind("@")
    return (name[:at] if at > 0 else name) or None
