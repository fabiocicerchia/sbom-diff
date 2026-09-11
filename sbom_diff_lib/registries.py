"""What npm and PyPI will tell you about one package at one version.

Three of the signals -- install scripts, the maintainer set, how old the
release is -- are questions only the package's own registry can answer, and
only two registries answer them at all. Everything here therefore returns
`VersionFacts`, where a field is either a fact or a None with a note saying
why nobody could check it. "Not checkable" is an answer the report prints; it
is never silently the same as "clean".
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import cast
from urllib.parse import quote

from sbom_diff_lib.fetch import Fetcher
from sbom_diff_lib.types import Json

# The `ecosystem` values (see purl.ECOSYSTEM) whose registries answer these
# questions. Everything else is honestly reported as not checkable.
NPM = "npm"
PYPI = "PyPI"
SUPPORTED_REGISTRIES = (NPM, PYPI)

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_SITE = "https://www.npmjs.com/package"
PYPI_API = "https://pypi.org/pypi"
PYPI_SITE = "https://pypi.org/project"

# The npm lifecycle scripts that run on `npm install` without anybody asking.
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")

NO_REGISTRY_NOTE = "no registry this tool reads exposes it for {ecosystem}"


@dataclass(frozen=True)
class VersionFacts:
    """One package at one version, as its registry describes it.

    Every field is `None` when it could not be established, and `notes[field]`
    then says why.
    """

    scripts: dict[str, str] | None = None
    maintainers: frozenset[str] | None = None
    published: datetime | None = None
    provenance: bool | None = None
    link: str | None = None
    notes: dict[str, str] = field(default_factory=dict)


def _unavailable(reason: str, link: str | None = None) -> VersionFacts:
    """Facts nobody could establish, all four fields carrying the same reason."""
    return VersionFacts(link=link, notes=dict.fromkeys(("scripts", "maintainers", "published", "provenance"), reason))


def package_link(ecosystem: str, name: str, version: str) -> str | None:
    """Where a human goes to read the package itself."""
    if ecosystem == NPM:
        return f"{NPM_SITE}/{name}/v/{version}"
    if ecosystem == PYPI:
        return f"{PYPI_SITE}/{name}/{version}/"
    return None


def version_facts(fetcher: Fetcher, ecosystem: str, name: str, version: str) -> VersionFacts:
    """Registry facts for `name@version`, or a note per field saying why not."""
    if ecosystem == NPM:
        return _npm_facts(fetcher, name, version)
    if ecosystem == PYPI:
        return _pypi_facts(fetcher, name, version)
    return _unavailable(NO_REGISTRY_NOTE.format(ecosystem=ecosystem))


def _npm_facts(fetcher: Fetcher, name: str, version: str) -> VersionFacts:
    """From the packument: install scripts, maintainers, publish time, provenance.

    The full packument rather than the abbreviated one or the per-version
    document: it is the only response carrying all four facts, so one request
    per package answers four signals for both sides of the change. The
    abbreviated form omits the script bodies and the maintainers; the
    per-version form omits the publish times.
    """
    link = package_link(NPM, name, version)
    # Scoped names are one path segment on the registry: @scope%2fname.
    fetched = fetcher.get(f"{NPM_REGISTRY}/{quote(name, safe='')}")
    if not fetched.ok or fetched.data is None:
        return _unavailable(f"npm: {fetched.note}", link)

    versions: Json = fetched.data.get("versions") or {}
    release: Json | None = versions.get(version)
    if not isinstance(release, dict):
        return _unavailable(f"npm has no record of {name}@{version}", link)

    scripts: Json = release.get("scripts") or {}
    maintainers = _npm_maintainers(release, fetched.data)
    times: Json = fetched.data.get("time") or {}
    dist: Json = release.get("dist") or {}
    return VersionFacts(
        scripts={k: str(v) for k in INSTALL_SCRIPTS if (v := scripts.get(k))},
        maintainers=maintainers,
        published=_parse_time(times.get(version)),
        # A published attestation is npm provenance; its absence is the thing
        # the signal cares about, so False is a fact, not a missing value.
        provenance=bool(dist.get("attestations")),
        link=link,
        notes={} if maintainers is not None else {"maintainers": "npm listed no maintainers for this version"},
    )


def _npm_maintainers(release: Json, packument: Json) -> frozenset[str] | None:
    """Who could publish this version: the per-version list, else the current one.

    The per-version list is the one that matters -- it is who the package
    belonged to *at that publish* -- but old versions often omit it, and the
    packument's current list is a fair stand-in.
    """
    entries: list[object] = release.get("maintainers") or packument.get("maintainers") or []
    names = {_maintainer_name(cast(Json, m)) for m in entries if isinstance(m, dict)}
    names |= {m for m in entries if isinstance(m, str)}
    names.discard("")
    return frozenset(names) if names else None


def _maintainer_name(entry: Json) -> str:
    """npm writes maintainers as {name, email}; either identifies a person."""
    return str(entry.get("name") or entry.get("email") or "")


def _pypi_facts(fetcher: Fetcher, name: str, version: str) -> VersionFacts:
    """From the per-version JSON API: maintainers and the upload time."""
    link = package_link(PYPI, name, version)
    fetched = fetcher.get(f"{PYPI_API}/{quote(name, safe='')}/{quote(version, safe='')}/json")
    if not fetched.ok or fetched.data is None:
        return _unavailable(f"PyPI: {fetched.note}", link)

    info: Json = fetched.data.get("info") or {}
    urls: list[Json] = fetched.data.get("urls") or []
    uploads = [t for t in (_parse_time(u.get("upload_time_iso_8601")) for u in urls) if t]
    maintainers = frozenset(
        str(v).strip() for key in ("maintainer", "maintainer_email", "author", "author_email") if (v := info.get(key))
    )
    return VersionFacts(
        maintainers=maintainers or None,
        published=min(uploads) if uploads else None,
        link=link,
        notes={
            # setup.py runs arbitrary code by design and the API does not say
            # whether this package's does; claiming "no install scripts" for a
            # sdist would be a lie by omission.
            "scripts": "PyPI does not expose whether a package runs code at install time",
            "provenance": "PyPI attestations are not exposed by the JSON API",
            **({} if maintainers else {"maintainers": "PyPI listed no maintainer or author"}),
            **({} if uploads else {"published": "PyPI listed no upload time for this version"}),
        },
    )


def _parse_time(raw: object) -> datetime | None:
    """An ISO-8601 timestamp from a registry, as an aware datetime."""
    if not isinstance(raw, str):
        return None
    try:
        # 3.10's fromisoformat does not take the "Z" that both registries send.
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
