"""Advisories for one package version, from OSV.

OSV is queried for both sides of a version change, so that the signal reports
what the *new* version brings rather than what the package has ever had: an
upgrade that fixes three advisories should not read like an upgrade that
introduces them.
"""

from dataclasses import dataclass

from sbom_diff_lib.fetch import Fetcher
from sbom_diff_lib.types import Json

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_ADVISORY_URL = "https://osv.dev/vulnerability"

# purl ecosystem (as purl.ECOSYSTEM names it) -> the ecosystem OSV indexes it
# under. The OS package ecosystems are left out on purpose: OSV wants them
# qualified by distribution release ("Debian:12"), which an SBOM's purl does
# not reliably carry, and guessing the wrong release means querying nothing.
OSV_ECOSYSTEM = {
    "npm": "npm",
    "PyPI": "PyPI",
    "Cargo": "crates.io",
    "RubyGems": "RubyGems",
    "Composer": "Packagist",
    "Go": "Go",
    "Maven": "Maven",
    "NuGet": "NuGet",
    "hex": "Hex",
    "pub": "Pub",
    "conan": "ConanCenter",
}


@dataclass(frozen=True)
class Advisory:
    """One OSV record, trimmed to what a reviewer needs to decide to click."""

    id: str
    summary: str
    severity: str | None

    @property
    def link(self) -> str:
        return f"{OSV_ADVISORY_URL}/{self.id}"


@dataclass(frozen=True)
class Advisories:
    """The advisories affecting a version, or a note saying why nobody knows."""

    records: tuple[Advisory, ...] | None = None
    note: str = ""

    @property
    def ids(self) -> frozenset[str]:
        return frozenset(a.id for a in self.records or ())


def advisories(fetcher: Fetcher, ecosystem: str, name: str, version: str) -> Advisories:
    """Query OSV for `name@version`."""
    osv_ecosystem = OSV_ECOSYSTEM.get(ecosystem)
    if not osv_ecosystem:
        return Advisories(note=f"OSV is not queried for {ecosystem} packages")

    fetched = fetcher.post(OSV_QUERY_URL, {"version": version, "package": {"name": name, "ecosystem": osv_ecosystem}})
    if not fetched.ok or fetched.data is None:
        return Advisories(note=f"OSV: {fetched.note}")

    entries: list[Json] = fetched.data.get("vulns") or []
    return Advisories(records=tuple(sorted((_advisory(v) for v in entries), key=lambda a: a.id)))


def _advisory(entry: Json) -> Advisory:
    specific: Json = entry.get("database_specific") or {}
    severity = specific.get("severity")
    summary = entry.get("summary") or (entry.get("details") or "").split("\n")[0]
    return Advisory(
        id=str(entry.get("id", "?")),
        summary=str(summary).strip(),
        severity=str(severity).lower() if isinstance(severity, str) else None,
    )
