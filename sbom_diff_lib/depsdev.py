"""OpenSSF Scorecard for the project behind a package version, via deps.dev.

Scorecard runs against a *repository*, and deps.dev is what maps a package
version to one. Two lookups are needed per version -- the version, to learn
which project it declares, and the project, for its score -- which is also why
a drop is worth reporting: it usually means the new version points at a
different repository than the old one did.
"""

from dataclasses import dataclass
from urllib.parse import quote

from sbom_diff_lib.fetch import Fetcher
from sbom_diff_lib.types import Json

DEPSDEV_API = "https://api.deps.dev/v3"
SCORECARD_VIEWER = "https://scorecard.dev/viewer/?uri="

# purl ecosystem -> the deps.dev system name. deps.dev covers these and no
# more; anything else is reported as not checkable rather than guessed at.
DEPSDEV_SYSTEM = {
    "npm": "npm",
    "PyPI": "pypi",
    "Go": "go",
    "Maven": "maven",
    "NuGet": "nuget",
    "Cargo": "cargo",
    "RubyGems": "rubygems",
}


@dataclass(frozen=True)
class Scorecard:
    """A project's Scorecard result, or a note saying why there is none."""

    score: float | None = None
    project: str | None = None
    note: str = ""

    @property
    def link(self) -> str | None:
        return f"{SCORECARD_VIEWER}{self.project}" if self.project else None


def scorecard(fetcher: Fetcher, ecosystem: str, name: str, version: str) -> Scorecard:
    """The Scorecard of the project deps.dev links `name@version` to."""
    system = DEPSDEV_SYSTEM.get(ecosystem)
    if not system:
        return Scorecard(note=f"deps.dev does not index {ecosystem} packages")

    url = f"{DEPSDEV_API}/systems/{system}/packages/{quote(name, safe='')}/versions/{quote(version, safe='')}"
    fetched = fetcher.get(url)
    if not fetched.ok or fetched.data is None:
        return Scorecard(note=f"deps.dev: {fetched.note}")

    project = _source_project(fetched.data)
    if not project:
        return Scorecard(note="deps.dev links this version to no source project")

    project_fetch = fetcher.get(f"{DEPSDEV_API}/projects/{quote(project, safe='')}")
    if not project_fetch.ok or project_fetch.data is None:
        return Scorecard(project=project, note=f"deps.dev: {project_fetch.note}")

    card: Json = project_fetch.data.get("scorecard") or {}
    overall = card.get("overallScore")
    if not isinstance(overall, (int, float)):
        return Scorecard(project=project, note="the project has no Scorecard result")
    return Scorecard(score=float(overall), project=project)


def _source_project(version_doc: Json) -> str | None:
    """The repository deps.dev ties this version to, preferring the source repo."""
    related: list[Json] = version_doc.get("relatedProjects") or []
    ordered = sorted(related, key=lambda p: p.get("relationType") != "SOURCE_REPO")
    for entry in ordered:
        key: Json = entry.get("projectKey") or {}
        project = key.get("id")
        if isinstance(project, str) and project:
            return project
    return None
