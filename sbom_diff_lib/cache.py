"""The on-disk response cache: one JSON file per request, with a TTL.

The signals hit third-party APIs (npm, PyPI, OSV, deps.dev) once per package
per run. Two runs of the same pull request would hit them twice, and a CI job
that re-runs on every push would hit them on every push -- so every response
is written to disk and re-read until it goes stale. This is the tool's only
state; deleting the directory loses nothing but the head start.
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import cast

from sbom_diff_lib.types import Json

# Bumped when the stored shape changes, so an old cache is ignored rather than
# misread. It is a directory name, not a field inside the file: an entry whose
# shape this version does not understand is one this version never opens.
CACHE_FORMAT = "v1"

# A day. Long enough that a pull request's re-runs are free, short enough that
# an advisory published this morning is picked up by tomorrow's run.
DEFAULT_TTL_SECONDS = 24 * 60 * 60


def default_cache_dir() -> Path:
    """`$XDG_CACHE_HOME/sbom-diff`, falling back to `~/.cache/sbom-diff`."""
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base) if base else Path.home() / ".cache") / "sbom-diff"


def cache_key(method: str, url: str, body: bytes | None) -> str:
    """The identity of a request: what was asked, of whom, with what.

    The body is part of it because OSV is queried by POST -- two queries to the
    same URL are different questions.
    """
    digest = hashlib.sha256()
    digest.update(f"{method} {url}\n".encode())
    digest.update(body or b"")
    return digest.hexdigest()


class Cache:
    """A TTL'd JSON cache under one directory. Every failure is a miss.

    A cache that raises is worse than no cache: an unwritable directory, a
    half-written file from a killed run and a corrupt entry all have the same
    right answer, which is to go and ask the network again.
    """

    def __init__(self, directory: Path | None, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self.directory = directory / CACHE_FORMAT if directory else None
        self.ttl_seconds = ttl_seconds
        self.hits = 0
        self.writes = 0

    @property
    def enabled(self) -> bool:
        return self.directory is not None and self.ttl_seconds > 0

    def _path(self, key: str) -> Path | None:
        # Two levels of fan-out: a busy cache is thousands of files, and some
        # filesystems get slow long before that in a single directory.
        return self.directory / key[:2] / f"{key}.json" if self.directory else None

    def get(self, key: str) -> Json | None:
        """The stored value, or None when it is absent, stale or unreadable."""
        path = self._path(key)
        if not self.enabled or path is None or not path.is_file():
            return None
        try:
            parsed: object = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(parsed, dict):
            return None
        entry = cast(Json, parsed)
        stored_at = entry.get("stored_at")
        value = entry.get("value")
        if not isinstance(stored_at, (int, float)) or not isinstance(value, dict):
            return None
        if time.time() - stored_at > self.ttl_seconds:
            return None
        self.hits += 1
        return cast(Json, value)

    def put(self, key: str, url: str, value: Json) -> None:
        """Store a response, quietly doing nothing if the cache cannot be written."""
        path = self._path(key)
        if not self.enabled or path is None:
            return
        entry: Json = {"stored_at": time.time(), "url": url, "value": value}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Written beside the target and renamed: a run killed mid-write
            # leaves a temp file, not an entry that parses as half a response.
            tmp = path.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_text(json.dumps(entry))
            tmp.replace(path)
        except OSError:
            return
        self.writes += 1
