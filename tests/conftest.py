"""Recorded HTTP and the fixture SBOM pairs. No test here opens a socket.

Every response the review tests need was recorded into `fixtures/http/` by
hand, keyed by the request that asks for it. The `no_network` fixture is
autouse: a test that reaches for a source nobody recorded fails loudly instead
of quietly depending on npm being up.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from sbom_diff_lib import fetch
from sbom_diff_lib.fetch import RawResponse, Request

FIXTURES = Path(__file__).parent / "fixtures"
HTTP_FIXTURES = FIXTURES / "http"
SBOM_FIXTURES = FIXTURES / "sboms"


def request_key(method: str, url: str, body: object) -> str:
    """One string per distinct question, so a POST body is part of the identity."""
    payload = json.dumps(body, sort_keys=True) if body else ""
    return f"{method} {url} {payload}"


class RecordedTransport:
    """A `fetch.Transport` backed by the files in `fixtures/http/`."""

    def __init__(self, directory: Path = HTTP_FIXTURES) -> None:
        self.calls: list[str] = []
        self.recordings: dict[str, dict[str, Any]] = {}
        for path in sorted(directory.glob("*.json")):
            entry = json.loads(path.read_text())
            self.recordings[request_key(entry["method"], entry["url"], entry.get("request"))] = entry

    def __call__(self, request: Request) -> RawResponse:
        body = json.loads(request.body) if request.body else None
        key = request_key(request.method, request.url, body)
        self.calls.append(key)
        entry = self.recordings.get(key)
        if entry is None:
            available = "\n  ".join(sorted(self.recordings))
            raise AssertionError(f"no recorded response for:\n  {key}\nrecorded:\n  {available}")
        return RawResponse(entry.get("status", 200), json.dumps(entry["response"]).encode())


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the real transport unusable for the whole suite."""

    def refuse(request: Request) -> RawResponse:
        raise AssertionError(f"a test tried to reach {request.url}")

    monkeypatch.setattr(fetch, "urllib_transport", refuse)


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> RecordedTransport:
    """The recorded transport, also installed as the default one for CLI runs."""
    transport = RecordedTransport()
    monkeypatch.setattr(fetch, "urllib_transport", transport)
    return transport


@pytest.fixture
def sbom_pair() -> Callable[[str], tuple[str, str]]:
    """`sbom_pair("install-scripts")` -> the (old, new) paths of that fixture pair."""

    def pair(name: str) -> tuple[str, str]:
        directory = SBOM_FIXTURES / name
        return str(directory / "old.json"), str(directory / "new.json")

    return pair
