"""HTTP for the signal sources: cached, rate-limit polite, offline-aware.

Everything the judgement layer asks of npm, PyPI, OSV and deps.dev goes
through `Fetcher`. It is one class so that the politeness -- a gap between
requests to the same host, `Retry-After` obeyed, a bounded number of requests
per run -- is a property of the tool rather than of whoever wrote a signal.

The network itself is behind a `Transport`, which is what lets the tests run
against recorded responses: no test in this repository opens a socket.
"""

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import cast
from urllib.parse import urlsplit

from sbom_diff_lib.cache import Cache, cache_key
from sbom_diff_lib.types import Json

# Identifies the tool to the registries, with somewhere to go when one of them
# wants the traffic to stop.
USER_AGENT = "sbom-diff (+https://github.com/fabiocicerchia/sbom-diff)"

# Seconds between two requests to the same host. A diff of a few hundred
# packages is a burst to a free public API; this makes it a trickle.
MIN_HOST_INTERVAL = 0.2

# How many requests one run may make before it stops asking. A 2000-component
# SBOM would otherwise be thousands of requests to somebody else's free API on
# every push. Exhausting it is reported, not hidden.
DEFAULT_MAX_REQUESTS = 300

# A request that has not answered in this long is not going to.
TIMEOUT_SECONDS = 10.0

# Retries for a 429 or a 5xx, and the longest we are willing to wait for one.
MAX_RETRIES = 2
MAX_BACKOFF_SECONDS = 10.0

HTTP_OK = 200
HTTP_NOT_FOUND = 404
HTTP_TOO_MANY_REQUESTS = 429
HTTP_SERVER_ERROR = 500


@dataclass(frozen=True)
class Request:
    """One HTTP request, as the transport receives it."""

    method: str
    url: str
    body: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RawResponse:
    """What a transport returns: a status, a body, and any Retry-After."""

    status: int
    body: bytes
    retry_after: float | None = None


# A transport is anything that can turn a Request into a RawResponse. The
# default one uses urllib; the tests use one backed by recorded files.
Transport = Callable[[Request], RawResponse]


@dataclass(frozen=True)
class Fetched:
    """The answer to one lookup: the data, or the reason there is none.

    `note` is written to be shown to a human, because it is: a signal that
    could not be checked says so in the report, next to the ones that could.
    """

    status: int
    data: Json | None = None
    note: str = ""

    @property
    def ok(self) -> bool:
        return self.data is not None


def _retry_after(headers: object) -> float | None:
    """`Retry-After` in seconds, when the server sent a number of them.

    The header may also be an HTTP date, which this deliberately does not
    parse: a date that far out is a "come back much later", and the caller
    treats an unreadable delay as a reason to stop rather than to hammer.
    """
    get = getattr(headers, "get", None)
    raw: object = get("Retry-After") if callable(get) else None
    try:
        return float(raw) if isinstance(raw, (str, int, float)) else None
    except ValueError:
        return None


def urllib_transport(request: Request) -> RawResponse:
    """The real network. Only https, only the status and the bytes."""
    if urlsplit(request.url).scheme != "https":
        raise ValueError(f"refusing to fetch a non-https URL: {request.url}")
    req = urllib.request.Request(  # noqa: S310 — the scheme is checked on the line above
        request.url,
        data=request.body,
        headers={"User-Agent": USER_AGENT, **request.headers},
        method=request.method,
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 — as above
            return RawResponse(response.status, response.read())
    except urllib.error.HTTPError as exc:
        # A 404 from a registry is an answer ("no such package"), not a
        # failure, so the status travels back rather than an exception.
        return RawResponse(exc.code, exc.read(), _retry_after(exc.headers))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return RawResponse(0, str(exc).encode())


class Fetcher:
    """Cached, polite JSON lookups. Never raises for a network condition."""

    def __init__(  # noqa: PLR0913 — one keyword per knob, and every one of them is a CLI flag
        self,
        cache: Cache,
        *,
        transport: Transport | None = None,
        offline: bool = False,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        min_host_interval: float = MIN_HOST_INTERVAL,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.cache = cache
        self.transport = transport or urllib_transport
        self.offline = offline
        self.max_requests = max_requests
        self.min_host_interval = min_host_interval
        self._sleep = sleep
        self._last_request: dict[str, float] = {}
        # One run asks npm for the same packument twice -- once per side of a
        # version change -- and a run with --no-cache would really send both.
        # Answering the second from memory is the politeness the disk cache
        # cannot provide when it is turned off.
        self._answered: dict[str, Fetched] = {}
        self.requests_made = 0
        self.budget_spent = False

    def get(self, url: str) -> Fetched:
        return self._fetch(Request("GET", url, headers={"Accept": "application/json"}))

    def post(self, url: str, payload: Json) -> Fetched:
        return self._fetch(
            Request(
                "POST",
                url,
                body=json.dumps(payload).encode(),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
            )
        )

    def _wait_turn(self, url: str) -> None:
        """Leave a gap between two requests to the same host."""
        host = urlsplit(url).netloc
        last = self._last_request.get(host)
        now = time.monotonic()
        if last is not None:
            gap = self.min_host_interval - (now - last)
            if gap > 0:
                self._sleep(gap)
                now = time.monotonic()
        self._last_request[host] = now

    def _fetch(self, request: Request) -> Fetched:
        key = cache_key(request.method, request.url, request.body)
        answered = self._answered.get(key)
        if answered is not None:
            return answered
        result = self._lookup(request, key)
        self._answered[key] = result
        return result

    def _lookup(self, request: Request, key: str) -> Fetched:
        cached = self.cache.get(key)
        if cached is not None:
            return Fetched(HTTP_OK, cached, "")
        if self.offline:
            return Fetched(0, None, "offline: not fetched")
        if self.max_requests and self.requests_made >= self.max_requests:
            self.budget_spent = True
            return Fetched(0, None, f"request budget of {self.max_requests} spent")

        response = self._send(request)
        if response.status == HTTP_OK:
            data = _decode(response.body)
            if data is None:
                return Fetched(response.status, None, "the response was not a JSON object")
            self.cache.put(key, request.url, data)
            return Fetched(response.status, data, "")
        return Fetched(response.status, None, _status_note(response.status))

    def _send(self, request: Request) -> RawResponse:
        """One request, retried while the other end asks us to back off."""
        response = RawResponse(0, b"")
        for attempt in range(MAX_RETRIES + 1):
            self._wait_turn(request.url)
            self.requests_made += 1
            response = self.transport(request)
            if not _should_retry(response.status) or attempt == MAX_RETRIES:
                return response
            delay = response.retry_after if response.retry_after is not None else 2.0**attempt
            if delay > MAX_BACKOFF_SECONDS:
                # Being told to come back in five minutes is a no for this run.
                return response
            self._sleep(delay)
        return response


def _should_retry(status: int) -> bool:
    return status == HTTP_TOO_MANY_REQUESTS or status >= HTTP_SERVER_ERROR


def _decode(body: bytes) -> Json | None:
    try:
        parsed: object = json.loads(body)
    except ValueError:
        return None
    return cast(Json, parsed) if isinstance(parsed, dict) else None


def _status_note(status: int) -> str:
    if status == HTTP_NOT_FOUND:
        return "no record of this package version"
    if status == HTTP_TOO_MANY_REQUESTS:
        return "rate limited"
    if status == 0:
        return "the request did not complete"
    return f"the source answered {status}"
