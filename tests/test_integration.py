"""`Fetcher` against the real on-disk `Cache`: files written, re-read, aged out, corrupted.

The transport is still a stub -- no test opens a socket -- but the cache is the
real one, in a temporary directory, so what is asserted is what lands on disk.
"""

import json
from pathlib import Path

from sbom_diff_lib.cache import CACHE_FORMAT, Cache
from sbom_diff_lib.fetch import Fetcher, RawResponse, Request

URL = "https://registry.npmjs.org/left-pad"


class CountingTransport:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, _request: Request) -> RawResponse:
        self.calls += 1
        return RawResponse(200, json.dumps({"name": "left-pad", "call": self.calls}).encode())


def fetcher(directory: Path, transport: CountingTransport, ttl: int = 3600) -> Fetcher:
    return Fetcher(Cache(directory, ttl_seconds=ttl), transport=transport, sleep=lambda _: None)


def entries(directory: Path) -> list[Path]:
    return sorted((directory / CACHE_FORMAT).glob("*/*.json"))


def test_a_response_is_written_to_disk_and_answers_a_later_offline_run(tmp_path: Path) -> None:
    transport = CountingTransport()
    assert fetcher(tmp_path, transport).get(URL).data == {"name": "left-pad", "call": 1}

    (entry,) = entries(tmp_path)
    stored = json.loads(entry.read_text())
    assert stored["url"] == URL
    assert stored["value"] == {"name": "left-pad", "call": 1}

    later = Fetcher(Cache(tmp_path), transport=transport, offline=True)
    assert later.get(URL).data == {"name": "left-pad", "call": 1}
    assert later.cache.hits == 1
    assert transport.calls == 1


def test_a_stale_entry_is_fetched_again_and_overwritten(tmp_path: Path) -> None:
    transport = CountingTransport()
    fetcher(tmp_path, transport).get(URL)
    (entry,) = entries(tmp_path)
    stored = json.loads(entry.read_text())
    stored["stored_at"] -= 7200
    entry.write_text(json.dumps(stored))

    assert fetcher(tmp_path, transport).get(URL).data == {"name": "left-pad", "call": 2}
    assert json.loads(entry.read_text())["value"]["call"] == 2


def test_a_corrupt_entry_is_a_miss_not_a_crash(tmp_path: Path) -> None:
    transport = CountingTransport()
    fetcher(tmp_path, transport).get(URL)
    (entry,) = entries(tmp_path)
    entry.write_text('{"stored_at": 1, "val')  # a run killed mid-write by something else

    assert fetcher(tmp_path, transport).get(URL).data == {"name": "left-pad", "call": 2}
    assert transport.calls == 2


def test_an_unwritable_cache_directory_still_answers(tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")  # a file where the cache directory should be
    transport = CountingTransport()
    fetched = fetcher(blocker, transport)

    assert fetched.get(URL).ok
    assert fetched.cache.writes == 0
