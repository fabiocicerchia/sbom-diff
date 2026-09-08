"""Reading an SBOM off disk: format detection, VEX data, and failure to codes."""

import json
from pathlib import Path

from sbom_diff_lib.exits import (
    EXIT_DATAERR,
    EXIT_IOERR,
    EXIT_NOINPUT,
    EXIT_NOPERM,
    SbomError,
)
from sbom_diff_lib.normalize import MISSING_FIELD, load_cyclonedx, load_spdx
from sbom_diff_lib.types import Components, Json, Vulnerabilities


def load_components(path: str) -> Components:
    """Return {key: {name, version, ...}} plus license info from either format.

    Keyed by PURL identity when the component carries one (rename-aware: the
    same purl matches across a name change), falling back to name otherwise.
    """
    parsed = json.loads(Path(path).read_text())
    # Valid JSON that is not an object (a bare array, a string) is not an SBOM
    # either; it reaches the same "not recognizable" error rather than an
    # AttributeError on the first .get below.
    doc: Json = parsed if isinstance(parsed, dict) else {}

    # A *list* under "components", or a document that says it is CycloneDX.
    # `"components": null` is what several scanners write for an empty scan, and
    # inside a real CycloneDX document it means exactly that — but on its own it
    # is a fragment, not an SBOM, and calling that "no dependency changes" is
    # how a truncated file passes a gate.
    if isinstance(doc.get("components"), list) or doc.get("bomFormat") == "CycloneDX":
        return load_cyclonedx(doc)
    if "spdxVersion" in doc:
        return load_spdx(doc)
    raise ValueError(f"{path}: not a recognizable CycloneDX or SPDX JSON SBOM")


def load_vulnerabilities(path: str) -> Vulnerabilities:
    """Return {id: {state, severity}} from a CycloneDX doc's embedded VEX data.

    No-op (empty dict) for SBOMs without a "vulnerabilities" array, e.g. SPDX
    or a CycloneDX SBOM that wasn't augmented with vulnerability/VEX info.
    """
    doc = json.loads(Path(path).read_text())

    vulns: Vulnerabilities = {}
    entries: list[Json] = doc.get("vulnerabilities", []) or []
    for v in entries:
        analysis: Json = v.get("analysis") or {}
        ratings: list[Json] = v.get("ratings", [])
        vulns[v.get("id", MISSING_FIELD)] = {
            "state": analysis.get("state", "unknown"),
            "severity": next((r.get("severity") for r in ratings if r.get("severity")), None),
        }
    return vulns


def read_sbom(path: str) -> tuple[Components, Vulnerabilities]:
    """Return (components, vulnerabilities) for one SBOM, or raise SbomError.

    Every expected failure becomes an SbomError so main can print one line and
    exit with a code that says which kind it was. Anything not listed here is a
    bug in this tool and keeps its traceback.
    """
    try:
        return load_components(path), load_vulnerabilities(path)
    except FileNotFoundError:
        raise SbomError(f"{path}: no such file", EXIT_NOINPUT) from None
    except PermissionError:
        raise SbomError(f"{path}: permission denied", EXIT_NOPERM) from None
    except OSError as exc:
        raise SbomError(f"{path}: {exc.strerror}", EXIT_IOERR) from None
    except json.JSONDecodeError as exc:
        raise SbomError(f"{path}: not valid JSON: {exc}", EXIT_DATAERR) from None
    except RecursionError:
        # json recurses once per level of nesting, so a file that is nothing but
        # 10k open brackets exhausts the stack before any of it is an SBOM. That
        # is a cheap denial of service against anything ingesting a build's
        # output, and it arrives here as a crash rather than an input error.
        raise SbomError(f"{path}: nested too deeply to parse", EXIT_DATAERR) from None
    except ValueError as exc:
        raise SbomError(str(exc), EXIT_DATAERR) from None
