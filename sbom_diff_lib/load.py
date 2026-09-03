"""Reading an SBOM off disk: format detection, VEX data, and failure to codes."""

import json

from sbom_diff_lib.exits import (
    EXIT_DATAERR,
    EXIT_IOERR,
    EXIT_NOINPUT,
    EXIT_NOPERM,
    SbomError,
)
from sbom_diff_lib.normalize import MISSING_FIELD, load_cyclonedx, load_spdx


def load_components(path):
    """Return {key: {name, version, ...}} plus license info from either format.

    Keyed by PURL identity when the component carries one (rename-aware: the
    same purl matches across a name change), falling back to name otherwise.
    """
    with open(path) as fh:
        doc = json.load(fh)

    if "components" in doc or doc.get("bomFormat") == "CycloneDX":
        return load_cyclonedx(doc)
    if "spdxVersion" in doc:
        return load_spdx(doc)
    raise ValueError(f"{path}: not a recognizable CycloneDX or SPDX JSON SBOM")


def load_vulnerabilities(path):
    """Return {id: {state, severity}} from a CycloneDX doc's embedded VEX data.

    No-op (empty dict) for SBOMs without a "vulnerabilities" array, e.g. SPDX
    or a CycloneDX SBOM that wasn't augmented with vulnerability/VEX info.
    """
    with open(path) as fh:
        doc = json.load(fh)

    vulns = {}
    for v in doc.get("vulnerabilities", []) or []:
        analysis = v.get("analysis") or {}
        vulns[v.get("id", MISSING_FIELD)] = {
            "state": analysis.get("state", "unknown"),
            "severity": next(
                (r.get("severity") for r in v.get("ratings", []) if r.get("severity")), None
            ),
        }
    return vulns


def read_sbom(path):
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
    except ValueError as exc:
        raise SbomError(str(exc), EXIT_DATAERR) from None
