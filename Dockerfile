# sbom-diff is a small pure-Python CLI, so a single stage is enough (no compiled
# artifacts to leave behind). Mount your SBOMs and pass them as arguments:
#   docker run --rm -v "$PWD:/work" -w /work sbom-diff old.json new.json
# ponytail: single-stage on purpose; switch to multi-stage only if native
# build deps ever get added.
FROM python:3.14-alpine@sha256:5862d971d1f0ae26b258cefa4e893556b1d3aba81bd2ff30888704ad378bab67

WORKDIR /app
COPY . .
# The build backend comes from a hash-pinned lockfile and isolation is off, so
# building the wheel fetches nothing. `pip wheel` on its own would still be
# reported as pinned while PEP 517 isolation quietly downloaded setuptools
# from PyPI -- Scorecard cannot see inside pip, which makes that a silenced
# finding rather than a pinned build.
RUN pip install --no-cache-dir --require-hashes -r requirements-build.txt \
    && pip wheel --no-cache-dir --no-build-isolation --no-deps -w /tmp/wheel . \
    && pip install --no-cache-dir --no-deps /tmp/wheel/*.whl \
    && rm -rf /tmp/wheel \
    && adduser -D -u 10001 app
USER app
# hardener: run this image with `docker run --read-only` for a read-only rootfs

# One-shot CLI tool, not a service — this just confirms the interpreter starts.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=1 \
    CMD ["python3", "-c", "import sys; sys.exit(0)"]

ENTRYPOINT ["sbom-diff"]
