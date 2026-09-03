# sbom-diff is a small pure-Python CLI, so a single stage is enough (no compiled
# artifacts to leave behind). Mount your SBOMs and pass them as arguments:
#   docker run --rm -v "$PWD:/work" -w /work sbom-diff old.json new.json
# ponytail: single-stage on purpose; switch to multi-stage only if native
# build deps ever get added.
FROM python:3.14-alpine@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir . \
    && adduser -D -u 10001 app
USER app
# hardener: run this image with `docker run --read-only` for a read-only rootfs

# One-shot CLI tool, not a service — this just confirms the interpreter starts.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=1 \
    CMD ["python3", "-c", "import sys; sys.exit(0)"]

ENTRYPOINT ["sbom-diff"]
