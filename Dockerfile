# sbom-diff is a small pure-Python CLI, so a single stage is enough (no compiled
# artifacts to leave behind). Mount your SBOMs and pass them as arguments:
#   docker run --rm -v "$PWD:/work" -w /work sbom-diff old.json new.json
# ponytail: single-stage on purpose; switch to multi-stage only if native
# build deps ever get added.
FROM python:3.12-alpine

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir . \
    && adduser -D -u 10001 app
USER app

ENTRYPOINT ["sbom-diff"]
