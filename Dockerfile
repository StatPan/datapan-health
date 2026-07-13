# syntax=docker/dockerfile:1.7
# The live target deliberately stays scratch-only. DuckDB's prebuilt archive
# library needs glibc, so only the archive target uses the Debian/Python path.
ARG LIVE_GO_IMAGE=golang:1.26.4-alpine3.22@sha256:727cfc3c40be55cd1bc9a4a059406b28a059857e3be752aa9d09531e12c20c56
ARG ARCHIVE_GO_IMAGE=golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b
ARG HF_IMAGE=python:3.13-slim-bookworm@sha256:fcbd8dfc2605ba7c2eca646846c5e892b2931e41f6227985154a596f26ab8ed7

FROM ${LIVE_GO_IMAGE} AS live-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY schemas ./schemas

# The live processes must not pull archive's CGO/DuckDB or Python dependency
# graph into their final image.
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o /health-runner ./cmd/health-runner \
 && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o /health-scheduler ./cmd/health-scheduler

FROM ${ARCHIVE_GO_IMAGE} AS archive-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY schemas ./schemas
RUN CGO_ENABLED=1 go build -trimpath -buildvcs=false -ldflags='-s -w' -o /health-archive ./cmd/health-archive

FROM scratch AS runtime
ARG VCS_REF=unknown
ARG CREATED=1970-01-01T00:00:00Z
LABEL org.opencontainers.image.title="Datapan Health runtime" \
      org.opencontainers.image.description="Runner and scheduler only; no archive or Hugging Face tooling" \
      org.opencontainers.image.source="https://github.com/StatPan/datapan-health" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${CREATED}"
COPY --from=live-build /health-runner /health-runner
COPY --from=live-build /health-scheduler /health-scheduler
ENTRYPOINT ["/health-runner"]

FROM ${HF_IMAGE} AS archive
ARG VCS_REF=unknown
ARG CREATED=1970-01-01T00:00:00Z
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
COPY docker/hf-requirements.txt /tmp/hf-requirements.txt
RUN python -m pip install --requirement /tmp/hf-requirements.txt \
 && rm -f /tmp/hf-requirements.txt \
 && command -v hf >/dev/null
LABEL org.opencontainers.image.title="Datapan Health archive" \
      org.opencontainers.image.description="Asynchronous health archive with Hugging Face CLI; never a live runtime role" \
      org.opencontainers.image.source="https://github.com/StatPan/datapan-health" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${CREATED}"
COPY --from=archive-build /health-archive /health-archive
ENTRYPOINT ["/health-archive"]

# Existing local Compose builds intentionally use Docker's default target for
# the live runner/scheduler profile. Keep it role-correct after the archive
# target above.
FROM runtime AS default
