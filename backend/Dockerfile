# syntax=docker/dockerfile:1
# Multi-stage build for the SecOps Coordinator API.
#
# This Dockerfile is for platforms that build from a Dockerfile (Render,
# Fly.io, plain `docker run`, etc). It is NOT used by the Cloud Run deploy
# path (`gcloud run deploy --source .`), which instead builds via Google
# Cloud Buildpacks using project.toml / GOOGLE_BUILDABLE. Keep both working;
# don't let changes here affect project.toml or vice versa.

FROM golang:1.26-alpine AS build
WORKDIR /src

# Cache module downloads in their own layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 for a static binary that runs on the minimal runtime image
# below without needing glibc/musl shared libs present.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

# ---------------------------------------------------------------------------
FROM alpine:3.22 AS runtime

# ca-certificates: required for outbound TLS calls this service makes
# (Postgres sslmode=require, Gemini, AbuseIPDB, Slack/Discord webhooks,
# Google's OIDC JWKS endpoint, the GCE metadata server if ever run there).
# tzdata: migrations/log timestamps are UTC-only, but keep it for any future
# dependency that reads the system zoneinfo database.
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S app && adduser -S -G app app

WORKDIR /app
COPY --from=build /out/api ./api

# Everything the service needs at runtime comes from environment variables
# (see .env.example) — Render's dashboard / `render.yaml` envVars, or
# `docker run -e` / `--env-file`. No secrets are baked into the image.
USER app

EXPOSE 8080

# No HEALTHCHECK instruction here: Render has its own external health check
# (configured against GET /healthz in render.yaml / the dashboard) and a
# container-level check would duplicate it. If you run this image somewhere
# without a platform health check, add:
#   HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://localhost:8080/healthz || exit 1

ENTRYPOINT ["./api"]
