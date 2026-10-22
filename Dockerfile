# syntax=docker/dockerfile:1.7
# Builds both binaries into small images.
#   docker build --target controlplane -t nightfix .
#   docker build --target agent -t nightfix-agent .
# Go cross-compiles, so the build stage runs natively and only the final
# stages are per-architecture (amd64 and arm64/Graviton).
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/nightfix ./cmd/nightfix-agent

FROM gcr.io/distroless/static-debian12:nonroot AS controlplane
# AWS's RDS CA bundle, so database connections use sslmode=verify-full.
ADD --chmod=0644 https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem /etc/ssl/rds/global-bundle.pem
COPY --from=build /out/nightfix /usr/local/bin/nightfix
ENTRYPOINT ["nightfix"]
CMD ["serve"]

# The agent image is "batteries-included" for shell steps (decision #24):
# aws CLI, psql, mysql, redis-cli, jq, curl, Python 3.
FROM debian:bookworm-slim AS agent
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates curl jq python3 python3-boto3 postgresql-client default-mysql-client redis-tools awscli \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /var/lib/nightfix nightfix
COPY --from=build /out/nightfix-agent /usr/local/bin/nightfix-agent
# Scratch space for shell steps. Declared as a volume so ECS gives tasks a
# writable /tmp with these permissions even with a read-only root filesystem.
RUN chmod 1777 /tmp
VOLUME ["/tmp"]
ENV HOME=/tmp TMPDIR=/tmp
USER nightfix
ENTRYPOINT ["nightfix-agent"]
