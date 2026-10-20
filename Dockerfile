# Builds both binaries into small images.
#   docker build --target controlplane -t nightfix .
#   docker build --target agent -t nightfix-agent .
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/nightfix ./cmd/nightfix-agent

FROM gcr.io/distroless/static-debian12:nonroot AS controlplane
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
USER nightfix
ENTRYPOINT ["nightfix-agent"]
