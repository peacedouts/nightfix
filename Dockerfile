# Builds both binaries into small images.
#   docker build --target controlplane -t lightning .
#   docker build --target agent -t lightning-agent .
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/lightning ./cmd/lightning-agent

FROM gcr.io/distroless/static-debian12:nonroot AS controlplane
COPY --from=build /out/lightning /usr/local/bin/lightning
ENTRYPOINT ["lightning"]
CMD ["serve"]

# The agent image is "batteries-included" for shell steps (decision #24):
# aws CLI, psql, mysql, redis-cli, jq, curl, Python 3.
FROM debian:bookworm-slim AS agent
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates curl jq python3 python3-boto3 postgresql-client default-mysql-client redis-tools awscli \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /var/lib/lightning lightning
COPY --from=build /out/lightning-agent /usr/local/bin/lightning-agent
USER lightning
ENTRYPOINT ["lightning-agent"]
