.PHONY: build test test-race cover demo demo-fail db db-stop lint

build:
	go build -o bin/ ./cmd/...

# Starts a throwaway local Postgres (port 54329) if NIGHTFIX_TEST_ADMIN_DSN isn't set.
test:
	@set -e; DSN="$${NIGHTFIX_TEST_ADMIN_DSN:-$$(scripts/dev-postgres.sh start)}"; \
	[ -n "$$DSN" ] || { echo "no Postgres for the tests (scripts/dev-postgres.sh start failed)" >&2; exit 1; }; \
	NIGHTFIX_TEST_ADMIN_DSN="$$DSN" go test ./...

# What CI runs: race detector, shuffled order, cross-package coverage.
test-race:
	@set -e; DSN="$${NIGHTFIX_TEST_ADMIN_DSN:-$$(scripts/dev-postgres.sh start)}"; \
	NIGHTFIX_TEST_ADMIN_DSN="$$DSN" go test -race -shuffle=on -count=1 -coverpkg=./... -coverprofile=cover.out ./...
	scripts/coverage.sh cover.out 75

cover: test-race

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

demo:
	scripts/demo.sh

demo-fail:
	DEMO_SCENARIO=fail scripts/demo.sh

db:
	scripts/dev-postgres.sh start

db-stop:
	scripts/dev-postgres.sh stop
