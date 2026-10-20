.PHONY: build test demo demo-fail db db-stop lint

build:
	go build -o bin/ ./cmd/...

# Starts a throwaway local Postgres (port 54329) if LIR_TEST_ADMIN_DSN isn't set.
test:
	@DSN="$${LIR_TEST_ADMIN_DSN:-$$(scripts/dev-postgres.sh start)}"; \
	LIR_TEST_ADMIN_DSN="$$DSN" go test ./...

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
