.PHONY: build test test-db vet up down

build:
	go build ./...

vet:
	go vet ./...

# integration tests need a Postgres superuser URL; test-db starts a local throwaway one
test-db:
	@scripts/test-postgres.sh

test:
	eval "$$(scripts/test-postgres.sh)" && go test -count=1 ./...

up:
	docker compose -f deploy/compose/compose.yaml up --build

down:
	docker compose -f deploy/compose/compose.yaml down
