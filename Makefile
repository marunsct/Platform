.PHONY: build test test-db vet up down keycloak-ext portal portal-test

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

# Keycloak extension (token mapper): Java 21 and Maven
keycloak-ext:
	cd keycloak/extensions && mvn -q -B package

# customer portal (web/portal): rebuilds internal/portal/dist, which is committed so go build needs no Node
portal:
	cd web/portal && npm ci && npm run build

portal-test:
	cd web/portal && npm ci && npm run typecheck && npm test
