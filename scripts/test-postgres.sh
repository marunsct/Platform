#!/usr/bin/env bash
# Starts a throwaway Postgres for the integration tests and prints the URL to export:
#   eval "$(scripts/test-postgres.sh)"   then   make test
# Uses the local Postgres binaries (no Docker needed). Stop it with: scripts/test-postgres.sh stop
set -euo pipefail

DIR="${MATURA_TEST_PGDATA:-/tmp/matura-test-pg}"
PORT="${MATURA_TEST_PGPORT:-55432}"
BIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)"
[ -n "$BIN" ] || BIN="$(dirname "$(command -v initdb)")"

as_pg() { if [ "$(id -u)" = 0 ]; then su postgres -s /bin/bash -c "$*"; else bash -c "$*"; fi; }

if [ "${1:-}" = stop ]; then
  as_pg "$BIN/pg_ctl -D $DIR -m fast stop" >/dev/null || true
  exit 0
fi

if [ ! -f "$DIR/PG_VERSION" ]; then
  mkdir -p "$DIR"
  [ "$(id -u)" = 0 ] && chown postgres "$DIR"
  as_pg "$BIN/initdb -D $DIR -U postgres --auth=trust" >/dev/null
fi
as_pg "$BIN/pg_ctl -D $DIR -o '-p $PORT -k /tmp -c listen_addresses=localhost' -l $DIR/log -w start" >/dev/null 2>&1 || true
echo "export MATURA_TEST_DATABASE_URL=postgres://postgres@localhost:$PORT/postgres?sslmode=disable"
