#!/usr/bin/env bash
# Backs up Matura's databases (control plane and Keycloak) to a directory, or restores and checks them.
#
#   scripts/backup.sh backup  <dir>                 pg_dump each database, write SHA-256 sums and a manifest
#   scripts/backup.sh verify  <dir>                 check the sums
#   scripts/backup.sh restore-test <dir>            restore into throwaway databases and compare row counts
#   scripts/backup.sh restore <dir> <db> <target>   restore one dump into an existing empty database
#
# Connection: MATURA_BACKUP_URL is a superuser (or owner) URL without a database name, e.g.
# postgres://postgres@db:5432 . MATURA_BACKUP_DATABASES lists the databases (default "matura keycloak").
# This covers Compose and VM installs; on Kubernetes use CloudNativePG backups (docs/guide/backup.md).
set -euo pipefail

cmd="${1:-}"; dir="${2:-}"
[ -n "$cmd" ] && [ -n "$dir" ] || { sed -n 2,11p "$0"; exit 2; }
base="${MATURA_BACKUP_URL:?set MATURA_BACKUP_URL, e.g. postgres://postgres@localhost:5432}"
dbs="${MATURA_BACKUP_DATABASES:-matura keycloak}"
url() { echo "${base%/}/$1"; }

counts() { # row counts of every user table, sorted, for comparing a restore with its source
  psql -X -q -At -d "$(url "$1")" -c "SELECT format('%I.%I', schemaname, relname) FROM pg_stat_user_tables ORDER BY 1" |
  while read -r t; do echo "$t $(psql -X -q -At -d "$(url "$1")" -c "SELECT count(*) FROM $t")"; done
}

case "$cmd" in
backup)
  mkdir -p "$dir"
  for db in $dbs; do
    pg_dump --format=custom --no-owner --no-privileges --file="$dir/$db.dump" "$(url "$db")"
    counts "$db" > "$dir/$db.counts"
  done
  (cd "$dir" && sha256sum ./*.dump ./*.counts > SHA256SUMS)
  printf '{"created_at":"%s","databases":"%s","server":"%s"}\n' "$(date -u +%FT%TZ)" "$dbs" \
    "$(psql -X -At -d "$(url postgres)" -c 'SHOW server_version')" > "$dir/manifest.json"
  echo "backup written to $dir"
  ;;
verify)
  (cd "$dir" && sha256sum --quiet -c SHA256SUMS) && echo "checksums ok"
  ;;
restore)
  db="${3:?database name}"; target="${4:?target database}"
  pg_restore --no-owner --no-privileges --exit-on-error -d "$(url "$target")" "$dir/$db.dump"
  ;;
restore-test)
  (cd "$dir" && sha256sum --quiet -c SHA256SUMS)
  status=0
  for db in $dbs; do
    tmp="restore_test_${db}_$$"
    psql -X -q -d "$(url postgres)" -c "CREATE DATABASE $tmp"
    pg_restore --no-owner --no-privileges --exit-on-error -d "$(url "$tmp")" "$dir/$db.dump"
    if diff <(counts "$tmp") "$dir/$db.counts" >/dev/null; then echo "$db: restored, row counts match"
    else echo "$db: row counts differ after restore"; status=1; fi
    psql -X -q -d "$(url postgres)" -c "DROP DATABASE $tmp"
  done
  exit $status
  ;;
*) sed -n 2,11p "$0"; exit 2 ;;
esac
