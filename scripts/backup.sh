#!/usr/bin/env bash
# Backs up Matura's databases (control plane and Keycloak) to a directory, or restores and checks them.
#
#   scripts/backup.sh backup  <dir>                 pg_dump each database, write SHA-256 sums and a manifest
#   scripts/backup.sh verify  <dir>                 check the sums
#   scripts/backup.sh restore-test <dir> [--report URL]
#                                                   restore into throwaway databases and compare row counts;
#                                                   --report posts the result to maturad at URL as evidence
#   scripts/backup.sh restore <dir> <db> <target>   restore one dump into an existing empty database
#
# Connection: MATURA_BACKUP_URL is a superuser (or owner) URL without a database name, e.g.
# postgres://postgres@db:5432 . MATURA_BACKUP_DATABASES lists the databases (default "matura keycloak").
# --report needs MATURA_TOKEN, an operator's access token (POST /admin/v1/evidence, kind restore-test).
# This covers Compose and VM installs; on Kubernetes use CloudNativePG backups (docs/guide/backup.md).
set -euo pipefail

usage() { sed -n 2,14p "$0"; exit 2; }
cmd="${1:-}"; dir="${2:-}"
[ -n "$cmd" ] && [ -n "$dir" ] || usage
report=""
if [ "$cmd" = restore-test ]; then
  shift 2
  while [ $# -gt 0 ]; do
    case "$1" in
    --report) report="${2:-}"; [ -n "$report" ] || usage; shift 2 ;;
    --report=*) report="${1#--report=}"; shift ;;
    *) echo "unknown option: $1" >&2; usage ;;
    esac
  done
  if [ -n "$report" ] && [ -z "${MATURA_TOKEN:-}" ]; then
    echo "--report needs MATURA_TOKEN (an operator's access token)" >&2; exit 2
  fi
fi
base="${MATURA_BACKUP_URL:?set MATURA_BACKUP_URL, e.g. postgres://postgres@localhost:5432}"
dbs="${MATURA_BACKUP_DATABASES:-matura keycloak}"
url() { echo "${base%/}/$1"; }
json_str() { local s="${1//\\/\\\\}"; s="${s//\"/\\\"}"; printf '"%s"' "$s"; }

# report_evidence <passed> <details JSON object>: records the restore test in maturad's audit log
report_evidence() {
  local body
  body="{\"kind\":\"restore-test\",\"passed\":$1,\"details\":$2}"
  if curl -fsS -o /dev/null -X POST -H "Authorization: Bearer $MATURA_TOKEN" -H 'Content-Type: application/json' \
    --data "$body" "${report%/}/admin/v1/evidence"; then
    echo "reported to ${report%/}"
  else
    echo "could not report the result to ${report%/}" >&2; return 1
  fi
}

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
  status=0; results=""
  if (cd "$dir" && sha256sum --quiet -c SHA256SUMS); then
    for db in $dbs; do
      tmp="restore_test_${db}_$$"
      if psql -X -q -d "$(url postgres)" -c "CREATE DATABASE $tmp" &&
        pg_restore --no-owner --no-privileges --exit-on-error -d "$(url "$tmp")" "$dir/$db.dump"; then
        if diff <(counts "$tmp") "$dir/$db.counts" >/dev/null; then r="restored, row counts match"
        else r="row counts differ after restore"; status=1; fi
      else r="restore failed"; status=1; fi
      echo "$db: $r"
      psql -X -q -d "$(url postgres)" -c "DROP DATABASE IF EXISTS $tmp" || true
      results="$results${results:+,}$(json_str "$db"):$(json_str "$r")"
    done
  else
    echo "checksums do not match"; status=1; results='"checksums":"do not match"'
  fi
  if [ -n "$report" ]; then
    created="$(sed -n 's/.*"created_at":"\([^"]*\)".*/\1/p' "$dir/manifest.json" 2>/dev/null || true)"
    passed=true; [ "$status" -eq 0 ] || passed=false
    details="{\"backup\":$(json_str "$(basename "$dir")"),\"backup_created_at\":$(json_str "$created"),\"host\":$(json_str "${HOSTNAME:-$(uname -n)}"),\"databases\":{$results}}"
    report_evidence "$passed" "$details" || { [ "$status" -ne 0 ] || status=3; }
  fi
  exit $status
  ;;
*) usage ;;
esac
