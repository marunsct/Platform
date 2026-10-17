# Backing up Matura

Matura keeps its state in two PostgreSQL databases: the control plane (`matura`) and Keycloak (`keycloak`). Apps keep
their own data; back those up as well, and note that an app restored to an older point catches up from Matura's
change feed on its next sync (contract §6).

## Compose and VM installs

`scripts/backup.sh` uses `pg_dump` and `pg_restore` (PostgreSQL client 16 or newer):

```sh
export MATURA_BACKUP_URL=postgres://postgres@db:5432        # superuser or owner, no database name
scripts/backup.sh backup /backups/$(date +%F)               # dumps, row counts, SHA-256 sums, manifest
scripts/backup.sh verify /backups/2026-10-17                # checksums only
scripts/backup.sh restore-test /backups/2026-10-17          # restores into throwaway databases and compares row counts
```

Run `backup` daily and `restore-test` weekly from cron or a systemd timer, and copy the directory to object storage
with object lock. A restore that passes `restore-test` is a backup you can rely on; one that has never been restored is not.

To restore for real: stop maturad and Keycloak, recreate the empty databases with their owners
(`deploy/compose/init-db.sql`), then `scripts/backup.sh restore <dir> matura matura` and the same for `keycloak`.
Dumps leave out privileges; maturad grants its runtime role the table privileges again when it starts.

The KEK (`MATURA_KEK`) is not in the dumps and must be backed up separately: without it, stored app secrets, webhook
signing keys and database-server credentials cannot be read.

For point-in-time recovery, use pgBackRest with WAL archiving on the database server; `scripts/backup.sh` gives
daily logical copies, which are also the simplest way to move an installation.

## Kubernetes

Use CloudNativePG `ScheduledBackup` with the Barman Cloud plugin for both databases, which gives point-in-time
recovery to object storage, and run `scripts/backup.sh restore-test` against a recovered cluster from a weekly job.
