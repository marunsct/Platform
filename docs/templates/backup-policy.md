# Backup policy — {{organisation}}

> **TEMPLATE.** Generated from a Matura template on {{generated_at}}. Review, adapt and approve it before use; it is
> not a statement that any control is effective or that any framework's requirements are met.

| | |
|---|---|
| Owner | {{policy_owner}} |
| Approved by | {{approver}} |
| Effective from | {{effective_date}} |
| Review | {{review_cycle}} |
| Applies to | {{product_name}} at {{public_url}} |

## 1. What is backed up

- Matura's control-plane database and the identity provider's database.
- The key-encryption key (`MATURA_KEK`), kept apart from the database backups; without it, stored secrets cannot be
  read.
- Each application's own data, under that application's backup procedure.

## 2. How often and where

- Backups run {{backup_frequency}} and are kept for {{backup_retention}}.
- Copies are stored in {{backup_location}}, encrypted, with write-once retention where the storage offers it.
- Recovery objectives: data loss of at most {{rpo}}, service back within {{rto}}.

## 3. Restore tests

- A restore test (`scripts/backup.sh restore-test <dir> --report <maturad URL>`) restores the newest backup into
  throwaway databases, compares row counts and records the result as evidence in the audit log.
- Restore tests run at least {{restore_test_frequency}}. Last recorded: {{last_restore_test}}
  ({{last_restore_test_result}}); {{restore_tests_90d}} in the 90 days before {{generated_at}}.
- A failed restore test is handled as a severity 2 incident.

## 4. Access

Only {{backup_admins}} can read or delete backups. Deleting a backup before its retention ends needs approval from
{{policy_owner}}.
