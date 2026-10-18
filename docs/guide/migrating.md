# Moving from Auth0, Clerk or Keycloak

`matura import` brings people, their organisations and their roles from another identity system into Matura.
It converts the other system's export and sends it to `POST /admin/v1/users:import`. Passwords are not moved:
hashes differ between systems, and Keycloak keeps its own. People set a new password with the link
`--send-password-email` sends them, or sign in through their company's SSO once it is connected.

```sh
export MATURA_URL=https://id.example.com MATURA_TOKEN=<operator token>
matura import auth0 --users users.ndjson --tenant acme --tenant-name "Acme" --owners ana@acme.com --dry-run
matura import auth0 --users users.ndjson --tenant acme --tenant-name "Acme" --owners ana@acme.com --send-password-email
```

Always run with `--dry-run` first: it prints what would be imported. Imports can be run again safely, because
accounts are found by email and existing memberships are kept. The command exits with status 1 when any person,
membership or role could not be imported, and lists each problem.

| From | Export to give `--users` | Organisations |
|---|---|---|
| Auth0 | the bulk user export job's file (JSON or JSON lines) | `app_metadata.tenant` (slug) and `app_metadata.tenant_role` when your app kept them there, otherwise `--tenant` |
| Clerk | `GET /v1/users` of the Backend API (JSON), or the dashboard's CSV export | `--memberships` with `GET /v1/organization_memberships` (JSON); `org:admin` becomes admin |
| Keycloak | the realm export (`realm-export.json`) or a users export | groups under `--group-prefix` become tenants: `/orgs/acme` makes tenant `acme`, and `/orgs/acme/admins` makes admins of it |

Other flags:

- `--role`: the tenant role for people put in `--tenant` (default `member`).
- `--map-role org:lead=admin`: maps a source role to a tenant role. It can be repeated.
- `--app-role devflow:viewer`: gives everyone an app role in every tenant they join. The app is enabled for the
  tenant if it is not already.
- `--batch`: how many people go in each request (default 500).

An organisation is created by the first owner the import lists for it, so make sure each new organisation has one:
use `--owners` with `--tenant`, or include an owner in the export. Disabled or blocked accounts are imported
deactivated. Keycloak service accounts are skipped; make them agents instead
([agents guide](agents.md)). The imported accounts carry `matura_import_source` and `matura_import_id`
attributes, so you can trace them back to the old system.
