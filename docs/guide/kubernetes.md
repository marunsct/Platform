# Running Matura on Kubernetes

The Helm chart in `deploy/helm/matura` runs maturad (two replicas by default) and, unless you bring your own,
Keycloak with Matura's extension. PostgreSQL is not in the chart: use a managed database or CloudNativePG.

## Before you install

1. **Images.** Build and push maturad (`Dockerfile`) and Keycloak with the extension
   (`deploy/compose/keycloak.Dockerfile`, then run `kc.sh build` in a derived image so `start --optimized` works),
   and set `image.repository` and `keycloak.image.repository`.
2. **Databases.** Create the control-plane database with two roles, as `deploy/compose/init-db.sql` does: an owner that
   runs migrations, and `matura_app` with `NOBYPASSRLS` that maturad runs as. Create a separate `keycloak` database.
3. **Secrets.**

   | Secret | Keys |
   |---|---|
   | `database.existingSecret` | `url` (runtime role), `migrateUrl` (owner role) |
   | `secrets.existingSecret` | `kek` (`openssl rand -base64 32`), `internalToken` (`openssl rand -hex 32`) |
   | `keycloak.database.existingSecret` | `url` (`jdbc:postgresql://…/keycloak`), `username`, `password` |
   | `keycloak.adminSecret` | `username`, `password` (bootstrap admin; remove after first sign-in) |
   | `smtp.existingSecret` (optional) | `user`, `password` |

   Keep the KEK somewhere other than the database backups: without it, stored app secrets and webhook keys cannot be read.

## Install

```sh
helm install matura deploy/helm/matura \
  --set publicURL=https://id.example.com \
  --set keycloak.hostname=https://login.example.com \
  --set database.existingSecret=matura-db --set secrets.existingSecret=matura-secrets \
  --set keycloak.database.existingSecret=keycloak-db --set keycloak.adminSecret=keycloak-admin \
  --set ingress.enabled=true --set ingress.className=nginx \
  --set ingress.maturad.host=id.example.com --set ingress.keycloak.host=login.example.com \
  --set smtp.addr=smtp.example.com:587 --set smtp.from=no-reply@example.com
```

maturad migrates the database on start-up under an advisory lock, so replicas can start together. Background work
(event relay, webhooks, provisioning, email, audit streaming, purges) runs on one replica at a time, chosen by
Postgres advisory locks; there is nothing to configure.

Add the redirect URIs of your hosts to the `matura-console` client in the realm (`keycloak/realm/matura-realm.json`)
before installing, or in Keycloak's admin console afterwards.

## Drop-in mode: your own Keycloak

Set `keycloak.enabled=false` and `keycloak.issuer=https://your-keycloak/realms/<realm>`. Install the Matura extension
jar (`make keycloak-ext`) in that Keycloak's `providers/`, set `MATURA_URL` and `MATURA_INTERNAL_TOKEN` there, and add
the Matura token mapper to the clients of apps that use Matura. Existing users keep signing in as before; they join
tenants when invited or added.

## What the chart sets up

- Pods run as non-root with a read-only root filesystem, no capabilities and the runtime-default seccomp profile.
- A pod disruption budget keeps one maturad running during node drains; replicas spread across nodes.
- Network policies allow only the HTTP ports, and Keycloak's cache port between Keycloak pods.
- `autoscaling.enabled` adds a CPU-based autoscaler; `metrics.serviceMonitor.enabled` scrapes `/metrics` with the
  Prometheus Operator.

Check the chart with `helm lint deploy/helm/matura` and `helm template … | kubeconform -strict`.
Backups: [backup.md](backup.md).
