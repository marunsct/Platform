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
   Better, keep it out of maturad altogether: set `keys.provider` to `transit` (OpenBao or Vault, with
   `keys.transit.addr` and a Secret holding its token in `keys.transit.tokenSecret`), `awskms` (`keys.aws.keyId`,
   `keys.aws.region`, credentials from IRSA or pod identity), `gcpkms` (`keys.gcp.key`, workload identity) or
   `azurekv` (`keys.azure.keyUrl`, managed identity); `secrets.kek` is then optional. Moving an installation that
   already has secrets: keep the old `kek` in the Secret, switch the provider, then call
   `POST /admin/v1/keys:rewrap` and remove the old key (technical specification §9.1). `keys.byokProviders` lets
   tenants bring their own key; `keys.tenantKeys` (on) gives each tenant its own key, destroyed when it is deleted.

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

## Fine-grained permissions (OpenFGA, optional)

Off by default; maturad's permission endpoints then answer 501. To turn them on, either run OpenFGA with the chart:

```sh
  --set openfga.enabled=true \
  --set openfga.datastore.existingSecret=openfga-db \     # key uri: postgres://openfga:…@db:5432/openfga
  --set openfga.presharedKeySecret=openfga-key            # key key: openssl rand -hex 32 (maturad sends it)
```

or point maturad at an OpenFGA you run yourself with `--set openfga.url=http://openfga.example:8080`. OpenFGA runs
two replicas against its own Postgres database (an init container runs `openfga migrate`); a network policy lets
only maturad reach it. `openfga.datastore.engine=memory` is for throwaway test installs (one replica; maturad writes
its facts again when the store disappears, but tuples apps wrote are lost). How tenants and apps share the store:
[technical specification §18](../spec/02-technical-specification.md).

## What the chart sets up

- Pods run as non-root with a read-only root filesystem, no capabilities and the runtime-default seccomp profile.
- A pod disruption budget keeps one maturad running during node drains; replicas spread across nodes.
- Network policies allow only the HTTP ports, Keycloak's cache port between Keycloak pods, and OpenFGA from maturad.
- `autoscaling.enabled` adds a CPU-based autoscaler; `metrics.serviceMonitor.enabled` scrapes `/metrics` on port 9090
  (`MATURA_METRICS_ADDR`) with the Prometheus Operator.

Check the chart with `helm lint deploy/helm/matura` and `helm template … | kubeconform -strict`.
Backups: [backup.md](backup.md).
