# 0002 — Licence policy

Status: proposed · 2026-10-11

## Context
The project must be usable by anyone to host their own app platform. Several infrastructure projects changed to
non-open licences (Vault and Terraform to BSL, Redis, Elastic, Phase Two's Keycloak extensions to ELv2) or were
abandoned upstream (MinIO community edition).

## Decision
Our code is Apache-2.0 with DCO sign-off (no CLA). Required components must be OSI-approved. Permissive licences
(Apache-2.0, MIT, BSD, ISC, MPL-2.0, PostgreSQL) are allowed freely. Copyleft (AGPL, GPL, LGPL) is allowed only for
separate, unmodified services or tools with a permissive alternative documented. BSL, SSPL, ELv2, Commons Clause and
other source-available licences are not allowed. CI enforces this from `deps/licences.yaml`; licences are re-audited
quarterly.

## Consequences
+ Anyone can host, modify and resell Matura.
− Some popular tools (Vault, MinIO, Grafana as default) are replaced by OpenBao, SeaweedFS, Perses.
