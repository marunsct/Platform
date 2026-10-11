# 12 — Running the open-source project

## 1. Licence policy (ADR 0002)

- Matura's own code: **Apache-2.0** (patent grant, enterprise-friendly, lets anyone host and modify).
- Dependencies and bundled components: OSI-approved only. Allowed without review: Apache-2.0, MIT, BSD, ISC, MPL-2.0,
  PostgreSQL, Zlib. Allowed as separate unmodified services or tools only, with a permissive alternative documented:
  AGPL-3.0, GPL, LGPL (e.g. Grafana, Citus, ClamAV, k6). Not allowed: BSL, SSPL, Elastic License, Commons Clause, any
  "source-available" or field-of-use licence.
- `deps/licences.yaml` records every component and version; CI (e.g. `go-licenses`, `license-checker`, ScanCode,
  Apache-2.0) fails on a disallowed licence; quarterly re-check because upstream licences change.
- DCO sign-off on contributions (no CLA), so the project can never be relicensed away from open source by one party.

## 2. Governance

- Start: maintainer-led (the owner as project lead), public roadmap, RFC process (`docs/rfcs/`) for big changes.
- Later: steering committee when there are outside maintainers; aim for a neutral foundation (CNCF sandbox or Linux
  Foundation) once adoption justifies it.
- Code of conduct (Contributor Covenant), CONTRIBUTING, GOVERNANCE, MAINTAINERS, SECURITY files.
- Trademark: the name and logo are the only thing reserved; usage guidelines so forks rename.

## 3. Releases

- Semantic versioning; minor releases every 6 weeks, patches as needed; an LTS line every 12 months supported 18
  months with security fixes.
- Each release: signed images (cosign), SBOMs, provenance, Helm chart, Compose bundle, air-gap bundle, changelog,
  upgrade notes, tested upgrade path from the previous two minors and the last LTS.
- Keycloak version policy: track upstream minor releases within 60 days; security releases within 72 hours.

## 4. Community and sustainability

- GitHub Discussions, a chat (Matrix, open protocol), monthly community call, good-first-issues, public roadmap board.
- Sustainability options that keep the code fully open: paid support, managed hosting, certification of
  installations, sponsorships. No feature is held back behind a commercial licence.

## 5. Repository hygiene

Protected `main`, required reviews, CI must pass (lint, tests, cross-tenant suite, security scans, licence check,
e2e on kind), CODEOWNERS for identity and crypto, Renovate/Dependabot updates, OpenSSF Scorecard, signed tags.
