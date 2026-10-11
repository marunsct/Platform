# 07 — Security and compliance

## 1. Threat model (STRIDE summary, full model in `docs/security/threat-model.md` during P1)

| Threat | Examples | Main controls |
|---|---|---|
| Spoofing | credential stuffing, phishing, token theft, SAML signature wrapping | MFA/passkeys, breached-password check, lockout, short tokens, refresh rotation with reuse detection, DPoP option, strict SAML validation (signed, audience, recipient, replay cache) |
| Tampering | audit log edits, cross-tenant writes, supply-chain injection | hash-chained audit with external anchoring, RLS + composite FKs, signed images and provenance, admission policies |
| Repudiation | admin denies an action | every mutation audited with actor, impersonator, IP, request id |
| Information disclosure | cross-tenant read, IDOR, secrets in logs, backup leak | RLS, 404 on foreign ids, per-tenant keys, log scrubbing, encrypted backups, least-privilege roles |
| Denial of service | sign-in floods, expensive queries, noisy tenant | gateway rate limits, WAF, CAPTCHA on risk, per-tenant quotas, autoscaling, circuit breakers |
| Elevation of privilege | role escalation, SSRF to metadata, container escape | role checks server-side, four-eyes for sensitive admin actions, egress allow-lists, metadata endpoint blocked, gVisor/Kata for untrusted code, Pod Security restricted |

## 2. Control catalogue

| Domain | Controls |
|---|---|
| Identity | doc 03: MFA enforceable, passkeys, SSO, SCIM deprovisioning SLA, session revocation, password policy, lockout |
| Access management | RBAC + ReBAC, least privilege defaults, access reviews, just-in-time elevation for platform staff (time-boxed role grants with approval), separation of duties (billing vs security admins) |
| Encryption in transit | TLS 1.2+ (1.3 preferred) at the edge with HSTS and modern ciphers; mTLS or WireGuard (Cilium) inside the cluster; TLS to Postgres, NATS, Infinispan, OpenBao |
| Encryption at rest | disk encryption (LUKS/cloud), Postgres TDE not required because sensitive fields use envelope encryption via OpenBao transit; object storage SSE with per-tenant keys; backups encrypted |
| Key management | OpenBao with auto-unseal (cloud KMS or HSM via PKCS#11), Shamir recovery keys split among named people, key rotation schedules, BYOK/HYOK |
| Secrets | no secrets in Git (SOPS for encrypted values), ESO for delivery, dynamic DB credentials, secret scanning in CI (Trivy/Gitleaks, MIT) |
| Application security | OWASP ASVS Level 2 (Level 3 for identity paths), secure headers (CSP with nonces, frame-ancestors, COOP/COEP), CSRF protection, input validation from OpenAPI schemas, output encoding, SSRF guard library, safe file uploads (type sniffing, size limits, ClamAV scanning, GPL-2.0 used unmodified as a separate service) |
| Supply chain | SLSA level 3 builds, cosign signatures and attestations, SBOM (SPDX + CycloneDX) per release, dependency pinning with Renovate (AGPL, used as a hosted/CI tool only) or Dependabot, OSV and Grype scans, Kyverno verifies signatures at admission, reproducible builds where possible |
| Infrastructure | CIS Kubernetes benchmark (kube-bench, Apache-2.0), Pod Security restricted, read-only root filesystems, non-root, seccomp, no privileged pods, node OS hardening (Talos or CIS images), private API server, etcd encryption |
| Network | default-deny Cilium policies, egress allow-lists, WAF (Coraza + OWASP CRS), DDoS protection at the provider edge, separate admin hostname, optional private link for silo tenants |
| Runtime detection | Falco rules (shell in container, unexpected outbound, crypto mining), Hubble flow logs, alerts to the security center |
| Logging and audit | §3 |
| Vulnerability management | scans on every build and nightly on running images; SLAs: critical 7 days, high 30 days, medium 90 days; VEX documents to explain non-exploitable findings |
| Testing | SAST (Semgrep CE, gosec, CodeQL queries), DAST (ZAP nightly against staging), fuzzing (Go native fuzzing on parsers: SAML, SCIM, tokens), cross-tenant suite, annual third-party penetration test, bug bounty after 1.0 |
| Change management | protected main, two-person review for identity and crypto code, signed commits, CODEOWNERS, release approvals |
| Incident response | runbooks, severity levels, on-call rota, customer notification within 72 h for personal-data breaches (GDPR art. 33), post-incident reviews |
| Business continuity | doc 08: backups, DR, restore tests |
| Privacy | data inventory, DPIA template, data processing agreement template, sub-processor list, retention policies, user export and deletion |

## 3. Audit logging

- **What:** every authentication event (from Keycloak's event listener), every admin and API mutation, every
  permission change, impersonation, key use (OpenBao audit device), export, deletion, policy change, failed
  authorisation.
- **Format:** CloudEvents with `actor`, `on_behalf_of`, `tenant`, `action`, `target`, `result`, `ip`, `user_agent`,
  `request_id`, `trace_id`, `before/after` diffs (redacted for secrets).
- **Integrity:** append-only table (no UPDATE/DELETE grants), each record carries `prev_hash` and `hash` (SHA-256 per
  tenant chain); a signed checkpoint every hour anchored to object storage with object lock (WORM) and optionally
  to a public transparency log (Sigstore Rekor); `tenantry audit verify` checks the chain.
- **Retention:** platform default 1 year online + 7 years archive (configurable per plan), legal hold per tenant.
- **Access:** tenant auditors see their tenant; platform auditors see staff actions; nobody can delete.
- **Export:** live streams to customer SIEMs (syslog RFC 5424 over TLS, HTTPS webhook, S3-compatible, Kafka,
  OpenSearch, Splunk HEC-compatible), CSV/JSON download, OCSF mapping for security events.

## 4. Compliance readiness

Tenantry cannot make an operator compliant by itself, but it ships the controls, evidence and documents so an
operator can pass audits quickly.

| Framework | What Tenantry provides |
|---|---|
| **SOC 2 Type II** | control mapping (CC6 logical access, CC7 operations, CC8 change, A1 availability, C1 confidentiality), evidence export (access reviews, MFA coverage, change history, backup and restore tests, vulnerability SLAs), policies templates |
| **ISO/IEC 27001:2022** | Annex A mapping, statement-of-applicability template, risk register template |
| **GDPR / UK GDPR** | data residency, export, erasure, consent records, DPA template, records of processing generator, breach workflow |
| **HIPAA** | encryption, audit, access controls, BAA-ready configuration profile (silo tier, PHI tagging, no PHI in logs) |
| **PCI DSS** | out of scope by design: card data handled by the payment provider through Kill Bill plug-ins |
| **FedRAMP / NIST 800-53 moderate** | control mapping, FIPS 140-3 mode (FIPS-validated crypto builds of Go and the Keycloak FIPS profile), air-gapped bundle |
| **CSA STAR / CAIQ** | pre-filled questionnaire |
| **Accessibility** | WCAG 2.2 AA for consoles and login |

Configuration profiles (`profile: standard | hipaa | fips | sovereign`) switch defaults (MFA required, shorter
sessions, retention, sandboxing, crypto modules) in one setting.

## 5. Security of the open-source project itself

Security policy and private reporting (GitHub security advisories), CVE numbering via GitHub CNA, embargo period
(90 days max), signed releases, OpenSSF Scorecard ≥ 8, OpenSSF Best Practices badge, security champions for the
Keycloak extensions and crypto code.
