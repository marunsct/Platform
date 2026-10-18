# {{product_name}} security overview — {{organisation}}

> **TEMPLATE.** Generated from a Matura template on {{generated_at}}. Review, adapt and approve it before sharing.
> It describes how the software is built and how this installation is configured; it is not a statement that any
> control is effective or that any framework's requirements are met. Readiness score at generation:
> {{readiness_score}} (a measure of configuration gaps, not an audit result).

| | |
|---|---|
| Service | {{product_name}} at {{public_url}} |
| Operated by | {{organisation}} |
| Hosting | {{hosting_provider}}, region {{hosting_region}} |
| Security contact | {{security_contact}} |
| Document owner | {{policy_owner}} |

## 1. Architecture

{{product_name}} runs on Matura, an open-source identity and tenancy control plane. Sign-in is handled by Keycloak;
the Matura control plane (`maturad`) keeps organisations, members, roles, policies and the audit log in PostgreSQL;
fine-grained permissions, where used, are kept in OpenFGA. Applications receive signed tokens and a signed event feed
and never see passwords.

## 2. Identity and sign-in

- People sign in with {{sign_in_method}}.
- Multi-factor authentication (authenticator app, security key or passkey) is {{mfa_requirement}}. Organisations
  set it in their security policy; enrolment is forced at the next sign-in. (Check `tenant-mfa`: {{control_tenant_mfa}}.)
- Organisations can connect their own identity provider over OpenID Connect or SAML after verifying their email
  domain, and provision people with SCIM 2.0. Accounts removed in the identity provider lose access at once.
- Session lifetimes are set per organisation ({{tenants_session_limits}} of {{tenants}} set their own). Removing a
  person, deactivating them or signing them out revokes their tokens across applications within seconds.
- Invitations can be restricted to an organisation's own domains ({{tenants_domain_restricted}} of {{tenants}} do),
  and an organisation's management API can be restricted to network ranges ({{tenants_ip_allowlist}} do).

## 3. Authorisation and isolation

- Every organisation's records carry its id, and PostgreSQL row-level security, forced on every tenant table,
  limits each request to the organisation it acts for. A request without an organisation sees no tenant rows.
- Roles are assigned per organisation and per application; admins cannot act on owners.
- Installation operators see an organisation's admin views only with read-only support access lasting at most
  eight hours, which an owner approves unless the organisation chose otherwise (or turned support access off); each
  request and its use is recorded in that organisation's audit log.
- Owners run access reviews; the last recorded installation-level review was on {{last_access_review}}.

## 4. AI agents

Agents act under their own identity, with an accountable owner, scoped permissions and, where an organisation asks
for it, each person's consent. Their actions and human oversight decisions are recorded in the audit log and kept for
at least six months while the organisation has agents. (Checks `tenant-agent-accountability`:
{{control_tenant_agent_accountability}}, `tenant-agent-oversight`: {{control_tenant_agent_oversight}}.)

## 5. Encryption

- In transit: TLS for every external connection (check `install-tls`: {{control_install_tls}}).
- At rest: secrets kept by the control plane (identity-provider credentials, webhook and audit-sink secrets) are
  sealed with AES-256-GCM under a key-encryption key held {{kek_location}} (check `install-kek`: {{control_install_kek}}).
- Each organisation has its own keys (check `install-tenant-keys`: {{control_install_tenant_keys}}); organisations
  can rotate them or bring their own key from a cloud key service. Deleting an organisation destroys its keys, so
  what was sealed under them, including export bundles, can no longer be read.
- Database storage and backups are encrypted by {{storage_encryption}}.

## 6. Audit logging

Security events (membership, role, policy and key changes, support access,
exports, agent actions) are written to append-only, hash-chained audit logs: one for the installation and one per
organisation. {{audit_chains_verified}} of {{audit_chains}} chains verified on {{generated_at}}. Organisations can
stream their log to their own systems ({{tenants_audit_streaming}} do) and export it.

## 7. Data protection and privacy

- Organisations export their data as a bundle with a SHA-256 checksum and can delete their organisation; deletion runs
  after a grace period and then removes or crypto-shreds the data.
- People can export their own data and delete their account.
- Data location: {{data_location}}.
- Sub-processors: {{subprocessors}}.

## 8. Resilience

Backups run {{backup_frequency}}. Restores are tested; the last recorded test was on {{last_restore_test}}
({{last_restore_test_result}}), with {{restore_tests_90d}} in the last 90 days. Recovery objectives: RPO
{{rpo}}, RTO {{rto}}.

## 9. Vulnerability management and development

- Dependencies are scanned; the last recorded scan was on {{last_vulnerability_scan}}.
- Matura's source is public and every change is reviewed and tested before release. {{organisation}} applies
  security releases within {{patch_sla}}.
- Penetration testing: {{pen_test}}.

## 10. Incidents

Incidents are handled under {{organisation}}'s incident response policy. Affected customers are told within
{{customer_notification_window}} of confirmation. Report a vulnerability to {{security_contact}}.
