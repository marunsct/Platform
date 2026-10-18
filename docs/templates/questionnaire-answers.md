# Security questionnaire answer bank — {{organisation}}

> **TEMPLATE.** Generated from a Matura template on {{generated_at}}. These are draft answers to copy into a
> customer's security questionnaire after review. They describe what the software does and how this installation is
> configured; they are not a statement that any control is effective or that any framework's requirements are met.
> The questionnaires themselves are not reproduced here: answers are grouped by the CSA CAIQ v4 domains and by the
> topics SIG Lite covers, so you can find the answer for a question in front of you. Answers marked
> **organisational** depend on how {{organisation}} works and must be written by you.

## Part A — CSA CAIQ v4, by CCM v4 domain

| Domain | Draft answer |
|---|---|
| A&A Audit and assurance | Readiness checks run against the live installation ({{readiness_score}} on {{generated_at}}); results can be exported as OSCAL assessment results. Independent audits: {{independent_audits}} (**organisational**). |
| AIS Application and interface security | Every API call is authenticated with OpenID Connect tokens, application credentials or scoped agent tokens and authorised per organisation and role. Webhooks are signed. Source is public; changes are reviewed and tested before release. Penetration testing: {{pen_test}}. |
| BCR Business continuity and resilience | Backups run {{backup_frequency}}; last restore test {{last_restore_test}} ({{last_restore_test_result}}), {{restore_tests_90d}} in 90 days. RPO {{rpo}}, RTO {{rto}} (**organisational**). |
| CCC Change control | Releases are versioned with a changelog and database migrations applied in order. Change approval: {{change_process}} (**organisational**). |
| CEK Cryptography, encryption and key management | TLS in transit ({{control_install_tls}}). Stored secrets sealed with AES-256-GCM under a key-encryption key held {{kek_location}} ({{control_install_kek}}). Per-organisation keys ({{control_install_tenant_keys}}) with rotation, customer-managed keys from AWS KMS, Google Cloud KMS, Azure Key Vault or Vault Transit, and crypto-shredding on deletion. |
| DCS Datacenter security | Hosted on {{hosting_provider}} in {{hosting_region}}; physical security is the provider's (**organisational**). |
| DSP Data security and privacy | Organisations and people export their data; deleting an organisation removes or crypto-shreds its data after a grace period. Data location {{data_location}}; sub-processors {{subprocessors}} (**organisational**). |
| GRC Governance, risk and compliance | Policies: {{policy_set}}, owned by {{policy_owner}} (**organisational**). |
| HRS Human resources | Background checks, training and confidentiality agreements: {{hr_controls}} (**organisational**). |
| IAM Identity and access management | Sign-in with {{sign_in_method}}. MFA {{mfa_requirement}}. Enterprise SSO (OIDC, SAML) after domain verification, SCIM 2.0 provisioning, per-organisation session limits, instant token revocation on removal, role-based and fine-grained permissions, access reviews ({{control_tenant_access_review}}), time-boxed read-only support access approved by the organisation. |
| IPY Interoperability and portability | Organisation export as a single bundle; standard protocols (OpenID Connect, SAML, SCIM 2.0, signed webhooks); the software is open source. |
| IVS Infrastructure and virtualisation security | Runs on Kubernetes or containers on {{hosting_provider}}; network segmentation: {{network_controls}} (**organisational**). |
| LOG Logging and monitoring | Append-only, hash-chained audit logs for the installation and each organisation; {{audit_chains_verified}} of {{audit_chains}} chains verified. Organisations stream logs to their own systems ({{tenants_audit_streaming}} do). Metrics: {{control_install_metrics}}. |
| SEF Security incident management | Incident response policy; customers told within {{customer_notification_window}} (**organisational**). Audit log exports serve as evidence. |
| STA Supply chain and transparency | Dependencies under OSI-approved licences and scanned (last scan {{last_vulnerability_scan}}). Sub-processors {{subprocessors}}. |
| TVM Threat and vulnerability management | Dependency scanning (last {{last_vulnerability_scan}}); security patches applied within {{patch_sla}} (**organisational**). |
| UEM Universal endpoint management | Staff endpoints: {{endpoint_controls}} (**organisational**). |

## Part B — SIG Lite topics

| Topic | Draft answer |
|---|---|
| Access control | See CAIQ IAM above. Shared accounts are not allowed; admins cannot act on owners; leavers lose access at once when removed or deprovisioned by SCIM. |
| Application security | See CAIQ AIS. Organisation data is isolated by PostgreSQL row-level security forced on every tenant table. |
| Business resiliency | See CAIQ BCR. |
| Cloud hosting | {{hosting_provider}}, {{hosting_region}}. |
| Compliance management | Readiness report and OSCAL export; independent audits: {{independent_audits}}. |
| Data and information management | Encryption as in CAIQ CEK; export and deletion as in DSP; audit retention: {{audit_retention}}, at least six months while an organisation has AI agents. |
| AI and automated agents | Agents have their own identity, an accountable owner, scoped permissions, optional per-person consent, and recorded human-oversight decisions ({{control_tenant_agent_oversight}}). |
| Incident management | See CAIQ SEF. |
| Network security | TLS ({{control_install_tls}}); optional per-organisation IP allow-lists for the management API ({{tenants_ip_allowlist}} of {{tenants}}). Other controls: {{network_controls}}. |
| Privacy | See CAIQ DSP. |
| Threat management | See CAIQ TVM. |
| Third-party management | Sub-processors {{subprocessors}}; vendor review: {{vendor_review}} (**organisational**). |
| Human resources and physical security | See CAIQ HRS and DCS. |
| Policies and procedures | {{policy_set}}. |
