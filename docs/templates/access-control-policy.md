# Access control policy — {{organisation}}

> **TEMPLATE.** Generated from a Matura template on {{generated_at}}. Review, adapt and approve it before use; it is
> not a statement that any control is effective or that any framework's requirements are met.

| | |
|---|---|
| Owner | {{policy_owner}} |
| Approved by | {{approver}} |
| Effective from | {{effective_date}} |
| Review | {{review_cycle}} |
| Applies to | {{product_name}} at {{public_url}} and the people who use or operate it |

## 1. Purpose

Access to {{product_name}} and the data in it is given only to people who need it, at the least privilege their work
needs, and taken away when they no longer do.

## 2. Sign-in

- People sign in with {{sign_in_method}}. Shared accounts are not allowed.
- Multi-factor authentication is {{mfa_requirement}} (installation check `tenant-mfa`: {{control_tenant_mfa}}).
- Sessions end after the limits each organisation sets in its security policy; {{tenants_session_limits}} of
  {{tenants}} organisations set their own limits, the rest use the installation defaults.
- Installation operators always sign in with multi-factor authentication.

## 3. Granting access

- Organisations add people by invitation. {{tenants_domain_restricted}} of {{tenants}} organisations restrict
  invitations to their own email domains.
- Each person gets the lowest role that lets them do their work. Owner and admin roles are given only to people
  responsible for the organisation's account.
- Network allow-lists are used by {{tenants_ip_allowlist}} organisations where their risk calls for them.
- Installation operator access is approved by {{policy_owner}} and recorded.

## 4. Changes and removal

- Role changes and removals take effect at once and are recorded in the tamper-evident audit log.
- When someone leaves, their access is removed within {{leaver_sla}}.

## 5. Reviews

- Operators, organisation owners and admins are reviewed at least {{access_review_cycle}}. The last recorded review
  was on {{last_access_review}}.
- Reviews are recorded as evidence (`POST /admin/v1/evidence`, kind `access-review`).

## 6. Logging

Every sign-in-related change, administrative action and refused request is written to a hash-chained audit log
({{audit_chains_verified}} of {{audit_chains}} chains verified on {{generated_at}}). Audit records are
{{audit_retention}}. {{tenants_audit_streaming}} organisations stream their audit log to their own systems.

## 7. Exceptions

Exceptions are approved in writing by {{policy_owner}}, time-limited and reviewed with this policy.
