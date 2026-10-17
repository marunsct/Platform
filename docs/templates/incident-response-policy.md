# Incident response policy — {{organisation}}

> **TEMPLATE.** Generated from a Matura template on {{generated_at}}. Review, adapt and approve it before use; it is
> not a statement that any control is effective or that any framework's requirements are met.

| | |
|---|---|
| Owner | {{policy_owner}} |
| Approved by | {{approver}} |
| Effective from | {{effective_date}} |
| Review | {{review_cycle}} |
| Applies to | {{product_name}} at {{public_url}} |

## 1. Reporting

Anyone who suspects a security incident reports it at once to {{incident_contact}}. Customers and researchers
report to the same address.

## 2. Severities

| Severity | Meaning | First response |
|---|---|---|
| 1 | personal or customer data exposed, or the service down for everyone | {{sev1_response}} |
| 2 | a security control failing, or one organisation affected | {{sev2_response}} |
| 3 | a weakness with no sign of use | next working day |

## 3. Roles

- **Incident lead** ({{incident_lead}}): runs the response and decides severity.
- **Communications** ({{communications_lead}}): customers, regulators and staff.
- **Scribe**: keeps the timeline.

## 4. Steps

1. **Contain**: deactivate affected accounts (`PATCH /admin/v1/users/{uid}`), revoke app secrets, tighten a
   tenant's IP allow-list, rotate keys.
2. **Investigate**: export the affected audit chains (`GET /v1/tenants/{tid}/audit/export`) and verify them
   (`audit:verify`) before relying on them; audit integrity on {{generated_at}}: {{audit_chains_verified}} of
   {{audit_chains}} chains verified.
3. **Recover**: restore from backup if data was changed (last restore test {{last_restore_test}}:
   {{last_restore_test_result}}).
4. **Notify**: where personal data is involved, the controller notifies the supervisory authority within 72 hours
   of becoming aware (GDPR Art. 33) and the people affected when the risk is high (Art. 34). Processors tell their
   controllers without undue delay.
5. **Review**: a blameless review within {{review_window}}, with actions tracked to closure.

## 5. Records

Every incident is recorded with its timeline, impact, decisions and actions, and kept for {{record_retention}}.
