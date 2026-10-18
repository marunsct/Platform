# Policy templates

These are **templates**, not policies. They give an organisation running Matura a starting point for the
documents auditors and customers ask for. They say nothing about compliance on their own: an organisation adopts a policy by
reviewing it, changing it to match how it works, approving it and following it.

| Template | Covers |
|---|---|
| [access-control-policy.md](access-control-policy.md) | sign-in, MFA, sessions, roles, joiners and leavers, access reviews |
| [incident-response-policy.md](incident-response-policy.md) | severities, roles, steps, evidence from the audit log, breach notification |
| [backup-policy.md](backup-policy.md) | what is backed up, how often, restore tests, keys |
| [security-whitepaper.md](security-whitepaper.md) | a security overview for customers: sign-in, isolation, encryption, audit, resilience |
| [questionnaire-answers.md](questionnaire-answers.md) | draft answers grouped by CSA CAIQ v4 domain and SIG Lite topic (the questionnaires are not reproduced) |

## Filling them

`{{placeholder}}` marks a value. `matura check --policies docs/templates --out policies` fills the ones that come
from the installation's readiness report (sign-in method, MFA coverage, audit integrity, last restore test, …) and
lists the rest, which are organisational choices only you can make. Supply those with `--set`:

```sh
matura check --policies docs/templates --out policies \
  --set organisation="Acme Ltd" --set policy_owner="Head of Engineering" \
  --set backup_frequency=daily --set incident_contact=security@acme.example
```

Re-run it after changing settings so the filled values stay true. See [the readiness guide](../guide/readiness.md)
for every placeholder.
