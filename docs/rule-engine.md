# Initial AWS rules (M4)

Use the Python pipeline; the scan command arrives in M5:

```python
from iamcheck.providers.aws import AWSProvider
from iamcheck.rules.engine import evaluate

collection = AWSProvider(profile="prod").collect()
result = evaluate(collection)
for finding in result.findings:
    print(finding.model_dump_json())
for evaluation in result.evaluations:
    print(evaluation.rule_id, evaluation.entity_id,
          evaluation.status, evaluation.reason)
```

## Checks

| Rule ID | Behaviour | Scope and limitations |
|---|---|---|
| CIS-AWS-1.16 | Flags AdministratorAccess or PowerUserAccess directly attached to an AWS user | Exact AWS-managed ARNs only. This is a subset of the older direct-policy control, not a full compliance check. PowerUserAccess is broad access, not equivalent to AdministratorAccess. |
| CUSTOM-001 | Flags Allow statements with exact Action `*`, including action lists | Reads resolved managed and inline documents. Retains resource/condition evidence; does not evaluate effective access, overrides, NotAction or service-specific wildcards. |
| CIS-AWS-1.3 | Flags observed credential or role activity at least 90 days old | User credentials are checked separately; recent activity on one does not hide another. Unknown/naive/future dates are not inactivity. Role findings and custom thresholds have no CIS reference. |
| CIS-AWS-1.14 | Flags root console credentials with disabled MFA or known absence of hardware MFA | Root console-password presence must be known. Missing hardware type stays skipped. Root accounts with absent/unknown console credentials are not flagged. |
| CUSTOM-002 | Flags external AWS trust with no mandatory restrictive ExternalId | Allow/AssumeRole statements only; services/federation and same-account principals are excluded. This is a third-party trust review prompt, not proof that every cross-account relationship needs ExternalId. |

Referenced CIS numbering is explicitly pinned to AWS Foundations v1.2.0,
matching the original project notes. User direct-policy and inactivity
coverage are partial; this is not a CIS compliance certification or a
full implementation of any benchmark. Role inactivity retains the original
rule family ID but has no CIS mapping. A custom rule's CIS reference is null.

AWS reference for the control intent and versioned mappings:
https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html

Third-party ExternalId context:
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html

## Evidence-aware execution

`evaluate()` combines provider failures, rule scope and per-rule evidence
checks. `RuleResult.collection_issues` preserves errors even when enumeration
returned no entities. A scoped failed API blocks dependent rules for that
identity; unrelated rules and identities can continue.

Each rule/entity pair has a status:

- `finding`: evidence produced one or more findings.
- `clear`: this supported check found no issue in the available evidence.
- `partial`: known evidence produced findings but other required activity
  values were unknown. It is not a complete assessment.
- `skipped`: missing, conflicting or unusable evidence prevents a result.
- `not_applicable`: the provider or identity type is outside rule scope.

Root MFA and password activity require a timezone-aware credential-report
snapshot no older than four hours and not in the future. The clock is
injectable for deterministic tests. Direct `rule.check(entity)` calls do not
have collection-level failure or freshness information; use `evaluate()`
for provider results.

M4 adds `console_password_enabled` to the entity model and populates it from
the credential report. This prevents treating absent root console credentials
as an unprotected root login. M3 still cannot identify root hardware device
type; enabled-MFA accounts with unknown type therefore remain skipped.

Findings have evidence and project-defined scores; these are not CVSS scores
and do not claim an exploitable attack path. Report output remains M6 work.

## Extensions and configuration

Subclass `Rule`, declare a unique `rule_id`, provider and entity_types, and
implement `check(entity) -> list[Finding]`. Optional `skip_reason()`,
`required_operations()` and `requires_credential_report()` hooks declare
evidence dependencies. Supply instances with `evaluate(collection, rules=[...])`;
the engine needs no changes. `default_rules()` returns fresh instances, and
`ALL_RULES` exposes the initial registry.

Configure `InactiveCredentials(days=90, now=...)` for an explicit threshold
and clock. Configure `CrossAccountNoExternalId(trusted_accounts=frozenset({...}))`
to exclude reviewed internal account relationships. Exact mandatory
StringEquals or non-wildcard StringLike ExternalIds are recognised;
IfExists, Null and wildcard patterns are not sufficient guards for this check.

Required tests include positive and negative cases, multiple credentials,
statement shapes, Deny/service/same-account exclusions, missing evidence,
report freshness and scoped collection failures. CI now requires at least
80% total coverage. No real cloud account is used in the tests.
