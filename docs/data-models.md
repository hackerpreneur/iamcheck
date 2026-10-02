# Data contracts (M2)

Providers return `IAMEntity` dataclasses. Rules produce Pydantic `Finding`
objects; reporters can call `model_dump(mode="json")` or `model_dump_json()`.

## Provider data

`IAMEntity` requires an `id`, `name`, `entity_type`, and `provider`. Use
`Provider.AWS` or `Provider.GCP` and an `EntityType`: user, role, group,
service account, or root account. Root account supports future AWS root MFA
checks without pretending root is an ordinary IAM user.

The original M2 fields are retained: attached policy IDs, inline policy
documents, last activity, and tags. Additional evidence fields support the
planned policy and credential checks:

- `attached_policy_documents`: resolved documents keyed by policy ID.
- `trust_policy`: the role's trust document, if available.
- `mfa_enabled` and `hardware_mfa_enabled`: observed MFA state.
- `credential_last_used`: activity per credential ID, separate from overall
  identity activity. Store identifiers and timestamps, never secret keys.

Providers must supply timezone-aware timestamps. `last_used=None` means
activity is unknown; it does not establish that a credential was never used.
Unknown MFA is `None`, distinct from an observed `False`.
`attached_policy_documents=None` means documents have not been collected;
`{}` means collection completed with no documents. Providers must surface
partial collection failures separately in a later scan result rather than
treating missing evidence as a clean check.

Each instance gets independent default collections. This dataclass is an
internal, statically typed contract, not a runtime validator. Raw policy
documents retain cloud-specific semantics; future rules must explicitly
select the providers and identity kinds they support. Resource-scoped GCP
bindings and richer scan coverage are later provider-design work.

## Findings

Required fields are `rule_id`, `title`, `severity`, `entity_id`, `entity_name`,
`entity_type`, `provider`, `detail`, `remediation`, and `score`. Stable entity
IDs distinguish identities with the same display name. Required text must
contain non-whitespace characters; multiline remediation is preserved.

Severity values are `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFO`. Enum
values can be read from JSON and are serialised as strings. Enum declaration
order is not a severity comparison operation.

`score` accepts finite numbers from 0 through 10. Strings, booleans, NaN,
and infinity are rejected. This is a project-defined risk score; no formal
CVSS methodology is implemented in M2.

`cis_reference` defaults to `None` for custom rules; supplied references must
be nonblank and should identify a verified benchmark version and control.
`evidence` is an optional dictionary of JSON-compatible supporting data,
such as a policy identifier, statement index, and offending statement.

Unknown fields are rejected to catch spelling mistakes. Field assignments
are validated too; nested mutable collections should be replaced through
validated assignment if their contents change.

Run the M2 checks with:

```sh
uv sync --extra dev
uv run ruff check .
uv run ruff format --check .
uv run mypy iamcheck/
uv run pytest --cov=iamcheck --cov-report=term-missing
```
