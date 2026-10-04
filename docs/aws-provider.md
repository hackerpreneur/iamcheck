# AWS evidence collection (M3)

The provider collects data; it does not yet run rules or produce a report.
Use the Python API until the CLI is implemented in M5:

```python
from iamcheck.providers.aws import AWSProvider

result = AWSProvider(profile="prod").collect()
print(f"Collected {len(result.entities)} identities")
for issue in result.issues:
    print(issue.operation, issue.code, issue.entity_id)
```

Omit `profile` to let boto3 use its normal credential chain, including
environment credentials, configured profiles and role credentials. An
existing `boto3.Session` can instead be injected with `session=`. Do not
pass both. No credentials are accepted as tool-specific arguments.

## Collected evidence

- Users, groups and roles, using boto3 paginators for list operations.
- Stable ARNs, names and user/role tags.
- Direct attached policy ARNs and default-version policy documents.
- Inline policy documents for all three identity kinds.
- Role trust policies and the role's reported last-used timestamp.
- User MFA presence and last-used evidence for active access keys.
- Password activity from an existing IAM credential report, if available.
- A root-account identity from STS, with MFA evidence from that report.

`CollectionResult.credential_report_generated_at` preserves the report's
snapshot time. The provider reads a report but does not generate one. An
operator can generate it separately if desired; a missing, expired or
inaccessible report is retained as a collection issue.

## Required read operations

The provider attempts these operations in the caller's account:

```text
sts:GetCallerIdentity
iam:GetCredentialReport
iam:ListUsers / iam:GetUser
iam:ListGroups / iam:GetGroup
iam:ListRoles / iam:GetRole
iam:ListAttachedUserPolicies / iam:ListUserPolicies / iam:GetUserPolicy
iam:ListAttachedGroupPolicies / iam:ListGroupPolicies / iam:GetGroupPolicy
iam:ListAttachedRolePolicies / iam:ListRolePolicies / iam:GetRolePolicy
iam:GetPolicy / iam:GetPolicyVersion
iam:ListMFADevices
iam:ListAccessKeys / iam:GetAccessKeyLastUsed
```

Use your organisation's reviewed read-only auditor role with the necessary
scope. No create, update, delete or credential-report generation operation
is called. The standard botocore retry policy is configured for transient
API failures. Terminal/authentication behaviour belongs to the later CLI.

## Interpreting failures and missing data

Each failed operation creates a `CollectionIssue` containing the operation,
error code and affected entity ARN where applicable. A warning is logged
without dumping AWS credentials or full service error responses. Collection
continues after API permission, throttling or connection failures; identities
already obtained from earlier pages remain available. Missing/expired
credentials raise `ProviderAuthenticationError` instead of returning a
misleading empty result. Repeated calls produce independent results.

`complete` means all attempted operations succeeded. It does not mean every
AWS permission source has been evaluated. Consumers must inspect scoped
issues before using evidence in a rule:

- Failed managed-policy resolution leaves `attached_policy_documents=None`.
- A successful empty policy list produces `{}`.
- Unknown activity stays `None`; it does not prove inactivity or never-use.
- Failed MFA enumeration leaves user MFA unknown rather than false.
- Inline-policy collections and access-key evidence can be partial; consult
  issues rather than treating the remaining values as exhaustive.

## Limits

This is identity evidence, not an effective-permission evaluator. User group
membership/inheritance, resource policies, permissions boundaries, SCPs,
Identity Center, federation inventories and cross-account enumeration are
not resolved in M3. Hardware MFA status remains unknown because presence of
MFA or a credential-report boolean does not establish device type.

Inactive access keys are excluded from the current activity map. `last_used`
is the latest observed active-key/password activity for users, not a complete
audit of every possible session. Role activity is AWS's reported evidence;
missing values and the service's tracking window need care in M4 rules.
Groups have no activity/MFA semantics. The root identity's password evidence
does not describe root access-key activity. No secret access keys are stored
in returned entities.

Tests use moto and botocore Stubber with fake credentials. They exercise
policies, tags, trust, MFA, activity, multiple pages, partial failure and
authentication without contacting a real AWS account.
