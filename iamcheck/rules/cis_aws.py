"""Five focused AWS checks, with explicitly versioned partial CIS mappings."""

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase

from pydantic import JsonValue

from iamcheck.models import EntityType, Finding, IAMEntity, PolicyDocument, Severity
from iamcheck.rules.base import Rule

POLICY_OPERATIONS = frozenset(
    {
        "list_attached_user_policies",
        "list_attached_group_policies",
        "list_attached_role_policies",
        "get_policy",
        "get_policy_version",
        "list_user_policies",
        "list_group_policies",
        "list_role_policies",
        "get_user_policy",
        "get_group_policy",
        "get_role_policy",
    }
)


def statements(document: PolicyDocument) -> Iterator[tuple[int, PolicyDocument]]:
    value = document.get("Statement", [])
    if isinstance(value, dict):
        yield 0, value
    elif isinstance(value, list):
        for index, statement in enumerate(value):
            if isinstance(statement, dict):
                yield index, statement


def strings(value: JsonValue) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def finding(
    entity: IAMEntity,
    rule_id: str,
    title: str,
    severity: Severity,
    score: float,
    detail: str,
    remediation: str,
    evidence: dict[str, JsonValue],
    cis_reference: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        score=score,
        entity_id=entity.id,
        entity_name=entity.name,
        entity_type=entity.entity_type,
        provider=entity.provider,
        detail=detail,
        remediation=remediation,
        evidence=evidence,
        cis_reference=cis_reference,
    )


class AdminPolicyAttached(Rule):
    rule_id = "CIS-AWS-1.16"
    entity_types = frozenset({EntityType.USER})
    operations = frozenset({"list_attached_user_policies"})

    def check(self, entity: IAMEntity) -> list[Finding]:
        if not self.supports(entity):
            return []
        findings = []
        for arn in entity.attached_policies:
            if not re.fullmatch(
                r"arn:[^:]+:iam::aws:policy/(AdministratorAccess|PowerUserAccess)",
                arn,
            ):
                continue
            admin = arn.endswith("/AdministratorAccess")
            findings.append(
                finding(
                    entity,
                    self.rule_id,
                    "Broad AWS managed policy attached directly to user",
                    Severity.CRITICAL if admin else Severity.HIGH,
                    10.0 if admin else 8.0,
                    f"The user has {arn.rsplit('/', 1)[-1]} attached directly. "
                    "This is a configuration risk, not proof of effective access.",
                    "Review required permissions; prefer federation and scoped roles "
                    "or "
                    "groups. Test workload access before detaching the policy.",
                    {"policy_id": arn},
                    "CIS AWS Foundations Benchmark v1.2.0 / 1.16 (partial check)",
                )
            )
        return findings


class WildcardAction(Rule):
    rule_id = "CUSTOM-001"
    entity_types = frozenset({EntityType.USER, EntityType.ROLE, EntityType.GROUP})
    operations = POLICY_OPERATIONS

    def skip_reason(self, entity: IAMEntity) -> str | None:
        if entity.attached_policy_documents is None:
            return "Managed policy documents were not fully collected"
        return None

    def check(self, entity: IAMEntity) -> list[Finding]:
        if not self.supports(entity) or self.skip_reason(entity):
            return []
        documents = list((entity.attached_policy_documents or {}).items())
        documents.extend(
            (f"inline:{i}", d) for i, d in enumerate(entity.inline_policies)
        )
        findings = []
        for policy_id, document in documents:
            for index, statement in statements(document):
                if statement.get("Effect") != "Allow" or "*" not in strings(
                    statement.get("Action"),
                ):
                    continue
                findings.append(
                    finding(
                        entity,
                        self.rule_id,
                        "Wildcard action in Allow statement",
                        Severity.HIGH,
                        8.0,
                        "An identity policy allows Action '*'. Resource and condition "
                        "constraints are retained in the evidence; effective access "
                        "and overriding denies are not evaluated.",
                        "Replace the wildcard with required actions and review "
                        "resources "
                        "and conditions. Preserve necessary workload access.",
                        {
                            "policy_id": policy_id,
                            "statement_index": index,
                            "statement": statement,
                        },
                    )
                )
        return findings


class InactiveCredentials(Rule):
    rule_id = "CIS-AWS-1.3"
    entity_types = frozenset({EntityType.USER, EntityType.ROLE})
    operations = frozenset(
        {
            "list_access_keys",
            "get_access_key_last_used",
            "get_role",
            "get_credential_report",
        }
    )

    def __init__(self, *, now: datetime | None = None, days: int = 90) -> None:
        if days < 1:
            raise ValueError("days must be positive")
        if now is not None and now.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        self.now = now
        self.days = days

    def required_operations(self, entity: IAMEntity) -> frozenset[str]:
        if entity.entity_type is EntityType.ROLE:
            return frozenset({"get_role"})
        return self.operations

    def requires_credential_report(self, entity: IAMEntity) -> bool:
        return entity.entity_type is EntityType.USER and "password" in (
            entity.credential_last_used
        )

    def skip_reason(self, entity: IAMEntity) -> str | None:
        times = (
            list(entity.credential_last_used.values())
            if entity.entity_type is EntityType.USER
            else [entity.last_used]
        )
        if not times or any(t is None or t.utcoffset() is None for t in times):
            return "Activity is missing or has no timezone; inactivity is unknown"
        now = self.now or datetime.now(UTC)
        if any(t is not None and t > now for t in times):
            return "Activity timestamp is in the future"
        return None

    def check(self, entity: IAMEntity) -> list[Finding]:
        if not self.supports(entity):
            return []
        now = self.now or datetime.now(UTC)
        activity = (
            entity.credential_last_used
            if entity.entity_type is EntityType.USER
            else {"role": entity.last_used}
        )
        findings = []
        for credential, used in activity.items():
            if used is None or used.utcoffset() is None or used > now:
                continue
            if now - used < timedelta(days=self.days):
                continue
            role = entity.entity_type is EntityType.ROLE
            findings.append(
                finding(
                    entity,
                    self.rule_id,
                    "Inactive role" if role else "Inactive credential",
                    Severity.MEDIUM,
                    5.0,
                    f"Observed {credential} activity is at least {self.days} days old. "
                    "This is based on collected activity, not a complete "
                    "usage history.",
                    "Confirm ownership and usage before disabling a credential or "
                    "removing a role. Unknown and never-used dates require "
                    "separate review.",
                    {
                        "credential_id": credential,
                        "last_used": used.isoformat(),
                        "evaluated_at": now.isoformat(),
                        "threshold_days": self.days,
                    },
                    None
                    if role or self.days != 90
                    else "CIS AWS Foundations Benchmark v1.2.0 / 1.3 (partial check)",
                )
            )
        return findings


class MissingMFA(Rule):
    rule_id = "CIS-AWS-1.14"
    entity_types = frozenset({EntityType.ROOT_ACCOUNT})
    operations = frozenset({"get_credential_report"})

    def requires_credential_report(self, entity: IAMEntity) -> bool:
        return True

    def skip_reason(self, entity: IAMEntity) -> str | None:
        if entity.console_password_enabled is not True:
            return "Root console credentials are absent or unknown"
        if entity.mfa_enabled is False and entity.hardware_mfa_enabled is True:
            return "Conflicting root MFA evidence"
        if entity.mfa_enabled is not False and entity.hardware_mfa_enabled is None:
            return "Hardware MFA type is unknown"
        return None

    def check(self, entity: IAMEntity) -> list[Finding]:
        if not self.supports(entity) or self.skip_reason(entity):
            return []
        if entity.hardware_mfa_enabled is True:
            return []
        missing = entity.mfa_enabled is False
        return [
            finding(
                entity,
                self.rule_id,
                "Root MFA is disabled"
                if missing
                else "Root hardware MFA is not enabled",
                Severity.CRITICAL if missing else Severity.HIGH,
                10.0 if missing else 8.0,
                "Root console credentials are present and the collected evidence "
                "does not meet the hardware MFA requirement.",
                "Review root credential management and register an appropriate "
                "hardware "
                "MFA device. Confirm recovery access before changing authentication.",
                {
                    "mfa_enabled": entity.mfa_enabled,
                    "hardware_mfa_enabled": entity.hardware_mfa_enabled,
                },
                "CIS AWS Foundations Benchmark v1.2.0 / 1.14",
            )
        ]


class CrossAccountNoExternalId(Rule):
    rule_id = "CUSTOM-002"
    entity_types = frozenset({EntityType.ROLE})
    operations = frozenset({"get_role"})

    def __init__(self, *, trusted_accounts: frozenset[str] = frozenset()) -> None:
        if any(not re.fullmatch(r"\d{12}", a) for a in trusted_accounts):
            raise ValueError("trusted_accounts must contain 12-digit account IDs")
        self.trusted_accounts = trusted_accounts

    def skip_reason(self, entity: IAMEntity) -> str | None:
        if entity.trust_policy is None:
            return "Role trust policy was not collected"
        if not re.fullmatch(r"arn:[^:]+:iam::\d{12}:role/.+", entity.id):
            return "Role account cannot be determined from its ARN"
        return None

    @staticmethod
    def _external_id(statement: PolicyDocument) -> bool:
        condition = statement.get("Condition")
        if not isinstance(condition, dict):
            return False
        for operator in ("StringEquals", "StringLike"):
            values = condition.get(operator)
            if isinstance(values, dict):
                for key, value in values.items():
                    if key.lower() != "sts:externalid":
                        continue
                    ids = strings(value)
                    if ids and all(v and "*" not in v and "?" not in v for v in ids):
                        return True
        return False

    def check(self, entity: IAMEntity) -> list[Finding]:
        if not self.supports(entity) or self.skip_reason(entity):
            return []
        account = entity.id.split(":")[4]
        findings = []
        for index, statement in statements(entity.trust_policy or {}):
            if statement.get("Effect") != "Allow" or not any(
                fnmatchcase("sts:assumerole", a.lower())
                for a in strings(statement.get("Action"))
            ):
                continue
            principal = statement.get("Principal")
            aws = principal.get("AWS") if isinstance(principal, dict) else principal
            external: list[JsonValue] = []
            for value in strings(aws):
                match = re.fullmatch(r"(?:arn:[^:]+:iam::)?(\d{12})(?::.+)?", value)
                if value == "*" or (
                    match
                    and match[1] != account
                    and match[1] not in self.trusted_accounts
                ):
                    external.append(value)
            if not external or self._external_id(statement):
                continue
            findings.append(
                finding(
                    entity,
                    self.rule_id,
                    "External trust without a restrictive ExternalId",
                    Severity.HIGH,
                    8.0,
                    "The trust statement permits an external AWS principal without "
                    "a mandatory, non-wildcard ExternalId. Review whether this is "
                    "third-party access; ExternalId is not required for every "
                    "cross-account use.",
                    "For third-party delegated access, agree a unique ExternalId and "
                    "require it with StringEquals. Review other trust conditions and "
                    "explicitly configure approved internal accounts "
                    "where appropriate.",
                    {
                        "statement_index": index,
                        "external_principals": external,
                        "statement": statement,
                    },
                )
            )
        return findings
