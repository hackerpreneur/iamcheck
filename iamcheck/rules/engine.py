"""Rule execution with evidence gaps carried into evaluation outcomes."""

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal

from iamcheck.models import Finding
from iamcheck.providers.base import CollectionIssue, CollectionResult
from iamcheck.rules.base import Rule
from iamcheck.rules.cis_aws import (
    AdminPolicyAttached,
    CrossAccountNoExternalId,
    InactiveCredentials,
    MissingMFA,
    WildcardAction,
)


def default_rules(*, now: datetime | None = None) -> list[Rule]:
    """Construct fresh rule instances; inactivity clocks are evaluated at run time."""
    return [
        AdminPolicyAttached(),
        WildcardAction(),
        InactiveCredentials(now=now),
        MissingMFA(),
        CrossAccountNoExternalId(),
    ]


ALL_RULES = default_rules()


@dataclass(frozen=True)
class Evaluation:
    rule_id: str
    entity_id: str
    status: Literal["clear", "finding", "skipped", "partial", "not_applicable"]
    reason: str | None = None


@dataclass
class RuleResult:
    findings: list[Finding] = field(default_factory=list)
    evaluations: list[Evaluation] = field(default_factory=list)
    collection_issues: list[CollectionIssue] = field(default_factory=list)


def evaluate(
    collection: CollectionResult,
    *,
    rules: Iterable[Rule] | None = None,
    now: datetime | None = None,
) -> RuleResult:
    """Evaluate supported checks and never label missing collection as clear.

    The credential-report freshness limit is four hours. Direct rule.check()
    calls cannot apply collection-level permission/freshness guards.
    """
    clock = now or datetime.now(UTC)
    if clock.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    active = default_rules(now=clock) if rules is None else list(rules)
    if len({r.rule_id for r in active}) != len(active):
        raise ValueError("Rule IDs must be unique")
    result = RuleResult(collection_issues=list(collection.issues))
    for entity in collection.entities:
        for rule in active:
            if not rule.supports(entity):
                result.evaluations.append(
                    Evaluation(
                        rule.rule_id,
                        entity.id,
                        "not_applicable",
                    )
                )
                continue
            failures = [
                i
                for i in collection.issues
                if (
                    i.operation in rule.required_operations(entity)
                    and i.entity_id in {None, entity.id}
                )
            ]
            if failures:
                result.evaluations.append(
                    Evaluation(
                        rule.rule_id,
                        entity.id,
                        "skipped",
                        "Required API collection failed",
                    )
                )
                continue
            if rule.requires_credential_report(entity):
                timestamp = collection.credential_report_generated_at
                if (
                    timestamp is None
                    or timestamp.utcoffset() is None
                    or timestamp > clock
                    or clock - timestamp > timedelta(hours=4)
                ):
                    result.evaluations.append(
                        Evaluation(
                            rule.rule_id,
                            entity.id,
                            "skipped",
                            "Credential report is missing, stale, future-dated "
                            "or timezone-naive",
                        )
                    )
                    continue
            reason = rule.skip_reason(entity)
            found = rule.check(entity)
            result.findings.extend(found)
            status: Literal["clear", "finding", "skipped", "partial", "not_applicable"]
            status = (
                ("partial" if found else "skipped")
                if reason
                else ("finding" if found else "clear")
            )
            result.evaluations.append(
                Evaluation(rule.rule_id, entity.id, status, reason)
            )
    return result
