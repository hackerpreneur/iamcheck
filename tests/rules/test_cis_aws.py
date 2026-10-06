"""Positive, negative and evidence-gap cases for all five initial checks."""

from datetime import UTC, datetime, timedelta

import pytest

from iamcheck.models import EntityType, IAMEntity, Provider, Severity
from iamcheck.providers.base import CollectionIssue, CollectionResult
from iamcheck.rules.base import Rule
from iamcheck.rules.cis_aws import (
    AdminPolicyAttached,
    CrossAccountNoExternalId,
    InactiveCredentials,
    MissingMFA,
    WildcardAction,
)
from iamcheck.rules.engine import default_rules, evaluate

NOW = datetime(2026, 10, 6, tzinfo=UTC)


def test_role_activity_survives_unrelated_report_failure() -> None:
    role = entity(EntityType.ROLE)
    role.last_used = NOW - timedelta(days=100)
    result = evaluate(
        CollectionResult(
            entities=[role],
            issues=[CollectionIssue("get_credential_report", "AccessDenied")],
        ),
        rules=[InactiveCredentials(now=NOW)],
        now=NOW,
    )
    assert result.evaluations[0].status == "finding"


def test_trust_action_patterns_and_condition_key_case() -> None:
    role = entity(EntityType.ROLE)
    role.trust_policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:Assume*",
                "Principal": {"AWS": "999999999999"},
            }
        ]
    }
    rule = CrossAccountNoExternalId()
    assert len(rule.check(role)) == 1
    role.trust_policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:Assume*",
                "Principal": {"AWS": "999999999999"},
                "Condition": {"StringEquals": {"STS:ExternalID": "customer-123"}},
            }
        ]
    }
    assert rule.check(role) == []


def entity(kind: EntityType = EntityType.USER) -> IAMEntity:
    return IAMEntity(
        f"arn:aws:iam::123456789012:{kind.value}/example",
        "example",
        kind,
        Provider.AWS,
        attached_policy_documents={},
    )


@pytest.mark.parametrize(
    "policy,severity",
    [
        ("AdministratorAccess", Severity.CRITICAL),
        ("PowerUserAccess", Severity.HIGH),
    ],
)
def test_direct_broad_policy(policy: str, severity: Severity) -> None:
    user = entity()
    user.attached_policies = [f"arn:aws:iam::aws:policy/{policy}"]
    findings = AdminPolicyAttached().check(user)
    assert len(findings) == 1
    assert findings[0].severity is severity
    assert findings[0].entity_id == user.id
    assert findings[0].cis_reference.endswith("(partial check)")


@pytest.mark.parametrize(
    "arn",
    [
        "arn:aws:iam::123456789012:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/ReadOnlyAccess",
        "arn:aws:iam::aws:policy/path/AdministratorAccess",
        "AdministratorAccess",
    ],
)
def test_admin_rule_does_not_match_custom_or_readonly_policies(arn: str) -> None:
    user = entity()
    user.attached_policies = [arn]
    assert AdminPolicyAttached().check(user) == []


@pytest.mark.parametrize(
    "effect,action,expected",
    [
        ("Allow", "*", 1),
        ("Allow", ["s3:GetObject", "*"], 1),
        ("Deny", "*", 0),
        ("Allow", "s3:*", 0),
        ("Allow", "s3:GetObject", 0),
        ("Allow", None, 0),
    ],
)
def test_wildcard_statement_shapes(effect: str, action: object, expected: int) -> None:
    user = entity()
    statement = {
        "Effect": effect,
        "Action": action,
        "Resource": "arn:aws:s3:::bucket/*",
    }
    user.inline_policies = [{"Statement": statement}]
    findings = WildcardAction().check(user)
    assert len(findings) == expected
    if findings:
        assert findings[0].evidence["statement"] == statement
        assert findings[0].cis_reference is None


def test_wildcard_checks_resolved_managed_and_inline_documents() -> None:
    user = entity()
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Condition": {
                    "StringEquals": {"aws:RequestedRegion": "eu-west-1"},
                },
            }
        ]
    }
    user.attached_policy_documents = {"managed": doc}
    user.inline_policies = [doc]
    findings = WildcardAction().check(user)
    assert [f.evidence["policy_id"] for f in findings] == ["managed", "inline:0"]
    assert "Condition" in findings[0].evidence["statement"]


@pytest.mark.parametrize("age,expected", [(89, 0), (90, 1), (91, 1)])
def test_inactivity_boundary(age: int, expected: int) -> None:
    user = entity()
    user.credential_last_used = {"key": NOW - timedelta(days=age)}
    assert len(InactiveCredentials(now=NOW).check(user)) == expected


def test_recent_key_does_not_hide_old_password_or_another_key() -> None:
    user = entity()
    user.credential_last_used = {
        "new": NOW,
        "old": NOW - timedelta(days=100),
        "unknown": None,
    }
    collection = CollectionResult(entities=[user])
    result = evaluate(collection, now=NOW, rules=[InactiveCredentials(now=NOW)])
    assert [f.evidence["credential_id"] for f in result.findings] == ["old"]
    assert result.evaluations[0].status == "partial"


@pytest.mark.parametrize("used", [None, datetime(2020, 1, 1), NOW + timedelta(days=1)])
def test_unknown_naive_or_future_activity_is_not_inactive(
    used: datetime | None,
) -> None:
    user = entity()
    user.credential_last_used = {"key": used}
    rule = InactiveCredentials(now=NOW)
    assert rule.check(user) == []
    assert rule.skip_reason(user)


def test_old_role_has_no_cis_mapping() -> None:
    role = entity(EntityType.ROLE)
    role.last_used = NOW - timedelta(days=100)
    assert InactiveCredentials(now=NOW).check(role)[0].cis_reference is None


@pytest.mark.parametrize(
    "enabled,hardware,expected",
    [
        (False, None, 1),
        (True, False, 1),
        (True, True, 0),
        (True, None, 0),
        (None, None, 0),
        (False, True, 0),
    ],
)
def test_root_mfa_requires_known_evidence(
    enabled: bool | None,
    hardware: bool | None,
    expected: int,
) -> None:
    root = entity(EntityType.ROOT_ACCOUNT)
    root.console_password_enabled = True
    root.mfa_enabled = enabled
    root.hardware_mfa_enabled = hardware
    assert len(MissingMFA().check(root)) == expected


@pytest.mark.parametrize("enabled", [False, None])
def test_root_without_known_console_credentials_is_not_flagged(
    enabled: bool | None,
) -> None:
    root = entity(EntityType.ROOT_ACCOUNT)
    root.console_password_enabled = enabled
    root.mfa_enabled = False
    assert MissingMFA().check(root) == []


def trust(
    principal: object, condition: object = None, effect: str = "Allow"
) -> IAMEntity:
    role = entity(EntityType.ROLE)
    statement = {"Effect": effect, "Action": "sts:AssumeRole", "Principal": principal}
    if condition is not None:
        statement["Condition"] = condition
    role.trust_policy = {"Statement": [statement]}
    return role


@pytest.mark.parametrize(
    "principal,expected",
    [
        ({"AWS": "arn:aws:iam::999999999999:root"}, 1),
        ({"AWS": "999999999999"}, 1),
        ("*", 1),
        ({"AWS": "arn:aws:iam::123456789012:root"}, 0),
        ({"Service": "ec2.amazonaws.com"}, 0),
        ({"Federated": "arn:aws:iam::123456789012:saml-provider/idp"}, 0),
    ],
)
def test_external_principal_scope(principal: object, expected: int) -> None:
    assert len(CrossAccountNoExternalId().check(trust(principal))) == expected


@pytest.mark.parametrize(
    "operator,value,expected",
    [
        ("StringEquals", "customer-123", 0),
        ("StringLike", "customer-123", 0),
        ("StringEquals", ["customer-123", "customer-456"], 0),
        ("StringEqualsIfExists", "customer-123", 1),
        ("StringLike", "*", 1),
        ("StringLike", "customer-*", 1),
        ("StringEquals", "", 1),
        ("Null", "false", 1),
    ],
)
def test_external_id_must_be_mandatory_and_restrictive(
    operator: str,
    value: object,
    expected: int,
) -> None:
    role = trust({"AWS": "999999999999"}, {operator: {"sts:ExternalId": value}})
    assert len(CrossAccountNoExternalId().check(role)) == expected


def test_external_trust_allowlist_and_deny() -> None:
    rule = CrossAccountNoExternalId(trusted_accounts=frozenset({"999999999999"}))
    assert rule.check(trust({"AWS": "999999999999"})) == []
    assert (
        CrossAccountNoExternalId().check(trust({"AWS": "999999999999"}, effect="Deny"))
        == []
    )


@pytest.mark.parametrize("rule", default_rules(now=NOW))
def test_all_rules_ignore_gcp_and_nonapplicable_kinds(rule: Rule) -> None:
    account = entity(EntityType.SERVICE_ACCOUNT)
    account.provider = Provider.GCP
    assert rule.check(account) == []


def test_engine_blocks_scoped_api_failures_without_hiding_other_users() -> None:
    first, second = entity(), entity()
    second.id += "-other"
    arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    first.attached_policies = second.attached_policies = [arn]
    collection = CollectionResult(
        entities=[first, second],
        issues=[
            CollectionIssue("list_attached_user_policies", "AccessDenied", first.id),
        ],
    )
    result = evaluate(collection, rules=[AdminPolicyAttached()], now=NOW)
    assert [e.status for e in result.evaluations] == ["skipped", "finding"]
    assert result.findings[0].entity_id == second.id
    assert result.collection_issues == collection.issues


@pytest.mark.parametrize("age", [None, timedelta(hours=5), timedelta(hours=-1)])
def test_report_freshness_guards_root_and_password_checks(
    age: timedelta | None,
) -> None:
    root = entity(EntityType.ROOT_ACCOUNT)
    root.console_password_enabled = True
    root.mfa_enabled = False
    user = entity()
    user.credential_last_used = {"password": NOW - timedelta(days=100)}
    collection = CollectionResult(
        entities=[root, user],
        credential_report_generated_at=NOW - age if age is not None else None,
    )
    result = evaluate(
        collection, rules=[MissingMFA(), InactiveCredentials(now=NOW)], now=NOW
    )
    assert result.findings == []
    assert any(e.status == "skipped" for e in result.evaluations)


def test_fresh_root_evidence_produces_critical_finding() -> None:
    root = entity(EntityType.ROOT_ACCOUNT)
    root.console_password_enabled = True
    root.mfa_enabled = False
    result = evaluate(
        CollectionResult(entities=[root], credential_report_generated_at=NOW),
        rules=[MissingMFA()],
        now=NOW,
    )
    assert result.findings[0].severity is Severity.CRITICAL


def test_unknown_documents_are_skipped_and_explicit_empty_is_clear() -> None:
    user = entity()
    user.attached_policy_documents = None
    result = evaluate(
        CollectionResult(entities=[user]), rules=[WildcardAction()], now=NOW
    )
    assert result.evaluations[0].status == "skipped"
    user.attached_policy_documents = {}
    assert (
        evaluate(CollectionResult(entities=[user]), rules=[WildcardAction()], now=NOW)
        .evaluations[0]
        .status
        == "clear"
    )


def test_custom_rule_registry_requires_no_engine_changes() -> None:
    class OrganisationRule(Rule):
        rule_id = "ORG-001"
        entity_types = frozenset({EntityType.USER})

        def check(self, entity: IAMEntity):
            return []

    result = evaluate(CollectionResult(entities=[entity()]), rules=[OrganisationRule()])
    assert result.evaluations[0].rule_id == "ORG-001"
    assert result.evaluations[0].status == "clear"
    with pytest.raises(ValueError):
        evaluate(CollectionResult(), rules=[OrganisationRule(), OrganisationRule()])


@pytest.mark.parametrize(
    "constructor",
    [
        lambda: InactiveCredentials(days=0),
        lambda: InactiveCredentials(now=datetime(2020, 1, 1)),
        lambda: CrossAccountNoExternalId(trusted_accounts=frozenset({"invalid"})),
        lambda: evaluate(CollectionResult(), now=datetime(2020, 1, 1)),
    ],
)
def test_invalid_rule_configuration_is_rejected(constructor) -> None:
    with pytest.raises(ValueError):
        constructor()
