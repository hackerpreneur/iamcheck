"""Validation and serialisation tests for the pipeline's data contracts."""

import json
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from iamcheck.models import EntityType, Finding, IAMEntity, Provider, Severity


def finding_data() -> dict[str, Any]:
    """A custom AWS finding, intentionally without a CIS mapping."""
    return {
        "rule_id": "CUSTOM-001",
        "title": "Wildcard action",
        "severity": Severity.HIGH,
        "entity_id": "arn:aws:iam::123456789012:role/worker",
        "entity_name": "worker",
        "entity_type": EntityType.ROLE,
        "provider": Provider.AWS,
        "detail": "Statement 0 allows all actions on all resources.",
        "remediation": "Replace wildcard actions with the required actions.",
        "score": 8.0,
    }


def test_entity_minimal_defaults_preserve_unknown_evidence() -> None:
    entity = IAMEntity("role-id", "worker", EntityType.ROLE, Provider.AWS)

    assert is_dataclass(entity)
    assert entity.attached_policies == []
    assert entity.inline_policies == []
    assert entity.tags == {}
    assert entity.credential_last_used == {}
    assert entity.last_used is None
    assert entity.attached_policy_documents is None
    assert entity.trust_policy is None
    assert entity.mfa_enabled is None
    assert entity.hardware_mfa_enabled is None


def test_entity_collection_defaults_are_independent() -> None:
    first = IAMEntity("first", "first", EntityType.USER, Provider.AWS)
    second = IAMEntity("second", "second", EntityType.USER, Provider.AWS)
    first.attached_policies.append("policy-id")
    first.inline_policies.append({"Statement": []})
    first.tags["owner"] = "team-a"
    first.credential_last_used["key-id"] = datetime(2026, 1, 1, tzinfo=UTC)

    assert second.attached_policies == []
    assert second.inline_policies == []
    assert second.tags == {}
    assert second.credential_last_used == {}


def test_entity_retains_policy_and_credential_evidence() -> None:
    last_used = datetime(2026, 1, 1, tzinfo=UTC)
    entity = IAMEntity(
        id="arn:aws:iam::123456789012:role/worker",
        name="worker",
        entity_type=EntityType.ROLE,
        provider=Provider.AWS,
        attached_policies=["policy-id"],
        attached_policy_documents={
            "policy-id": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            }
        },
        inline_policies=[{"Statement": []}],
        trust_policy={"Statement": [{"Principal": {"AWS": "123456789012"}}]},
        last_used=last_used,
        credential_last_used={"key-id": last_used, "unknown-key": None},
        tags={"owner": "team-a"},
    )

    data = asdict(entity)
    assert data["attached_policies"] == ["policy-id"]
    assert (
        data["attached_policy_documents"]["policy-id"]["Statement"][0]["Action"] == "*"
    )
    assert data["trust_policy"]["Statement"][0]["Principal"]["AWS"] == "123456789012"
    assert data["last_used"] == last_used
    assert data["credential_last_used"] == {"key-id": last_used, "unknown-key": None}
    assert data["tags"] == {"owner": "team-a"}


def test_entity_distinguishes_collected_empty_and_disabled_from_unknown() -> None:
    entity = IAMEntity(
        "root-id",
        "root",
        EntityType.ROOT_ACCOUNT,
        Provider.AWS,
        attached_policy_documents={},
        mfa_enabled=False,
        hardware_mfa_enabled=False,
    )
    assert entity.attached_policy_documents == {}
    assert entity.mfa_enabled is False
    assert entity.hardware_mfa_enabled is False


def test_entity_supports_gcp_service_accounts() -> None:
    entity = IAMEntity(
        "worker@project.iam.gserviceaccount.com",
        "worker",
        EntityType.SERVICE_ACCOUNT,
        Provider.GCP,
        attached_policies=["roles/viewer"],
    )
    assert entity.provider is Provider.GCP
    assert entity.entity_type is EntityType.SERVICE_ACCOUNT
    assert entity.attached_policies == ["roles/viewer"]


@pytest.mark.parametrize("severity", list(Severity))
def test_finding_json_round_trip_preserves_enums_and_evidence(
    severity: Severity,
) -> None:
    data = finding_data()
    data["severity"] = severity
    data["evidence"] = {
        "policy_id": "policy-id",
        "statement_index": 0,
        "statement": {"Effect": "Allow", "Action": ["*"], "Resource": "*"},
        "verified": True,
        "context": None,
    }
    finding = Finding(**data)

    payload = json.loads(finding.model_dump_json())
    assert payload["severity"] == severity.value
    assert payload["provider"] == "aws"
    assert payload["entity_type"] == "role"
    assert payload["entity_id"] == data["entity_id"]
    assert payload["evidence"] == data["evidence"]
    assert payload["cis_reference"] is None
    assert finding.model_dump(mode="json") == payload
    restored = Finding.model_validate_json(finding.model_dump_json())
    assert restored == finding
    assert restored.severity is severity
    assert restored.provider is Provider.AWS
    assert restored.entity_type is EntityType.ROLE


def test_finding_accepts_json_enum_values_for_gcp() -> None:
    data = finding_data()
    data.update(
        provider="gcp",
        entity_type="service_account",
        entity_id="worker@project.iam.gserviceaccount.com",
        severity="MEDIUM",
    )
    finding = Finding.model_validate(data)
    assert finding.provider is Provider.GCP
    assert finding.entity_type is EntityType.SERVICE_ACCOUNT
    assert finding.severity is Severity.MEDIUM


@pytest.mark.parametrize("score", [0, 0.5, 8.0, 10])
def test_finding_accepts_numeric_scores_including_boundaries(score: float) -> None:
    data = finding_data()
    data["score"] = score
    assert Finding(**data).score == score


@pytest.mark.parametrize(
    "score", [-0.1, 10.1, float("nan"), float("inf"), -float("inf"), "8", True, None]
)
def test_finding_rejects_invalid_scores(score: object) -> None:
    data = finding_data()
    data["score"] = score
    with pytest.raises(ValidationError):
        Finding(**data)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [("severity", "URGENT"), ("provider", "azure"), ("entity_type", "bucket")],
)
def test_finding_rejects_unknown_enum_values(field_name: str, value: str) -> None:
    data = finding_data()
    data[field_name] = value
    with pytest.raises(ValidationError):
        Finding(**data)


@pytest.mark.parametrize(
    "field_name",
    ["rule_id", "title", "entity_id", "entity_name", "detail", "remediation"],
)
@pytest.mark.parametrize("value", ["", " \n\t", 123, None])
def test_finding_requires_nonblank_text(field_name: str, value: object) -> None:
    data = finding_data()
    data[field_name] = value
    with pytest.raises(ValidationError):
        Finding(**data)


@pytest.mark.parametrize("field_name", list(finding_data()))
def test_finding_requires_each_contract_field(field_name: str) -> None:
    data = finding_data()
    del data[field_name]
    with pytest.raises(ValidationError):
        Finding(**data)


def test_finding_preserves_multiline_remediation() -> None:
    data = finding_data()
    snippet = 'resource "aws_iam_policy" "worker" {\n  name = "worker"\n}\n'
    data["remediation"] = snippet
    assert Finding(**data).remediation == snippet


def test_finding_cis_reference_is_optional_but_can_be_supplied() -> None:
    data = finding_data()
    assert Finding(**data).cis_reference is None
    data["cis_reference"] = "Example benchmark version / control"
    finding = Finding(**data)
    assert (
        Finding.model_validate_json(finding.model_dump_json()).cis_reference
        == (data["cis_reference"])
    )


@pytest.mark.parametrize("value", ["", " \n\t"])
def test_finding_rejects_blank_cis_reference(value: str) -> None:
    data = finding_data()
    data["cis_reference"] = value
    with pytest.raises(ValidationError):
        Finding(**data)


def test_finding_rejects_unknown_fields() -> None:
    data = finding_data()
    data["entitiy_id"] = "misspelled"
    with pytest.raises(ValidationError):
        Finding(**data)


def test_finding_rejects_non_json_evidence() -> None:
    data = finding_data()
    data["evidence"] = {"unsupported": object()}
    with pytest.raises(ValidationError):
        Finding(**data)


def test_finding_evidence_defaults_are_independent() -> None:
    first = Finding(**finding_data())
    second = Finding(**finding_data())
    first.evidence["statement_index"] = 0
    assert second.evidence == {}


def test_finding_validates_assignment_and_keeps_previous_score_on_failure() -> None:
    finding = Finding(**finding_data())
    finding.score = 9.5
    assert finding.score == 9.5
    with pytest.raises(ValidationError):
        finding.score = 11
    assert finding.score == 9.5
