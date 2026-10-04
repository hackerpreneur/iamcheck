"""AWS collection tests using fake credentials and no live cloud calls."""

import json
from datetime import UTC, datetime
from unittest.mock import patch
from urllib.parse import quote

import boto3
import pytest
from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    ProfileNotFound,
)
from botocore.stub import Stubber
from moto import mock_aws

from iamcheck.models import EntityType
from iamcheck.providers.aws import AWSProvider
from iamcheck.providers.base import (
    BaseProvider,
    CollectionResult,
    ProviderAuthenticationError,
)

TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
        }
    ],
}


def session() -> boto3.Session:
    return boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        region_name="us-east-1",
    )


@mock_aws
def test_collect_users_roles_groups_and_policy_documents() -> None:
    sdk = session()
    iam = sdk.client("iam")
    iam.create_user(UserName="alice", Tags=[{"Key": "owner", "Value": "team"}])
    iam.create_group(GroupName="developers")
    iam.create_role(
        RoleName="worker",
        AssumeRolePolicyDocument=json.dumps(TRUST),
        Tags=[{"Key": "service", "Value": "billing"}],
    )
    arn = iam.create_policy(PolicyName="reader", PolicyDocument=json.dumps(POLICY))[
        "Policy"
    ]["Arn"]
    for kind, name in [("user", "alice"), ("group", "developers"), ("role", "worker")]:
        args = {f"{kind.title()}Name": name}
        getattr(iam, f"attach_{kind}_policy")(**args, PolicyArn=arn)
        getattr(iam, f"put_{kind}_policy")(
            **args,
            PolicyName="inline",
            PolicyDocument=json.dumps(POLICY),
        )
    iam.generate_credential_report()

    result = AWSProvider(session=sdk).collect()
    assert result.complete
    assert {e.entity_type for e in result.entities} == {
        EntityType.USER,
        EntityType.GROUP,
        EntityType.ROLE,
        EntityType.ROOT_ACCOUNT,
    }
    entities = {e.name: e for e in result.entities}
    assert entities["alice"].tags == {"owner": "team"}
    assert entities["alice"].mfa_enabled is False
    assert entities["worker"].tags == {"service": "billing"}
    assert entities["worker"].trust_policy == TRUST
    for name in ["alice", "developers", "worker"]:
        assert entities[name].attached_policies == [arn]
        assert entities[name].attached_policy_documents == {arn: POLICY}
        assert entities[name].inline_policies == [POLICY]
    assert entities["root"].id == "arn:aws:iam::123456789012:root"
    assert entities["root"].hardware_mfa_enabled is None


@mock_aws
def test_user_mfa_and_active_key_activity() -> None:
    sdk = session()
    iam = sdk.client("iam")
    iam.create_user(UserName="alice")
    key = iam.create_access_key(UserName="alice")["AccessKey"]["AccessKeyId"]
    inactive = iam.create_access_key(UserName="alice")["AccessKey"]["AccessKeyId"]
    iam.update_access_key(UserName="alice", AccessKeyId=inactive, Status="Inactive")
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName="alice")
    iam.enable_mfa_device(
        UserName="alice",
        SerialNumber=device["VirtualMFADevice"]["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )
    iam.generate_credential_report()
    provider = AWSProvider(session=sdk)
    last_used = datetime(2026, 1, 2, tzinfo=UTC)
    with patch.object(
        provider.iam,
        "get_access_key_last_used",
        return_value={
            "AccessKeyLastUsed": {"LastUsedDate": last_used},
        },
    ) as mocked:
        result = provider.collect()
        mocked.assert_called_once_with(AccessKeyId=key)
    user = next(e for e in result.entities if e.name == "alice")
    assert user.mfa_enabled is True
    assert user.hardware_mfa_enabled is None
    assert user.credential_last_used == {key: last_used}
    assert user.last_used == last_used


@mock_aws
def test_missing_report_is_explicit_and_results_are_fresh() -> None:
    sdk = session()
    provider = AWSProvider(session=sdk)
    first = provider.collect()
    assert not first.complete
    assert any(i.operation == "get_credential_report" for i in first.issues)
    assert first.entities[0].mfa_enabled is None
    sdk.client("iam").generate_credential_report()
    second = provider.collect()
    assert second.complete
    assert second.issues == []
    assert first.issues


@mock_aws
def test_access_denied_does_not_hide_other_identity_types(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sdk = session()
    iam = sdk.client("iam")
    iam.create_role(RoleName="worker", AssumeRolePolicyDocument=json.dumps(TRUST))
    iam.generate_credential_report()
    provider = AWSProvider(session=sdk)
    with Stubber(provider.iam) as stub:
        stub.add_response("get_credential_report", iam.get_credential_report(), {})
        stub.add_client_error(
            "list_users", service_error_code="AccessDenied", expected_params={}
        )
        # Stubber is removed once the blocked paginator has been exercised;
        # other operations still use the isolated moto account.
        original = provider._items

        def items(*args: object, **kwargs: object):
            if args[1] == "list_groups":
                stub.deactivate()
            yield from original(*args, **kwargs)

        with patch.object(provider, "_items", side_effect=items):
            result = provider.collect()
    assert not result.complete
    assert any(e.name == "worker" for e in result.entities)
    assert [(i.operation, i.code) for i in result.issues] == [
        ("list_users", "AccessDenied")
    ]
    assert "list_users" in caplog.text


@mock_aws
def test_policy_read_denied_preserves_ids_and_marks_documents_unknown() -> None:
    sdk = session()
    iam = sdk.client("iam")
    iam.create_user(UserName="alice")
    arn = iam.create_policy(PolicyName="reader", PolicyDocument=json.dumps(POLICY))[
        "Policy"
    ]["Arn"]
    iam.attach_user_policy(UserName="alice", PolicyArn=arn)
    iam.generate_credential_report()
    provider = AWSProvider(session=sdk)

    with patch.object(
        provider.iam,
        "get_policy",
        side_effect=ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GetPolicy",
        ),
    ):
        result = provider.collect()
    user = next(e for e in result.entities if e.name == "alice")
    assert user.attached_policies == [arn]
    assert user.attached_policy_documents is None
    assert user.mfa_enabled is False
    assert any(
        i.operation == "get_policy" and i.entity_id == user.id for i in result.issues
    )


@mock_aws
def test_paginator_retains_first_page_when_later_page_fails() -> None:
    provider = AWSProvider(session=session())
    user = {
        "Path": "/",
        "UserName": "alice",
        "UserId": "AIDAEXAMPLE123456",
        "Arn": "arn:aws:iam::123456789012:user/alice",
        "CreateDate": datetime.now(UTC),
    }
    result = CollectionResult()
    with Stubber(provider.iam) as stub:
        stub.add_response(
            "list_users", {"Users": [user], "IsTruncated": True, "Marker": "next"}, {}
        )
        stub.add_client_error(
            "list_users",
            service_error_code="AccessDenied",
            expected_params={"Marker": "next"},
        )
        assert list(provider._items(result, "list_users", "Users")) == [user]
    assert not result.complete
    assert result.issues[0].operation == "list_users"


@mock_aws
def test_paginator_collects_all_pages() -> None:
    provider = AWSProvider(session=session())
    result = CollectionResult()
    with Stubber(provider.iam) as stub:
        stub.add_response(
            "list_user_policies",
            {"PolicyNames": ["one"], "IsTruncated": True, "Marker": "next"},
            {"UserName": "alice"},
        )
        stub.add_response(
            "list_user_policies",
            {"PolicyNames": ["two"], "IsTruncated": False},
            {"UserName": "alice", "Marker": "next"},
        )
        assert list(
            provider._items(
                result, "list_user_policies", "PolicyNames", UserName="alice"
            )
        ) == ["one", "two"]
    assert result.complete


@mock_aws
@pytest.mark.parametrize("code", ["ExpiredToken", "InvalidClientTokenId"])
def test_authentication_failure_stops_collection(code: str) -> None:
    provider = AWSProvider(session=session())
    with Stubber(provider.sts) as stub:
        stub.add_client_error(
            "get_caller_identity", service_error_code=code, expected_params={}
        )
        with pytest.raises(ProviderAuthenticationError):
            provider.collect()


@mock_aws
def test_missing_credentials_are_reported_as_authentication_failure() -> None:
    provider = AWSProvider(session=session())
    with (
        patch.object(
            provider.sts, "get_caller_identity", side_effect=NoCredentialsError()
        ),
        pytest.raises(ProviderAuthenticationError),
    ):
        provider.collect()


def test_profile_is_passed_to_sdk_and_invalid_profile_is_explained() -> None:
    with (
        patch(
            "iamcheck.providers.aws.boto3.Session",
            side_effect=ProfileNotFound(profile="missing"),
        ) as mocked,
        pytest.raises(ProviderAuthenticationError),
    ):
        AWSProvider(profile="missing")
    mocked.assert_called_once_with(profile_name="missing")


@mock_aws
def test_profile_and_session_are_mutually_exclusive() -> None:
    with pytest.raises(ValueError):
        AWSProvider(profile="prod", session=session())


def test_base_provider_is_abstract() -> None:
    with pytest.raises(TypeError):
        BaseProvider()  # type: ignore[abstract]


@pytest.mark.parametrize(
    "value", [POLICY, json.dumps(POLICY), quote(json.dumps(POLICY))]
)
def test_policy_documents_accept_sdk_or_encoded_json(value: object) -> None:
    assert AWSProvider._document(value) == POLICY


def test_raw_policy_json_preserves_percent_escapes_in_resources() -> None:
    document = {"Statement": [{"Resource": "arn:aws:s3:::bucket/a%2Fb/*"}]}
    assert AWSProvider._document(json.dumps(document)) == document


@mock_aws
def test_password_and_root_evidence_keep_report_timestamp() -> None:
    sdk = session()
    iam = sdk.client("iam")
    user = iam.create_user(UserName="alice")["User"]
    provider = AWSProvider(session=sdk)
    generated = datetime(2026, 1, 3, tzinfo=UTC)
    content = (
        "arn,password_enabled,password_last_used,mfa_active\n"
        f"{user['Arn']},true,2026-01-02T00:00:00Z,false\n"
        "arn:aws:iam::123456789012:root,true,2026-01-01T00:00:00Z,true\n"
    ).encode()
    with patch.object(
        provider.iam,
        "get_credential_report",
        return_value={
            "Content": content,
            "GeneratedTime": generated,
        },
    ):
        result = provider.collect()
    assert result.complete
    assert result.credential_report_generated_at == generated
    entities = {e.name: e for e in result.entities}
    assert entities["alice"].last_used == datetime(2026, 1, 2, tzinfo=UTC)
    assert entities["root"].mfa_enabled is True
    assert entities["root"].credential_last_used["password"] == datetime(
        2026,
        1,
        1,
        tzinfo=UTC,
    )


@mock_aws
def test_mfa_denial_leaves_state_unknown() -> None:
    sdk = session()
    iam = sdk.client("iam")
    iam.create_user(UserName="alice")
    iam.generate_credential_report()
    provider = AWSProvider(session=sdk)
    original = provider.iam.get_paginator

    def paginator(operation: str):
        if operation == "list_mfa_devices":
            raise ClientError({"Error": {"Code": "AccessDenied"}}, operation)
        return original(operation)

    with patch.object(provider.iam, "get_paginator", side_effect=paginator):
        result = provider.collect()
    user = next(e for e in result.entities if e.name == "alice")
    assert user.mfa_enabled is None
    assert not result.complete


@mock_aws
def test_role_last_used_is_preserved() -> None:
    sdk = session()
    iam = sdk.client("iam")
    role = iam.create_role(
        RoleName="worker", AssumeRolePolicyDocument=json.dumps(TRUST)
    )["Role"]
    iam.generate_credential_report()
    used = datetime(2026, 1, 1, tzinfo=UTC)
    provider = AWSProvider(session=sdk)
    role["RoleLastUsed"] = {"LastUsedDate": used}
    with patch.object(provider.iam, "get_role", return_value={"Role": role}):
        result = provider.collect()
    assert next(e for e in result.entities if e.name == "worker").last_used == used


@mock_aws
def test_connection_failure_is_an_explicit_collection_issue() -> None:
    provider = AWSProvider(session=session())
    with patch.object(
        provider.sts,
        "get_caller_identity",
        side_effect=EndpointConnectionError(endpoint_url="https://example.invalid"),
    ):
        result = provider.collect()
    assert not result.complete
    assert any(
        i.operation == "get_caller_identity" and i.code == "EndpointConnectionError"
        for i in result.issues
    )


@mock_aws
@pytest.mark.parametrize("value", ["N/A", "no_information", "not_supported"])
def test_unknown_password_activity_stays_unknown(value: str) -> None:
    from iamcheck.models import IAMEntity, Provider

    entity = IAMEntity("user-id", "alice", EntityType.USER, Provider.AWS)
    AWSProvider._password_activity(
        entity,
        {
            "password_enabled": "true",
            "password_last_used": value,
        },
    )
    assert entity.last_used is None
    assert entity.credential_last_used == {"password": None}
