"""Read-only AWS IAM evidence collection using the SDK credential chain."""

import csv
import io
import json
import logging
from collections.abc import Iterator
from datetime import datetime
from typing import Any, cast
from urllib.parse import unquote

import boto3
from botocore.client import BaseClient
from botocore.config import Config
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    PartialCredentialsError,
    ProfileNotFound,
)
from pydantic import TypeAdapter

from iamcheck.models import EntityType, IAMEntity, PolicyDocument, Provider
from iamcheck.providers.base import (
    BaseProvider,
    CollectionIssue,
    CollectionResult,
    ProviderAuthenticationError,
)

logger = logging.getLogger(__name__)
AUTH_ERRORS = {
    "ExpiredToken",
    "ExpiredTokenException",
    "InvalidClientTokenId",
    "UnrecognizedClientException",
    "SignatureDoesNotMatch",
    "RequestExpired",
}


class AWSProvider(BaseProvider):
    """Collect users, groups, roles and root evidence in the caller's account.

    Credential reports are read if already available; this provider never
    generates one or modifies IAM. Raw documents are not effective access.
    """

    def __init__(
        self,
        profile: str | None = None,
        *,
        session: boto3.Session | None = None,
    ) -> None:
        if profile is not None and session is not None:
            raise ValueError("Supply either a profile or a session, not both")
        try:
            self.session = session or boto3.Session(profile_name=profile)
            config = Config(retries={"mode": "standard", "max_attempts": 3})
            self.iam = self.session.client("iam", config=config)
            self.sts = self.session.client("sts", config=config)
        except (ProfileNotFound, NoCredentialsError, PartialCredentialsError) as exc:
            raise ProviderAuthenticationError("AWS credentials unavailable") from exc

    def _issue(
        self,
        result: CollectionResult,
        operation: str,
        code: str,
        entity_id: str | None = None,
    ) -> None:
        result.issues.append(CollectionIssue(operation, code, entity_id))
        logger.warning("AWS collection incomplete: %s (%s)", operation, code)

    def _error(
        self,
        result: CollectionResult,
        operation: str,
        exc: BotoCoreError | ClientError,
        entity_id: str | None,
    ) -> None:
        code = (
            str(exc.response["Error"]["Code"])
            if isinstance(exc, ClientError)
            else type(exc).__name__
        )
        if isinstance(exc, (NoCredentialsError, PartialCredentialsError)) or (
            code in AUTH_ERRORS
        ):
            raise ProviderAuthenticationError("AWS authentication failed") from exc
        self._issue(result, operation, code, entity_id)

    def _call(
        self,
        result: CollectionResult,
        operation: str,
        entity_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        try:
            client = self.sts if operation == "get_caller_identity" else self.iam
            return cast(dict[str, Any], getattr(client, operation)(**kwargs))
        except (ClientError, BotoCoreError) as exc:
            self._error(result, operation, exc, entity_id)
            return None

    def _items(
        self,
        result: CollectionResult,
        operation: str,
        key: str,
        entity_id: str | None = None,
        **kwargs: Any,
    ) -> Iterator[Any]:
        try:
            paginator = cast(BaseClient, self.iam).get_paginator(operation)
            for page in paginator.paginate(**kwargs):
                yield from page[key]
        except (ClientError, BotoCoreError) as exc:
            self._error(result, operation, exc, entity_id)

    @staticmethod
    def _document(value: Any) -> PolicyDocument:
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = json.loads(unquote(value))
        return TypeAdapter(PolicyDocument).validate_python(value)

    def _policies(self, entity: IAMEntity, result: CollectionResult) -> None:
        kind = entity.entity_type.value
        argument = {f"{kind.title()}Name": entity.name}
        issue_count = len(result.issues)
        documents: dict[str, PolicyDocument] = {}
        for attached in self._items(
            result,
            f"list_attached_{kind}_policies",
            "AttachedPolicies",
            entity.id,
            **argument,
        ):
            arn = attached["PolicyArn"]
            entity.attached_policies.append(arn)
            policy = self._call(result, "get_policy", entity.id, PolicyArn=arn)
            if policy:
                version = self._call(
                    result,
                    "get_policy_version",
                    entity.id,
                    PolicyArn=arn,
                    VersionId=policy["Policy"]["DefaultVersionId"],
                )
                if version:
                    documents[arn] = self._document(
                        version["PolicyVersion"]["Document"]
                    )
        # An incomplete resolution is never presented as a complete empty set.
        entity.attached_policy_documents = (
            documents if len(result.issues) == issue_count else None
        )
        for policy in self._items(
            result,
            f"list_{kind}_policies",
            "PolicyNames",
            entity.id,
            **argument,
        ):
            response = self._call(
                result,
                f"get_{kind}_policy",
                entity.id,
                **argument,
                PolicyName=policy,
            )
            if response:
                entity.inline_policies.append(
                    self._document(response["PolicyDocument"])
                )

    def _user_evidence(self, entity: IAMEntity, result: CollectionResult) -> None:
        devices = list(
            self._items(
                result,
                "list_mfa_devices",
                "MFADevices",
                entity.id,
                UserName=entity.name,
            )
        )
        if not any(
            i.operation == "list_mfa_devices" and i.entity_id == entity.id
            for i in result.issues
        ):
            entity.mfa_enabled = bool(devices)
        for key in self._items(
            result,
            "list_access_keys",
            "AccessKeyMetadata",
            entity.id,
            UserName=entity.name,
        ):
            if key["Status"] != "Active":
                continue
            key_id = key["AccessKeyId"]
            response = self._call(
                result,
                "get_access_key_last_used",
                entity.id,
                AccessKeyId=key_id,
            )
            used = (
                response["AccessKeyLastUsed"].get("LastUsedDate") if response else None
            )
            entity.credential_last_used[key_id] = used
        known = [t for t in entity.credential_last_used.values() if t is not None]
        entity.last_used = max(known) if known else None

    def _credential_report(self, result: CollectionResult) -> dict[str, dict[str, str]]:
        response = self._call(result, "get_credential_report")
        if response is None:
            return {}
        result.credential_report_generated_at = response.get("GeneratedTime")
        content = response["Content"]
        text = content.decode("utf-8") if isinstance(content, bytes) else str(content)
        return {row["arn"]: row for row in csv.DictReader(io.StringIO(text))}

    @staticmethod
    def _password_activity(entity: IAMEntity, row: dict[str, str]) -> None:
        enabled = row.get("password_enabled")
        entity.console_password_enabled = (
            enabled == "true" if enabled in {"true", "false"} else None
        )
        value = row.get("password_last_used", "N/A")
        if row.get("password_enabled") == "true":
            used = None
            if value not in {"N/A", "no_information", "not_supported", ""}:
                used = datetime.fromisoformat(value.replace("Z", "+00:00"))
            entity.credential_last_used["password"] = used
            if used is not None:
                entity.last_used = (
                    max(entity.last_used, used) if entity.last_used else used
                )

    def collect(self) -> CollectionResult:
        """Collect fresh results on every call; retain API failures with scope."""
        result = CollectionResult()
        caller = self._call(result, "get_caller_identity")
        report = self._credential_report(result)
        for kind, key in (
            (EntityType.USER, "Users"),
            (EntityType.GROUP, "Groups"),
            (EntityType.ROLE, "Roles"),
        ):
            for item in self._items(result, f"list_{kind.value}s", key):
                name = item[f"{kind.value.title()}Name"]
                entity = IAMEntity(item["Arn"], name, kind, Provider.AWS)
                # The detail API includes tags and, for roles, last-used evidence.
                detail = self._call(
                    result,
                    f"get_{kind.value}",
                    entity.id,
                    **{f"{kind.value.title()}Name": name},
                )
                source = detail[kind.value.title()] if detail else item
                entity.tags = {t["Key"]: t["Value"] for t in source.get("Tags", [])}
                if kind is EntityType.ROLE:
                    entity.trust_policy = self._document(
                        source["AssumeRolePolicyDocument"]
                    )
                    entity.last_used = source.get("RoleLastUsed", {}).get(
                        "LastUsedDate"
                    )
                self._policies(entity, result)
                if kind is EntityType.USER:
                    self._user_evidence(entity, result)
                    if entity.id in report:
                        self._password_activity(entity, report[entity.id])
                result.entities.append(entity)
        if caller:
            partition = caller["Arn"].split(":")[1]
            arn = f"arn:{partition}:iam::{caller['Account']}:root"
            root = IAMEntity(arn, "root", EntityType.ROOT_ACCOUNT, Provider.AWS)
            row = report.get(arn)
            if row:
                mfa = row.get("mfa_active")
                root.mfa_enabled = mfa == "true" if mfa in {"true", "false"} else None
                self._password_activity(root, row)
            # Hardware MFA cannot be inferred from the credential report.
            result.entities.append(root)
        return result
