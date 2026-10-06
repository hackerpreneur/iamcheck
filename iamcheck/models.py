"""Data contracts shared by cloud providers, rules, and reporters."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, JsonValue


class Severity(StrEnum):
    """Finding severity; declaration order is not a risk ordering."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Provider(StrEnum):
    """Supported cloud providers."""

    AWS = "aws"
    GCP = "gcp"


class EntityType(StrEnum):
    """Identity kinds, including AWS root for account-level MFA checks."""

    USER = "user"
    ROLE = "role"
    GROUP = "group"
    SERVICE_ACCOUNT = "service_account"
    ROOT_ACCOUNT = "root_account"


type PolicyDocument = dict[str, JsonValue]


@dataclass
class IAMEntity:
    """Normalised provider data, trusted and type-checked inside the pipeline.

    Providers must use timezone-aware activity timestamps. ``None`` denotes
    unavailable evidence, not an inactive identity or disabled MFA. For
    attached policy documents, ``None`` means not collected; an empty dict
    means collection completed without any documents. Policy IDs remain
    separate from their resolved documents so rules can inspect both.

    Raw documents retain provider-specific semantics. A shared entity model
    does not imply that every rule applies to every cloud or identity kind.
    """

    id: str
    name: str
    entity_type: EntityType
    provider: Provider
    attached_policies: list[str] = field(default_factory=list)
    inline_policies: list[PolicyDocument] = field(default_factory=list)
    last_used: datetime | None = None
    tags: dict[str, str] = field(default_factory=dict)
    attached_policy_documents: dict[str, PolicyDocument] | None = None
    trust_policy: PolicyDocument | None = None
    mfa_enabled: bool | None = None
    hardware_mfa_enabled: bool | None = None
    console_password_enabled: bool | None = None
    credential_last_used: dict[str, datetime | None] = field(default_factory=dict)


class Finding(BaseModel):
    """Validated security finding with a stable target and supporting evidence.

    ``score`` is a project-defined 0-10 risk value, not a formal CVSS score.
    Custom rules leave ``cis_reference`` unset. Evidence must be JSON-compatible
    so reporters can preserve it without provider-specific encoders.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    rule_id: str = Field(min_length=1, pattern=r"\S")
    title: str = Field(min_length=1, pattern=r"\S")
    severity: Severity
    entity_id: str = Field(min_length=1, pattern=r"\S")
    entity_name: str = Field(min_length=1, pattern=r"\S")
    entity_type: EntityType
    provider: Provider
    detail: str = Field(min_length=1, pattern=r"\S")
    remediation: str = Field(min_length=1, pattern=r"\S")
    score: float = Field(ge=0, le=10, allow_inf_nan=False, strict=True)
    cis_reference: str | None = Field(default=None, min_length=1, pattern=r"\S")
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
