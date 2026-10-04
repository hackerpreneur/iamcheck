"""Provider interface and collection results, separate from security findings."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from iamcheck.models import IAMEntity


class ProviderAuthenticationError(RuntimeError):
    """The SDK credential chain could not authenticate the collection."""


@dataclass(frozen=True)
class CollectionIssue:
    """An API operation whose evidence could not be collected."""

    operation: str
    code: str
    entity_id: str | None = None


@dataclass
class CollectionResult:
    """Collected identities and explicit gaps in attempted API operations.

    Complete means attempted operations succeeded, not that every AWS
    permission source or resource has been audited.
    """

    entities: list[IAMEntity] = field(default_factory=list)
    issues: list[CollectionIssue] = field(default_factory=list)
    credential_report_generated_at: datetime | None = None

    @property
    def complete(self) -> bool:
        return not self.issues


class BaseProvider(ABC):
    """Cloud providers normalise evidence without evaluating security rules."""

    @abstractmethod
    def collect(self) -> CollectionResult:
        """Collect identities and retain failures rather than implying a pass."""
