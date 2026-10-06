"""Extensible rule contract; absent evidence is distinct from a clear result."""

from abc import ABC, abstractmethod

from iamcheck.models import EntityType, Finding, IAMEntity, Provider


class Rule(ABC):
    """A rule declares scope and evaluates one identity at a time."""

    rule_id: str
    entity_types: frozenset[EntityType]
    provider: Provider = Provider.AWS
    operations: frozenset[str] = frozenset()

    def supports(self, entity: IAMEntity) -> bool:
        return (
            entity.provider is self.provider and entity.entity_type in self.entity_types
        )

    def skip_reason(self, entity: IAMEntity) -> str | None:
        """Return an explanation when evidence is insufficient."""
        return None

    def required_operations(self, entity: IAMEntity) -> frozenset[str]:
        return self.operations

    def requires_credential_report(self, entity: IAMEntity) -> bool:
        return False

    @abstractmethod
    def check(self, entity: IAMEntity) -> list[Finding]:
        """Return findings; callers use the engine to retain skipped checks."""
