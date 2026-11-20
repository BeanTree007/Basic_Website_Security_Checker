"""Standard finding model for security vulnerabilities."""

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """Severity levels for security findings."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Finding:
    """A security vulnerability finding from a check."""

    name: str
    severity: Severity
    url: str
    description: str
    recommendation: str

    def __str__(self) -> str:
        """Format finding as a readable string."""
        return (
            f"[{self.severity}]\n"
            f"{self.name}\n\n"
            f"URL:\n{self.url}\n\n"
            f"Description:\n{self.description}\n\n"
            f"Recommendation:\n{self.recommendation}"
        )
