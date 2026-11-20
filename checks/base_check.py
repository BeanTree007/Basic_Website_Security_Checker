"""Base class for all vulnerability checks."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

import requests

from models.finding import Finding


@dataclass
class CheckTarget:
    """Information about the target website for security checks."""

    url: str
    urls: list[str]
    session: requests.Session


class VulnerabilityCheck(ABC):
    """Base class for security vulnerability checks."""

    @abstractmethod
    def run(self, target: CheckTarget) -> list[Finding]:
        """
        Execute this security check against the target website.

        Returns a list of findings; an empty list indicates no vulnerabilities detected.
        """
        pass
