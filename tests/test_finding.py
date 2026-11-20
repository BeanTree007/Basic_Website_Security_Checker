"""Tests for the finding model."""

import unittest

from models import Finding, Severity


class TestFinding(unittest.TestCase):
    """Test cases for the Finding class."""

    def test_finding_creation(self):
        """Test creating a finding with all required fields."""
        finding = Finding(
            name="Test Issue",
            severity=Severity.HIGH,
            url="https://example.com",
            description="This is a test.",
            recommendation="Fix it.",
        )
        self.assertEqual(finding.name, "Test Issue")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.url, "https://example.com")
        self.assertEqual(finding.description, "This is a test.")
        self.assertEqual(finding.recommendation, "Fix it.")

    def test_severity_enum_values(self):
        """Test that severity enum has expected values."""
        self.assertEqual(str(Severity.LOW), "Low")
        self.assertEqual(str(Severity.MEDIUM), "Medium")
        self.assertEqual(str(Severity.HIGH), "High")
        self.assertEqual(str(Severity.CRITICAL), "Critical")

    def test_finding_string_representation(self):
        """Test that finding can be converted to a readable string."""
        finding = Finding(
            name="Missing Header",
            severity=Severity.MEDIUM,
            url="https://example.com",
            description="A header is missing.",
            recommendation="Add the header.",
        )
        str_repr = str(finding)
        self.assertIn("[Medium]", str_repr)
        self.assertIn("Missing Header", str_repr)
        self.assertIn("https://example.com", str_repr)
        self.assertIn("A header is missing.", str_repr)
        self.assertIn("Add the header.", str_repr)

    def test_finding_immutable(self):
        """Test that findings are immutable (frozen dataclass)."""
        finding = Finding(
            name="Test",
            severity=Severity.LOW,
            url="https://example.com",
            description="Test",
            recommendation="Test",
        )
        with self.assertRaises(AttributeError):
            finding.name = "Changed"


if __name__ == "__main__":
    unittest.main()
