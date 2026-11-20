"""Tests for sensitive file exposure checks."""

import unittest
from unittest.mock import Mock

from checks import CheckTarget, SensitiveFileExposureCheck
from models import Severity


class TestSensitiveFileExposureCheck(unittest.TestCase):
    """Test cases for SensitiveFileExposureCheck."""

    def setUp(self):
        """Set up test fixtures."""
        self.check = SensitiveFileExposureCheck()

    def test_no_exposed_files(self):
        """Test when no sensitive files are exposed."""
        mock_response = Mock()
        mock_response.status_code = 404

        mock_session = Mock()
        mock_session.head.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 0)

    def test_exposed_env_file(self):
        """Test detection of exposed .env file."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url == "https://example.com/.env":
                mock_response.status_code = 200
            else:
                mock_response.status_code = 404
            return mock_response

        mock_session = Mock()
        mock_session.head.side_effect = side_effect

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 1)
        self.assertIn(".env", findings[0].name)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_exposed_git_directory(self):
        """Test detection of exposed .git directory."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url == "https://example.com/.git/":
                mock_response.status_code = 200
            else:
                mock_response.status_code = 404
            return mock_response

        mock_session = Mock()
        mock_session.head.side_effect = side_effect

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 1)
        self.assertIn(".git/", findings[0].name)

    def test_multiple_exposed_files(self):
        """Test detection of multiple exposed files."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url in ["https://example.com/.env", "https://example.com/backup.zip"]:
                mock_response.status_code = 200
            else:
                mock_response.status_code = 404
            return mock_response

        mock_session = Mock()
        mock_session.head.side_effect = side_effect

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 2)
        exposed_names = {f.name for f in findings}
        self.assertIn("Sensitive File Exposed: /.env", exposed_names)
        self.assertIn("Sensitive File Exposed: /backup.zip", exposed_names)

    def test_findings_have_correct_severity(self):
        """Test that findings have HIGH severity."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url == "https://example.com/.env":
                mock_response.status_code = 200
            else:
                mock_response.status_code = 404
            return mock_response

        mock_session = Mock()
        mock_session.head.side_effect = side_effect

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        for finding in findings:
            self.assertEqual(finding.severity, Severity.HIGH)

    def test_status_codes_2xx_are_exposed(self):
        """Test that any 2xx status code indicates exposure."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url == "https://example.com/.env":
                # 201 Created should be detected as exposed
                mock_response.status_code = 201
            else:
                mock_response.status_code = 404
            return mock_response

        mock_session = Mock()
        mock_session.head.side_effect = side_effect

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 1)

    def test_handles_request_errors(self):
        """Test that request errors are handled gracefully."""
        mock_session = Mock()
        mock_session.head.side_effect = Exception("Network error")

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        # Should return empty list when all requests fail
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
