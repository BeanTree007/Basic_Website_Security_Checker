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
        mock_response.content = b""
        mock_response.text = ""

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 0)

    def test_exposed_env_file_with_valid_content(self):
        """Test detection of exposed .env file with environment variable patterns."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url == "https://example.com/.env":
                mock_response.status_code = 200
                mock_response.content = b"DB_HOST=localhost\nDB_USER=root\nAPP_KEY=secret123"
                mock_response.text = "DB_HOST=localhost\nDB_USER=root\nAPP_KEY=secret123"
            else:
                mock_response.status_code = 404
                mock_response.content = b""
                mock_response.text = ""
            return mock_response

        mock_session = Mock()
        mock_session.get.side_effect = side_effect

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 1)
        self.assertIn(".env", findings[0].name)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_false_positive_200_with_unrelated_html(self):
        """Test that 200 response with unrelated HTML doesn't create false positive."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url == "https://example.com/.env":
                mock_response.status_code = 200
                # Custom error page with HTML
                mock_response.content = b"<html><body>404 Not Found</body></html>"
                mock_response.text = "<html><body>404 Not Found</body></html>"
            else:
                mock_response.status_code = 404
                mock_response.content = b""
                mock_response.text = ""
            return mock_response

        mock_session = Mock()
        mock_session.get.side_effect = side_effect

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        # Should not detect .env since content doesn't match validation pattern
        self.assertEqual(len(findings), 0)

    def test_exposed_git_directory_with_git_markers(self):
        """Test detection of exposed .git directory with git metadata."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url == "https://example.com/.git/":
                mock_response.status_code = 200
                mock_response.content = b"ref: refs/heads/main"
                mock_response.text = "ref: refs/heads/main"
            else:
                mock_response.status_code = 404
                mock_response.content = b""
                mock_response.text = ""
            return mock_response

        mock_session = Mock()
        mock_session.get.side_effect = side_effect

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 1)
        self.assertIn(".git/", findings[0].name)

    def test_false_positive_git_with_short_response(self):
        """Test that very short 200 responses are filtered out."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url == "https://example.com/.git/":
                mock_response.status_code = 200
                mock_response.content = b"x"  # Only 1 byte
                mock_response.text = "x"
            else:
                mock_response.status_code = 404
                mock_response.content = b""
                mock_response.text = ""
            return mock_response

        mock_session = Mock()
        mock_session.get.side_effect = side_effect

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        # Should not detect .git since content is too short (likely error page)
        self.assertEqual(len(findings), 0)

    def test_exposed_backup_zip_file(self):
        """Test detection of exposed ZIP backup file by magic number."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url == "https://example.com/backup.zip":
                mock_response.status_code = 200
                # ZIP file magic number: 0x504B0304 (PK\x03\x04)
                zip_header = bytes([0x50, 0x4B, 0x03, 0x04])
                # Add enough content to pass the 50-byte minimum check
                mock_response.content = zip_header + b"\x14\x00\x00\x00" + b"x" * 100
                mock_response.text = ""
            else:
                mock_response.status_code = 404
                mock_response.content = b""
                mock_response.text = ""
            return mock_response

        mock_session = Mock()
        mock_session.get.side_effect = side_effect

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 1)
        self.assertIn("backup.zip", findings[0].name)

    def test_exposed_php_config_file(self):
        """Test detection of exposed PHP configuration file."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url == "https://example.com/config.php.bak":
                mock_response.status_code = 200
                mock_response.content = b"<?php\nreturn [\n'db' => 'secret'\n];"
                mock_response.text = "<?php\nreturn [\n'db' => 'secret'\n];"
            else:
                mock_response.status_code = 404
                mock_response.content = b""
                mock_response.text = ""
            return mock_response

        mock_session = Mock()
        mock_session.get.side_effect = side_effect

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 1)
        self.assertIn("config.php.bak", findings[0].name)

    def test_exposed_xml_config_file(self):
        """Test detection of exposed XML configuration file."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url == "https://example.com/web.config":
                mock_response.status_code = 200
                mock_response.content = b'<?xml version="1.0"?>\n<configuration><connection>...</connection></configuration>'
                mock_response.text = '<?xml version="1.0"?>\n<configuration><connection>...</connection></configuration>'
            else:
                mock_response.status_code = 404
                mock_response.content = b""
                mock_response.text = ""
            return mock_response

        mock_session = Mock()
        mock_session.get.side_effect = side_effect

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 1)
        self.assertIn("web.config", findings[0].name)

    def test_multiple_exposed_files(self):
        """Test detection of multiple exposed files."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url == "https://example.com/.env":
                mock_response.status_code = 200
                mock_response.content = b"DB_HOST=localhost"
                mock_response.text = "DB_HOST=localhost"
            elif url == "https://example.com/backup.zip":
                mock_response.status_code = 200
                # ZIP magic number with enough content
                zip_header = bytes([0x50, 0x4B, 0x03, 0x04])
                mock_response.content = zip_header + b"x" * 100
                mock_response.text = ""
            else:
                mock_response.status_code = 404
                mock_response.content = b""
                mock_response.text = ""
            return mock_response

        mock_session = Mock()
        mock_session.get.side_effect = side_effect

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
                mock_response.content = b"DB_HOST=localhost"
                mock_response.text = "DB_HOST=localhost"
            else:
                mock_response.status_code = 404
                mock_response.content = b""
                mock_response.text = ""
            return mock_response

        mock_session = Mock()
        mock_session.get.side_effect = side_effect

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        for finding in findings:
            self.assertEqual(finding.severity, Severity.HIGH)

    def test_status_codes_2xx_with_valid_content(self):
        """Test that 2xx status codes with valid content are detected."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url == "https://example.com/.env":
                # 201 Created with valid env content
                mock_response.status_code = 201
                mock_response.content = b"SECRET_KEY=mysecret"
                mock_response.text = "SECRET_KEY=mysecret"
            else:
                mock_response.status_code = 404
                mock_response.content = b""
                mock_response.text = ""
            return mock_response

        mock_session = Mock()
        mock_session.get.side_effect = side_effect

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
        mock_session.get.side_effect = Exception("Network error")

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        # Should return empty list when all requests fail
        self.assertEqual(len(findings), 0)

    def test_redirect_scenario(self):
        """Test that redirects are handled correctly."""
        def side_effect(url, **kwargs):
            mock_response = Mock()
            if url == "https://example.com/.env":
                # Redirect case - should not be treated as exposed
                mock_response.status_code = 301
                mock_response.content = b""
                mock_response.text = ""
            else:
                mock_response.status_code = 404
                mock_response.content = b""
                mock_response.text = ""
            return mock_response

        mock_session = Mock()
        mock_session.get.side_effect = side_effect

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        # Redirects (3xx) should not be treated as exposed
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
