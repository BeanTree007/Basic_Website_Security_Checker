"""Tests for security header checks."""

import unittest
from unittest.mock import Mock

from checks import CheckTarget, SecurityHeadersCheck
from models import Severity


class TestSecurityHeadersCheck(unittest.TestCase):
    """Test cases for SecurityHeadersCheck."""

    def setUp(self):
        """Set up test fixtures."""
        self.check = SecurityHeadersCheck()

    def test_missing_all_headers(self):
        """Test detection of all missing security headers."""
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.status_code = 200

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)

        self.assertEqual(len(findings), 3)
        header_names = [f.name for f in findings]
        self.assertIn("Missing Content-Security-Policy Header", header_names)
        self.assertIn("Missing X-Frame-Options Header", header_names)
        self.assertIn("Missing Strict-Transport-Security Header", header_names)

    def test_missing_no_headers(self):
        """Test when all headers are present."""
        mock_response = Mock()
        mock_response.headers = {
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "strict-transport-security": "max-age=31536000",
        }
        mock_response.status_code = 200

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 0)

    def test_missing_some_headers(self):
        """Test detection of some missing headers."""
        mock_response = Mock()
        mock_response.headers = {
            "content-security-policy": "default-src 'self'",
            # Missing x-frame-options and strict-transport-security
        }
        mock_response.status_code = 200

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 2)
        header_names = [f.name for f in findings]
        self.assertIn("Missing X-Frame-Options Header", header_names)
        self.assertIn("Missing Strict-Transport-Security Header", header_names)

    def test_findings_have_correct_severity(self):
        """Test that findings have MEDIUM severity."""
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.status_code = 200

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        for finding in findings:
            self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_header_name_case_insensitive(self):
        """Test that header matching is case-insensitive."""
        mock_response = Mock()
        mock_response.headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
        }
        mock_response.status_code = 200

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 0)

    def test_no_duplicate_findings_across_urls(self):
        """Test that missing headers don't create duplicate findings."""
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.status_code = 200

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=[
                "https://example.com",
                "https://example.com/page1",
                "https://example.com/page2",
            ],
            session=mock_session,
        )

        findings = self.check.run(target)
        # Should have 3 findings (one per missing header), not 9 (3 headers * 3 URLs)
        self.assertEqual(len(findings), 3)

    def test_redirect_chain_checks_final_response(self):
        """Test that security headers are checked on the final response after redirects."""
        # Simulate a redirect chain: 302 -> 301 -> 200 with headers
        mock_response = Mock()
        # The final response (after following redirects) has headers
        mock_response.headers = {
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "SAMEORIGIN",
            "strict-transport-security": "max-age=31536000",
        }
        mock_response.status_code = 200

        mock_session = Mock()
        # allow_redirects=True should return the final response
        mock_session.get.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        # All headers present, so no findings
        self.assertEqual(len(findings), 0)
        # Verify get was called with allow_redirects=True
        mock_session.get.assert_called_with(
            "https://example.com", timeout=10, allow_redirects=True
        )

    def test_https_redirect_scenario(self):
        """Test checking headers after HTTPS redirect."""
        mock_response = Mock()
        # After redirecting from http to https, check final response headers
        mock_response.headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            # Missing other headers
        }
        mock_response.status_code = 200

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        # Should detect missing CSP and X-Frame-Options
        self.assertEqual(len(findings), 2)
        header_names = [f.name for f in findings]
        self.assertIn("Missing Content-Security-Policy Header", header_names)
        self.assertIn("Missing X-Frame-Options Header", header_names)

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
        # Should return empty list when request fails
        self.assertEqual(len(findings), 0)

    def test_multiple_urls_with_different_headers(self):
        """Test that headers are checked on multiple URLs and deduplicated."""
        mock_response1 = Mock()
        mock_response1.headers = {"content-security-policy": "default-src 'self'"}

        mock_response2 = Mock()
        mock_response2.headers = {"x-frame-options": "DENY"}

        mock_session = Mock()
        # Return different responses for different URLs
        mock_session.get.side_effect = [mock_response1, mock_response2]

        target = CheckTarget(
            url="https://example.com",
            urls=[
                "https://example.com",
                "https://example.com/page1",
            ],
            session=mock_session,
        )

        findings = self.check.run(target)
        # Should collect all missing headers across URLs
        # URL1: missing x-frame-options, strict-transport-security
        # URL2: missing content-security-policy, strict-transport-security
        # Combined unique: all 3 headers missing
        self.assertEqual(len(findings), 3)


if __name__ == "__main__":
    unittest.main()
