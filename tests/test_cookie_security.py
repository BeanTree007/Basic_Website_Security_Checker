"""Tests for cookie security checks."""

import unittest
from unittest.mock import Mock
from http.cookiejar import Cookie

from checks import CheckTarget, CookieSecurityCheck
from models import Severity


class TestCookieSecurityCheck(unittest.TestCase):
    """Test cases for CookieSecurityCheck."""

    def setUp(self):
        """Set up test fixtures."""
        self.check = CookieSecurityCheck()

    def _create_mock_cookie(
        self, name="test", secure=False, httponly=False, samesite=False
    ):
        """Create a mock cookie with specified attributes."""
        cookie = Mock(spec=Cookie)
        cookie.name = name
        cookie.secure = secure

        # Set up has_nonstandard_attr to return values based on attribute
        def has_attr(attr):
            if attr == "HttpOnly":
                return httponly
            elif attr == "SameSite":
                return samesite
            return False

        cookie.has_nonstandard_attr.side_effect = has_attr
        return cookie

    def test_no_cookies(self):
        """Test response with no cookies."""
        mock_response = Mock()
        mock_response.cookies = []

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 0)

    def test_insecure_cookie_all_flags_missing(self):
        """Test detection of a cookie missing all security flags."""
        cookie = self._create_mock_cookie(
            name="session", secure=False, httponly=False, samesite=False
        )

        mock_response = Mock()
        mock_response.cookies = [cookie]

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 3)

        finding_names = {f.name for f in findings}
        self.assertIn("Cookie Missing HttpOnly Flag", finding_names)
        self.assertIn("Cookie Missing Secure Flag", finding_names)
        self.assertIn("Cookie Missing SameSite Flag", finding_names)

    def test_secure_cookie_all_flags_set(self):
        """Test that a fully secure cookie generates no findings."""
        cookie = self._create_mock_cookie(
            name="session", secure=True, httponly=True, samesite=True
        )

        mock_response = Mock()
        mock_response.cookies = [cookie]

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        self.assertEqual(len(findings), 0)

    def test_findings_have_correct_severity(self):
        """Test that findings have LOW severity."""
        cookie = self._create_mock_cookie(
            name="session", secure=False, httponly=False, samesite=False
        )

        mock_response = Mock()
        mock_response.cookies = [cookie]

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        for finding in findings:
            self.assertEqual(finding.severity, Severity.LOW)

    def test_multiple_cookies(self):
        """Test detection across multiple cookies."""
        cookie1 = self._create_mock_cookie(
            name="session", secure=False, httponly=False, samesite=False
        )
        cookie2 = self._create_mock_cookie(
            name="tracking", secure=True, httponly=False, samesite=False
        )

        mock_response = Mock()
        mock_response.cookies = [cookie1, cookie2]

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        target = CheckTarget(
            url="https://example.com",
            urls=["https://example.com"],
            session=mock_session,
        )

        findings = self.check.run(target)
        # cookie1: 3 issues (no secure, httponly, samesite)
        # cookie2: 2 issues (no httponly, samesite)
        self.assertEqual(len(findings), 5)

    def test_no_duplicate_findings_across_urls(self):
        """Test that missing cookie flags don't create duplicate findings."""
        cookie = self._create_mock_cookie(
            name="session", secure=False, httponly=False, samesite=False
        )

        mock_response = Mock()
        mock_response.cookies = [cookie]

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
        # Should have 3 findings (one per missing flag), not 9 (3 flags * 3 URLs)
        self.assertEqual(len(findings), 3)


if __name__ == "__main__":
    unittest.main()
