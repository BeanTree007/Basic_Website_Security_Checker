"""Cookie security vulnerability check."""

from checks.base_check import CheckTarget, VulnerabilityCheck
from models.finding import Finding, Severity


class CookieSecurityCheck(VulnerabilityCheck):
    """Detect insecure cookie attributes."""

    def run(self, target: CheckTarget) -> list[Finding]:
        """Check for insecure cookie attributes on the target website."""
        findings: list[Finding] = []
        all_issues: dict[str, set[str]] = {}  # cookie_name -> set of issues

        for url in target.urls:
            try:
                response = target.session.get(url, timeout=10, allow_redirects=False)
            except Exception:
                # Skip URLs that cannot be accessed during cookie check
                continue

            cookie_issues = self._check_cookies(response)
            for cookie_name, issues in cookie_issues.items():
                if cookie_name not in all_issues:
                    all_issues[cookie_name] = set()
                all_issues[cookie_name].update(issues)

        # Create findings for each cookie with missing security attributes
        for cookie_name, issues in all_issues.items():
            for issue_type in sorted(issues):
                findings.append(
                    Finding(
                        name=f"Cookie Missing {self._issue_display_name(issue_type)} Flag",
                        severity=Severity.LOW,
                        url=target.url,
                        description=f"The cookie '{cookie_name}' does not have the {self._issue_display_name(issue_type)} flag set.",
                        recommendation=self._get_recommendation(issue_type),
                    )
                )

        return findings

    @staticmethod
    def _check_cookies(response) -> dict[str, set[str]]:
        """Return dict of cookie names to missing security attributes."""
        issues: dict[str, set[str]] = {}

        for cookie in response.cookies:
            cookie_issues = set()

            # Check for HttpOnly flag
            if not cookie.has_nonstandard_attr("HttpOnly"):
                cookie_issues.add("httponly")

            # Check for Secure flag
            if not cookie.secure:
                cookie_issues.add("secure")

            # Check for SameSite attribute
            if not cookie.has_nonstandard_attr("SameSite"):
                cookie_issues.add("samesite")

            if cookie_issues:
                issues[cookie.name] = cookie_issues

        return issues

    @staticmethod
    def _issue_display_name(issue_type: str) -> str:
        """Convert issue type to display format."""
        display_names = {
            "httponly": "HttpOnly",
            "secure": "Secure",
            "samesite": "SameSite",
        }
        return display_names.get(issue_type, issue_type)

    @staticmethod
    def _get_recommendation(issue_type: str) -> str:
        """Get recommendation for the issue type."""
        recommendations = {
            "httponly": "Set the HttpOnly flag to prevent JavaScript access to the cookie.",
            "secure": "Set the Secure flag to ensure the cookie is only sent over HTTPS.",
            "samesite": "Set the SameSite attribute to 'Lax' or 'Strict' to prevent CSRF attacks.",
        }
        return recommendations.get(issue_type, "Secure this cookie attribute.")
