"""Security headers vulnerability check."""

from checks.base_check import CheckTarget, VulnerabilityCheck
from models.finding import Finding, Severity


class SecurityHeadersCheck(VulnerabilityCheck):
    """Detect missing security headers on responses."""

    REQUIRED_HEADERS = {
        "content-security-policy": {
            "description": "Content Security Policy restricts script execution and resource loading.",
            "recommendation": "Implement a Content-Security-Policy header.",
        },
        "x-frame-options": {
            "description": "X-Frame-Options prevents clickjacking attacks.",
            "recommendation": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'.",
        },
        "strict-transport-security": {
            "description": "Strict-Transport-Security enforces HTTPS connections.",
            "recommendation": "Implement Strict-Transport-Security (HSTS).",
        },
    }

    def run(self, target: CheckTarget) -> list[Finding]:
        """Check for missing security headers on the target website."""
        findings: list[Finding] = []
        missing_headers_per_url: dict[str, set[str]] = {}

        for url in target.urls:
            try:
                # Follow redirects to check headers on the final response.
                # This ensures we evaluate security headers on the page
                # the user actually receives, not intermediate redirects.
                response = target.session.get(url, timeout=10, allow_redirects=True)

                missing_headers = self._check_headers(response)
                if missing_headers:
                    missing_headers_per_url[url] = missing_headers
            except Exception:
                # Skip URLs that cannot be accessed during header check
                continue

        # Create one finding per missing header to avoid duplication
        all_missing = set()
        for missing in missing_headers_per_url.values():
            all_missing.update(missing)

        for header_name in all_missing:
            header_info = self.REQUIRED_HEADERS[header_name]
            findings.append(
                Finding(
                    name=f"Missing {self._header_display_name(header_name)} Header",
                    severity=Severity.MEDIUM,
                    url=target.url,
                    description=f"The website does not send a {self._header_display_name(header_name)} header. {header_info['description']}",
                    recommendation=header_info["recommendation"],
                )
            )

        return findings

    @staticmethod
    def _check_headers(response) -> set[str]:
        """
        Return set of missing security headers for this response.

        Checks the final response after following redirects to ensure
        we evaluate headers on the actual content served to users.
        """
        missing = set()
        response_headers = {k.lower(): v for k, v in response.headers.items()}

        for header_name in SecurityHeadersCheck.REQUIRED_HEADERS:
            if header_name not in response_headers:
                missing.add(header_name)

        return missing

    @staticmethod
    def _header_display_name(header_name: str) -> str:
        """Convert header name to display format."""
        parts = header_name.split("-")
        return "-".join(part.capitalize() for part in parts)
