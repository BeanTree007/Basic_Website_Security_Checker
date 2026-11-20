"""Sensitive file exposure vulnerability check."""

import re

from checks.base_check import CheckTarget, VulnerabilityCheck
from models.finding import Finding, Severity


class SensitiveFileExposureCheck(VulnerabilityCheck):
    """Detect exposure of common sensitive files and directories."""

    SENSITIVE_PATHS = [
        {
            "path": "/.env",
            "description": "Environment configuration file containing sensitive variables.",
            "file_type": "env",
        },
        {
            "path": "/.git/",
            "description": "Git repository directory exposing version control history.",
            "file_type": "git",
        },
        {
            "path": "/backup.zip",
            "description": "Backup archive that may contain sensitive data.",
            "file_type": "zip",
        },
        {
            "path": "/config.php.bak",
            "description": "PHP configuration backup file.",
            "file_type": "php",
        },
        {
            "path": "/web.config",
            "description": "ASP.NET configuration file containing sensitive settings.",
            "file_type": "xml",
        },
        {
            "path": "/.htaccess",
            "description": "Apache configuration file that may expose sensitive rules.",
            "file_type": "htaccess",
        },
        {
            "path": "/config.xml",
            "description": "Generic configuration file.",
            "file_type": "xml",
        },
        {
            "path": "/web.config.bak",
            "description": "ASP.NET configuration backup file.",
            "file_type": "xml",
        },
    ]

    # Validation patterns to reduce false positives
    # Maps file_type to list of regex patterns that should match if the file is genuine
    VALIDATION_PATTERNS = {
        "env": [
            r"[A-Z_]+\s*=",  # Environment variable format: VAR=value
            r"(DB_|APP_|API_|SECRET_|DATABASE_|CACHE_|SESSION_|MAIL_)",  # Common prefixes
        ],
        "git": [
            r"ref:\s+refs/heads/",  # Git HEAD reference
            r"^[0-9a-f]{40}$",  # Git object hash
            b"GIT dir:",  # Git directory marker (as bytes)
        ],
        "zip": [
            bytes([0x50, 0x4B, 0x03, 0x04]),  # ZIP file magic number (PK\x03\x04)
        ],
        "php": [
            r"<\?php",  # PHP opening tag
            r"return\s*\[",  # PHP array
            r"'[A-Za-z_]+'\s*=>",  # PHP array key-value
        ],
        "xml": [
            r"<\?xml",  # XML declaration
            r"<[a-zA-Z:]+[\s>]",  # XML tag
        ],
        "htaccess": [
            r"RewriteEngine\s+on",  # Apache rewrite directive
            r"RewriteRule",  # Apache rewrite rule
            r"</?IfModule",  # Apache conditional
        ],
    }

    def run(self, target: CheckTarget, verbose: bool = False) -> list[Finding]:
        """Check for exposed sensitive files on the target website."""
        findings: list[Finding] = []
        base_url = target.url.rstrip("/")
        exposed_files = {}  # Maps path to validation result

        for path_info in self.SENSITIVE_PATHS:
            path = path_info["path"]
            check_url = base_url + path

            try:
                # Use GET to get response body for validation (some HEAD requests don't return body)
                response = target.session.get(
                    check_url, timeout=10, allow_redirects=False
                )

                if verbose:
                    print(f"    Testing: {check_url}")
                    print(f"    Status: {response.status_code}")

                # Check if status is 2xx
                if 200 <= response.status_code < 300:
                    # Validate content to reduce false positives
                    file_type = path_info.get("file_type")
                    is_valid = self._validate_file_content(
                        response, file_type, verbose=verbose
                    )

                    if is_valid:
                        exposed_files[path] = True
                        if verbose:
                            print(f"    Result: exposed file detected")
                    elif verbose:
                        print(f"    Result: validation failed, likely false positive")

            except Exception as exc:
                # Network errors, timeouts, etc. - skip this path
                if verbose:
                    print(f"    Status: Error - {exc}")
                continue

        # Create findings for each exposed file
        for path_info in self.SENSITIVE_PATHS:
            if path_info["path"] in exposed_files:
                findings.append(
                    Finding(
                        name=f"Sensitive File Exposed: {path_info['path']}",
                        severity=Severity.HIGH,
                        url=base_url + path_info["path"],
                        description=path_info["description"],
                        recommendation=f"Remove or restrict access to {path_info['path']}.",
                    )
                )

        return findings

    @staticmethod
    def _validate_file_content(response, file_type: str, verbose: bool = False) -> bool:
        """
        Validate response content to reduce false positives.

        Returns True if content appears consistent with the file type,
        False if it's likely a generic error page or catch-all response.
        """
        if not file_type or file_type not in SensitiveFileExposureCheck.VALIDATION_PATTERNS:
            # If no validation pattern defined, trust the status code
            return True

        content = response.content
        text_content = None

        # Try to decode as text for regex matching
        try:
            text_content = response.text
        except Exception:
            pass

        patterns = SensitiveFileExposureCheck.VALIDATION_PATTERNS[file_type]

        # For binary patterns, check against raw content
        for pattern in patterns:
            if isinstance(pattern, bytes):
                if pattern in content:
                    if verbose:
                        print(f"[VALIDATION] Matched binary pattern for {file_type}")
                    return True
            else:
                # Text pattern
                if text_content and re.search(pattern, text_content, re.MULTILINE):
                    if verbose:
                        print(
                            f"[VALIDATION] Matched text pattern for {file_type}: {pattern}"
                        )
                    return True

        # Heuristic: if content is very short or looks like a standard error page, likely false positive
        content_length = len(content)
        if content_length < 50:
            # Likely a simple error response or empty page
            return False

        # Check for common error page indicators
        error_indicators = [
            b"404",
            b"not found",
            b"does not exist",
            b"not found on this server",
        ]
        content_lower = content.lower()
        for indicator in error_indicators:
            if indicator in content_lower and content_length < 1000:
                if verbose:
                    print(f"[VALIDATION] Content looks like error page, skipping")
                return False

        # If no patterns matched but content doesn't look like an error page,
        # be conservative: only report if we have matching patterns above
        # This requires at least some validation pattern to match
        if verbose:
            print(f"[VALIDATION] No patterns matched, treating as false positive")
        return False
