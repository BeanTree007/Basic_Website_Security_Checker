"""Sensitive file exposure vulnerability check."""

from checks.base_check import CheckTarget, VulnerabilityCheck
from models.finding import Finding, Severity


class SensitiveFileExposureCheck(VulnerabilityCheck):
    """Detect exposure of common sensitive files and directories."""

    SENSITIVE_PATHS = [
        {
            "path": "/.env",
            "description": "Environment configuration file containing sensitive variables.",
        },
        {
            "path": "/.git/",
            "description": "Git repository directory exposing version control history.",
        },
        {
            "path": "/backup.zip",
            "description": "Backup archive that may contain sensitive data.",
        },
        {
            "path": "/config.php.bak",
            "description": "PHP configuration backup file.",
        },
        {
            "path": "/web.config",
            "description": "ASP.NET configuration file containing sensitive settings.",
        },
        {
            "path": "/.htaccess",
            "description": "Apache configuration file that may expose sensitive rules.",
        },
        {
            "path": "/config.xml",
            "description": "Generic configuration file.",
        },
        {
            "path": "/web.config.bak",
            "description": "ASP.NET configuration backup file.",
        },
    ]

    def run(self, target: CheckTarget) -> list[Finding]:
        """Check for exposed sensitive files on the target website."""
        findings: list[Finding] = []
        base_url = target.url.rstrip("/")
        exposed_files = set()

        for path_info in self.SENSITIVE_PATHS:
            path = path_info["path"]
            check_url = base_url + path

            try:
                response = target.session.head(check_url, timeout=10, allow_redirects=False)
                # 2xx status codes indicate the file/directory exists and is accessible
                if 200 <= response.status_code < 300:
                    exposed_files.add(path)
            except Exception:
                # Network errors, timeouts, etc. - skip this path
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
