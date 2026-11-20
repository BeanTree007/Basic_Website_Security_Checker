# Basic Website Security Checker

A web vulnerability assessment tool that safely evaluates websites for common security weaknesses. The project crawls a target website and performs modular security checks to identify potential security issues.

**Important:** Only crawl websites you own or have explicit permission to assess. The tool sends real HTTP requests and can place load on a website.

## Current Capabilities

✅ **Website Crawling** – Discover pages within a target website  
✅ **Security Header Analysis** – Detect missing security headers  
✅ **Cookie Security Analysis** – Identify insecure cookie attributes  
✅ **Sensitive File Exposure Detection** – Find exposed common files  

The tool does not exploit vulnerabilities or perform harmful actions. New security checks can be added with minimal modification to the core application.

## Installation

Requires Python 3.10 or newer. From the project directory:

```shell
python -m venv .venv
```

Activate the environment (`.venv\Scripts\activate` on Windows or
`source .venv/bin/activate` on macOS/Linux), then install:

```shell
python -m pip install -r requirements.txt
```

## Usage

```shell
python scanner.py 'https://example.com/'
python scanner.py 'https://example.com/' --max-depth 2 --max-pages 100 --timeout 10
```

Quote URLs, particularly those containing `&`, so that the shell passes the
entire URL to the program. In PowerShell, single quotes work well.

The starting page is depth 0; `--max-depth 0` visits only the starting URL and
its redirects. The default maximum depth is 2. `--max-pages` defaults to 100 and
limits the number of distinct discovered URLs, including the starting URL and
redirect destinations. The timeout defaults to 10 seconds per request; it applies
to connection and read operations, not the entire crawl. Use `python scanner.py --help` for all options.

## Example Output

```
Target: https://example.com

Discovered 15 page(s)
Crawl Complete

============================================================
Running Security Checks...
============================================================

Scan Results

[High]
Sensitive File Exposed: /.env

URL:
https://example.com/.env

Description:
Environment configuration file containing sensitive variables.

Recommendation:
Remove or restrict access to /.env.

------------------------------------------------------------

[Medium]
Missing Content-Security-Policy Header

URL:
https://example.com

Description:
The website does not send a Content-Security-Policy header. Content Security Policy restricts script execution and resource loading.

Recommendation:
Implement a Content-Security-Policy header.

------------------------------------------------------------

[Low]
Cookie Missing Secure Flag

URL:
https://example.com

Description:
The cookie 'session' does not have the Secure flag set.

Recommendation:
Set the Secure flag to ensure the cookie is only sent over HTTPS.
```

## Security Checks

### Security Headers Check
Detects missing HTTP security headers:
- **Content-Security-Policy** – Restricts script execution and resource loading
- **X-Frame-Options** – Prevents clickjacking attacks
- **Strict-Transport-Security** – Enforces HTTPS connections

Severity: **MEDIUM**

### Cookie Security Check
Analyzes cookies for missing security attributes:
- **HttpOnly** – Prevents JavaScript access to the cookie
- **Secure** – Ensures the cookie is only sent over HTTPS
- **SameSite** – Prevents CSRF attacks

Severity: **LOW**

### Sensitive File Exposure Check
Safely tests for exposure of common sensitive files and directories:
- `/.env` – Environment configuration
- `/.git/` – Git repository directory
- `/backup.zip` – Backup archives
- `/config.php.bak` – PHP configuration backups
- `/web.config` – ASP.NET configuration
- `/.htaccess` – Apache configuration
- `/config.xml` – Generic configuration
- `/web.config.bak` – ASP.NET backup

Only performs simple GET requests (HEAD requests where possible) and does not attempt exploitation.

Severity: **HIGH**

## Crawler Details

The crawler follows HTML links on the exact starting hostname, resolves relative links and HTML base URLs, removes fragments, and avoids fetching the same normalized URL twice. It uses one `requests` session with Chrome-like headers and cookies throughout a crawl.

It does not visit subdomains or follow redirects to other hostnames. Redirects are followed automatically one at a time so each destination can be checked before requesting it; loops and excessive redirects are stopped. Query strings are retained, so distinct queries are distinct URLs. Pages are listed when discovered, even if a later request fails.

**Browser and access limitations:** The headers resemble a browser, but `requests` is not a browser. It does not execute JavaScript, render pages, solve challenges, or submit forms. Some sites only reveal links after JavaScript runs; others require a login, block automated requests, or present a CAPTCHA or Cloudflare challenge. Those sites may be inaccessible or only partially visible to this crawler. This is expected and does not indicate a crawler bug.

## Project Structure

```
.
├── scanner.py              # Command-line entry point and security check orchestration
├── crawler.py              # Website crawler and crawl result model
├── config.py               # Default configuration (timeout, limits, headers)
├── checks/                 # Security check modules (plugin-style architecture)
│   ├── __init__.py        # Check exports
│   ├── base_check.py      # Base class for all security checks
│   ├── security_headers.py # Security header check implementation
│   ├── cookie_security.py  # Cookie security check implementation
│   └── sensitive_files.py  # Sensitive file exposure check implementation
├── models/                 # Shared data models
│   ├── __init__.py        # Model exports
│   └── finding.py         # Finding and severity models
├── reports/               # Reserved for future report output
├── tests/                 # Automated tests
│   ├── test_crawler.py    # Crawler tests
│   ├── test_finding.py    # Finding model tests
│   ├── test_security_headers.py  # Security header check tests
│   ├── test_cookie_security.py   # Cookie security check tests
│   └── test_sensitive_files.py   # Sensitive file check tests
├── requirements.txt       # Project dependencies
└── README.md             # This file
```

## Architecture: Plugin-Style Security Checks

The security check framework uses an extensible plugin architecture. Each check:

1. Extends the `VulnerabilityCheck` base class
2. Implements the `run(target: CheckTarget)` method
3. Returns a list of `Finding` objects
4. Operates independently with no special logic in the core application

**To add a new check:**

1. Create a new module in `checks/` (e.g., `checks/xss_detection.py`)
2. Define a class extending `VulnerabilityCheck`
3. Implement the `run()` method
4. Export the class in `checks/__init__.py`
5. Add an instance to the `checks` list in `scanner.py`'s `run_security_checks()` function

Example:

```python
# checks/xss_detection.py
from checks.base_check import CheckTarget, VulnerabilityCheck
from models.finding import Finding, Severity

class XSSDetectionCheck(VulnerabilityCheck):
    def run(self, target: CheckTarget) -> list[Finding]:
        findings = []
        # Perform XSS detection
        return findings
```

Then in `scanner.py`:

```python
from checks import XSSDetectionCheck

def run_security_checks(...):
    checks = [
        SecurityHeadersCheck(),
        CookieSecurityCheck(),
        SensitiveFileExposureCheck(),
        XSSDetectionCheck(),  # Add new check
    ]
    # ...
```

## Testing

Run the automated tests without contacting external websites:

```shell
python -m unittest discover -s tests -v
```

## Future Enhancements

The modular architecture is designed to easily support additional vulnerability checks such as:

- XSS (Cross-Site Scripting) detection
- SQL injection detection
- Directory traversal testing
- CORS misconfiguration detection
- Additional security header checks
- SSRF (Server-Side Request Forgery) detection
- API security testing
- And many more...

A future browser-based crawler (for example, using Playwright) could support JavaScript-rendered content when authorized; it would not guarantee access or bypass a site's protections.

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN: HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
