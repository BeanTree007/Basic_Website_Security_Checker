# Basic Website Security Checker

A semester project for assessing websites for common security weaknesses. Phase 1
provides a command-line website crawler and a foundation for future checks and
reports. **It does not perform vulnerability detection.**

Only crawl websites you own or have explicit permission to assess. Crawling
sends real HTTP requests and can place load on a website.

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
redirect destinations. The crawler visits already-discovered URLs where possible,
but does not add or request new URLs past the limit. It reports when the limit
prevents discovery or following a redirect. The timeout defaults to 10 seconds
per request; it applies to connection and read operations, not the entire crawl.
These defaults and the request headers can be changed in `config.py`.
Use `python scanner.py --help` for options.

The crawler follows HTML links on the exact starting hostname (including links
using another scheme or port), resolves relative links and HTML base URLs,
removes fragments, and avoids fetching the same normalized URL twice. It uses
one `requests` session with Chrome-like headers and cookies throughout a crawl.
It does not visit subdomains or follow redirects to other hostnames. Redirects
are followed automatically one at a time so each destination can be checked
before requesting it; loops and excessive redirects are stopped. Redirect URLs
are listed at the same depth as the page that redirected to them, and the final
URL reached for the starting page is displayed. Query strings are retained, so
distinct queries are distinct URLs. Pages are listed when discovered, even if a
later request fails. Non-HTML responses are not parsed.

Failures on the starting request are reported as errors with a nonzero exit
status. Ordinary failures on later requests are shown as warnings and remaining
pages are crawled. If a request returns HTTP 403 or 429, or an explicit challenge
indicator is detected, the crawl stops and returns a nonzero status. A 403 does
not prove bot detection: the resource may require permission or authentication.
Detection is heuristic and may miss challenges or misidentify an unusual page.
Reaching the page limit is reported as a partial crawl but returns zero.
Neither the page limit nor the timeout limits overall crawl time or response size.

## Browser and access limitations

The headers resemble a browser, but `requests` is not a browser. It does not
execute JavaScript, render pages, solve challenges, or submit forms. Some sites
only reveal links after JavaScript runs; others require a login, block automated
requests, or present a CAPTCHA or Cloudflare challenge. Those sites may be
inaccessible or only partially visible to this crawler even when they work in
a normal browser. This is expected and does not necessarily indicate a crawler
bug. The crawler does not try to bypass access controls or solve challenges.
If access is denied, stop and consult the site owner rather than retrying to
evade the restriction. Use only sites you have permission to assess.

## Structure and roadmap

- `scanner.py`: command-line input and output.
- `crawler.py`: reusable crawler and crawl result.
- `config.py`: default limits, timeout, and request headers.
- `checks/`: reserved for future vulnerability-check modules.
- `models/`: reserved for future shared findings and scan models.
- `reports/`: reserved for future report output.
- `tests/`: automated crawler and CLI tests.

Future phases can add security checks, structured findings, and report
generation on top of the discovered URLs. A future browser-based crawler
(for example, using Playwright) could support JavaScript-rendered content when
authorized; it would not guarantee access or bypass a site's protections. None
of these features are implemented yet.

Run the tests without contacting external websites:

```shell
python -m unittest discover -s tests -v
```
