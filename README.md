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
python scanner.py https://example.com
python scanner.py https://example.com --max-depth 2 --timeout 10
```

The starting page is depth 0; `--max-depth 0` visits only the starting URL and
its redirects. The default maximum depth is 2. The timeout defaults to 10 seconds
per request; it applies to connection and read operations, not the entire crawl.
Use `python scanner.py --help` for options.

The crawler follows HTML links on the exact starting hostname (including links
using another scheme or port), resolves relative links and HTML base URLs,
removes fragments, and avoids fetching the same normalized URL twice. It does not visit subdomains or
follow redirects to other hostnames. Redirect URLs are listed at the same depth
as the page that redirected to them. Query strings are retained, so distinct
queries are distinct URLs. Pages are listed when discovered, even if a later
request fails. Non-HTML responses are not parsed. The crawler does not execute
JavaScript or submit forms.

Failures on the starting request are reported as errors with a nonzero exit
status. Failures on later requests are shown as warnings and the remaining
pages are crawled. Depth limits how far links are followed, not the number of
pages or the overall runtime; even a shallow crawl may be large.

## Structure and roadmap

- `scanner.py`: command-line input and output.
- `crawler.py`: reusable crawler and crawl result.
- `checks/`: reserved for future vulnerability-check modules.
- `models/`: reserved for future shared findings and scan models.
- `reports/`: reserved for future report output.
- `tests/`: automated crawler and CLI tests.

Future phases can add security checks, structured findings, and report
generation on top of the discovered URLs. None of these are implemented yet.

Run the tests without contacting external websites:

```shell
python -m unittest discover -s tests -v
```
