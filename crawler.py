"""Discover links on a single website without running security checks."""

from collections import deque
from dataclasses import dataclass, field
import math
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup

from config import MAX_DEPTH, MAX_PAGES, MAX_REDIRECTS, REQUEST_HEADERS, REQUEST_TIMEOUT


class CrawlError(Exception):
    """A target could not be crawled."""


class AccessRestricted(CrawlError):
    """The site appears to be rejecting or limiting the crawler."""


@dataclass
class CrawlResult:
    """The URLs discovered and any errors encountered after the first page."""

    target: str
    urls: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    final_url: str | None = None
    redirects: dict[str, str] = field(default_factory=dict)
    page_limit_reached: bool = False
    stopped_reason: str | None = None


def check_access(response: requests.Response) -> None:
    """Report explicit challenge indicators and common access restrictions."""
    indicators = []
    if response.status_code in (403, 429):
        explanations = {
            403: "HTTP 403 Forbidden: the website rejected this request",
            429: "HTTP 429 Too Many Requests: the website is limiting requests",
        }
        indicators.append(explanations[response.status_code])
    if response.headers.get("cf-mitigated", "").lower() == "challenge":
        indicators.append("Cloudflare challenge detected")

    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if content_type in ("text/html", "application/xhtml+xml"):
        soup = BeautifulSoup(response.content, "html.parser")
        title = soup.title.get_text(" ", strip=True).lower() if soup.title else ""
        if title in ("access denied", "just a moment...", "attention required! | cloudflare"):
            indicators.append(f"challenge or access-denied page title: {title}")
        if soup.select_one("form#challenge-form, form[action*='/cdn-cgi/challenge-platform/']"):
            indicators.append("Cloudflare challenge form detected")
        if soup.select_one("form[action*='/captcha/'], form#captcha-form"):
            indicators.append("CAPTCHA challenge form detected")
    if indicators:
        raise AccessRestricted(
            f"Automated access may be restricted at {response.url}. "
            + "; ".join(indicators) + "."
        )


def http_error_message(response: requests.Response) -> str:
    """Provide a useful description of a failed HTTP response."""
    if response.status_code == 404:
        return f"HTTP 404 Not Found: the requested page was not found: {response.url}"
    return f"HTTP {response.status_code} {response.reason}: {response.url}"


def normalize_url(url: str) -> str:
    """Validate an HTTP(S) URL and remove fragments and default ports."""
    if not url or any(character.isspace() or ord(character) < 32 for character in url):
        raise ValueError("URL must not be empty or contain whitespace or control characters")
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"invalid URL: {exc}") from exc
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not hostname:
        raise ValueError("URL must include http:// or https:// and a hostname")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URLs containing credentials are not supported")
    if port == 0:
        raise ValueError("port must be between 1 and 65535")
    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
        # Requests validates the hostname and detects malformed IPv6 addresses.
        requests.Request("GET", urlunsplit((scheme, parts.netloc, "/", "", ""))).prepare()
    except (UnicodeError, ValueError, requests.exceptions.RequestException) as exc:
        raise ValueError(f"invalid hostname: {exc}") from exc
    host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and port != (443 if scheme == "https" else 80):
        host = f"{host}:{port}"
    return urlunsplit((scheme, host, parts.path or "/", parts.query, ""))


def crawl(
    target: str,
    max_depth: int = MAX_DEPTH,
    timeout: float = REQUEST_TIMEOUT,
    max_pages: int = MAX_PAGES,
) -> CrawlResult:
    """Crawl same-host links breadth-first, starting with the target at depth zero."""
    if max_depth < 0:
        raise ValueError("maximum depth must be non-negative")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a positive, finite number")
    if not isinstance(max_pages, int) or isinstance(max_pages, bool) or max_pages < 1:
        raise ValueError("maximum pages must be a positive integer")
    target = normalize_url(target)
    target_host = urlsplit(target).hostname
    result = CrawlResult(target=target, urls=[target])
    discovered = {target}
    visited: set[str] = set()
    queue = deque([(target, 0)])

    with requests.Session() as session:
        session.headers.update(REQUEST_HEADERS)
        while queue:
            url, depth = queue.popleft()
            if url in visited:
                continue
            current = url
            redirects: set[str] = set()
            try:
                while True:
                    if current in visited:
                        break
                    visited.add(current)
                    # Check every redirect before following it to preserve the same-host boundary.
                    response = session.get(current, timeout=timeout, allow_redirects=False)
                    if url == target:
                        result.final_url = current
                    check_access(response)
                    if response.is_redirect:
                        if len(redirects) >= MAX_REDIRECTS:
                            raise CrawlError("too many redirects")
                        redirects.add(current)
                        try:
                            next_url = normalize_url(urljoin(current, response.headers["Location"]))
                        except ValueError as exc:
                            raise CrawlError(f"invalid redirect: {exc}") from exc
                        if urlsplit(next_url).hostname != target_host:
                            raise CrawlError(f"redirect to a different host was blocked: {next_url}")
                        if next_url in redirects:
                            raise CrawlError("redirect loop detected")
                        if next_url not in discovered:
                            if len(discovered) >= max_pages:
                                result.page_limit_reached = True
                                break
                            discovered.add(next_url)
                            result.urls.append(next_url)
                        result.redirects[current] = next_url
                        current = next_url
                        continue

                    if response.status_code >= 400:
                        raise CrawlError(http_error_message(response))
                    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                    if depth < max_depth and content_type in ("text/html", "application/xhtml+xml"):
                        soup = BeautifulSoup(response.content, "html.parser")
                        base_url = current
                        base = soup.find("base", href=True)
                        if base is not None:
                            try:
                                base_url = normalize_url(requests.utils.requote_uri(
                                    urljoin(current, str(base["href"]))))
                            except ValueError as exc:
                                result.warnings.append(f"invalid HTML base URL on {current}: {exc}")
                        for link in soup.find_all("a", href=True):
                            try:
                                linked_url = normalize_url(requests.utils.requote_uri(
                                    urljoin(base_url, str(link["href"]))))
                            except ValueError:
                                continue
                            if urlsplit(linked_url).hostname == target_host and linked_url not in discovered:
                                if len(discovered) >= max_pages:
                                    result.page_limit_reached = True
                                    continue
                                discovered.add(linked_url)
                                result.urls.append(linked_url)
                                queue.append((linked_url, depth + 1))
                    break
            except requests.exceptions.Timeout as exc:
                message = f"network timeout while requesting {current}: the website did not respond in time"
                if url == target:
                    raise CrawlError(message) from exc
                result.warnings.append(message)
            except AccessRestricted as exc:
                if url == target:
                    raise AccessRestricted(f"{exc} Scan terminated before crawling could begin.") from exc
                result.stopped_reason = str(exc)
                break
            except (requests.exceptions.RequestException, CrawlError) as exc:
                message = f"could not fetch {current}: {exc}"
                if url == target:
                    raise CrawlError(message) from exc
                result.warnings.append(message)
    return result
