"""Discover links on a single website without running security checks."""

from collections import deque
from dataclasses import dataclass, field
import math
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup


DEFAULT_MAX_DEPTH = 2
DEFAULT_TIMEOUT = 10
MAX_REDIRECTS = 10


class CrawlError(Exception):
    """A target could not be crawled."""


@dataclass
class CrawlResult:
    """The URLs discovered and any errors encountered after the first page."""

    target: str
    urls: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


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


def crawl(target: str, max_depth: int = DEFAULT_MAX_DEPTH, timeout: float = DEFAULT_TIMEOUT) -> CrawlResult:
    """Crawl same-host links breadth-first, starting with the target at depth zero."""
    if max_depth < 0:
        raise ValueError("maximum depth must be non-negative")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a positive, finite number")
    target = normalize_url(target)
    target_host = urlsplit(target).hostname
    result = CrawlResult(target=target, urls=[target])
    discovered = {target}
    visited: set[str] = set()
    queue = deque([(target, 0)])

    with requests.Session() as session:
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
                    response = session.get(current, timeout=timeout, allow_redirects=False)
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
                            discovered.add(next_url)
                            result.urls.append(next_url)
                        current = next_url
                        continue

                    response.raise_for_status()
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
                                discovered.add(linked_url)
                                result.urls.append(linked_url)
                                queue.append((linked_url, depth + 1))
                    break
            except requests.exceptions.Timeout as exc:
                message = f"network timeout while requesting {current}"
                if url == target:
                    raise CrawlError(message) from exc
                result.warnings.append(message)
            except (requests.exceptions.RequestException, CrawlError) as exc:
                message = f"could not fetch {current}: {exc}"
                if url == target:
                    raise CrawlError(message) from exc
                result.warnings.append(message)
    return result
