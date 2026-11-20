"""Command-line entry point for website security scanning."""

import argparse
import math
import sys
from urllib.parse import urlsplit

import requests

from checks import (
    CheckTarget,
    CookieSecurityCheck,
    SecurityHeadersCheck,
    SensitiveFileExposureCheck,
)
from config import MAX_DEPTH, MAX_PAGES, REQUEST_TIMEOUT, REQUEST_HEADERS
from crawler import CrawlError, crawl
from models import Finding


def non_negative_int(value: str) -> int:
    """Parse a non-negative crawl depth for argparse."""
    try:
        depth = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("depth must be a non-negative integer") from exc
    if depth < 0:
        raise argparse.ArgumentTypeError("depth must be a non-negative integer")
    return depth


def positive_float(value: str) -> float:
    """Parse a positive, finite timeout for argparse."""
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a positive number") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be a positive, finite number")
    return timeout


def positive_int(value: str) -> int:
    """Parse a positive page limit for argparse."""
    result = non_negative_int(value)
    if result == 0:
        raise argparse.ArgumentTypeError("maximum pages must be a positive integer")
    return result


def run_security_checks(target_url: str, discovered_urls: list[str], verbose: bool = False) -> list[Finding]:
    """Execute all vulnerability checks against the target website."""
    findings: list[Finding] = []

    with requests.Session() as session:
        session.headers.update(REQUEST_HEADERS)
        check_target = CheckTarget(url=target_url, urls=discovered_urls, session=session)

        checks = [
            SecurityHeadersCheck(),
            CookieSecurityCheck(),
            SensitiveFileExposureCheck(),
        ]

        for check in checks:
            check_name = check.__class__.__name__
            if verbose:
                print(f"[*] Running {check_name}...")
            try:
                # Pass verbose parameter if the check supports it
                if hasattr(check.run, '__code__') and 'verbose' in check.run.__code__.co_varnames:
                    check_findings = check.run(check_target, verbose=verbose)
                else:
                    check_findings = check.run(check_target)
                findings.extend(check_findings)
                if verbose and check_findings:
                    print(f"    Found {len(check_findings)} issue(s)")
            except Exception as exc:
                print(f"Warning: {check_name} failed: {exc}", file=sys.stderr)

    return findings


def print_findings(findings: list[Finding]) -> None:
    """Print security findings in a readable format."""
    if not findings:
        print("No security issues found.")
        return

    # Group findings by severity (High, Medium, Low, Critical)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(str(f.severity), 999))

    for i, finding in enumerate(sorted_findings):
        if i > 0:
            print("\n" + "-" * 60 + "\n")
        print(finding)


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the crawler and security checks, and print results."""
    parser = argparse.ArgumentParser(
        description="Crawl a website and check for common security vulnerabilities."
    )
    parser.add_argument("url", help="target URL, including http:// or https://")
    parser.add_argument(
        "--max-depth",
        type=non_negative_int,
        default=MAX_DEPTH,
        help=f"maximum link depth (default: {MAX_DEPTH})",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=REQUEST_TIMEOUT,
        help=f"request timeout in seconds (default: {REQUEST_TIMEOUT})",
    )
    parser.add_argument(
        "--max-pages",
        type=positive_int,
        default=MAX_PAGES,
        help=f"maximum discovered URLs, including redirects (default: {MAX_PAGES})",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="enable verbose output for debugging",
    )
    args = parser.parse_args(argv)

    # Run the crawler
    try:
        result = crawl(args.url, max_depth=args.max_depth, timeout=args.timeout, max_pages=args.max_pages)
    except (ValueError, CrawlError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Target: {result.target}")
    if result.final_url and result.final_url != result.target:
        print(f"Starting URL redirected to: {result.final_url}")
    print(f"\nDiscovered {len(result.urls)} page(s)")

    for warning in result.warnings:
        print(f"Warning: {warning}", file=sys.stderr)
    if result.stopped_reason:
        print(f"Warning: {result.stopped_reason}", file=sys.stderr)
        print("Crawl stopped because access may be restricted")
        return 1
    if result.page_limit_reached:
        print(f"Crawl stopped discovering new URLs at the {args.max_pages}-page limit")
    elif result.warnings:
        print("Crawl Complete (with warnings)")
    else:
        print("Crawl Complete")

    # Run security checks
    print("\n" + "=" * 60)
    print("Running Security Checks...")
    print("=" * 60 + "\n")

    findings = run_security_checks(result.target, result.urls, verbose=args.verbose)

    print("Scan Results\n")
    print_findings(findings)

    return 0


if __name__ == "__main__":
    sys.exit(main())

