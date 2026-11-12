"""Command-line entry point for the website crawler."""

import argparse
import math
import sys
from urllib.parse import urlsplit

from config import MAX_DEPTH, MAX_PAGES, REQUEST_TIMEOUT
from crawler import CrawlError, crawl


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


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the crawler, and print its results."""
    parser = argparse.ArgumentParser(description="Discover pages on a website without vulnerability scanning.")
    parser.add_argument("url", help="target URL, including http:// or https://")
    parser.add_argument("--max-depth", type=non_negative_int, default=MAX_DEPTH,
                        help=f"maximum link depth (default: {MAX_DEPTH})")
    parser.add_argument("--timeout", type=positive_float, default=REQUEST_TIMEOUT,
                        help=f"request timeout in seconds (default: {REQUEST_TIMEOUT})")
    parser.add_argument("--max-pages", type=positive_int, default=MAX_PAGES,
                        help=f"maximum discovered URLs, including redirects (default: {MAX_PAGES})")
    args = parser.parse_args(argv)
    try:
        result = crawl(args.url, max_depth=args.max_depth, timeout=args.timeout, max_pages=args.max_pages)
    except (ValueError, CrawlError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Target: {result.target}")
    if result.final_url and result.final_url != result.target:
        print(f"Starting URL redirected to: {result.final_url}")
    print("\nDiscovered Pages:")
    target_parts = urlsplit(result.target)
    for url in result.urls:
        parts = urlsplit(url)
        if (parts.scheme, parts.netloc) == (target_parts.scheme, target_parts.netloc):
            display = parts.path + (f"?{parts.query}" if parts.query else "")
        else:
            display = url
        print(f"- {display}")
    print(f"\nTotal Pages Found: {len(result.urls)}")
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
