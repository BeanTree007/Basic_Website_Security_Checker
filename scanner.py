"""Command-line entry point for the website crawler."""

import argparse
import math
import sys
from urllib.parse import urlsplit

from crawler import CrawlError, DEFAULT_MAX_DEPTH, DEFAULT_TIMEOUT, crawl


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


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the crawler, and print its results."""
    parser = argparse.ArgumentParser(description="Discover pages on a website without vulnerability scanning.")
    parser.add_argument("url", help="target URL, including http:// or https://")
    parser.add_argument("--max-depth", type=non_negative_int, default=DEFAULT_MAX_DEPTH,
                        help=f"maximum link depth (default: {DEFAULT_MAX_DEPTH})")
    parser.add_argument("--timeout", type=positive_float, default=DEFAULT_TIMEOUT,
                        help=f"request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    args = parser.parse_args(argv)
    try:
        result = crawl(args.url, max_depth=args.max_depth, timeout=args.timeout)
    except (ValueError, CrawlError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Target: {result.target}\n\nDiscovered Pages:")
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
    print("Crawl Complete" if not result.warnings else "Crawl Complete (with warnings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
