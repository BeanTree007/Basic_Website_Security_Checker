"""Tests for URL discovery, redirect handling, and command-line behavior."""

import contextlib
import io
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import requests

from config import REQUEST_HEADERS
from crawler import AccessRestricted, CrawlError, crawl, normalize_url
from scanner import main


class TestHandler(BaseHTTPRequestHandler):
    requests_seen = []
    headers_seen = []

    def do_GET(self):
        self.requests_seen.append(self.path)
        self.headers_seen.append((self.path, dict(self.headers)))
        routes = {
            "/": (200, "text/html", b"""
                <a href="/about#section">About</a>
                <a href="contact?from=home">Contact</a>
                <a href="/about">Duplicate</a>
                <a href="#top">Fragment</a>
                <a href="https://external.example/page">External</a>
                <a href="mailto:test@example.com">Email</a>
                <a href="/redirect">Redirect</a>
                <a href="/external-redirect">External redirect</a>
                <a href="/broken">Broken</a>
                <a href="/image">Image</a>
            """),
            "/about": (200, "text/html; charset=utf-8", b'<a href="/deep">Deep</a>'),
            "/contact?from=home": (200, "text/html", b'<a href="/about">About</a>'),
            "/deep": (200, "text/html", b'<a href="/too-deep">Too deep</a>'),
            "/image": (200, "image/png", b'<a href="/not-html">Not HTML</a>'),
            "/broken": (404, "text/plain", b"Not found"),
            "/base": (200, "text/html", b'<base href="/folder/"><a href="hello world">Space</a>'),
            "/folder/hello%20world": (200, "text/html", b"OK"),
            "/limited": (429, "text/plain", b"Too many requests"),
            "/forbidden": (403, "text/plain", b"Forbidden"),
            "/captcha": (200, "text/html", b'<form id="captcha-form"></form>'),
            "/denied": (200, "text/html", b"<title>Access Denied</title>"),
            "/normal-captcha": (200, "text/html", b'<p>About CAPTCHA</p><a href="/deep">Link</a>'),
            "/restriction-links": (200, "text/html", b'<a href="/limited">Limit</a><a href="/deep">Next</a>'),
            "/cookies": (200, "text/html", b'<a href="/cookie-check">Check</a>'),
            "/cookie-check": (200, "text/html", b"OK"),
            "/single": (200, "text/html", b"<p>No links</p>"),
        }
        if self.path.startswith("/redirect-status/"):
            status = int(self.path.rsplit("/", 1)[-1])
            self.send_response(status)
            self.send_header("Location", "/single")
            self.end_headers()
            return
        if self.path == "/challenge":
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.send_header("cf-mitigated", "challenge")
            self.end_headers()
            self.wfile.write(b"<title>Just a moment...</title>")
            return
        if self.path in ("/redirect", "/external-redirect", "/loop"):
            self.send_response(302)
            locations = {"/redirect": "/about", "/external-redirect": "http://localhost:1/outside",
                         "/loop": "/loop"}
            location = locations[self.path]
            self.send_header("Location", location)
            self.end_headers()
            return
        status, content_type, body = routes.get(self.path, (404, "text/plain", b"Not found"))
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if self.path == "/cookies":
            self.send_header("Set-Cookie", "session=example; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class CrawlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), TestHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()

    def setUp(self):
        TestHandler.requests_seen = []
        TestHandler.headers_seen = []

    def test_depth_links_deduplication_and_warnings(self):
        result = crawl(self.base, max_depth=2)
        self.assertEqual(result.urls, [
            self.base + "/", self.base + "/about", self.base + "/contact?from=home",
            self.base + "/redirect", self.base + "/external-redirect",
            self.base + "/broken", self.base + "/image", self.base + "/deep",
        ])
        self.assertEqual(TestHandler.requests_seen.count("/about"), 1)
        self.assertNotIn("/too-deep", TestHandler.requests_seen)
        self.assertNotIn("/not-html", TestHandler.requests_seen)
        self.assertTrue(any("different host" in warning for warning in result.warnings))
        self.assertTrue(any("404" in warning for warning in result.warnings))

    def test_depth_zero_does_not_discover_links(self):
        result = crawl(self.base, max_depth=0)
        self.assertEqual(result.urls, [self.base + "/"])
        self.assertEqual(TestHandler.requests_seen, ["/"])

    def test_same_host_redirect_is_discovered_and_not_fetched_twice(self):
        result = crawl(self.base + "/redirect", max_depth=0)
        self.assertEqual(result.urls, [self.base + "/redirect", self.base + "/about"])
        self.assertEqual(result.final_url, self.base + "/about")
        self.assertEqual(result.redirects, {self.base + "/redirect": self.base + "/about"})
        self.assertEqual(TestHandler.requests_seen, ["/redirect", "/about"])

    def test_persistent_session_and_headers(self):
        crawl(self.base + "/cookies", max_depth=1)
        self.assertEqual(len(TestHandler.headers_seen), 2)
        for _, headers in TestHandler.headers_seen:
            for name, value in REQUEST_HEADERS.items():
                self.assertEqual(headers.get(name), value)
        self.assertEqual(TestHandler.headers_seen[1][1].get("Cookie"), "session=example")

    def test_page_limit_caps_discovered_urls_and_requests(self):
        result = crawl(self.base, max_depth=2, max_pages=2)
        self.assertEqual(result.urls, [self.base + "/", self.base + "/about"])
        self.assertEqual(TestHandler.requests_seen, ["/", "/about"])
        self.assertTrue(result.page_limit_reached)

    def test_redirect_respects_page_limit(self):
        result = crawl(self.base + "/redirect", max_depth=0, max_pages=1)
        self.assertEqual(result.urls, [self.base + "/redirect"])
        self.assertEqual(result.final_url, self.base + "/redirect")
        self.assertEqual(TestHandler.requests_seen, ["/redirect"])
        self.assertTrue(result.page_limit_reached)

    def test_limit_at_exact_count_without_more_links_is_not_reported(self):
        result = crawl(self.base + "/single", max_pages=1)
        self.assertFalse(result.page_limit_reached)

    def test_common_redirect_statuses(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                result = crawl(self.base + f"/redirect-status/{status}", max_depth=0)
                self.assertEqual(result.final_url, self.base + "/single")
                self.assertEqual(result.urls[-1], self.base + "/single")

    def test_cli_page_limit_is_reported(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = main([self.base, "--max-pages", "1"])
        self.assertEqual(status, 0)
        self.assertIn("1-page limit", stdout.getvalue())

    def test_restricted_start_responses(self):
        for path, text in (("/forbidden", "403 Forbidden"), ("/limited", "429 Too Many Requests"),
                           ("/challenge", "Cloudflare challenge"), ("/captcha", "CAPTCHA"),
                           ("/denied", "access-denied")):
            with self.subTest(path=path):
                with self.assertRaisesRegex(AccessRestricted, text) as exc:
                    crawl(self.base + path)
                self.assertIn("before crawling could begin", str(exc.exception))

    def test_cli_challenge_failure_explains_restriction(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = main([self.base + "/challenge"])
        self.assertEqual(status, 1)
        self.assertIn("403 Forbidden", stderr.getvalue())
        self.assertIn("Cloudflare challenge", stderr.getvalue())
        self.assertIn("before crawling could begin", stderr.getvalue())

    def test_normal_captcha_reference_does_not_stop_crawl(self):
        result = crawl(self.base + "/normal-captcha", max_depth=1)
        self.assertIsNone(result.stopped_reason)
        self.assertIn(self.base + "/deep", result.urls)

    def test_access_restriction_stops_remaining_requests(self):
        result = crawl(self.base + "/restriction-links", max_depth=1)
        self.assertIn("429 Too Many Requests", result.stopped_reason)
        self.assertEqual(TestHandler.requests_seen, ["/restriction-links", "/limited"])

    def test_cli_returns_failure_for_mid_crawl_restriction(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = main([self.base + "/restriction-links", "--max-depth", "1"])
        self.assertEqual(status, 1)
        self.assertIn("Crawl stopped", stdout.getvalue())
        self.assertIn("429 Too Many Requests", stderr.getvalue())

    def test_cli_displays_start_redirect_final_url(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main([self.base + "/redirect", "--max-depth", "0"])
        self.assertEqual(status, 0)
        self.assertIn("Starting URL redirected to: " + self.base + "/about", stdout.getvalue())

    def test_start_redirect_to_different_host_fails(self):
        with self.assertRaisesRegex(CrawlError, "different host"):
            crawl(self.base + "/external-redirect")
        self.assertEqual(TestHandler.requests_seen, ["/external-redirect"])

    def test_start_http_error_fails(self):
        with self.assertRaisesRegex(CrawlError, "404 Not Found"):
            crawl(self.base + "/broken")

    def test_redirect_loop_fails(self):
        with self.assertRaisesRegex(CrawlError, "redirect loop"):
            crawl(self.base + "/loop")
        self.assertEqual(TestHandler.requests_seen, ["/loop"])

    def test_html_base_and_url_encoding(self):
        result = crawl(self.base + "/base", max_depth=1)
        self.assertEqual(result.urls, [self.base + "/base", self.base + "/folder/hello%20world"])
        self.assertEqual(TestHandler.requests_seen, ["/base", "/folder/hello%20world"])

    def test_child_timeout_is_reported_and_crawl_continues(self):
        original_get = requests.Session.get

        def get_with_timeout(session, url, **kwargs):
            if url == self.base + "/about":
                raise requests.exceptions.Timeout("timed out")
            return original_get(session, url, **kwargs)

        with patch("requests.Session.get", autospec=True, side_effect=get_with_timeout):
            result = crawl(self.base, max_depth=1)
        self.assertTrue(any("network timeout" in warning for warning in result.warnings))
        self.assertIn("/image", TestHandler.requests_seen)

    def test_cli_prints_summary_and_warnings(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = main([self.base, "--max-depth", "1"])
        self.assertEqual(status, 0)
        self.assertIn("Discovered Pages:", stdout.getvalue())
        self.assertIn("- /about", stdout.getvalue())
        self.assertNotIn("- /deep", stdout.getvalue())
        self.assertIn("Total Pages Found: 7", stdout.getvalue())
        self.assertIn("Crawl Complete (with warnings)", stdout.getvalue())
        self.assertIn("Warning:", stderr.getvalue())

    def test_cli_process(self):
        process = subprocess.run(
            [sys.executable, "scanner.py", self.base, "--max-depth", "0"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn("Total Pages Found: 1", process.stdout)
        self.assertIn("Crawl Complete", process.stdout)


class ValidationTests(unittest.TestCase):
    def test_url_normalization(self):
        self.assertEqual(normalize_url("HTTPS://EXAMPLE.COM:443/a?q=1#fragment"),
                         "https://example.com/a?q=1")
        self.assertEqual(normalize_url("http://[::1]:80"), "http://[::1]/")

    def test_invalid_urls(self):
        for value in ("example.com", "ftp://example.com", "http://", "http://user:pass@example.com",
                      "http://example.com:99999", "http://example.com:0", "http://exa mple.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_url(value)

    def test_invalid_crawl_options(self):
        with self.assertRaises(ValueError):
            crawl("https://example.com", max_depth=-1)
        with self.assertRaises(ValueError):
            crawl("https://example.com", timeout=0)
        with self.assertRaises(ValueError):
            crawl("https://example.com", timeout=float("nan"))
        with self.assertRaises(ValueError):
            crawl("https://example.com", max_pages=0)
        with self.assertRaises(ValueError):
            crawl("https://example.com", max_pages=1.5)

    @patch("requests.Session.get", side_effect=requests.exceptions.Timeout("timed out"))
    def test_start_timeout_is_helpful(self, mock_get):
        with self.assertRaisesRegex(CrawlError, "network timeout"):
            crawl("https://example.com")
        mock_get.assert_called_once()

    @patch("requests.Session.get", side_effect=requests.exceptions.ConnectionError("unreachable"))
    def test_connection_error_is_helpful(self, mock_get):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = main(["https://example.com"])
        self.assertEqual(status, 1)
        self.assertIn("unreachable", stderr.getvalue())
        mock_get.assert_called_once()

    def test_cli_invalid_input(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = main(["not-a-url"])
        self.assertEqual(status, 1)
        self.assertIn("Error:", stderr.getvalue())

    def test_cli_invalid_options(self):
        for arguments in (["--max-depth", "-1"], ["--timeout", "nan"], ["--timeout", "0"],
                          ["--max-pages", "0"], ["--max-pages", "1.5"]):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exc:
                    main(["https://example.com"] + arguments)
                self.assertEqual(exc.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
