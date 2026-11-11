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

from crawler import CrawlError, crawl, normalize_url
from scanner import main


class TestHandler(BaseHTTPRequestHandler):
    requests_seen = []

    def do_GET(self):
        self.requests_seen.append(self.path)
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
        }
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
        self.assertEqual(TestHandler.requests_seen, ["/redirect", "/about"])

    def test_start_redirect_to_different_host_fails(self):
        with self.assertRaisesRegex(CrawlError, "different host"):
            crawl(self.base + "/external-redirect")
        self.assertEqual(TestHandler.requests_seen, ["/external-redirect"])

    def test_start_http_error_fails(self):
        with self.assertRaisesRegex(CrawlError, "404"):
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
        for arguments in (["--max-depth", "-1"], ["--timeout", "nan"], ["--timeout", "0"]):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exc:
                    main(["https://example.com"] + arguments)
                self.assertEqual(exc.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
