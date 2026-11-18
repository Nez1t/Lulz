"""Network-free tests for response semantics, boundaries and secret handling."""
from email.message import Message
from io import BytesIO
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl
import threading
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from lulz import web
from lulz.models import ScanResult


def response(body=b"<html><body>hello</body></html>", url="https://example.test/", status=200, headers=None):
    message = Message()
    for key, value in (headers or {"Content-Type": "text/html"}).items():
        if isinstance(value, list):
            for item in value:
                message.add_header(key, item)
        else:
            message.add_header(key, value)
    return web._Response(url, status, message, body)


def scan_mock(body=b"<html><body>hello</body></html>", headers=None, modules=None, status=200):
    with patch.object(web, "_fetch", return_value=response(body, headers=headers, status=status)):
        return web.scan_url("https://example.test/?secret=never-print-me", modules or ["headers", "cookies", "html", "disclosure"])


def ids(result):
    return {finding.rule_id for finding in result.findings}


class FakeNetworkResponse(BytesIO):
    def __init__(self, body=b"", status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def getcode(self):
        return self.status


class URLTests(unittest.TestCase):
    def test_defaults_to_https_and_preserves_query(self):
        self.assertEqual(web.normalize_url("example.test/a?q=hello#fragment"), "https://example.test/a?q=hello")

    def test_rejects_credentials_and_non_http(self):
        for value in ["ftp://example.test", "https://user:secret@example.test/", "https://example.test:bad", "https://exa mple.test/", "https://x/\nsecret"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                web.normalize_url(value)

    def test_query_values_are_masked(self):
        shown = web.display_url("https://user:password@example.test/path?token=never-print-me&x=abc#frag")
        for secret in ["password", "never-print-me", "abc", "frag"]:
            self.assertNotIn(secret, shown)
        self.assertIn("token", shown)

    def test_scope_rules(self):
        self.assertTrue(web._redirect_allowed("http://example.test/", "https://example.test/path"))
        self.assertTrue(web._redirect_allowed("https://example.test/a", "https://example.test/b"))
        for target in ["http://example.test/", "https://elsewhere.test/", "https://example.test:8443/"]:
            self.assertFalse(web._redirect_allowed("https://example.test/", target))


class FetchTests(unittest.TestCase):
    def fresh(self):
        return ScanResult(kind="web", target="https://example.test/", metadata={"http_requests": 0})

    def test_one_get_no_auth_or_cookie(self):
        fake = MagicMock()
        fake.open.return_value = FakeNetworkResponse(b"ok", headers={"Content-Type": "text/plain"})
        with patch.object(web, "build_opener", return_value=fake):
            result = self.fresh()
            fetched = web._fetch(result.target, 1, result)
        self.assertEqual(fetched.body, b"ok")
        self.assertEqual(fake.open.call_count, 1)
        req = fake.open.call_args.args[0]
        self.assertEqual(req.get_method(), "GET")
        self.assertIsNone(req.data)
        self.assertIsNone(req.get_header("Cookie"))
        self.assertIsNone(req.get_header("Authorization"))

    def test_cross_origin_redirect_is_not_requested(self):
        fake = MagicMock()
        fake.open.return_value = FakeNetworkResponse(status=302, headers={"Location": "https://other.test/?secret=secret"})
        with patch.object(web, "build_opener", return_value=fake):
            result = self.fresh()
            web._fetch(result.target, 1, result)
        self.assertEqual(fake.open.call_count, 1)
        self.assertTrue(result.errors)
        self.assertNotIn("secret", str(result.to_dict()))

    def test_same_origin_redirect_limit(self):
        fake = MagicMock()
        fake.open.side_effect = [FakeNetworkResponse(status=302, headers={"Location": f"/p{i}"}) for i in range(4)]
        with patch.object(web, "build_opener", return_value=fake):
            result = self.fresh()
            web._fetch(result.target, 1, result)
        self.assertEqual(fake.open.call_count, 4)
        self.assertTrue(result.errors)

    def test_redirect_cycle(self):
        fake = MagicMock()
        fake.open.return_value = FakeNetworkResponse(status=302, headers={"Location": "/"})
        with patch.object(web, "build_opener", return_value=fake), self.assertRaises(ValueError):
            web._fetch("https://example.test/", 1, self.fresh())
        self.assertEqual(fake.open.call_count, 1)

    def test_body_size_limit_marks_incomplete(self):
        fake = MagicMock()
        fake.open.return_value = FakeNetworkResponse(b"x" * (web.MAX_BODY + 100))
        result = self.fresh()
        with patch.object(web, "build_opener", return_value=fake):
            fetched = web._fetch(result.target, 1, result)
        self.assertEqual(len(fetched.body), web.MAX_BODY)
        self.assertTrue(fetched.truncated)
        self.assertTrue(result.metadata["incomplete"])

    def test_server_compression_is_not_decompressed(self):
        fake = MagicMock()
        fake.open.return_value = FakeNetworkResponse(b"untrusted-gzip", headers={"Content-Encoding": "gzip"})
        result = self.fresh()
        with patch.object(web, "build_opener", return_value=fake):
            fetched = web._fetch(result.target, 1, result)
        self.assertEqual(fetched.body, b"")
        self.assertTrue(result.metadata["incomplete"])


class HeaderTests(unittest.TestCase):
    def test_cookie_prefix_requirements_and_case_sensitivity(self):
        result = scan_mock(headers={"Content-Type": "text/html", "Set-Cookie": [
            "__Secure-test=SECRET; SameSite=Lax", "__Host-test=SECRET; Secure; Domain=example.test; SameSite=Lax",
            "__Host-valid=SECRET; Secure; Path=/; SameSite=Lax", "__secure-case=SECRET; SameSite=Lax"]}, modules=["cookies"])
        self.assertIn("WEB-COOKIE-PREFIX-SECURE", ids(result))
        self.assertIn("WEB-COOKIE-PREFIX-HOST", ids(result))
        prefixed = [f for f in result.findings if "PREFIX" in f.rule_id]
        self.assertEqual(len(prefixed), 2)
        self.assertFalse(any("__Host-valid" in f.location for f in prefixed))
        self.assertNotIn("SECRET", str(result.to_dict()))

    def test_partitioned_requires_secure(self):
        result = scan_mock(headers={"Content-Type": "text/html", "Set-Cookie": "partition=SECRET; Partitioned; SameSite=Lax"}, modules=["cookies"])
        self.assertIn("WEB-COOKIE-PARTITIONED", ids(result))

    def test_csp_base_and_legacy_filter(self):
        result = scan_mock(headers={"Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'", "X-XSS-Protection": "1; mode=block"})
        self.assertIn("WEB-CSP-BASE", ids(result))
        self.assertIn("WEB-LEGACY-XSS-FILTER", ids(result))
        restrictive = scan_mock(headers={"Content-Type": "text/html", "Content-Security-Policy": ["base-uri *", "base-uri 'none'"], "X-XSS-Protection": "0"})
        self.assertNotIn("WEB-CSP-BASE", ids(restrictive))
        self.assertNotIn("WEB-LEGACY-XSS-FILTER", ids(restrictive))

    def test_huge_hsts_integer_does_not_crash(self):
        result = scan_mock(headers={"Content-Type": "text/html", "Strict-Transport-Security": "max-age=" + "1" * 5000})
        self.assertNotIn("WEB-HSTS", ids(result))

    def test_empty_204_304_and_redirect_do_not_get_html_warnings(self):
        for status in (204, 304, 302):
            with self.subTest(status=status):
                result = scan_mock(b"", {"Content-Type": "text/html"}, status=status)
                self.assertNotIn("WEB-CSP-MISSING", ids(result))
                self.assertNotIn("WEB-FRAMING", ids(result))

    def test_cookie_overflow_marks_incomplete(self):
        result = scan_mock(headers={"Content-Type": "text/html", "Set-Cookie": [
            f"cookie{i}=SECRET; Secure; HttpOnly; SameSite=Lax" for i in range(101)
        ]}, modules=["cookies"])
        self.assertTrue(result.metadata["incomplete"])
        self.assertFalse(result.to_dict()["complete"])
        self.assertTrue(any("100 Set-Cookie" in note for note in result.notes))
        self.assertNotIn("SECRET", str(result.to_dict()))

    def test_json_does_not_get_html_only_warnings(self):
        result = scan_mock(b"{}", {"Content-Type": "application/json"})
        self.assertNotIn("WEB-CSP-MISSING", ids(result))
        self.assertNotIn("WEB-FRAMING", ids(result))
        self.assertNotIn("WEB-REFERRER", ids(result))

    def test_report_only_is_not_enforcement(self):
        result = scan_mock(headers={"Content-Type": "text/html", "Content-Security-Policy-Report-Only": "default-src 'self'"})
        self.assertIn("WEB-CSP-MISSING", ids(result))
        finding = next(f for f in result.findings if f.rule_id == "WEB-CSP-MISSING")
        self.assertIn("Report-Only", finding.evidence)
        self.assertEqual(finding.cve, [])
        self.assertNotIn("CWE-79", finding.cwe)

    def test_nonce_disables_unsafe_inline(self):
        result = scan_mock(headers={"Content-Type": "text/html", "Content-Security-Policy": "script-src 'nonce-c2VjcmV0' 'unsafe-inline'; frame-ancestors 'none'"})
        self.assertNotIn("WEB-CSP-INLINE", ids(result))
        self.assertNotIn("WEB-FRAMING", ids(result))
        self.assertNotIn("c2VjcmV0", str(result.to_dict()))

    def test_strict_parallel_policy_wins(self):
        result = scan_mock(headers={"Content-Type": "text/html", "Content-Security-Policy": ["script-src * 'unsafe-inline' 'unsafe-eval'", "default-src 'self'; frame-ancestors 'self'"]})
        self.assertNotIn("WEB-CSP-INLINE", ids(result))
        self.assertNotIn("WEB-CSP-EVAL", ids(result))
        self.assertNotIn("WEB-CSP-SOURCES", ids(result))

    def test_meta_does_not_supply_frame_ancestors(self):
        result = scan_mock(b'<meta http-equiv="Content-Security-Policy" content="default-src &#39;self&#39;; frame-ancestors &#39;none&#39;">')
        self.assertIn("WEB-CSP-META", ids(result))
        self.assertIn("WEB-FRAMING", ids(result))
        self.assertNotIn("WEB-CSP-MISSING", ids(result))

    def test_cookie_values_never_saved(self):
        result = scan_mock(headers={"Content-Type": "text/html", "Set-Cookie": ["session=TOPSECRET; Path=/", "csrf=HIDDEN; Secure; SameSite=Lax"]})
        self.assertIn("WEB-COOKIE-HTTPONLY", ids(result))
        self.assertIn("WEB-COOKIE-SECURE", ids(result))
        self.assertNotIn("TOPSECRET", str(result.to_dict()))
        self.assertNotIn("HIDDEN", str(result.to_dict()))

    def test_secure_flags_no_cookie_findings(self):
        result = scan_mock(headers={"Content-Type": "text/html", "Set-Cookie": "session=SECRET; Secure; HttpOnly; SameSite=Lax"})
        self.assertFalse([f for f in result.findings if f.category == "cookies"])

    def test_cookie_with_js_requirement_not_blanket_httponly_warning(self):
        result = scan_mock(headers={"Content-Type": "text/html", "Set-Cookie": "theme=dark; Secure; SameSite=Lax"})
        self.assertNotIn("WEB-COOKIE-HTTPONLY", ids(result))

    def test_cors_star_credentials_is_informational(self):
        result = scan_mock(headers={"Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
        finding = next(f for f in result.findings if f.rule_id == "WEB-CORS-CONFLICT")
        self.assertEqual(finding.severity, "info")


class HTMLTests(unittest.TestCase):
    def test_forms_not_submitted_and_password_get_identified(self):
        with patch.object(web, "_fetch", return_value=response(b'<form action="/auth" method="get"><input type="password" name="password" value="SECRET"></form>')) as fetch:
            result = web.scan_url("https://example.test", ["html"])
        self.assertEqual(fetch.call_count, 1)
        self.assertIn("WEB-PASSWORD-GET", ids(result))
        self.assertNotIn("SECRET", str(result.to_dict()))
        self.assertFalse(any("csrf" in f.rule_id.lower() for f in result.findings))

    def test_unnamed_or_disabled_password_not_submitted(self):
        result = scan_mock(b'<form><input type="password"><input type="password" name="p" disabled></form>', modules=["html"])
        self.assertNotIn("WEB-PASSWORD-GET", ids(result))

    def test_mixed_content_and_base(self):
        result = scan_mock(b'<base href="http://cdn.example.test/"><script src="app.js"></script>', modules=["html"])
        self.assertIn("WEB-MIXED-CONTENT", ids(result))
        self.assertIn("WEB-SRI", ids(result))

    def test_bad_embedded_urls_do_not_crash(self):
        result = scan_mock(b'<script src="https://x:invalid/a"></script><form action="http://["><input type="password" name="p"></form>', modules=["html"])
        self.assertTrue(result.notes)
        self.assertTrue(result.completed_at)


class FailureTests(unittest.TestCase):
    def test_audit_response_never_opens_network(self):
        with patch.object(web, "_fetch") as fetch, patch.object(web.socket, "create_connection") as socket:
            result = web.audit_response("https://example.test/?token=SECRET", 200,
                [("Content-Type", "text/html"), ("Set-Cookie", "session=COOKIE_SECRET")], b"<html></html>")
        fetch.assert_not_called()
        socket.assert_not_called()
        self.assertEqual(result.metadata["http_requests"], 0)
        self.assertNotIn("SECRET", str(result.to_dict()))

    def test_audit_response_rejects_malformed_input(self):
        cases = [dict(url=[], status=200, headers={}, body=b""),
                 dict(url="https://example.test", status=True, headers={}, body=b""),
                 dict(url="https://example.test", status=200, headers={"X": "SECRET\n"}, body=b""),
                 dict(url="https://example.test", status=200, headers={}, body=b"", modules=[{}])]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                result = web.audit_response(**kwargs)
                self.assertTrue(result.errors)
                self.assertNotIn("SECRET", str(result.to_dict()))

    def test_network_failure_does_not_echo_secrets(self):
        with patch.object(web, "_fetch", side_effect=URLError("https://x?password=SECRET")):
            result = web.scan_url("https://example.test/?password=SECRET", ["headers"])
        self.assertTrue(result.errors)
        self.assertNotIn("SECRET", str(result.to_dict()))
        self.assertFalse(result.to_dict()["complete"])

    def test_invalid_timeout_and_modules_do_not_fetch(self):
        with patch.object(web, "_fetch") as fetch:
            self.assertTrue(web.scan_url("https://example.test", ["headers"], timeout=0).errors)
            self.assertTrue(web.scan_url("https://example.test", ["unknown"]).errors)
            self.assertTrue(web.scan_url("https://example.test", []).errors)
        fetch.assert_not_called()

    def test_403_is_partial_not_clean(self):
        result = scan_mock(status=403)
        self.assertFalse(result.to_dict()["complete"])
        self.assertIn("403", result.errors[0])

    def test_tls_only_does_not_fetch_http(self):
        with patch.object(web, "_fetch") as fetch, patch.object(web, "_check_tls") as tls:
            web.scan_url("https://example.test", ["tls"])
        fetch.assert_not_called()
        tls.assert_called_once()

    def test_tls_verification_failure_is_reported(self):
        result = ScanResult(kind="web", target="https://example.test", metadata={"tls_handshakes": 0})
        with patch.object(web.socket, "create_connection", side_effect=ssl.SSLCertVerificationError("untrusted")):
            web._check_tls(result.target, 1, result)
        self.assertIn("WEB-CERT-INVALID", ids(result))
        self.assertTrue(result.errors)


class LocalTransportTests(unittest.TestCase):
    def test_real_http_stack_fetches_once_and_preserves_bounded_read(self):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.path)
                body = b'<html><form method="post"></form></html>'
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = web.scan_url(f"http://127.0.0.1:{server.server_port}/one?x=unchanged", ["headers", "html"], timeout=2)
            self.assertFalse(result.errors)
            self.assertEqual(received, ["/one?x=unchanged"])
            self.assertEqual(result.metadata["http_requests"], 1)
            self.assertEqual(result.metadata["http_status"], 200)
            self.assertNotIn("unchanged", str(result.to_dict()))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
