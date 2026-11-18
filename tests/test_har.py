import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lulz import har, web


def entry(url="https://example.test/page", body="<html><body>hello</body></html>", status=200, headers=None):
    content = {"mimeType": "text/html", "size": 42}
    if body is not None:
        content["text"] = body
    return {"request": {"url": url, "method": "GET", "headers": [], "cookies": []},
            "response": {"status": status, "headers": headers if headers is not None else [
                {"name": "Content-Type", "value": "text/html; charset=utf-8"}], "content": content}}


class HarTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "capture.har"

    def capture(self, entries, modules=None, host=None):
        self.path.write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}, ensure_ascii=False), encoding="utf-8")
        return har.scan_har(str(self.path), modules=modules, host=host)

    def test_offline_multi_response_no_fetch_or_socket(self):
        with patch.object(web, "_fetch") as fetch, patch.object(web.socket, "create_connection") as socket:
            result = self.capture([entry(), entry("https://example.test/two")])
        fetch.assert_not_called()
        socket.assert_not_called()
        self.assertEqual(result.metadata["entries_analyzed"], 2)
        self.assertEqual(result.metadata["http_requests"], 0)
        self.assertTrue(result.to_dict()["complete"])
        self.assertEqual(result.kind, "har")
        self.assertIsNone(result.metadata["scope_host"])

    def test_query_cookie_auth_post_body_and_nonce_values_are_not_exported(self):
        record = entry("https://example.test/page?access_token=CAPTURE_SECRET", body='<input value="BODY_SECRET">', headers=[
            {"name": "Content-Type", "value": "text/html"},
            {"name": "Set-Cookie", "value": "session=COOKIE_SECRET; Path=/"},
            {"name": "Content-Security-Policy", "value": "script-src 'nonce-NONCESECRET' 'unsafe-inline'"}])
        record["request"]["headers"].append({"name": "Authorization", "value": "Bearer AUTH_SECRET"})
        record["request"]["postData"] = {"text": "POST_SECRET"}
        result = self.capture([record])
        exported = json.dumps(result.to_dict())
        for secret in ("CAPTURE_SECRET", "COOKIE_SECRET", "BODY_SECRET", "NONCESECRET", "AUTH_SECRET", "POST_SECRET"):
            self.assertNotIn(secret, exported)
        self.assertIn("redacted", exported)

    def test_duplicate_set_cookie_headers_are_preserved(self):
        result = self.capture([entry(headers=[{"name": "Content-Type", "value": "text/html"},
            {"name": "Set-Cookie", "value": "session_first=FIRST_SECRET"},
            {"name": "Set-Cookie", "value": "session_second=SECOND_SECRET"}])], ["cookies"])
        secure = [f for f in result.findings if f.rule_id == "WEB-COOKIE-SECURE"]
        self.assertEqual(len(secure), 2)
        self.assertTrue(any("session_first" in f.location for f in secure))
        self.assertTrue(any("session_second" in f.location for f in secure))

    def test_exact_host_not_suffix_match_and_canonical_scope(self):
        result = self.capture([entry(), entry("https://example.test.evil.invalid/"),
                               entry("https://other.example.test/")], host="EXAMPLE.TEST.")
        self.assertEqual(result.metadata["entries_analyzed"], 1)
        self.assertEqual(result.metadata["entries_filtered"], 2)
        self.assertEqual(result.metadata["scope_host"], "example.test")
        self.assertTrue(result.to_dict()["complete"])

    def test_invalid_host_does_not_read_capture(self):
        for host in ("https://example.test", "*.test", "example.test:443", "bad host", "example.test/path"):
            with self.subTest(host=host):
                result = har.scan_har(str(self.path), host=host)
                self.assertTrue(result.errors)
                self.assertEqual(result.metadata["entries_analyzed"], 0)

    def test_empty_or_fully_filtered_capture_is_not_clean(self):
        self.assertFalse(self.capture([]).to_dict()["complete"])
        result = self.capture([entry()], host="other.test")
        self.assertEqual(result.metadata["entries_analyzed"], 0)
        self.assertFalse(result.to_dict()["complete"])

    def test_base64_body_is_decoded_without_network(self):
        record = entry(body=base64.b64encode(b'<form method="get"><input type="password" name="p"></form>').decode())
        record["response"]["content"]["encoding"] = "base64"
        result = self.capture([record], ["html"])
        self.assertIn("WEB-PASSWORD-GET", {f.rule_id for f in result.findings})
        self.assertTrue(result.to_dict()["complete"])

    def test_invalid_base64_is_partial_and_does_not_echo_text(self):
        record = entry(body="%%%SECRET_INVALID_BASE64")
        record["response"]["content"]["encoding"] = "base64"
        result = self.capture([record], ["html"])
        self.assertFalse(result.to_dict()["complete"])
        self.assertEqual(result.metadata["body_unavailable"], 1)
        self.assertNotIn("SECRET_INVALID_BASE64", str(result.to_dict()))
        self.assertTrue(any(check["status"] == "skipped" for check in result.checks if check["module"] == "html"))

    def test_missing_body_skips_html_and_csp_claims(self):
        result = self.capture([entry(body=None)])
        self.assertFalse(result.to_dict()["complete"])
        self.assertNotIn("WEB-CSP-MISSING", {f.rule_id for f in result.findings})
        self.assertEqual(result.metadata["body_unavailable"], 1)

    def test_cookie_only_missing_body_can_be_complete(self):
        result = self.capture([entry(body=None)], ["cookies"])
        self.assertTrue(result.to_dict()["complete"])
        self.assertFalse(result.metadata["coverage"][0]["body_required"])

    def test_empty_204_and_head_do_not_require_saved_body(self):
        no_content = entry(body=None, status=204)
        head = entry(body=None)
        head["request"]["method"] = "HEAD"
        result = self.capture([no_content, head])
        self.assertTrue(result.to_dict()["complete"])
        self.assertEqual(result.metadata["body_unavailable"], 0)
        self.assertNotIn("WEB-CSP-MISSING", {f.rule_id for f in result.findings})

    def test_plain_har_text_is_already_decoded(self):
        record = entry(body='<form action="/проверка"><input type="password" name="p"></form>',
                       headers=[{"name": "Content-Type", "value": "text/html; charset=windows-1251"}])
        result = self.capture([record], ["html"])
        finding = next(f for f in result.findings if f.rule_id == "WEB-PASSWORD-GET")
        self.assertIn("%D0%BF", finding.evidence)
        self.assertNotIn("%D0%A0", finding.evidence)

    def test_identical_observations_deduplicate_and_status_is_distinct(self):
        result = self.capture([entry(), entry(), entry(status=403)], ["headers"])
        findings = [f for f in result.findings if f.rule_id == "WEB-HSTS"]
        self.assertEqual(len(findings), 2)
        self.assertTrue(any("HTTP 200" in f.location for f in findings))
        self.assertTrue(any("HTTP 403" in f.location for f in findings))

    def test_non_http_and_cancelled_entries_are_skipped(self):
        result = self.capture([entry("file:///private/SECRET_FILE"), entry(status=0), entry()])
        self.assertEqual(result.metadata["entries_skipped"], 2)
        self.assertEqual(result.metadata["entries_analyzed"], 1)
        self.assertFalse(result.to_dict()["complete"])
        self.assertNotIn("SECRET_FILE", str(result.to_dict()))

    def test_entry_limit_visible(self):
        with patch.object(har, "MAX_ENTRIES", 2):
            result = self.capture([entry(), entry(), entry()])
        self.assertEqual(result.metadata["entries_total"], 3)
        self.assertEqual(result.metadata["entries_considered"], 2)
        self.assertFalse(result.to_dict()["complete"])

    def test_whole_body_budget_and_individual_cap(self):
        with patch.object(har, "MAX_TOTAL_BODY_BYTES", 20):
            result = self.capture([entry(body="a" * 12), entry(body="b" * 12), entry(body="c" * 12)], ["html"])
        self.assertLessEqual(result.metadata["body_bytes_analyzed"], 20)
        self.assertFalse(result.to_dict()["complete"])
        self.assertTrue(any("бюджет" in note for note in result.notes))
        record = entry(body=base64.b64encode(b'x' * 40).decode())
        record['response']['content']['encoding'] = 'base64'
        with patch.object(har, "MAX_BODY", 16):
            result = self.capture([record], ["html"])
        self.assertEqual(result.metadata['body_bytes_analyzed'], 0)
        self.assertFalse(result.to_dict()['complete'])

    def test_file_limit_and_malformed_json(self):
        self.path.write_text("not-json SECRET", encoding="utf-8")
        result = har.scan_har(str(self.path))
        self.assertTrue(result.errors)
        self.assertNotIn("SECRET", str(result.to_dict()))
        self.path.write_text('{"log":{"entries":[]}}', encoding='utf-8')
        with patch.object(har, "MAX_FILE_BYTES", 4):
            self.assertTrue(har.scan_har(str(self.path)).errors)

    def test_missing_headers_and_malformed_data_not_success(self):
        for invalid in (None, {"request": []}, entry(headers=[{"name": "bad\nname", "value": "SECRET"}])):
            with self.subTest(invalid=invalid):
                result = self.capture([invalid])
                self.assertFalse(result.to_dict()["complete"])
                self.assertNotIn("SECRET", str(result.to_dict()))
                self.assertEqual(result.metadata["entries_analyzed"], 0)

    def test_empty_text_with_nonzero_recorded_body_is_partial(self):
        result = self.capture([entry(body="")], ["html"])
        self.assertFalse(result.to_dict()["complete"])
        self.assertEqual(result.metadata["body_unavailable"], 1)

    def test_invalid_modules_and_symbolic_file_are_rejected(self):
        for modules in (["tls"], [], [{}], "headers"):
            self.assertTrue(har.scan_har(str(self.path), modules=modules).errors)
        self.path.write_text('{"log":{"entries":[]}}', encoding='utf-8')
        link = self.path.parent / 'link.har'
        try:
            link.symlink_to(self.path)
        except (OSError, NotImplementedError):
            return
        self.assertTrue(har.scan_har(str(link)).errors)


if __name__ == "__main__":
    unittest.main()
