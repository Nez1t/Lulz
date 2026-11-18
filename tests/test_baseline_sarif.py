import base64
import copy
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import tempfile
import unittest

from lulz.baseline import apply_baseline
from lulz.models import Finding, ScanResult
from lulz.reports import compare_reports, load_report, plain, render_html, render_sarif, save_reports


def finding(rule="TEST-1", location="src/app.py:12", **changes):
    values = dict(rule_id=rule, title="Кандидат", severity="medium", category="xss",
                  description="Требуется проверка контекста", evidence="API: render", remediation="Экранировать вывод",
                  location=location, status="review", confidence="medium", cwe=["CWE-79"], cve=[])
    values.update(changes)
    return Finding(**values)


def scan(*items, **kwargs):
    values = dict(kind="source", target="project", modules=["xss"], findings=list(items))
    values.update(kwargs)
    return ScanResult(**values).finish()


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def baseline(self, result):
        return save_reports(result, self.root)["json"]

    def test_new_unchanged_updated_and_not_seen_preserve_findings(self):
        before = scan(finding(), finding("TEST-2"), finding("TEST-4"))
        path = self.baseline(before)
        after = scan(finding(), finding("TEST-2", severity="high"), finding("TEST-3"))
        result = apply_baseline(after, path)
        states = {item.rule_id: item.baseline_state for item in result.findings}
        self.assertEqual(states, {"TEST-1": "unchanged", "TEST-2": "updated", "TEST-3": "new"})
        self.assertEqual(len(result.findings), 3)
        self.assertEqual(result.metadata['baseline']['new'], 1)
        self.assertEqual(result.metadata['baseline']['updated'], 1)
        self.assertEqual(result.metadata['baseline']['not_seen'], 1)
        self.assertNotIn(str(self.root), result.metadata['baseline']['file'])

    def test_status_or_confidence_changes_are_not_waived(self):
        path = self.baseline(scan(finding()))
        for change in ({"status": "observed"}, {"confidence": "high"}, {"cve": ["CVE-2025-12345"]}):
            with self.subTest(change=change):
                result = apply_baseline(scan(finding(**change)), path)
                self.assertEqual(result.findings[0].baseline_state, "updated")

    def test_incomplete_baseline_or_current_rejected_without_mutation(self):
        path = self.baseline(scan(finding()))
        current = scan(finding(), errors=["timeout"])
        with self.assertRaises(ValueError):
            apply_baseline(current, path)
        self.assertEqual(current.findings[0].baseline_state, "")
        partial = self.baseline(scan(finding(), metadata={"incomplete": True}))
        with self.assertRaises(ValueError):
            apply_baseline(scan(finding()), partial)

    def test_project_offline_inventory_not_compatible_with_online(self):
        def project(online):
            return scan(finding(), kind="project", modules=["source.xss", "dependencies"],
                        metadata={"components": {"dependencies": {"online": online, "advisories_checked": online}}})
        path = self.baseline(project(True))
        with self.assertRaises(ValueError):
            apply_baseline(project(False), path)
        self.assertIn("CVE не проверялись (офлайн)", render_html(project(False).to_dict()))

    def test_host_scope_mismatch_rejected(self):
        before = scan(finding(), kind="har", modules=["headers"], metadata={"scope_host": "example.org"})
        after = scan(finding(), kind="har", modules=["headers"], metadata={"scope_host": None})
        with self.assertRaises(ValueError):
            apply_baseline(after, self.baseline(before))

    def test_old_v1_report_without_baseline_field_supported(self):
        data = scan(finding()).to_dict()
        data["findings"][0].pop("baseline_state")
        data["tool"]["version"] = "1.0.0"
        data["findings"][0]["fingerprint"] = "untrusted-value"
        path = self.root / "v1.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        result = apply_baseline(scan(finding()), path)
        self.assertEqual(result.findings[0].baseline_state, "unchanged")

    def test_diff_reports_changed_severity(self):
        before = scan(finding()).to_dict()
        after = scan(finding(severity="high")).to_dict()
        diff = compare_reports(before, after)
        self.assertEqual(len(diff["updated"]), 1)
        self.assertEqual(diff["unchanged"], 0)

    def test_bad_nested_report_shapes_and_false_complete_are_handled(self):
        for change in ({"cwe": [None]}, {"references": "https://example.org"}, {"severity": "bogus"}, {"baseline_state": {}}):
            data = scan(finding()).to_dict()
            data["findings"][0].update(change)
            path = self.root / "bad.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.subTest(change=change), self.assertRaises(ValueError):
                load_report(path)
        data = scan(finding()).to_dict()
        data["errors"] = ["incomplete"]
        data["complete"] = True
        path.write_text(json.dumps(data), encoding="utf-8")
        self.assertFalse(load_report(path)["complete"])

    def test_deep_or_nonfinite_json_rejected(self):
        data = scan().to_dict()
        branch = data["metadata"]
        for _ in range(80):
            branch["child"] = {}
            branch = branch["child"]
        path = self.root / "deep.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ValueError):
            load_report(path)
        data = scan().to_dict()
        data["metadata"]["bad"] = float("nan")
        path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ValueError):
            load_report(path)


class _ReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts, self.current_script, self.csp, self.inputs = [], None, "", []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script":
            self.current_script = ""
        if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy":
            self.csp = attrs["content"]
        if tag in {"input", "select", "button"}:
            self.inputs.append(attrs.get("id"))

    def handle_data(self, text):
        if self.current_script is not None:
            self.current_script += text

    def handle_endtag(self, tag):
        if tag == "script" and self.current_script is not None:
            self.scripts.append(self.current_script)
            self.current_script = None


class ExportTests(unittest.TestCase):
    def test_sarif_file_locations_and_fingerprints(self):
        result = scan(finding(location=r"C:\Projects\мой файл.py:12"),
                      finding("TEST-2", location="/tmp/my file.py:5"),
                      finding("TEST-3", location="src/app.js:3"))
        sarif = render_sarif(result.to_dict())
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        locations = {entry["ruleId"]: entry["locations"][0]["physicalLocation"] for entry in run["results"]}
        self.assertTrue(locations["TEST-1"]["artifactLocation"]["uri"].startswith("file:///C:/Projects/"))
        self.assertIn("%20", locations["TEST-1"]["artifactLocation"]["uri"])
        self.assertEqual(locations["TEST-2"]["artifactLocation"]["uri"], "file:///tmp/my%20file.py")
        self.assertEqual(locations["TEST-3"]["artifactLocation"]["uri"], "src/app.js")
        self.assertEqual(locations["TEST-1"]["region"]["startLine"], 12)
        self.assertIn("lulzRuleLocationEvidence/v1", run["results"][0]["partialFingerprints"])
        for entry in run["results"]:
            self.assertEqual(run["tool"]["driver"]["rules"][entry["ruleIndex"]]["id"], entry["ruleId"])

    def test_sarif_web_location_redacts_credentials_query_and_fragment(self):
        result = scan(finding(location="https://user:pass@example.org/page?token=secret#fragment"), kind="web")
        uri = render_sarif(result.to_dict())["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for secret in ("user", "pass", "secret", "fragment"):
            self.assertNotIn(secret, uri)
        self.assertTrue(uri.startswith("https://example.org/page?token="))

    def test_sarif_failure_and_baseline_only_when_applied(self):
        result = scan(finding(baseline_state="unchanged"), errors=["timeout"])
        data = result.to_dict()
        sarif = render_sarif(data)
        self.assertFalse(sarif["runs"][0]["invocations"][0]["executionSuccessful"])
        self.assertNotIn("baselineState", sarif["runs"][0]["results"][0])
        data = scan(finding(baseline_state="new"), metadata={"baseline": {"applied": True}}).to_dict()
        self.assertEqual(render_sarif(data)["runs"][0]["results"][0]["baselineState"], "new")

    def test_html_script_is_fixed_and_hash_matches_csp(self):
        payload = '</script><img src=x onerror="alert(1)">'
        data = scan(finding(title=payload, category='xss" onmouseover="bad()', evidence=payload)).to_dict()
        html = render_html(data)
        parser = _ReportParser()
        parser.feed(html)
        self.assertEqual(len(parser.scripts), 1)
        self.assertNotIn(payload, html)
        digest = base64.b64encode(hashlib.sha256(parser.scripts[0].encode("utf-8")).digest()).decode("ascii")
        self.assertIn("'sha256-" + digest + "'", parser.csp)
        self.assertNotIn("unsafe-inline", parser.csp.split("script-src", 1)[1].split(";", 1)[0])
        self.assertNotIn("innerHTML", parser.scripts[0])
        self.assertIn("filter-search", parser.inputs)
        self.assertIn("filter-reset", parser.inputs)

    def test_terminal_bidi_controls_are_removed(self):
        self.assertEqual(plain("abc\u202edef\u2066ghi"), "abcdefghi")


if __name__ == "__main__":
    unittest.main()
