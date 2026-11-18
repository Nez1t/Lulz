from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lulz.cli import main, _parse_modules
from lulz.models import Finding, ScanResult
from lulz.reports import compare_reports, load_report, plain, render_html, save_reports, report_history


def result_with(evidence="Проверка атрибута"):
    result = ScanResult(kind="source", target="project", modules=["xss"])
    result.findings.append(Finding(rule_id="TEST-1", title="Кандидат", severity="medium", category="xss",
        description="Нужна проверка контекста", evidence=evidence, remediation="Контекстное экранирование",
        location="app.js:7", cwe=["CWE-79"]))
    return result.finish()


class ReportTests(unittest.TestCase):
    def test_reports_are_unicode_and_html_is_escaped(self):
        result = result_with('<img src="x" onerror="bad()">\x1b[31m')
        result.findings[0].references = ["javascript:bad()", "https://example.org/reference"]
        with tempfile.TemporaryDirectory() as temporary:
            paths = save_reports(result, temporary)
            self.assertEqual(set(paths), {"html", "json", "md", "sarif"})
            data = load_report(paths['json'])
            html = paths['html'].read_text(encoding='utf-8')
            self.assertNotIn('<img src="x"', html)
            self.assertIn('&lt;img', html)
            self.assertNotIn('href="javascript:', html)
            self.assertNotIn('\x1b', html)
            self.assertIn('Кандидат', html)
            self.assertEqual(data['findings'][0]['cwe'], ['CWE-79'])
            self.assertEqual(data['findings'][0]['cve'], [])
            self.assertEqual(len(report_history(temporary)), 1)

    def test_filenames_do_not_overwrite_concurrent_same_second(self):
        with tempfile.TemporaryDirectory() as temporary:
            a = save_reports(result_with(), temporary)
            b = save_reports(result_with(), temporary)
            self.assertNotEqual(a['json'], b['json'])
            self.assertTrue(a['json'].exists())

    def test_partial_empty_result_never_claims_safe(self):
        result = ScanResult(kind='web', target='https://example.org', errors=['timeout']).finish()
        data = result.to_dict()
        self.assertFalse(data['complete'])
        html = render_html(data)
        self.assertIn('Проверка неполная', html)
        self.assertIn('не подтверждает отсутствие', html)

    def test_comparison_validates_scope_and_distinguishes_missing(self):
        a = result_with().to_dict()
        b = result_with('другое доказательство').to_dict()
        diff = compare_reports(a, b)
        self.assertEqual(len(diff['new']), 1)
        self.assertEqual(len(diff['not_seen']), 1)
        self.assertFalse(diff['partial'])
        b['complete'] = False
        self.assertTrue(compare_reports(a, b)['partial'])
        b['target'] = 'another'
        with self.assertRaises(ValueError):
            compare_reports(a, b)
        b['target'] = a['target']
        b['modules'] = ['sql']
        with self.assertRaises(ValueError):
            compare_reports(a, b)

    def test_imported_fingerprints_do_not_control_diff(self):
        a = result_with().to_dict()
        b = result_with().to_dict()
        b['findings'][0]['fingerprint'] = 'untrusted-fingerprint'
        self.assertEqual(compare_reports(a, b)['unchanged'], 1)

    def test_offline_inventory_cannot_make_online_advisory_disappear(self):
        before = ScanResult(kind='dependencies', target='project', modules=['dependencies'],
                            metadata={'online': True, 'advisories_checked': True}).finish().to_dict()
        after = ScanResult(kind='dependencies', target='project', modules=['dependencies'],
                           metadata={'online': False, 'advisories_checked': False}).finish().to_dict()
        with self.assertRaises(ValueError):
            compare_reports(before, after)
        self.assertIn('поиск CVE не выполнялся', render_html(after))

    def test_invalid_modules_do_not_crash_comparison(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'report.json'
            for modules in (None, [None], [{}], 'xss'):
                data = result_with().to_dict()
                data['modules'] = modules
                path.write_text(json.dumps(data), encoding='utf-8')
                with self.assertRaises(ValueError):
                    load_report(path)

    def test_malformed_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'report.json'
            path.write_text(json.dumps({'target': 'x', 'findings': []}), encoding='utf-8')
            with self.assertRaises(ValueError):
                load_report(path)

    def test_plain_removes_terminal_controls(self):
        self.assertEqual(plain('\x1b[31mHello\x1b[0m\x00'), 'Hello')


class CliTests(unittest.TestCase):
    def test_invalid_module_rejected_before_request(self):
        with self.assertRaises(ValueError):
            _parse_modules('sql', {'headers': 'HTTP'})

    def test_command_line_returns_partial_failure(self):
        result = ScanResult(kind='web', target='https://example.org', errors=['timeout']).finish()
        with tempfile.TemporaryDirectory() as temporary, patch('lulz.web.scan_url', return_value=result), redirect_stdout(StringIO()):
            self.assertEqual(main(['--no-color', 'web', 'https://example.org', '--output', temporary]), 1)

    def test_fail_threshold_is_operational(self):
        result = result_with()
        with tempfile.TemporaryDirectory() as temporary, patch('lulz.source.scan_source', return_value=result), redirect_stdout(StringIO()):
            self.assertEqual(main(['source', '.', '--no-color', '--fail-on', 'medium', '--output', temporary]), 2)

    def test_menu_exit_needs_no_network(self):
        output = StringIO()
        with patch('builtins.input', return_value='0'), redirect_stdout(output):
            self.assertEqual(main(['--no-color']), 0)
        self.assertIn('Проверить URL', output.getvalue())


if __name__ == '__main__':
    unittest.main()
