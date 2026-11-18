from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lulz.cli import main
from lulz.models import Finding, ScanResult
from lulz.project import scan_project
from lulz.reports import save_reports


class ProjectIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_combines_local_results_without_network(self):
        (self.root / 'app.py').write_text('def lookup(db, name):\n    db.execute(f"SELECT id FROM items WHERE name={name}")\n', encoding='utf-8')
        (self.root / 'Dockerfile').write_text('FROM example/runtime:1\nUSER root\n', encoding='utf-8')
        (self.root / 'requirements.txt').write_text('demo==1.2.3\n', encoding='utf-8')
        with patch('lulz.dependencies._post_query', side_effect=AssertionError('network')):
            result = scan_project(str(self.root))
        self.assertEqual(result.kind, 'project')
        self.assertEqual(set(result.metadata['components']), {'source', 'project_checks', 'dependencies'})
        self.assertTrue(any(f.category == 'sql' for f in result.findings))
        self.assertTrue(any(f.rule_id.startswith('CFG-') for f in result.findings))
        self.assertFalse(result.metadata['components']['dependencies']['advisories_checked'])

    def test_missing_dependency_manifest_not_silent(self):
        (self.root / 'app.py').write_text('pass\n', encoding='utf-8')
        result = scan_project(str(self.root), modules=['source', 'dependencies'])
        self.assertTrue(result.metadata['incomplete'])
        self.assertTrue(any(c.get('status') == 'skipped' for c in result.checks))
        self.assertNotIn('dependencies', result.metadata['sections_completed'])
        self.assertEqual(result.metadata['component_status']['dependencies'], 'skipped')

    def test_quick_profile_omits_dependency_calls(self):
        (self.root / 'app.py').write_text('pass\n', encoding='utf-8')
        with patch('lulz.dependencies.scan_dependencies', side_effect=AssertionError('unexpected deps')), redirect_stdout(StringIO()):
            code = main(['project', str(self.root), '--profile', 'quick', '--output', str(self.root / 'out')])
        self.assertIn(code, (0, 1))
        paths = list((self.root / 'out').glob('*/report.json'))
        self.assertEqual(len(paths), 1)
        report = json.loads(paths[0].read_text(encoding='utf-8'))
        self.assertNotIn('dependencies', report['modules'])

    def test_new_only_requires_baseline_before_scan(self):
        with patch('lulz.web.scan_url', side_effect=AssertionError('network')), redirect_stdout(StringIO()):
            self.assertEqual(main(['web', 'https://example.invalid', '--new-only']), 1)

    def test_unchanged_findings_do_not_fail_new_only_threshold(self):
        def result():
            return ScanResult(kind='source', target='project', modules=['sql'], findings=[Finding(
                rule_id='SRC-SQL-DYNAMIC', title='Candidate', severity='high', category='sql', description='Review',
                evidence='Dynamic SQL', remediation='Parameterize', location='app.py:4')]).finish()
        baseline = save_reports(result(), self.root / 'baseline')['json']
        with patch('lulz.source.scan_source', side_effect=lambda *a, **k: result()), redirect_stdout(StringIO()):
            code = main(['source', 'project', '--checks', 'sql', '--baseline', str(baseline), '--new-only',
                         '--fail-on', 'medium', '--output', str(self.root / 'current')])
        self.assertEqual(code, 0)

    def test_incompatible_baseline_still_saves_current_report(self):
        baseline = save_reports(ScanResult(kind='source', target='different', modules=['sql']).finish(), self.root / 'baseline')['json']
        current = ScanResult(kind='source', target='project', modules=['sql']).finish()
        with patch('lulz.source.scan_source', return_value=current), redirect_stdout(StringIO()):
            code = main(['source', 'project', '--checks', 'sql', '--baseline', str(baseline), '--output', str(self.root / 'out')])
        self.assertEqual(code, 1)
        report = json.loads(next((self.root / 'out').glob('*/report.json')).read_text(encoding='utf-8'))
        self.assertFalse(report['complete'])

    def test_removed_baseline_does_not_lose_scan_report(self):
        result = ScanResult(kind='source', target='project', modules=['sql']).finish()
        baseline = save_reports(result, self.root / 'baseline')['json']
        def scan(*args, **kwargs):
            baseline.unlink()
            return result
        with patch('lulz.source.scan_source', side_effect=scan), redirect_stdout(StringIO()):
            code = main(['source', 'project', '--checks', 'sql', '--baseline', str(baseline), '--output', str(self.root / 'out')])
        self.assertEqual(code, 1)
        self.assertEqual(len(list((self.root / 'out').glob('*/report.json'))), 1)


if __name__ == '__main__':
    unittest.main()
