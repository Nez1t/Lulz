"""Contract tests for source review: no execution, no vulnerability claims."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lulz.source import scan_source


class SourceReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def file(self, text, name="app.py"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def scan(self, text, name="app.py", modules=None):
        return scan_source(str(self.file(text, name)), modules)

    def ids(self, result):
        return {finding.rule_id for finding in result.findings}

    def test_dynamic_sql_and_parameter_binding_are_distinguished(self):
        result = self.scan('''def lookup(cursor, name):
    dynamic = f"SELECT id FROM users WHERE name = {name}"
    cursor.execute(dynamic)
    cursor.execute("SELECT id FROM users WHERE name = ?", (name,))
''', modules=["sql"])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].cwe, ["CWE-89"])
        self.assertEqual(result.findings[0].location, "app.py:3")
        self.assertEqual(result.findings[0].status, "review")
        self.assertEqual(result.findings[0].cve, [])

    def test_dynamic_format_and_percent_queries(self):
        result = self.scan('''def lookup(cursor, name):
    cursor.execute("SELECT id FROM users WHERE name = {}".format(name))
    cursor.execute("SELECT id FROM users WHERE name = %s" % name)
''', modules=["sql"])
        self.assertEqual(len(result.findings), 2)

    def test_function_scopes_do_not_share_query_bindings(self):
        result = self.scan('''query = "SELECT id FROM users WHERE name = " + request_name
def lookup(cursor, query):
    cursor.execute(query)
def another(cursor):
    query = "SELECT id FROM users"
    cursor.execute(query)
''', modules=["sql"])
        self.assertEqual(result.findings, [])

    def test_reassignment_invalidates_dynamic_value(self):
        result = self.scan('''query = "SELECT id FROM users WHERE name = " + request_name
query = "SELECT id FROM users WHERE name = ?"
cursor.execute(query, (request_name,))
''', modules=["sql"])
        self.assertEqual(result.findings, [])

    def test_conditional_bindings_are_not_assumed_unconditionally(self):
        result = self.scan('''if condition:
    query = "SELECT id FROM users WHERE name = " + request_name
else:
    query = "SELECT id FROM users"
cursor.execute(query)
''', modules=["sql"])
        self.assertEqual(result.findings, [])

    def test_sql_alias_assignment_is_followed_within_scope(self):
        result = self.scan('''def lookup(cursor, name):
    query = "SELECT id FROM users WHERE name = " + name
    alias = query
    cursor.execute(alias)
''', modules=["sql"])
        self.assertEqual(len(result.findings), 1)

    def test_bound_targets_do_not_reuse_outer_dynamic_sql(self):
        result = self.scan('''query = "SELECT id FROM users WHERE name = " + name
[cursor.execute(query) for query in fixed_queries]
with acquire_query() as query:
    cursor.execute(query)
''', modules=["sql"])
        self.assertEqual(result.findings, [])

    def test_xss_bypass_and_fixed_markup(self):
        result = self.scan('''from django.utils.safestring import mark_safe
from markupsafe import Markup
a = mark_safe(value)
b = Markup("<p>fixed text</p>")
''', modules=["xss"])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].cwe, ["CWE-79"])

    def test_yaml_safe_loader_and_pickle_aliases(self):
        result = self.scan('''import yaml as y
from yaml import SafeLoader
from pickle import loads as unpack
y.load(data, Loader=SafeLoader)
y.safe_load(data)
y.load(data, Loader=y.Loader)
unpack(data)
''', modules=["code"])
        self.assertEqual(self.ids(result), {"SRC-CODE-YAML", "SRC-CODE-PICKLE"})
        self.assertEqual(len(result.findings), 2)

    def test_shell_array_safe_and_shell_string_candidate(self):
        result = self.scan('''import subprocess
subprocess.run(["tool", argument], shell=False)
subprocess.run(command, shell=True)
''', modules=["code"])
        self.assertEqual(self.ids(result), {"SRC-CODE-SHELL"})
        self.assertEqual(len(result.findings), 1)

    def test_config_options(self):
        result = self.scan('''import requests
DEBUG = True
requests.get(url, verify=False)
requests.get(url, verify=True)
''', modules=["config"])
        self.assertEqual(self.ids(result), {"SRC-CONFIG-DEBUG", "SRC-CONFIG-TLS"})

    def test_no_source_or_secret_values_in_report(self):
        result = self.scan('''import requests
secret = "SPECIAL_SECRET_123456"
requests.get("https://internal.example/?token=SPECIAL_SECRET_123456", verify=False)
''', modules=["config"])
        self.assertNotIn("SPECIAL_SECRET_123456", str(result.to_dict()))
        self.assertNotIn("internal.example", str(result.to_dict()))

    def test_javascript_static_and_dynamic_html(self):
        result = self.scan('''element.innerHTML = "<p>fixed</p>";
element.innerHTML = value;
element.textContent = value;
element.innerHTML = DOMPurify.sanitize(value);
// other.innerHTML = request_value;
''', "client.js", ["xss"])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].location, "client.js:2")

    def test_javascript_sql_heuristic_excludes_parameterized_query(self):
        result = self.scan('''db.query("SELECT id FROM users WHERE name = ?", [name]);
db.query(`SELECT id FROM users WHERE name = ${name}`);
''', "db.js", ["sql"])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].confidence, "low")

    def test_php_raw_output_and_escaped_output(self):
        result = self.scan('''<?php
echo $_GET['name'];
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
''', "index.php", ["xss"])
        self.assertEqual(len(result.findings), 1)

    def test_template_escaping_and_comments(self):
        result = self.scan('''<p>{{ user_name }}</p>
<p>{{ user_name | safe }}</p>
<!-- <p>{{ other_name | safe }}</p> -->
''', "page.html", ["xss"])
        self.assertEqual(len(result.findings), 1)

    def test_excluded_directories_and_symlinks(self):
        self.file("eval(value)\n", "node_modules/vendor.py")
        self.file("eval(value)\n", ".git/hidden.py")
        self.file("pass\n", "real.py")
        outside = self.root.parent / (self.root.name + "-outside.py")
        outside.write_text("eval(value)\n", encoding="utf-8")
        try:
            try:
                (self.root / "linked.py").symlink_to(outside)
            except (OSError, NotImplementedError):
                pass
            result = scan_source(str(self.root), ["code"])
            self.assertEqual(result.findings, [])
            self.assertEqual(result.metadata["files_scanned"], 1)
            self.assertEqual(result.metadata["skipped_directories"], 2)
        finally:
            outside.unlink()

    def test_scanned_source_is_never_executed(self):
        marker = self.root / "must_not_exist"
        text = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
        self.scan(text)
        self.assertFalse(marker.exists())

    def test_syntax_error_never_reports_source_text(self):
        result = self.scan("def broken(SPECIAL_SECRET_123456\n", modules=["sql"])
        self.assertTrue(result.errors)
        self.assertFalse(result.to_dict()["complete"])
        self.assertNotIn("SPECIAL_SECRET_123456", str(result.to_dict()))

    def test_size_limit_marks_partial(self):
        with patch("lulz.source.MAX_FILE_BYTES", 32):
            result = self.scan("#" + "x" * 100)
        self.assertTrue(result.metadata["incomplete"])
        self.assertEqual(result.metadata["skipped_files"], 1)

    def test_file_count_limit_marks_partial(self):
        self.file("pass\n", "one.py")
        self.file("pass\n", "two.py")
        with patch("lulz.source.MAX_FILES", 1):
            result = scan_source(str(self.root))
        self.assertEqual(result.metadata["files_scanned"], 1)
        self.assertFalse(result.to_dict()["complete"])

    def test_findings_limit_marks_partial(self):
        with patch("lulz.source.MAX_FINDINGS", 1):
            result = self.scan("eval(value)\neval(other)\n", modules=["code"])
        self.assertEqual(len(result.findings), 1)
        self.assertFalse(result.to_dict()["complete"])

    def test_total_read_budget_includes_skipped_files(self):
        self.file("#" + "x" * 64, "one.py")
        self.file("#" + "x" * 64, "two.py")
        with patch("lulz.source.MAX_FILE_BYTES", 32), patch("lulz.source.MAX_TOTAL_BYTES", 40):
            result = scan_source(str(self.root))
        self.assertLessEqual(result.metadata["files_considered"], 2)
        self.assertFalse(result.to_dict()["complete"])

    def test_binary_source_is_not_interpreted(self):
        (self.root / "data.py").write_bytes(b"abc\x00eval(value)")
        result = scan_source(str(self.root))
        self.assertEqual(result.findings, [])
        self.assertFalse(result.to_dict()["complete"])

    def test_missing_path_and_module_errors(self):
        self.assertTrue(scan_source(str(self.root / "missing")).errors)
        self.assertTrue(scan_source(str(self.root), ["bad-module"]).errors)
        self.assertTrue(scan_source(str(self.root), []).errors)


if __name__ == "__main__":
    unittest.main()
