"""Dependency inventory/API contract tests. All network responses are mocked."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from lulz import dependencies as dep


def advisory(identifier="GHSA-test-record", package="demo", ecosystem="PyPI", **extra):
    data = {
        "id": identifier, "summary": "Dependency advisory",
        "aliases": ["CVE-2025-12345"],
        "affected": [{"package": {"name": package, "ecosystem": ecosystem},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}],
        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-79"]},
    }
    data.update(extra)
    return data


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def manifest(self, name="requirements.txt", content="demo==1.2.3\n"):
        path = self.root / name
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return path

    def test_exact_requirements_only_no_include_following(self):
        path = self.manifest(content=("Demo_Package[extra]==1.2.3 ; python_version > '3.8'\n"
                                      "range>=2.0\nfoo==1.*\n-r private.txt\n"
                                      "--index-url https://name:password@example.invalid\n"
                                      "bar @ https://example.invalid/bar.whl\n"))
        result = dep.scan_dependencies(str(path))
        self.assertEqual(result.metadata["packages"], 1)
        self.assertEqual(result.metadata["inventory"][0]["name"], "demo-package")
        self.assertEqual(result.metadata["skipped_entries"], 5)
        self.assertNotIn("password", json.dumps(result.to_dict()))

    def test_requirements_hashes_preserve_original_line_numbers(self):
        packages, skipped = dep._parse_requirements(
            "demo==1.2.3 \\\n  --hash=sha256:abcdef\nother==2.0.0\n", "requirements.txt")
        self.assertEqual(skipped, 0)
        self.assertEqual(packages[1].sources, ["requirements.txt:3"])

    def test_offline_never_calls_network(self):
        path = self.manifest()
        with patch.object(dep, "_post_query") as network:
            result = dep.scan_dependencies(str(path))
        network.assert_not_called()
        self.assertEqual(result.checks[0]["status"], "skipped")
        self.assertFalse(result.metadata["advisories_checked"])
        self.assertEqual(result.findings, [])

    def test_npm_v2_scoped_nested_and_alias_name(self):
        path = self.manifest("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/@scope/one": {"version": "1.2.3"},
            "node_modules/outer/node_modules/two": {"version": "2.1.0-beta.1"},
            "node_modules/alias": {"name": "real-name", "version": "3.0.0"},
            "node_modules/workspace": {"link": True, "resolved": "packages/workspace"},
        }})
        result = dep.scan_dependencies(str(path))
        self.assertEqual({p["name"] for p in result.metadata["inventory"]},
                         {"@scope/one", "two", "real-name"})
        self.assertEqual(result.metadata["skipped_entries"], 1)

    def test_npm_v1_recursive_deduplication(self):
        path = self.manifest("package-lock.json", {"lockfileVersion": 1, "dependencies": {
            "outer": {"version": "1.0.0", "dependencies": {"inner": {"version": "2.0.0"}}},
            "inner": {"version": "2.0.0"},
        }})
        result = dep.scan_dependencies(str(path))
        self.assertEqual(result.metadata["packages"], 2)

    def test_cyclonedx_purl_and_conflicting_version(self):
        path = self.manifest("bom.json", {"bomFormat": "CycloneDX", "components": [
            {"purl": "pkg:npm/%40scope/name@1.2.3", "version": "1.2.3"},
            {"purl": "pkg:pypi/demo@2.0.0", "version": "1.0.0"},
            {"purl": "pkg:pypi/second", "version": "3.0.0"},
        ]})
        result = dep.scan_dependencies(str(path))
        self.assertEqual({p["name"] for p in result.metadata["inventory"]}, {"@scope/name", "second"})
        self.assertEqual(result.metadata["skipped_entries"], 1)

    def test_malformed_cyclonedx_is_reported(self):
        path = self.manifest("bom.json", {"bomFormat": "CycloneDX", "components": 123})
        result = dep.scan_dependencies(str(path))
        self.assertTrue(result.errors)
        self.assertFalse(result.to_dict()["complete"])

    def test_online_uses_exact_version_and_real_cve_alias(self):
        path = self.manifest()
        with patch.object(dep, "_post_query", return_value={"vulns": [advisory()]}) as query:
            result = dep.scan_dependencies(str(path), online=True)
        query.assert_called_once()
        payload = query.call_args.args[0]
        self.assertEqual(payload, {"package": {"name": "demo", "ecosystem": "PyPI"}, "version": "1.2.3"})
        self.assertNotIn(str(self.root), json.dumps(payload))
        finding = result.findings[0]
        self.assertEqual(finding.status, "advisory_match")
        self.assertEqual(finding.cve, ["CVE-2025-12345"])
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.cwe, ["CWE-79"])
        self.assertIn("2.0.0", finding.remediation)
        self.assertEqual(result.metadata["checked_packages"], 1)

    def test_unknown_severity_not_guessed_from_vector(self):
        path = self.manifest()
        record = advisory(database_specific={}, severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}])
        with patch.object(dep, "_post_query", return_value={"vulns": [record]}):
            result = dep.scan_dependencies(str(path), online=True)
        self.assertEqual(result.findings[0].severity, "info")
        self.assertIn("неопределённую", result.findings[0].description)

    def test_no_cve_invented_from_summary(self):
        path = self.manifest()
        record = advisory(aliases=[], summary="Possible CVE-2025-99999 mentioned in text")
        with patch.object(dep, "_post_query", return_value={"vulns": [record]}):
            result = dep.scan_dependencies(str(path), online=True)
        self.assertEqual(result.findings[0].cve, [])

    def test_pagination_preserves_identity_and_deduplicates(self):
        path = self.manifest()
        pages = [{"vulns": [advisory()], "next_page_token": "page2"},
                 {"vulns": [advisory(), advisory("GHSA-second-record")]}]
        with patch.object(dep, "_post_query", side_effect=pages) as query:
            result = dep.scan_dependencies(str(path), online=True)
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(query.call_args_list[1].args[0]["page_token"], "page2")
        self.assertEqual(query.call_args_list[1].args[0]["version"], "1.2.3")
        self.assertTrue(result.to_dict()["complete"])

    def test_repeated_pagination_marks_partial(self):
        path = self.manifest()
        with patch.object(dep, "_post_query", return_value={"vulns": [advisory()], "next_page_token": "repeat"}) as query:
            result = dep.scan_dependencies(str(path), online=True)
        self.assertEqual(query.call_count, 2)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.metadata["checked_packages"], 0)
        self.assertFalse(result.to_dict()["complete"])

    def test_withdrawn_advisory_ignored(self):
        path = self.manifest()
        with patch.object(dep, "_post_query", return_value={"vulns": [advisory(withdrawn="2026-01-01T00:00:00Z")]}):
            result = dep.scan_dependencies(str(path), online=True)
        self.assertEqual(result.findings, [])

    def test_wrong_package_not_reported_as_match(self):
        path = self.manifest()
        with patch.object(dep, "_post_query", return_value={"vulns": [advisory(package="another")]}):
            result = dep.scan_dependencies(str(path), online=True)
        self.assertEqual(result.findings, [])
        self.assertTrue(result.errors)

    def test_partial_results_survive_later_network_failure(self):
        path = self.manifest()
        with patch.object(dep, "_post_query", side_effect=[
            {"vulns": [advisory()], "next_page_token": "next"}, URLError("private response data")]):
            result = dep.scan_dependencies(str(path), online=True)
        self.assertEqual(len(result.findings), 1)
        self.assertFalse(result.to_dict()["complete"])
        self.assertNotIn("private response data", str(result.errors))

    def test_malformed_api_response_not_success(self):
        path = self.manifest()
        with patch.object(dep, "_post_query", return_value={"vulns": {"bad": "shape"}}):
            result = dep.scan_dependencies(str(path), online=True)
        self.assertTrue(result.errors)
        self.assertEqual(result.metadata["checked_packages"], 0)

    def test_wall_time_budget_marks_remaining_packages_incomplete(self):
        path = self.manifest(content="demo==1.2.3\nsecond==2.0.0\n")
        with patch.object(dep, "MAX_AUDIT_SECONDS", 0), patch.object(dep, "_post_query") as query:
            result = dep.scan_dependencies(str(path), online=True)
        query.assert_not_called()
        self.assertFalse(result.to_dict()["complete"])
        self.assertEqual(result.metadata["checked_packages"], 0)

    def test_limit_packages_visible_in_report(self):
        path = self.manifest(content="first==1.0.0\nsecond==2.0.0\n")
        with patch.object(dep, "MAX_PACKAGES", 1):
            result = dep.scan_dependencies(str(path))
        self.assertEqual(result.metadata["packages"], 1)
        self.assertFalse(result.to_dict()["complete"])

    def test_file_size_limit(self):
        path = self.manifest()
        with patch.object(dep, "MAX_FILE_BYTES", 3):
            result = dep.scan_dependencies(str(path))
        self.assertTrue(result.errors)

    def test_nonexistent_path_and_bad_timeout(self):
        self.assertTrue(dep.scan_dependencies(str(self.root / "missing.txt")).errors)
        self.assertTrue(dep.scan_dependencies(str(self.root), timeout=0).errors)

    def test_symlink_manifest_not_read(self):
        real = self.manifest("private.txt")
        link = self.root / "requirements.txt"
        try:
            link.symlink_to(real)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks are unavailable on this platform")
        result = dep.scan_dependencies(str(link))
        self.assertTrue(result.errors)
        self.assertEqual(result.metadata["packages"], 0)

    def test_reference_urls_filtered(self):
        package = dep.Dependency("demo", "1.2.3", "PyPI", ["requirements.txt:1"])
        record = advisory(references=[{"url": "javascript:alert(1)"},
                                     {"url": "https://user:secret@example.invalid"},
                                     {"url": "https://advisories.example.invalid/record"}])
        finding = dep._advisory_finding(record, package)
        self.assertEqual(len(finding.references), 2)
        self.assertFalse(any("secret" in url for url in finding.references))

    def test_post_query_fixed_endpoint_and_verified_tls(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.read1.side_effect = [b'{"vulns": []}', b""]
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(dep.request, "build_opener", return_value=opener):
            result = dep._post_query({"package": {"name": "demo", "ecosystem": "PyPI"}, "version": "1.2.3"}, 1)
        req = opener.open.call_args.args[0]
        self.assertEqual(req.full_url, dep.OSV_ENDPOINT)
        self.assertEqual(req.method, "POST")
        self.assertEqual(result, {"vulns": []})
        self.assertIsNone(dep._NoRedirect().redirect_request(None, None, 302, "", {}, "https://elsewhere.invalid"))

    def test_response_size_limit(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.read1.side_effect = [b"abcd", b""]
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(dep.request, "build_opener", return_value=opener), patch.object(dep, "MAX_RESPONSE_BYTES", 3):
            with self.assertRaises(ValueError):
                dep._post_query({}, 1)


if __name__ == "__main__":
    unittest.main()
