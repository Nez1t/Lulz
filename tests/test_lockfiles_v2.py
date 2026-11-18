import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lulz.dependencies import scan_dependencies


class AdditionalLockfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def scan(self, name, data):
        path = self.root / name
        path.write_text(json.dumps(data) if isinstance(data, dict) else data, encoding="utf-8")
        return scan_dependencies(str(path))

    def test_uv_exact_pypi_and_local_workspace(self):
        result = self.scan("uv.lock", '''version = 1
[[package]]
name = "workspace"
version = "1.0.0"
source = { editable = "." }
[[package]]
name = "demo"
version = "1.2.3"
source = { registry = "https://pypi.org/simple" }
''')
        self.assertEqual(result.metadata["packages"], 1)
        self.assertEqual(result.metadata["inventory"][0]["ecosystem"], "PyPI")
        self.assertFalse(result.metadata.get("incomplete"))

    def test_private_registry_is_not_pypi_guess(self):
        result = self.scan("uv.lock", '''[[package]]
name = "private"
version = "1.2.3"
source = { registry = "https://private.example.invalid/simple" }
''')
        self.assertEqual(result.metadata["packages"], 0)
        self.assertTrue(result.metadata["incomplete"])
        self.assertNotIn("private.example.invalid", json.dumps(result.to_dict()))

    def test_poetry_default_and_git_sources(self):
        result = self.scan("poetry.lock", '''[[package]]
name = "example"
version = "1.0.1"
[[package]]
name = "private"
version = "1.0.0"
source = {type = "git", url = "https://example.invalid/repository"}
''')
        self.assertEqual(result.metadata["packages"], 1)
        self.assertEqual(result.metadata["skipped_entries"], 1)

    def test_cargo_registry_and_workspace(self):
        result = self.scan("Cargo.lock", '''version = 4
[[package]]
name = "workspace"
version = "0.1.0"
[[package]]
name = "example-crate"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
''')
        self.assertEqual(result.metadata["packages"], 1)
        self.assertEqual(result.metadata["inventory"][0]["ecosystem"], "crates.io")
        self.assertFalse(result.metadata.get("incomplete"))

    def test_pipenv_exact_and_source_provenance(self):
        result = self.scan("Pipfile.lock", {"_meta": {"sources": [{"name": "pypi", "url": "https://pypi.org/simple"}]},
            "default": {"demo": {"version": "==1.2.3", "index": "pypi"}},
            "develop": {"tester": {"version": "==2.0.0"}, "range": {"version": ">=1"}}})
        self.assertEqual(result.metadata["packages"], 2)
        self.assertEqual(result.metadata["skipped_entries"], 1)

    def test_composer_release_versions_not_dev_branches(self):
        result = self.scan("composer.lock", {"packages": [{"name": "vendor/demo", "version": "v1.2.3"}],
            "packages-dev": [{"name": "vendor/testing", "version": "2.0.0"}, {"name": "vendor/next", "version": "dev-main"}]})
        self.assertEqual(result.metadata["packages"], 2)
        self.assertTrue(all(p["ecosystem"] == "Packagist" for p in result.metadata["inventory"]))
        self.assertEqual(result.metadata["skipped_entries"], 1)

    def test_go_sum_go_mod_lines_not_runtime_inventory(self):
        result = self.scan("go.sum", "example.org/tool v1.2.3 h1:checksum\nexample.org/tool v1.2.3/go.mod h1:checksum\nexample.org/unused v0.1.0/go.mod h1:checksum\n")
        self.assertEqual(result.metadata["packages"], 1)
        self.assertEqual(result.metadata["inventory"][0]["ecosystem"], "Go")
        self.assertTrue(any("неиспользуемые" in note for note in result.notes))

    def test_cyclonedx_multiple_new_ecosystems(self):
        result = self.scan("bom.json", {"bomFormat": "CycloneDX", "components": [
            {"purl": "pkg:cargo/demo@1.2.3"}, {"purl": "pkg:composer/vendor/demo@1.2.3"},
            {"purl": "pkg:golang/example.org/tool@v1.2.3"}]})
        self.assertEqual({p["ecosystem"] for p in result.metadata["inventory"]}, {"crates.io", "Packagist", "Go"})

    def test_malformed_toml_is_failure_not_empty_success(self):
        result = self.scan("poetry.lock", '[[package\nversion="secret-placeholder"')
        self.assertTrue(result.errors)
        self.assertNotIn("secret-placeholder", json.dumps(result.to_dict()))

    def test_offline_new_formats_never_connect(self):
        with patch("lulz.dependencies._post_query", side_effect=AssertionError("network")):
            result = self.scan("composer.lock", {"packages": [{"name": "vendor/demo", "version": "1.2.3"}]})
        self.assertFalse(result.metadata["advisories_checked"])

    def test_new_manifest_discovery_in_directory(self):
        (self.root / "composer.lock").write_text('{"packages":[]}', encoding="utf-8")
        (self.root / "Cargo.lock").write_text('version=4\n', encoding="utf-8")
        result = scan_dependencies(str(self.root))
        self.assertEqual(result.metadata["manifest_count"], 2)

    def test_composer_branch_alias_not_an_exact_release(self):
        result = self.scan("composer.lock", {"packages": [
            {"name": "vendor/demo", "version": "1.2.x-dev"},
            {"name": "vendor/branch", "version": "1.2.3-dev"},
            {"name": "vendor/release", "version": "v1.2.3-RC1"}]})
        self.assertEqual(result.metadata["packages"], 1)
        self.assertEqual(result.metadata["skipped_entries"], 2)

    def test_bad_pipenv_index_and_vcs_are_skipped(self):
        result = self.scan("Pipfile.lock", {"_meta": {"sources": [{"name": "pypi", "url": "https://pypi.org/simple"}]},
            "default": {"malformed": {"version": "==1.2.3", "index": []},
                        "private": {"version": "==1.2.3", "git": "https://private.invalid/repo"}}})
        self.assertEqual(result.metadata["packages"], 0)
        self.assertEqual(result.metadata["skipped_entries"], 2)
        self.assertTrue(result.metadata["incomplete"])

    def test_qualified_purl_does_not_guess_public_registry(self):
        result = self.scan("bom.json", {"bomFormat": "CycloneDX", "components": [
            {"purl": "pkg:cargo/private@1.2.3?repository_url=https%3A%2F%2Fprivate.invalid"},
            {"purl": "pkg:pypi/demo@1.2.3?vers=vers%3Apypi%2F%3E%3D1.0"}]})
        self.assertEqual(result.metadata["packages"], 0)
        self.assertEqual(result.metadata["skipped_entries"], 2)


if __name__ == "__main__":
    unittest.main()
