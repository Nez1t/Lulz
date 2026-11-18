import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lulz import project_checks as pc


class ProjectChecksTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def file(self, text, name="settings.py"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text if isinstance(text, str) else json.dumps(text), encoding="utf-8")
        return path

    def scan(self, text, name="settings.py", modules=None):
        return pc.scan_project_checks(str(self.file(text, name)), modules)

    def ids(self, result):
        return {finding.rule_id for finding in result.findings}

    def pod(self, security_context=None, pod_context=None, **spec):
        container = {"name": "application", "image": "application:1"}
        if security_context is not None:
            container["securityContext"] = security_context
        pod_spec = {"containers": [container], **spec}
        if pod_context is not None:
            pod_spec["securityContext"] = pod_context
        return {"apiVersion": "v1", "kind": "Pod", "spec": pod_spec}

    def terraform(self, resource_type, attributes):
        return {"resource": {resource_type: {"resource_name": attributes}}}

    def test_secret_assignment_masks_values(self):
        value = "N7v!q2Zm9A@k4Rt8xY3cLp0u"
        result = self.scan(f'API_KEY = "{value}"\nPASSWORD = "{value}"\n', modules=['secrets'])
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(self.ids(result), {'SEC-CREDENTIAL-LITERAL'})
        serialized = json.dumps(result.to_dict())
        self.assertNotIn(value, serialized)
        self.assertNotIn(value[:6], serialized)
        self.assertTrue(all(finding.cve == [] for finding in result.findings))
        self.assertTrue(result.findings[0].location.endswith(':1'))

    def test_placeholder_weak_and_indirect_values_not_claimed(self):
        text = '''API_KEY = "your_api_key_replace_me"
PASSWORD = "change_me_please"
SECRET_KEY = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
PASSWORD = os.environ.get("DATABASE_PASSWORD")
API_KEY = "${ENV_APPLICATION_SECRET}"
api_key = config.security.credentials
password = "short"
'''
        self.assertEqual(self.scan(text, modules=['secrets']).findings, [])

    def test_env_and_docker_literal_detection(self):
        secret = 'q8B2mT9wR7sV4zK1nP6cX3dF'
        env = self.scan('export API_KEY=' + secret + '\n', '.env.production', ['secrets'])
        docker = self.scan('FROM base\nENV API_KEY=' + secret + '\nUSER 1000\n', 'Dockerfile', ['secrets'])
        self.assertIn('SEC-CREDENTIAL-LITERAL', self.ids(env))
        self.assertIn('SEC-CREDENTIAL-LITERAL', self.ids(docker))

    def test_private_key_block_and_marker_only(self):
        value = 'M7q9Ta3bX5r8Y1s4N6p2W0vU' * 3
        content = '-----BEGIN PRIVATE KEY-----\n' + value + '\n-----END PRIVATE KEY-----\n'
        result = self.scan(content, 'private.pem', ['secrets'])
        self.assertIn('SEC-PRIVATE-KEY', self.ids(result))
        self.assertNotIn(value, json.dumps(result.to_dict()))
        self.assertEqual(self.scan('BEGIN PRIVATE KEY', 'note.txt', ['secrets']).findings, [])

    def test_private_key_mismatched_end_not_detected(self):
        text = '-----BEGIN RSA PRIVATE KEY-----\n' + 'ABcd12/+' * 8 + '\n-----END EC PRIVATE KEY-----'
        self.assertEqual(self.scan(text, 'key.pem', ['secrets']).findings, [])

    def test_url_userinfo_is_fully_redacted(self):
        address = 'postgresql://backend:Tr8pL4m9aQ2zX7w6@db.internal:5432/secret_database'
        result = self.scan('DATABASE_URL="' + address + '"\n', '.env', ['secrets'])
        self.assertIn('SEC-URL-CREDENTIAL', self.ids(result))
        serialized = json.dumps(result.to_dict())
        for value in ('backend', 'Tr8pL4m9aQ2zX7w6', 'db.internal', 'secret_database'):
            self.assertNotIn(value, serialized)

    def test_url_placeholders_and_public_url_not_detected(self):
        text = 'DATABASE_URL="postgresql://user:${PASSWORD}@db.invalid/db"\nURL="https://example.org/?token=public"\n'
        self.assertEqual(self.scan(text, '.env', ['secrets']).findings, [])

    def test_comments_not_false_secret_findings(self):
        result = self.scan('# API_KEY="a9F3t6M2k7R8n4S1w5C0v9P3"\n', modules=['secrets'])
        self.assertEqual(result.findings, [])

    def test_kubernetes_dangerous_flags(self):
        pod = self.pod({'privileged': True, 'runAsUser': 0, 'allowPrivilegeEscalation': True,
                        'capabilities': {'add': ['NET_ADMIN', 'SYS_ADMIN']}}, hostPID=True,
                       volumes=[{'name': 'host', 'hostPath': {'path': '/sensitive'}}])
        result = self.scan(pod, 'pod.json', ['config'])
        self.assertTrue({'CFG-K8S-PRIVILEGED', 'CFG-K8S-ROOT', 'CFG-K8S-ESCALATION',
                         'CFG-K8S-CAPABILITIES', 'CFG-K8S-HOST-NAMESPACE', 'CFG-K8S-HOSTPATH'} <= self.ids(result))
        self.assertNotIn('/sensitive', json.dumps(result.to_dict()))
        self.assertTrue(all(f.cve == [] for f in result.findings))

    def test_kubernetes_pod_security_context_and_override(self):
        pod = self.pod({'runAsUser': 1000}, {'runAsUser': 0, 'runAsNonRoot': True})
        result = self.scan(pod, 'pod.json', ['config'])
        self.assertNotIn('CFG-K8S-ROOT', self.ids(result))
        self.assertNotIn('CFG-K8S-NONROOT', self.ids(result))
        pod['spec']['containers'][0]['securityContext']['runAsUser'] = 0
        result = self.scan(pod, 'pod2.json', ['config'])
        self.assertIn('CFG-K8S-ROOT', self.ids(result))

    def test_kubernetes_missing_nonroot_is_informational(self):
        result = self.scan(self.pod(), 'pod.json', ['config'])
        finding = next(f for f in result.findings if f.rule_id == 'CFG-K8S-NONROOT')
        self.assertEqual(finding.severity, 'info')
        self.assertEqual(finding.confidence, 'low')
        self.assertEqual(finding.cwe, [])

    def test_kubernetes_workload_cronjob_and_list(self):
        security = {'containers': [{'securityContext': {'privileged': True, 'runAsNonRoot': True}}]}
        deployment = {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'spec': {'template': {'spec': security}}}
        cron = {'apiVersion': 'batch/v1', 'kind': 'CronJob', 'spec': {'jobTemplate': {'spec': {'template': {'spec': security}}}}}
        result = self.scan({'apiVersion': 'v1', 'kind': 'List', 'items': [deployment, cron]}, 'list.json', ['config'])
        self.assertEqual(result.metadata['config_documents'], 2)
        self.assertEqual(sum(f.rule_id == 'CFG-K8S-PRIVILEGED' for f in result.findings), 2)
        self.assertTrue(any('.jobTemplate.' in f.evidence for f in result.findings))

    def test_windows_pod_skips_linux_uid_rules(self):
        result = self.scan(self.pod({'runAsUser': 0, 'privileged': True}, os={'name': 'windows'}), 'windows.json', ['config'])
        self.assertFalse(self.ids(result) & {'CFG-K8S-ROOT', 'CFG-K8S-PRIVILEGED', 'CFG-K8S-NONROOT'})
        self.assertTrue(any('windows' in note for note in result.notes))

    def test_kubernetes_string_flags_are_not_true(self):
        result = self.scan(self.pod({'privileged': 'true', 'allowPrivilegeEscalation': 1, 'runAsUser': False,
                                    'runAsNonRoot': True}, hostPID='true'), 'pod.json', ['config'])
        self.assertEqual(result.findings, [])

    def test_terraform_public_admin_ingress_not_egress(self):
        ingress = {'protocol': 'tcp', 'from_port': 22, 'to_port': 22, 'cidr_blocks': ['0.0.0.0/0']}
        result = self.scan(self.terraform('aws_security_group', {'ingress': [ingress]}), 'main.tf.json', ['config'])
        self.assertIn('CFG-TF-SG-ADMIN', self.ids(result))
        negative = self.scan(self.terraform('aws_security_group_rule', {**ingress, 'type': 'egress'}), 'egress.tf.json', ['config'])
        self.assertNotIn('CFG-TF-SG-ADMIN', self.ids(negative))

    def test_terraform_modern_ipv6_and_all_ports(self):
        record = {'ip_protocol': '-1', 'cidr_ipv6': '::/0'}
        result = self.scan(self.terraform('aws_vpc_security_group_ingress_rule', record), 'main.tf.json', ['config'])
        self.assertIn('CFG-TF-SG-ALL', self.ids(result))

    def test_terraform_private_or_unresolved_source_not_guessed(self):
        for cidr in ('10.0.0.0/8', '${var.cidr}', 'not-a-network'):
            entry = {'protocol': 'tcp', 'from_port': 22, 'to_port': 22, 'cidr_blocks': [cidr]}
            result = self.scan(self.terraform('aws_security_group', {'ingress': [entry]}), 'main.tf.json', ['config'])
            self.assertEqual(result.findings, [])
            self.assertEqual(result.errors, [])

    def test_terraform_public_database_and_s3(self):
        data = {'resource': {
            'aws_db_instance': {'db': {'publicly_accessible': True}},
            'aws_s3_bucket_acl': {'acl': {'acl': 'public-read'}},
            'aws_s3_bucket_public_access_block': {'block': {'block_public_acls': False}},
        }}
        result = self.scan(data, 'main.tf.json', ['config'])
        self.assertTrue({'CFG-TF-DB-PUBLIC', 'CFG-TF-S3-ACL', 'CFG-TF-S3-BLOCK'} <= self.ids(result))
        self.assertEqual(next(f.severity for f in result.findings if f.rule_id == 'CFG-TF-S3-BLOCK'), 'info')

    def test_terraform_imds_optional_and_disabled(self):
        optional = {'metadata_options': [{'http_tokens': 'optional'}]}
        result = self.scan(self.terraform('aws_instance', optional), 'main.tf.json', ['config'])
        self.assertIn('CFG-TF-IMDS', self.ids(result))
        optional['metadata_options'][0]['http_endpoint'] = 'disabled'
        result = self.scan(self.terraform('aws_instance', optional), 'disabled.tf.json', ['config'])
        self.assertNotIn('CFG-TF-IMDS', self.ids(result))

    def test_docker_final_stage_only_for_runtime_user(self):
        text = 'FROM base AS build\nUSER root\nRUN build-program\nFROM runtime\nUSER 1000:1000\n'
        result = self.scan(text, 'Dockerfile', ['config'])
        self.assertNotIn('CFG-DOCKER-ROOT', self.ids(result))
        self.assertNotIn('CFG-DOCKER-USER-UNSPECIFIED', self.ids(result))

    def test_docker_alias_inherits_nonroot_and_root(self):
        for user, found in (('1000', False), ('root', True)):
            result = self.scan(f'FROM base AS original\nUSER {user}\nFROM original AS final\n', 'Dockerfile', ['config'])
            self.assertEqual('CFG-DOCKER-ROOT' in self.ids(result), found)
            self.assertNotIn('CFG-DOCKER-USER-UNSPECIFIED', self.ids(result))

    def test_docker_no_user_is_not_asserted_root(self):
        result = self.scan('FROM base\nCMD ["application"]\n', 'Dockerfile', ['config'])
        finding = next(f for f in result.findings if f.rule_id == 'CFG-DOCKER-USER-UNSPECIFIED')
        self.assertEqual(finding.severity, 'info')
        self.assertEqual(finding.confidence, 'low')
        self.assertEqual(finding.cwe, [])

    def test_docker_heredoc_does_not_invent_user_instruction(self):
        text = 'FROM base\nUSER 1000\nRUN <<EOF\nUSER root\nFROM suspicious\nEOF\n'
        result = self.scan(text, 'Dockerfile', ['config'])
        self.assertEqual(result.findings, [])

    def test_docker_remote_add_checksum_and_redaction(self):
        address = 'https://user:Tr8pL4m9aQ2zX7w6@downloads.internal/private.tar'
        text = f'FROM base\nADD {address} /app/\nUSER 1000\n'
        result = self.scan(text, 'Dockerfile', ['config'])
        self.assertIn('CFG-DOCKER-REMOTE-ADD', self.ids(result))
        self.assertNotIn('downloads.internal', json.dumps(result.to_dict()))
        pinned = self.scan('FROM base\nADD --checksum=sha256:' + 'a'*64 + ' https://example.org/a /app/\nUSER 1000\n', 'Dockerfile.pinned', ['config'])
        self.assertNotIn('CFG-DOCKER-REMOTE-ADD', self.ids(pinned))

    def test_yaml_and_hcl_coverage_explicit(self):
        self.file('apiVersion: v1\nkind: Pod\nspec: {}\n', 'pod.yaml')
        self.file('resource "aws_db_instance" "db" {}\n', 'main.tf')
        result = pc.scan_project_checks(str(self.root), ['config'])
        self.assertEqual(result.metadata['unsupported_config_files'], 2)
        self.assertTrue(result.metadata['incomplete'])
        self.assertTrue(any('YAML' in note for note in result.notes))

    def test_malformed_json_does_not_expose_source(self):
        secret = 'AnExtremelyPrivateStringThatMustNotBePrinted'
        result = self.scan('{"apiVersion": "' + secret, 'bad.json', ['config'])
        self.assertTrue(result.errors)
        self.assertNotIn(secret, json.dumps(result.to_dict()))

    def test_unrecognized_json_does_not_invent_config(self):
        result = self.scan({'name': 'application', 'dependencies': {}}, 'package.json', ['config'])
        self.assertEqual(result.findings, [])
        self.assertEqual(result.metadata['config_documents'], 0)
        self.assertEqual(result.checks[0]['status'], 'skipped')

    def test_empty_directory_is_not_a_completed_security_check(self):
        result = pc.scan_project_checks(str(self.root))
        self.assertTrue(result.metadata['incomplete'])
        self.assertTrue(all(check['status'] == 'skipped' for check in result.checks))

    def test_files_are_never_executed(self):
        marker = self.root / 'must_not_exist'
        result = self.scan(f'from pathlib import Path\nPath({str(marker)!r}).touch()\n', modules=['secrets'])
        self.assertEqual(result.errors, [])
        self.assertFalse(marker.exists())

    def test_exclusions_and_no_symlink_following(self):
        self.file('API_KEY="q8B2mT9wR7sV4zK1nP6cX3dF"\n', 'node_modules/private.js')
        self.file('API_KEY="q8B2mT9wR7sV4zK1nP6cX3dF"\n', '.lulz-backups/old.py')
        self.file('pass\n', 'app.py')
        outside = self.root.parent / (self.root.name + '-outside.txt')
        outside.write_text('API_KEY="q8B2mT9wR7sV4zK1nP6cX3dF"\n', encoding='utf-8')
        try:
            try:
                (self.root / 'linked.txt').symlink_to(outside)
            except (OSError, NotImplementedError):
                pass
            result = pc.scan_project_checks(str(self.root), ['secrets'])
            self.assertEqual(result.findings, [])
            self.assertEqual(result.metadata['files_scanned'], 1)
            self.assertEqual(result.metadata['skipped_directories'], 2)
        finally:
            outside.unlink()

    def test_root_symlink_rejected(self):
        target = self.file('pass\n')
        link = self.root / 'link.py'
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest('Symlinks are unavailable')
        result = pc.scan_project_checks(str(link), ['secrets'])
        self.assertTrue(result.errors)

    def test_count_size_and_total_limits_visible(self):
        self.file('pass\n', 'first.py')
        self.file('pass\n', 'second.py')
        with patch.object(pc, 'MAX_FILES', 1):
            result = pc.scan_project_checks(str(self.root), ['secrets'])
        self.assertTrue(result.metadata['incomplete'])
        self.assertEqual(result.metadata['files_scanned'], 1)
        with patch.object(pc, 'MAX_FILE_BYTES', 3):
            result = pc.scan_project_checks(str(self.root), ['secrets'])
        self.assertTrue(result.metadata['incomplete'])
        self.assertEqual(result.metadata['files_scanned'], 0)
        with patch.object(pc, 'MAX_TOTAL_BYTES', 6):
            result = pc.scan_project_checks(str(self.root), ['secrets'])
        self.assertTrue(result.metadata['incomplete'])
        self.assertLessEqual(result.metadata['bytes_read'], 7)

    def test_entry_limit_does_not_read_outside_budget(self):
        for number in range(3):
            self.file('pass\n', f'{number}.py')
        with patch.object(pc, 'MAX_ENTRIES', 2):
            result = pc.scan_project_checks(str(self.root), ['secrets'])
        self.assertTrue(result.metadata['incomplete'])

    def test_invalid_inputs_and_modules(self):
        self.assertTrue(pc.scan_project_checks(str(self.root / 'missing')).errors)
        self.assertTrue(pc.scan_project_checks(str(self.root), ['unknown']).errors)
        self.assertTrue(pc.scan_project_checks(str(self.root), []).errors)
        self.assertTrue(self.scan('opaque', 'binary.dat', ['secrets']).errors)

    def test_binary_and_bad_unicode_not_interpreted(self):
        path = self.root / '.env'
        path.write_bytes(b'\x00\x01API_KEY=anything')
        result = pc.scan_project_checks(str(path), ['secrets'])
        self.assertTrue(result.metadata['incomplete'])
        self.assertEqual(result.findings, [])
        path.write_bytes(b'\xff\xfe')
        self.assertTrue(pc.scan_project_checks(str(path), ['secrets']).errors)


if __name__ == '__main__':
    unittest.main()
