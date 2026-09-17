"""Exercise deployment guards without contacting Coolify or a public site."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('landing_deploy',Path(__file__).resolve().parents[1]/'deploy.py')
deploy=importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)

class DeployTests(unittest.TestCase):
    def run_deploy(self,branch='landing',status='finished',revision=None):
        commit='a'*40
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'landing').mkdir()
            (root/'landing/release.json').write_text(json.dumps({'site_url':'https://site.example'}))
            for lang in ['es','en']:
                (root/'dist'/lang).mkdir(parents=True)
                (root/'dist'/lang/'index.html').write_bytes(b'expected-html')
            responses=[{'git_branch':branch,'git_repository':'686f6c61/mcp-zero-trust-layer'}, {}, {'deployments':[{'deployment_uuid':'deployment1'}]}, {'status':status,'commit':revision or commit}]
            with patch.dict('os.environ',{'COOLIFY_URL':'https://coolify.example','COOLIFY_TOKEN':'synthetic-test-token','COOLIFY_APP_UUID':'app1','GITHUB_SHA':commit},clear=True), patch.object(deploy,'__file__',str(root/'landing/deploy.py')), patch.object(deploy.subprocess,'check_output',return_value=commit+'\n'), patch.object(deploy,'api',side_effect=responses) as api, patch.object(deploy,'urlopen',side_effect=lambda *a,**k:io.BytesIO(b'expected-html')) as public:
                if branch!='landing':
                    with self.assertRaises(AssertionError): deploy.main()
                    self.assertEqual(api.call_count,1)
                    public.assert_not_called()
                elif status=='failed':
                    with self.assertRaises(RuntimeError): deploy.main()
                    public.assert_not_called()
                elif revision:
                    with self.assertRaises(AssertionError): deploy.main()
                    public.assert_not_called()
                else:
                    deploy.main()
                    self.assertEqual(api.call_args_list[1].args[-1],{'git_commit_sha':commit,'is_auto_deploy_enabled':False})
                    self.assertEqual(public.call_count,2)
    def test_deploys_only_exact_commit_and_compares_public_bytes(self): self.run_deploy()
    def test_wrong_application_branch_is_not_mutated(self): self.run_deploy(branch='main')
    def test_failed_deployment_never_reports_public_success(self): self.run_deploy(status='failed')
    def test_finished_wrong_commit_is_rejected(self): self.run_deploy(revision='b'*40)

    def test_transient_read_connection_failure_is_retried(self):
        with patch.object(deploy, 'urlopen', side_effect=[deploy.URLError('timed out'), io.BytesIO(b'{"status":"finished"}')]) as request, patch.object(deploy.time, 'sleep'):
            self.assertEqual(deploy.api('https://coolify.example', 'synthetic', '/deployments/test'), {'status':'finished'})
            self.assertEqual(request.call_count, 2)

    def test_uncertain_mutation_is_never_repeated(self):
        for method in ['POST', 'PATCH']:
            with self.subTest(method=method), patch.object(deploy, 'urlopen', side_effect=deploy.URLError('timed out')) as request, patch.object(deploy.time, 'sleep') as sleep:
                with self.assertRaisesRegex(RuntimeError, 'connection failed'):
                    deploy.api('https://coolify.example', 'synthetic', '/deploy', method, {})
                self.assertEqual(request.call_count, 1)
                sleep.assert_not_called()
