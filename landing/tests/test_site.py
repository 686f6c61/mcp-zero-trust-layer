import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]

class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.tags = []
        self.feed(text)
    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

class SiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.temp.name)
        subprocess.run(['python3', str(ROOT/'build.py'), '--out', str(cls.out), '--site-url', 'https://preview.example'], check=True)
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
    def test_language_parity(self):
        content = json.loads((ROOT/'content.json').read_text())
        self.assertEqual(content['es'].keys(), content['en'].keys())
        for key in ['examples', 'demoLabels', 'demoDescriptions', 'layers', 'details', 'installSteps']:
            self.assertEqual(len(content['es'][key]),len(content['en'][key]))
    def test_local_links_assets_anchors_and_metadata(self):
        for lang in ['es','en']:
            text = (self.out/lang/'index.html').read_text()
            page = Page(text)
            ids = [a['id'] for _, a in page.tags if 'id' in a]
            self.assertEqual(len(ids),len(set(ids)))
            self.assertEqual(sum(t=='h1' for t,_ in page.tags),1)
            self.assertEqual(sum(t=='main' for t,_ in page.tags),1)
            self.assertIn(f'<html lang="{lang}">',text)
            self.assertIn(f'rel="canonical" href="https://preview.example/{lang}/"',text)
            self.assertNotIn('0.3.0',text)
            self.assertNotIn('0.5.0',text)
            self.assertIn('mcp-zero-trust-layer==0.6.0',text)
            self.assertIn('mcpzt demo --output',text)
            self.assertIn('/tree/main/examples',text)
            self.assertIn('/blob/main/docs/',text)
            self.assertIn('/releases/tag/v0.6.0',text)
            self.assertNotIn('/tree/v0.6.0/',text)
            self.assertNotIn('/blob/v0.6.0/',text)
            self.assertNotIn('mcpzt demo --directory',text)
            self.assertNotIn('src="https://analytics.',text)
            for tag, attrs in page.tags:
                self.assertNotIn('onclick',attrs)
                for key in ['href','src']:
                    value=attrs.get(key,'')
                    if value.startswith('#'):
                        self.assertIn(value[1:],ids)
                    if value.startswith('/'):
                        p=self.out/value.lstrip('/')
                        self.assertTrue(p.exists(), value)
                if tag=='script': self.assertIn('src',attrs)
            css=next(self.out/a['href'].lstrip('/') for t,a in page.tags if t=='link' and a.get('rel')=='stylesheet')
            for font in ['archivo-latin','archivo-black-latin']:
                built=list((self.out/'assets').glob(font+'.*.woff2'))[0]
                self.assertIn('/assets/'+built.name,css.read_text())
    def test_scenarios_derive_from_records(self):
        cases=json.loads(next((self.out/'assets').glob('scenarios.*.json')).read_text())
        self.assertEqual(len(cases),8)
        comparison=json.loads((ROOT/'fixtures/comparison.json').read_text())
        for i,case in enumerate(cases):
            bundle=json.loads((ROOT/'fixtures'/(case['file']+'.json')).read_text())
            self.assertEqual(case['gateway'],'unknown')
            if i==0:
                self.assertIsNone(bundle['receipt'])
                self.assertEqual(case['trace'],['tools/call'])
            else:
                self.assertEqual(case['trace'],comparison['destination_methods'])
                self.assertEqual(case['trace'].count('tools/call'),1)
            if i>1:
                self.assertEqual(case['observer'],bundle['observations'][-1]['payload']['result'])
                self.assertEqual(case['reason'],bundle['observations'][-1]['payload']['reason'])
                self.assertEqual(case['history'],len(bundle['observations']))
        self.assertEqual(cases[4]['history'],3)
    def test_public_fixtures_unchanged_and_no_keys(self):
        built=next((self.out/'assets').glob('fixtures.*'))
        for source in (ROOT/'fixtures').iterdir():
            self.assertEqual(source.read_bytes(),(built/source.name).read_bytes())
        self.assertEqual(list(self.out.rglob('*.key')),[])
        self.assertNotIn('provider_contacted": true',(built/'comparison.json').read_text())
    def test_production_and_preview_separation(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(['python3',str(ROOT/'build.py'),'--out',directory],check=True,capture_output=True)
            p=Path(directory)
            self.assertIn('Disallow: /',(p/'robots.txt').read_text())
            self.assertNotIn('rel="canonical"',(p/'es/index.html').read_text())
            subprocess.run(['python3',str(ROOT/'build.py'),'--out',directory,'--site-url','https://site.example','--analytics'],check=True,capture_output=True)
            text=(p/'en/index.html').read_text()
            self.assertIn('data-domains="site.example"',text)
            self.assertIn('data-do-not-track="true"',text)
            self.assertIn('data-exclude-search="true"',text)
            self.assertIn('https://site.example/en/',(p/'sitemap.xml').read_text())
        result=subprocess.run(['python3',str(ROOT/'build.py'),'--analytics'],capture_output=True)
        self.assertNotEqual(result.returncode,0)
    def test_policy_results_and_production_origin(self):
        policy=json.loads((ROOT/'fixtures/policy-cases.json').read_text())
        self.assertEqual(policy['version'],'0.6.0')
        self.assertEqual([c['upstream_calls'] for c in policy['cases']],[1,0,0])
        self.assertIn('result',policy['cases'][0]['response'])
        self.assertEqual(policy['cases'][1]['response']['error']['code'],-32001)
        self.assertIn('approval_id',policy['cases'][2]['response']['error']['data'])
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(['python3',str(ROOT/'build.py'),'--out',directory,'--production','--analytics'],check=True,capture_output=True)
            text=(Path(directory)/'es/index.html').read_text()
            self.assertIn('https://mcp-zero-trust.686f6c61.dev/es/',text)
            self.assertIn('data-domains="mcp-zero-trust.686f6c61.dev"',text)

    def test_assets_have_content_hashes(self):
        for p in (self.out/'assets').iterdir():
            if p.is_file() and not p.name.startswith('scenarios.'):
                self.assertIn(hashlib.sha256(p.read_bytes()).hexdigest()[:12],p.name)

if __name__=='__main__':
    unittest.main()
