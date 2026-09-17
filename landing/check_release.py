"""Require the public product release and source links before deploying the website."""
import json
import os
from html.parser import HTMLParser
from pathlib import Path
import time
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError
ROOT=Path(__file__).resolve().parent
release=json.loads((ROOT/'release.json').read_text())
version=release['version']
urls={release['repository']+'/releases/tag/v'+version, 'https://pypi.org/pypi/mcp-zero-trust-layer/'+version+'/json'}
class Links(HTMLParser):
    def handle_starttag(self,tag,attrs):
        href=dict(attrs).get('href','')
        if href.startswith(release['repository']+'/') and ('/blob/' in href or '/tree/' in href or '/tag/v'+version in href): urls.add(href)
page=ROOT.parent/'dist/es/index.html'
if not page.exists(): raise SystemExit('Build the landing first.')
Links().feed(page.read_text())
failed=[]
for url in sorted(urls):
    target=url
    headers={'User-Agent':'MCPZT-release-check'}
    if url.startswith(release['repository']+'/'):
        repo_path=urlsplit(release['repository']).path.strip('/')
        suffix=url[len(release['repository'])+1:]
        if suffix.startswith('releases/tag/'):
            target=f'https://api.github.com/repos/{repo_path}/releases/tags/'+suffix[len('releases/tag/'):]
        else:
            _,ref,path=suffix.split('/',2)
            target=f'https://api.github.com/repos/{repo_path}/contents/{path}?ref={quote(ref,safe="")}'
        if os.environ.get('GH_TOKEN'): headers['Authorization']='Bearer '+os.environ['GH_TOKEN']
    for attempt in range(3):
        try:
            with urlopen(Request(target,headers=headers),timeout=30) as response:
                if response.status!=200: raise RuntimeError('Unexpected response')
            break
        except HTTPError as error:
            if error.code in {429,500,502,503,504} and attempt<2:
                time.sleep(5)
                continue
            failed.append(url)
            print(f'UNAVAILABLE: {url} (HTTP {error.code})')
            break
        except OSError as error:
            failed.append(url)
            print(f'UNAVAILABLE: {url} ({type(error).__name__})')
            break
if failed: raise SystemExit('Release gate failed: publish product artifacts and documentation before this landing.')
print(f'Public release and {len(urls)} linked destinations are reachable for {version}.')
