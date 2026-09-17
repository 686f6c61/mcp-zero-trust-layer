"""Deployment checks against the actual Nginx container."""
import sys
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args): return None
opener=build_opener(NoRedirect())
def get(path,headers=None):
    try: return opener.open(Request(sys.argv[1]+path,headers=headers or {}))
    except HTTPError as response: return response
r=get('/')
assert r.status==302 and r.headers['Location']=='/es/',dict(r.headers)
r=get('/',{'Cookie':'mcpzt_lang=en'})
assert r.status==302 and r.headers['Location']=='/en/'
for lang in ['es','en']:
    r=get('/'+lang, {'X-Forwarded-Proto':'https'})
    assert r.status==301 and r.headers['Location']=='/'+lang+'/'

    r=get('/'+lang+'/')
    assert r.status==200
    assert r.headers['X-Content-Type-Options']=='nosniff'
    assert "object-src 'none'" in r.headers['Content-Security-Policy']
    assert 'no-cache' in r.headers['Cache-Control']
    assert '0.6.0' in r.read().decode()
for path in ['/not-a-page','/assets/missing.js','/es/does-not-exist']:
    r=get(path)
    assert r.status==404,(path,r.status)
    assert 'Page not found' in r.read().decode()
print('Nginx routes, language preference, headers and 404s passed.')
