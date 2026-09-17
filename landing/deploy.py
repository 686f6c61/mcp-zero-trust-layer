"""Deploy the CI-tested landing commit through Coolify and verify public bytes."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def api(base, token, path, method='GET', payload=None):
    request = Request(base + '/api/v1' + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json', 'Content-Type': 'application/json'},
        method=method)
    # Only reads may be retried: a timed-out mutation may already have succeeded.
    attempts = 3 if method == 'GET' else 1
    for attempt in range(attempts):
        try:
            with urlopen(request, timeout=30) as response:
                return json.load(response)
        except HTTPError as error:
            raise RuntimeError(f'Coolify {method} {path}: HTTP {error.code}') from None
        except (URLError, TimeoutError):
            if attempt + 1 == attempts:
                raise RuntimeError(f'Coolify {method} {path}: connection failed; check runner connectivity') from None
            print(f'Coolify read connection failed; retry {attempt + 1}/{attempts - 1}', flush=True)
            time.sleep(5)


def main():
    base = os.environ['COOLIFY_URL'].rstrip('/')
    token = os.environ['COOLIFY_TOKEN']
    application = os.environ['COOLIFY_APP_UUID']
    commit = os.environ['GITHUB_SHA']
    assert urlsplit(base).scheme == 'https' and not urlsplit(base).path
    assert re.fullmatch(r'[a-zA-Z0-9]+', application)
    assert re.fullmatch(r'[a-f0-9]{40}', commit)
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == commit
    app = api(base, token, '/applications/' + application)
    assert app['git_branch'] == 'landing', 'Refusing a non-landing application'
    assert app['git_repository'].removesuffix('.git').endswith('686f6c61/mcp-zero-trust-layer')
    api(base, token, '/applications/' + application, 'PATCH',
        {'git_commit_sha': commit, 'is_auto_deploy_enabled': False})
    queued = api(base, token, '/deploy', 'POST', {'uuid': application, 'force': False})
    deployments = queued.get('deployments', [])
    assert len(deployments) == 1, 'Expected one queued deployment'
    deployment = deployments[0]['deployment_uuid']
    print(f'Queued deployment {deployment} for {commit}', flush=True)
    previous = None
    for _ in range(120):
        state = api(base, token, '/deployments/' + deployment)
        status = state['status']
        if status != previous:
            print('Deployment:', status, flush=True)
            previous = status
        if status == 'finished':
            assert state['commit'] == commit, 'Deployment revision mismatch'
            break
        if status in {'failed', 'cancelled', 'canceled'}:
            raise RuntimeError('Deployment ' + status)
        time.sleep(10)
    else:
        raise RuntimeError('Deployment timed out')
    root = Path(__file__).resolve().parent
    origin = json.loads((root / 'release.json').read_text())['site_url']
    # A production build is compared with public output, not only a success status.
    for lang in ['es', 'en']:
        expected = (root.parent / 'dist' / lang / 'index.html').read_bytes()
        for attempt in range(12):
            try:
                with urlopen(Request(f'{origin}/{lang}/', headers={'Cache-Control': 'no-cache'}), timeout=30) as response:
                    actual = response.read()
            except (HTTPError, URLError):
                actual = None
            if actual == expected:
                break
            if attempt == 11:
                raise RuntimeError(f'Public {lang} page differs from tested production build')
            time.sleep(5)
        print(f'Public {lang} HTML matches build: {hashlib.sha256(actual).hexdigest()}', flush=True)
    print('Exact landing commit deployed and both languages verified.')


if __name__ == '__main__':
    main()
