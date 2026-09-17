"""Dependency-free static site builder. Release metadata is independent of branch Python code."""
from __future__ import annotations
import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import shutil
from string import Template
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent

def esc(value):
    return html.escape(str(value), quote=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=ROOT.parent / 'dist')
    parser.add_argument('--site-url', default=os.environ.get('SITE_URL', ''))
    parser.add_argument('--analytics', action='store_true')
    parser.add_argument('--production', action='store_true', help='Use the configured production origin unless overridden')
    args = parser.parse_args()
    release = json.loads((ROOT / 'release.json').read_text())
    origin = (args.site_url or (release['site_url'] if args.production else '')).rstrip('/')
    if origin and (urlsplit(origin).scheme != 'https' or not urlsplit(origin).netloc or urlsplit(origin).path or urlsplit(origin).query or urlsplit(origin).fragment):
        parser.error('--site-url must be an HTTPS origin without a path, query or fragment')
    if args.analytics and not origin:
        parser.error('Production analytics requires --site-url; preview builds are analytics-free')
    content = json.loads((ROOT / 'content.json').read_text())
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assets = out / 'assets'
    assets.mkdir(exist_ok=True)
    names = {}
    for source in sorted((ROOT / 'assets').iterdir(), key=lambda p: p.suffix == '.css'):
        if source.is_file():
            data = source.read_bytes()
            if source.suffix == '.css':
                for original, built in names.items():
                    data = data.replace(('./' + original).encode(), built.encode())
            name = f'{source.stem}.{hashlib.sha256(data).hexdigest()[:12]}{source.suffix}'
            (assets / name).write_bytes(data)
            names[source.name] = '/assets/' + name
    fixture_dir = assets / ('fixtures.' + hashlib.sha256(b''.join(p.read_bytes() for p in sorted((ROOT / 'fixtures').iterdir()))).hexdigest()[:12])
    shutil.copytree(ROOT / 'fixtures', fixture_dir, dirs_exist_ok=True)
    fixture_url = '/assets/' + fixture_dir.name
    repo, version = release['repository'], release['version']
    ref = release['source_ref']
    docs = f'{repo}/blob/{ref}/docs/'
    files = ['bundle-at-timeout', 'bundle-after-reconciliation', 'signed-lie', 'corroborated', 'later-failure', 'wrong-amount', 'pending', 'not-found']
    trace = json.loads((ROOT / 'fixtures/comparison.json').read_text())['destination_methods']
    # Build views from frozen evidence, never from an invented successful execution.
    cases = []
    for i, file in enumerate(files):
        bundle = json.loads((ROOT / 'fixtures' / (file + '.json')).read_text())
        evidence = bundle.get('evidence', bundle)
        receipt = evidence.get('receipt')
        observations = bundle.get('observations', [])
        observation = observations[-1]['payload'] if observations else None
        cases.append({'file': file, 'gateway': 'unknown', 'destination': receipt['payload']['effect'] if receipt else '—', 'observer': observation['result'] if observation else '—', 'reason': observation['reason'] if observation else '', 'history': len(observations), 'trace': trace[:1] if i == 0 else trace, 'contracts': [evidence['permit']['authorization'], evidence['permit']['attempt'], receipt, observations[-1] if observations else None]})
    scenarios_path = assets / ('scenarios.' + hashlib.sha256(json.dumps(cases).encode()).hexdigest()[:12] + '.json')
    scenarios_path.write_text(json.dumps(cases, ensure_ascii=False))
    template = Template((ROOT / 'template.html').read_text())
    for lang, c in content.items():
        def command(text, identifier):
            return f'<div class="command"><pre><code id="{identifier}">{esc(text)}</code></pre><button type="button" data-copy="{identifier}" data-umami-event="copy-command">{esc(c["copy"])}</button></div>'
        def link(url, label, cls=''):
            return f'<a class="{cls}" href="{esc(url)}">{esc(label)}<span aria-hidden="true"> ↗</span></a>'
        nav = ''.join(f'<a href="#{anchor}">{esc(label)}</a>' for anchor, label in zip(['evidence', 'examples', 'how', 'install'], c['nav']))
        diagram = ''.join(f'<li><span class="step-number">{n}</span><div><strong>{esc(title)}</strong><span>{esc(desc)}</span></div></li>' for n, title, desc in c['diagram'])
        layers = ''.join(f'<article class="layer"><p class="kicker">{esc(k)}</p><h3>{esc(title)}</h3><p>{esc(body)}</p><p class="limit">{esc(limit)}</p></article>' for k, title, body, limit in c['layers'])
        examples = ''.join(f'<article class="example"><p class="kicker">0{i+1} / MCP</p><h3>{esc(title)}</h3><p>{esc(desc)}</p><p class="requirement">{esc(req)}</p>{link(repo + "/tree/" + ref + "/examples/" + slug, c["config"])}</article>' for i, (slug, title, desc, req) in enumerate(c['examples']))
        buttons = ''.join(f'<button type="button" data-case="{i}" aria-pressed="{str(i == 0).lower()}" aria-controls="demo-panel">{esc(label)}</button>' for i, label in enumerate(c['demoLabels']))
        policy_data = json.loads((ROOT / 'fixtures/policy-cases.json').read_text())
        policy_cases = ''.join(f'<details><summary>{esc(label)}</summary><p class="mono">{esc(case["request"]["params"]["name"])}</p><p>{esc(c["policyCalls"])}: <strong>{case["upstream_calls"]}</strong></p><pre><code>{esc(json.dumps(case["response"], indent=2))}</code></pre></details>' for label, case in zip(c['policyLabels'], policy_data['cases']))
        contract_nodes = ''.join(f'<button type="button" class="contract-node contract-node-{i}" data-contract="{i}" aria-pressed="{str(i == 0).lower()}" aria-controls="contract-inspector" disabled><span class="contract-number">0{i+1}</span><span class="contract-name">{esc(label)}</span><span class="contract-role">{esc(c["contractRoles"][i])}</span><span class="contract-state">{esc(c["contractPresent"] if i < 2 else c["contractMissing"])}</span></button>' for i, label in enumerate(c['contractLabels']))
        contract_summaries = ''.join(f'<p data-contract-summary="{i}" {"hidden" if i else ""}>{esc(summary)}</p>' for i, summary in enumerate(c['contractSummaries']))
        contract_relations = ''.join(f'<li><span class="mono">0{i+1} → 0{i+2}</span>{esc(label)}</li>' for i, label in enumerate(c['contractLinks']))
        descriptions = ''.join(f'<p data-description="{i}" {"hidden" if i else ""}>{esc(desc)}</p>' for i, desc in enumerate(c['demoDescriptions']))
        flow = ''.join(f'<li><span class="mono">0{i+1}</span>{esc(label)}</li>' for i, label in enumerate(c['flow']))
        details = ''.join(f'<details><summary>{esc(title)}</summary><p>{esc(body)}</p></details>' for title, body in c['details'])
        commands = [f'python -m pip install mcp-zero-trust-layer=={version}', 'mcpzt demo --output ./mcpzt-http-demo\ncd mcpzt-http-demo\nbash run-demo.sh', 'mcpzt evidence demo --directory ./mcpzt-receipt-demo', 'mcpzt evidence check-demo --directory ./mcpzt-check-demo']
        install = ''.join(f'<article class="install-step"><h3><span class="step-number">0{i+1}</span>{esc(title)}</h3>{command(cmd, "command-"+str(i))}<p class="small">{esc(c["httpNote"] if i == 1 else c["freshDir"] if i > 1 else "Python 3.11–3.14")}</p></article>' for i, (title, cmd) in enumerate(zip(c['installSteps'], commands)))
        seo = ''
        if origin:
            seo = f'<link rel="canonical" href="{esc(origin)}/{lang}/"><meta property="og:url" content="{esc(origin)}/{lang}/"><meta property="og:image" content="{esc(origin + names["social.png"])}"><meta name="twitter:image" content="{esc(origin + names["social.png"])}">'
            seo += ''.join(f'<link rel="alternate" hreflang="{other}" href="{esc(origin)}/{other}/">' for other in content)
            seo += f'<link rel="alternate" hreflang="x-default" href="{esc(origin)}/es/">'
        analytics = ''
        if args.analytics:
            analytics = f'<script defer src="{esc(release["analytics_script"])}" data-website-id="{esc(release["analytics_id"])}" data-domains="{esc(urlsplit(origin).hostname)}" data-do-not-track="true" data-exclude-search="true"></script>'
        values = {k: esc(v) for k, v in c.items() if isinstance(v, str)}
        values.update(lang=lang, version=version, hero=c['hero'], css=names['site.css'], js=names['site.js'], icon=names['icon.svg'], seo=seo, analytics=analytics,
            repo=repo, sourceRef=ref, docs=docs, docsLabel=esc(c['docs']), navLinks=nav, diagramItems=diagram, layerCards=layers, exampleCards=examples,
            scenarioButtons=buttons, contractNodes=contract_nodes, contractSummaries=contract_summaries, contractRelations=contract_relations, policyCases=policy_cases, descriptions=descriptions, flowItems=flow, detailItems=details, installCards=install,
            fixtureUrl=fixture_url, scenarios='/assets/'+scenarios_path.name,
            installCommand=command(commands[0], 'pip-command'), demoCommand=command(commands[3], 'demo-command'), dockerCommand=command(f'docker run --rm ghcr.io/686f6c61/mcp-zero-trust-layer:{version} --help', 'docker-command'),
            langLinks=''.join(f'<a href="/{other}/" lang="{other}" hreflang="{other}" {"aria-current=\"page\"" if lang == other else ""}>{other.upper()}</a>' for other in content),
            catalogLink=link(f'{repo}/tree/{ref}/examples', c['catalog']),
            demoLinks=link(docs+'EVIDENCE.md', c['receiptDemo']) + link(f'{repo}/tree/{ref}/examples/evidence/external-checks', c['externalDemo']) + link(f'{repo}/tree/{ref}/examples/evidence/stripe-sandbox', c['stripe']),
            validationLinks=link(docs+'TESTING_0.6.0.md', c['testReport']) + link(f'{repo}/releases/tag/v{version}', c['release']) + link(docs+'PRODUCTION.md', c['production']))
        rendered = template.substitute(values)
        (out / lang).mkdir(exist_ok=True)
        (out / lang / 'index.html').write_text(rendered)
        if lang == 'es':
            (out / 'index.html').write_text(rendered)
    (out / '404.html').write_text(f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>404 — MCPZT</title><link rel="stylesheet" href="{names["site.css"]}"><body><main class="sheet section"><p class="kicker">MCPZT / 404</p><h1>Page not found</h1><p lang="es">Esta página no existe.</p><p><a href="/es/">Inicio en español</a> · <a href="/en/">English home</a></p></main></body></html>')
    if origin:
        (out / 'sitemap.xml').write_text('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+''.join(f'<url><loc>{esc(origin)}/{lang}/</loc></url>' for lang in content)+'</urlset>')
    (out / 'robots.txt').write_text('User-agent: *\n' + ('Allow: /\nSitemap: '+origin+'/sitemap.xml\n' if origin else 'Disallow: /\n'))
    print(f'Built {version}: ES + EN in {out}; analytics={args.analytics}')

if __name__ == '__main__':
    main()
