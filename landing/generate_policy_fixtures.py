"""Generate synthetic policy outcomes with the installed MCPZT release and a fake peer."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
from mcp_zero_trust_layer import __version__
from mcp_zero_trust_layer.config import load_config
from mcp_zero_trust_layer.core.pipeline import MCPPipeline

parser=argparse.ArgumentParser()
parser.add_argument('--config',type=Path,required=True,help='Reviewed examples/github-readonly/mcpzt.yaml from the product checkout')
args=parser.parse_args()
root=Path(__file__).resolve().parent
version=json.loads((root/'release.json').read_text())['version']
if __version__!=version: raise SystemExit('Use the product version declared in landing/release.json')
class Peer:
    calls=0
    def send(self,server,request,**kwargs):
        self.calls+=1
        return {'jsonrpc':'2.0','id':request['id'],'result':{'content':[{'type':'text','text':'Synthetic issue search result'}]}}
with tempfile.TemporaryDirectory() as directory:
    cfg=load_config(args.config)
    cfg.audit.path=str(Path(directory)/'audit.jsonl')
    cfg.approvals.path=str(Path(directory)/'approvals.sqlite3')
    peer=Peer()
    pipeline=MCPPipeline(cfg,peer)
    cases=[]
    for name,tool,arguments in [('allowed','github.search_issues',{'q':'security'}),('denied','github.delete_repository',{}),('approval','github.merge_pull_request',{'repo':'demo','pull_number':1})]:
        before=peer.calls
        request={'jsonrpc':'2.0','id':len(cases)+1,'method':'tools/call','params':{'name':tool,'arguments':arguments}}
        response=pipeline.handle('github',request)
        cases.append({'case':name,'request':request,'response':response,'upstream_calls':peer.calls-before})
    assert 'result' in cases[0]['response'] and cases[0]['upstream_calls']==1
    assert cases[1]['response']['error']['code']==-32001 and cases[1]['upstream_calls']==0
    assert cases[2]['response']['error']['data']['approval_id'] and cases[2]['upstream_calls']==0
    data={'simulation':True,'provider_contacted':False,'version':version,'config':'examples/github-readonly/mcpzt.yaml','config_sha256':hashlib.sha256(args.config.read_bytes()).hexdigest(),'cases':cases}
    (root/'fixtures/policy-cases.json').write_text(json.dumps(data,indent=2)+'\n')
print('Generated allowed, denied and approval-pending outcomes; no provider contacted.')
