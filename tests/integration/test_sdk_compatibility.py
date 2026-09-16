"""Real MCP SDK smoke for the documented serial stdio subset (no vendor calls)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcp_zero_trust_layer.config.models import MCPZTConfig, PolicyConfig, PolicyMatch, ServerConfig
from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.upstream.stdio import StdioProcessUpstream

pytest.importorskip('mcp', reason='install the dev extra for real SDK interoperability smoke')

SERVER = '''from pathlib import Path
from mcp.server.fastmcp import FastMCP, Context
mcp = FastMCP("mcpzt-sdk-smoke")
@mcp.tool()
def echo(text: str) -> str:
    return text
@mcp.tool()
def forbidden() -> str:
    Path(__file__).with_suffix(".executed").write_text("executed")
    return "should not run"
@mcp.tool()
async def progress(ctx: Context) -> str:
    await ctx.report_progress(1, 2, "working")
    return "done"
mcp.run(transport="stdio")
'''


def test_real_sdk_initialization_filter_call_deny_and_interleaved_notification(tmp_path: Path):
    child = tmp_path / 'sdk_server.py'
    child.write_text(SERVER)
    server = ServerConfig(name='sdk', transport='stdio', command=[sys.executable, str(child)], timeout=5)
    config = MCPZTConfig(servers=[server], policies=[
        PolicyConfig(id='protocol', effect='allow', match=PolicyMatch(method='initialize')),
        PolicyConfig(id='echo', effect='allow', match=PolicyMatch(capability='echo')),
        PolicyConfig(id='progress', effect='allow', match=PolicyMatch(capability='progress')),
        PolicyConfig(id='forbidden', effect='deny', match=PolicyMatch(capability='forbidden')),
    ], audit={'path':str(tmp_path/'audit.jsonl')}, approvals={'path':str(tmp_path/'approvals.json')})
    upstream = StdioProcessUpstream(server)
    pipeline = MCPPipeline(config, upstream)
    try:
        initialized = pipeline.handle('sdk', {'jsonrpc':'2.0','id':1,'method':'initialize','params':{
            'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'audit-test','version':'1'}}})
        assert initialized['result']['protocolVersion'] == '2025-11-25'
        assert pipeline.handle('sdk', {'jsonrpc':'2.0','method':'notifications/initialized'}) is None
        listing = pipeline.handle('sdk', {'jsonrpc':'2.0','id':2,'method':'tools/list'})
        assert {tool['name'] for tool in listing['result']['tools']} == {'echo','progress'}
        result = pipeline.handle('sdk', {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'echo','arguments':{'text':'sdk actual response'}}})
        assert result['result']['content'][0]['text'] == 'sdk actual response'
        denied = pipeline.handle('sdk', {'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'forbidden','arguments':{}}})
        assert denied['error']['code'] == -32001
        assert not child.with_suffix('.executed').exists()
        progress = pipeline.handle('sdk', {'jsonrpc':'2.0','id':5,'method':'tools/call','params':{
            'name':'progress','arguments':{},'_meta':{'progressToken':'test-progress'}}})
        assert progress['error']['code'] == -32603
        assert 'notifications are unsupported' in progress['error']['message']
        assert upstream.process.poll() is not None
    finally:
        upstream.close()
