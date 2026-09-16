"""Safe local audit reproductions; run from repository root, not as pytest tests."""

import io
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path.cwd()))
from fastapi.testclient import TestClient

import mcp_zero_trust_layer.approvals.store as sm
import mcp_zero_trust_layer.audit.logger as lm
from mcp_zero_trust_layer.approvals.store import ApprovalStore
from mcp_zero_trust_layer.approvals.ui import create_approvals_app
from mcp_zero_trust_layer.audit.logger import AuditLogger, verify_audit_hash_chain
from mcp_zero_trust_layer.config.models import ApprovalsConfig, AuditConfig
from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.protocol import JSONRPCError
from tests.integration.test_approvals import RecordingUpstream, _config, _merge_message
from tests.unit.test_approval_store import _context

root = Path(tempfile.mkdtemp(prefix="mcpzt-audit-"))
# strict audit write failure occurs after tool dispatch
cfg = _config(root)
cfg.policies[0].effect = "allow"
cfg.audit.path = str(root)
cfg.audit.strict = True
up = RecordingUpstream()
pipe = MCPPipeline(cfg, up)
try:
    pipe.handle("github", _merge_message({"pull_number": 1}))
except OSError as e:
    print("STRICT", type(e).__name__, "upstream_calls", len(up.messages))
# SQL stale approval writer can undo consumption
store = ApprovalStore(ApprovalsConfig(backend="sqlite", path=str(root / "race.db")))
a = store.create(_context(), "p")
store.set_status(a.id, "approved", decided_by="reviewer")
read = threading.Event()
consumed = threading.Event()
orig = sm._with_status


def hook(a, status, **kw):
    if threading.current_thread().name == "stale-writer":
        read.set()
        assert consumed.wait(5)
    return orig(a, status, **kw)


def writer():
    store.set_status(a.id, "approved", decided_by="reviewer")


with patch.object(sm, "_with_status", hook):
    t = threading.Thread(target=writer, name="stale-writer")
    t.start()
    assert read.wait(5)
    first = store.consume_if_valid(a.id, _context(), "p")
    consumed.set()
    t.join()
print("SQL_REPLAY", first, store.consume_if_valid(a.id, _context(), "p"))
# UI has no audit events even after approved decision
cfg = _config(root)
client = TestClient(create_approvals_app(cfg))
st = ApprovalStore(cfg.approvals)
a = st.create(_context(), "p")
response = client.post(f"/api/approvals/{a.id}/allow", json={"comment": "review"})
print("UI_AUDIT", response.status_code, "audit_exists", Path(cfg.audit.path).exists())
# Default token-auth approval reads remain public
cfg.auth.mode = "static_token"
cfg.auth.token = "example-token"
client = TestClient(create_approvals_app(cfg))
print(
    "UNAUTH_LIST",
    client.get("/api/approvals").status_code,
    "items",
    len(client.get("/api/approvals").json()),
)
# stdout chain does not verify
logger = AuditLogger(AuditConfig(destination="stdout", hash_chain=True))
with patch("sys.stdout", new_callable=io.StringIO) as output:
    logger._write({"x": 1})
    logger._write({"x": 2})
    capture = output.getvalue()
f = root / "stdout.jsonl"
f.write_text(capture)
print("STDOUT_CHAIN", verify_audit_hash_chain(f))
# real concurrency audit chain race, no monkeypatch
f = root / "chain.jsonl"
logger = AuditLogger(AuditConfig(destination="file", path=str(f), hash_chain=True))
with ThreadPoolExecutor(max_workers=12) as ex:
    list(ex.map(lambda i: logger._write({"x": i}), range(1200)))
print("CONCURRENT_CHAIN", verify_audit_hash_chain(f))
print("ARTIFACTS", root)
# Force a valid scheduler interleaving after unlock and before buffered close

f = root / "interleaved.jsonl"
logger = AuditLogger(AuditConfig(destination="file", path=str(f), hash_chain=True))
real_flock = lm.fcntl.flock
unlocked = threading.Event()
second_done = threading.Event()


def scheduling_flock(fd, op):
    result = real_flock(fd, op)
    if op == lm.fcntl.LOCK_UN and threading.current_thread().name == "first-log":
        unlocked.set()
        assert second_done.wait(5)
    return result


def firstlog():
    logger._write({"x": 1})


with patch.object(lm.fcntl, "flock", scheduling_flock):
    t = threading.Thread(target=firstlog, name="first-log")
    t.start()
    assert unlocked.wait(5)
    logger._write({"x": 2})
    second_done.set()
    t.join()
print("SCHEDULED_CHAIN", verify_audit_hash_chain(f), f.read_text())
# Catch dropped upstream exception audit

cfg = _config(root)
cfg.policies[0].effect = "allow"
cfg.audit.path = str(root / "failed-call.jsonl")


class Failing:
    def send(self, *args, **kwargs):
        raise JSONRPCError(-32000, "transport failure after dispatch")


pipe = MCPPipeline(cfg, Failing())
response = pipe.handle("github", _merge_message({"pull_number": 1}))
print("UPSTREAM_ERROR_AUDIT", response, Path(cfg.audit.path).exists())
