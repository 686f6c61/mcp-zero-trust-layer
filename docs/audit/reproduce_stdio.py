import json
import sys
import time

from mcp_zero_trust_layer.config.models import ServerConfig
from mcp_zero_trust_layer.upstream.stdio import StdioProcessUpstream


def run(label, child, limit=32, timeout=0.1):
    server = ServerConfig(
        name="probe",
        transport="stdio",
        command=[sys.executable, "-u", "-c", child],
        max_response_bytes=limit,
        timeout=timeout,
    )
    upstream = StdioProcessUpstream(server)
    start = time.monotonic()
    try:
        result = upstream.send(server, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        print(
            label,
            json.dumps(
                {
                    "elapsed": round(time.monotonic() - start, 3),
                    "response_bytes": len(json.dumps(result)),
                    "result": result,
                }
            ),
        )
    finally:
        upstream.close()


run(
    "partial_frame_timeout",
    'import sys,time;sys.stdin.readline();sys.stdout.write("{");sys.stdout.flush();time.sleep(.5);print(\'"jsonrpc":"2.0","id":1,"result":{}}\',flush=True)',
)
run(
    "oversize_response",
    'import sys,json;sys.stdin.readline();print(json.dumps({"jsonrpc":"2.0","id":1,"result":{"data":"x"*100}}),flush=True)',
)
run(
    "wrong_id_response",
    'import sys,json;sys.stdin.readline();print(json.dumps({"jsonrpc":"2.0","id":999,"result":{}}),flush=True)',
)
run(
    "notification_as_response",
    'import sys,json;sys.stdin.readline();print(json.dumps({"jsonrpc":"2.0","method":"notifications/message","params":{}}),flush=True)',
)
