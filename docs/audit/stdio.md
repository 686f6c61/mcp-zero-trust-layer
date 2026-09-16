# Stdio transport contract review

Base `4c1061daab2fa2a7442d42e7412cf3c6c85ae89f`, 2026-09-16.

Reproduce using `.venv/bin/python docs/audit/reproduce_stdio.py`. Only temporary local child processes and synthetic messages are used.

| Finding | Evidence | Impact and fix |
| --- | --- | --- |
| T-01 High: response limit ignored | `upstream/stdio.py:61-83` uses unlimited `readline`; with `max_response_bytes=32`, a 151-byte decoded response is accepted | Bound bytes before buffering/parsing. `transports/stdio/wrapper.py:47` also reads inbound lines without `runtime.max_request_bytes`; source-confirmed inbound gap. README 1011 and PRODUCTION 100 state limits more broadly than implementation supports. |
| T-02 High: timeout only covers initial readability | `upstream/stdio.py:78-83`: after the first byte, blocking readline has no deadline. With timeout 0.1 seconds, a partial frame completed after 0.5 seconds returns successfully | A partial response can stall the process indefinitely. Use a whole-frame monotonic deadline with bounded buffering; test partial writes, no newline and stderr backpressure. |
| T-03 High interoperability: no message correlation | `upstream/stdio.py:65-70`: any dict is accepted as the response. Request ID 1 accepts response ID 999; an upstream notification is also returned as the response | Introduce an ID-correlated dispatcher for responses, notifications and server requests, or reject unsupported message classes explicitly. This is the same underlying finding as C-06, not an extra independent defect. |

A broader protocol test should use an actual MCP SDK server, not only the custom echo process in the existing integration suite. Include initialization, interleaved notifications, cancellation, mismatched IDs, byte limits and deadlines. No claim of completed SDK interoperability testing is made here.

## Remediation verification

The stdio adapter now reads bounded byte frames with a monotonic response deadline, checks JSON-RPC response IDs and closes the subprocess after framing/protocol failures so late responses cannot contaminate later calls. The wrapper bounds inbound frame size and rejects non-object messages. Discovery follows cursors (with repeated-cursor detection and a 1000-page ceiling), validates the negotiated version and scopes HTTP session state to an invocation.

The supported stdio profile remains **serial request/response on POSIX**. Server-initiated requests and notifications are explicitly rejected and terminate the upstream session; they are neither mistaken for replies nor forwarded around output policy. Concurrent cancellation, sampling, elicitation, progress and list-change dispatch need a bidirectional policy-aware dispatcher and remain unsupported. The deadline covers nonblocking stdin writes and the complete reply frame; downstream idle input waits remain intentional. Non-POSIX pipe operation is rejected explicitly.

`tests/integration/test_sdk_compatibility.py` uses the actual Python MCP SDK (locally exercised with mcp 1.30.0) in a temporary process: initialize/version negotiation, initialized, filtered tools/list, permitted echo execution, denied tool with non-execution marker, and explicit rejection of an interleaved progress notification. No live vendor or model calls are involved.
