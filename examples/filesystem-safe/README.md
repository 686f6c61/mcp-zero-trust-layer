# Filesystem example

This example targets `@modelcontextprotocol/server-filesystem@2026.8.31`, using its actual `read_text_file` and `write_file` tool names. Other tools are denied. The [upstream documentation](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) describes the server contract.

From the repository root, with MCPZT installed and Node.js/npm available:

```sh
cd examples/filesystem-safe
mcpzt wrap --config mcpzt.yaml --server filesystem
```

The wrapper speaks MCP JSON-RPC on stdin/stdout; connect an MCP client rather than interpreting an idle terminal as a failure. Initialize with `capabilities: {}`; client Roots negotiation would require server-initiated requests, which this bounded stdio profile does not support.

The working directory matters: `npx` resolves its `./workspace` argument from the launch directory, while the gateway's validator resolves `./workspace` from the YAML directory. The command above makes them agree. For desktop-client configuration, use absolute paths in both `servers[].command` and validator `allowed_roots` instead.

The shipped workspace contains only synthetic text. Read its README using an absolute `path`. Writes inside the workspace require approval; out-of-root reads and writes fail before dispatch. List discovery exposes the two supported tools without executing them. An operator can approve a pending write with `mcpzt approve allow APPROVAL_ID --config mcpzt.yaml --by reviewer` from this directory, followed by the same request with its approval control field.

To run the real peer regression locally from the repository root:

```sh
npm install --prefix /tmp/mcpzt-filesystem-peer --ignore-scripts --no-audit --no-fund @modelcontextprotocol/server-filesystem@2026.8.31
MCPZT_FILESYSTEM_ENTRYPOINT=/tmp/mcpzt-filesystem-peer/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js \
  python -m pytest tests/integration/test_repository_examples.py -k filesystem -q
```

This checks real stdio initialization, discovery, reading, rejection outside the root, approval before file creation and rejection of a consumed approval. All mutations use a temporary copy of the synthetic workspace. CI installs the same pinned peer.
