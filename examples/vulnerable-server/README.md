# Vulnerable Demo Server

A deliberately vulnerable MCP server used to demonstrate MCPLint's scanner. It
contains two intentional issues:

- A tool description with an embedded prompt-injection pattern (`MCP-SEC-040`)
- A tool named to shadow a common tool from another server (`MCP-SEC-041`)

Reproduce the scan output shown in the top-level README:

```bash
mcplint scan examples/vulnerable-server/server.py
```

Do not use this server as a template for real MCP servers.
