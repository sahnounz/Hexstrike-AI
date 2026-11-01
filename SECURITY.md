# API security and migration

HexStrike intentionally runs arbitrary shell commands and Python, installs
packages, and operates security tools. Treat API credentials as full control of
the service account. This change protects entry to the API, not execution inside
it. Run as a dedicated unprivileged account on an isolated host.

## Supported configuration

The default bind is `127.0.0.1:8888`. Startup requires a bearer token unless the
operator explicitly enables local compatibility mode. Every route, including
`/health`, tools, files, command execution, Python execution, and future routes,
is protected by a global request hook. Tokens are never printed by startup.

Generate a secret, then configure the same value on the server and MCP client:

```bash
export HEXSTRIKE_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
python3 hexstrike_server.py
# In a separate terminal, securely set the SAME token, then:
python3 hexstrike_mcp.py --server http://127.0.0.1:8888
```

Direct HTTP callers must send `Authorization: Bearer <token>`. Query parameters,
cookies, and forwarded authorization headers are not accepted. Tokens must be
32-514 characters of ASCII bearer-token syntax. Length validation cannot ensure
entropy; generate random secrets. Restart both processes to rotate the token.
Do not commit real tokens in MCP JSON files. Replace the sample placeholder.

| Setting | Default and behavior |
| --- | --- |
| `HEXSTRIKE_HOST` / `--host` | `127.0.0.1`; CLI takes precedence. IP literal or exact `localhost` only. `API_HOST` is a lower-priority legacy alias. |
| `HEXSTRIKE_PORT` / `--port` | `8888`; integer 1-65535, CLI takes precedence. |
| `HEXSTRIKE_API_TOKEN` | Required by default; shared with MCP client. |
| `HEXSTRIKE_ALLOW_UNAUTHENTICATED_LOCAL` | `0`; only exact `0` and `1` are accepted. |
| `HEXSTRIKE_COMMAND_TIMEOUT` / `--timeout` | `300` seconds; positive integer, CLI takes precedence. |
| `DEBUG_MODE` / `--debug` | Debug logging is restricted to loopback. Interactive debugger and reloader are always disabled. |

Invalid environment settings fail at import, even if a CLI override would have
replaced them. CLI configuration is validated before listening. Importing the app
without credentials leaves all requests denied (503), rather than silently
opening a WSGI deployment. WSGI operators must also configure their actual bind;
Flask's `API_HOST` cannot control a separate WSGI server's listener. Do not install
ProxyFix or other middleware that rewrites the peer address in local mode.

## Explicit local compatibility mode

For a trusted single-user machine with no proxy or forwarded port:

```bash
HEXSTRIKE_ALLOW_UNAUTHENTICATED_LOCAL=1 python3 hexstrike_server.py
```

This permits token-free requests only with a loopback bind, a loopback peer, and
a loopback Host header. Browser Origin headers, non-`none` Fetch Metadata origins,
and common forwarding headers are refused. If a token is configured, it remains
mandatory even in this mode. The MCP client works unchanged when no token is set.
This mode trusts local users and processes. A tunnel or proxy can appear as a
local peer, so never use it with network forwarding. Use tokens on multi-user hosts.

## Remote access

Set a strong token on both ends and explicitly choose a remote bind:

```bash
python3 hexstrike_server.py --host 0.0.0.0
```

This requires `HEXSTRIKE_API_TOKEN` and local compatibility mode must be disabled.
Remote debug mode is rejected. Use TLS termination or an authenticated SSH tunnel
and firewall restrictions. The built-in server does not provide TLS and is not a
production HTTP server. Plain HTTP exposes bearer tokens to network observers.
No public reachability or deployed infrastructure was tested by this patch.

## Timeout compatibility with upstream PR #293

This patch incorporates the proposed server env/CLI timeout, dynamically resolved
executor defaults, optional positive integer `/api/command` JSON `timeout`, and
exclusion of timed-out partial output from cache. Cache keys additionally include
the effective timeout. MCP `--timeout` remains an independent HTTP wait limit;
set it above the server limit, allowing response/cleanup overhead. Tool and Python
execution continue to use the server-wide command timeout. There is no new
per-request timeout field on the Python endpoint. Applying #293 afterward may
produce overlapping hunks because its behavior is already incorporated.

## Remaining limitations

- Authorized callers can execute arbitrary code, read accessible files, make
  outbound connections, install packages, and exploit shell interpolation in
  existing tool handlers. Authentication is not a sandbox or per-tool authorization.
- Shared tokens have no roles, expiry, rate limiting, or per-user audit trail.
- File APIs reject absolute paths, traversal and resolved symlink escapes, but
  check/use races and local filesystem tampering remain possible. These checks
  do not constrain shell/Python code or all other filesystem access.
- Browser navigation permits only HTTP(S), but does not prevent SSRF, internal
  destinations, or all redirect behaviors.
- Existing timeout handling terminates the shell, not reliably all descendants.
  Output/resource limits and complete process-tree cleanup require separate work.
- Full external tool, browser, mitmproxy and MCP stdio integration was not exercised.

## References and provenance

Adapted the global token hook, MCP token forwarding, filesystem containment,
browser scheme checks and baseline tests from upstream PR #292, head
`daa0df4cef20f552c2f12b27722f362f63013acf`. Incorporated timeout behavior from
PR #293, head `ce62055a0fa880d3e80cf5db413dd0058907fe5c`, with stricter validation
and timeout-aware cache keys. This branch adds default-required credentials,
explicit local compatibility, peer/browser checks, configuration validation and
expanded tests in response to issue #296.

- https://github.com/0x4m4/hexstrike-ai/issues/296
- https://github.com/0x4m4/hexstrike-ai/pull/292
- https://github.com/0x4m4/hexstrike-ai/pull/293
