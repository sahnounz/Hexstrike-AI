# Local security regression validation

```bash
python3 -m venv .venv-test
.venv-test/bin/pip install flask requests psutil
.venv-test/bin/python -m unittest discover -s tests
python3 -m py_compile hexstrike_security.py hexstrike_server.py hexstrike_mcp.py
```

No Docker, scanners, browser, remote targets, or package installation by the API
is needed. The test bootstrap stubs missing optional browser/proxy/MCP imports.
Actual Flask routing, requests HTTP, subprocess command execution, and the system
Python interpreter are used. The Python execution test substitutes the interpreter
path to avoid creating a package-enabled venv. Startup tests execute the complete
`__main__` path with only `Flask.run` mocked. One integration test runs Werkzeug
on an ephemeral loopback port. Tests must run in a trusted disposable environment
because they import the server and exercise its intended code-execution behavior.

## Coverage

- All registered routes and methods reject requests without the configured token.
- Malformed/wrong/missing credentials, JSON parsing order and no Python side effects.
- Real authorized shell/Python execution and real loopback HTTP authorization.
- Default loopback bind, remote binding with a token, invalid host/token/port/env/CLI.
- Explicit local compatibility, peer/Host/browser/forwarded header restrictions.
- No-token imported WSGI app fails closed; a token overrides local compatibility.
- MCP session bearer header forwarding, file containment, Python path quoting.
- Timeout env/CLI/default precedence and invalid per-request values.
- Real timeout with partial output, extended retry, successful result caching and
  timeout-separated cache keys.

## Recorded validation

Validated on Python 3.12.14, Linux, Flask 3.1.3, requests 2.34.2 and psutil 7.2.2.
The small test environment does not reproduce all requirements.txt pins.
44 unittest methods passed, including parameterized subtests. Full optional
dependency integration, an MCP stdio conversation, external tools and deployment
reachability were not tested. `py_compile` and `git diff --check` passed.

The suite emitted ResourceWarnings from existing logging file handles (repeated
module loads) and subprocess pipe handles. These did not fail tests; they are
recorded limitations, not evidence of clean resource lifecycle handling.
