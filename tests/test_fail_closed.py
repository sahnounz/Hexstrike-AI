"""Security boundary and PR #293 compatibility tests; no external tools."""
import contextlib
import io
import os
import runpy
import shlex
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from test_security_hardening import hs, SERVER_PATH
from hexstrike_security import validate_config, validate_token, boolean_env

TOKEN = 'regression-token-' * 3
AUTH = {'Authorization': 'Bearer ' + TOKEN}


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.client = hs.app.test_client()
        patch = mock.patch.object(hs, 'API_TOKEN', TOKEN)
        patch.start()
        self.addCleanup(patch.stop)

    def test_every_registered_route_requires_auth(self):
        with mock.patch.object(hs, 'execute_command') as execute:
            for rule in hs.app.url_map.iter_rules():
                for method in rule.methods:
                    with self.subTest(route=str(rule), method=method):
                        self.assertEqual(self.client.open(str(rule), method=method).status_code, 401)
            execute.assert_not_called()

    def test_denied_python_has_no_side_effects(self):
        with mock.patch.object(hs.file_manager, 'create_file') as create, \
                mock.patch.object(hs.env_manager, 'get_python_path') as env, \
                mock.patch.object(hs, 'execute_command') as execute:
            for auth in ('', 'Bearer wrong', 'Bearer é', 'Basic ' + TOKEN, 'Bearer ' + TOKEN + ' '):
                r = self.client.post('/api/python/execute', json={'script': 'print(42)'},
                                     headers={'Authorization': auth})
                self.assertEqual(r.status_code, 401)
            create.assert_not_called(); env.assert_not_called(); execute.assert_not_called()

    def test_auth_before_json_parsing(self):
        self.assertEqual(self.client.post('/api/command', data='{bad', content_type='application/json').status_code, 401)

    def test_query_cookie_and_forwarded_token_not_credentials(self):
        self.client.set_cookie('HEXSTRIKE_API_TOKEN', TOKEN)
        self.assertEqual(self.client.get('/health?token=' + TOKEN,
            headers={'X-Authorization': AUTH['Authorization']}).status_code, 401)

    def test_wsgi_no_configuration_fails_closed(self):
        with mock.patch.object(hs, 'API_TOKEN', ''), mock.patch.object(hs, 'ALLOW_UNAUTHENTICATED_LOCAL', False):
            self.assertEqual(self.client.post('/api/command', json={'command': 'echo no'}).status_code, 503)

    def test_local_mode_checks_peer_and_browser_headers(self):
        with mock.patch.object(hs, 'API_TOKEN', ''), mock.patch.object(hs, 'ALLOW_UNAUTHENTICATED_LOCAL', True), \
                mock.patch.object(hs, 'execute_command') as execute:
            for peer, headers in [('192.0.2.1', {'Host': 'localhost'}),
                                  ('192.0.2.1', {'Host': 'localhost', 'X-Forwarded-For': '127.0.0.1'}),
                                  ('127.0.0.1', {'Host': 'evil.example'}),
                                  ('127.0.0.1', {'X-Forwarded-For': '192.0.2.1'}),
                                  ('127.0.0.1', {'Forwarded': 'for=192.0.2.1'}),
                                  ('127.0.0.1', {'Origin': 'null'}),
                                  ('127.0.0.1', {'Origin': 'http://localhost:8888'}),
                                  ('127.0.0.1', {'Sec-Fetch-Site': 'cross-site'}),
                                  ('127.0.0.1', {'Host': 'localhost:bad'})]:
                with self.subTest(peer=peer, headers=headers):
                    self.assertEqual(self.client.post('/api/command', json={'command': 'echo no'},
                        headers=headers, environ_overrides={'REMOTE_ADDR': peer}).status_code, 403)
            execute.assert_not_called()

    def test_local_compatibility_executes(self):
        with mock.patch.object(hs, 'API_TOKEN', ''), mock.patch.object(hs, 'ALLOW_UNAUTHENTICATED_LOCAL', True):
            r = self.client.post('/api/command', json={'command': 'printf local-ok', 'use_cache': False})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json['stdout'], 'local-ok')

    def test_token_required_even_on_loopback_in_compatibility_mode(self):
        with mock.patch.object(hs, 'ALLOW_UNAUTHENTICATED_LOCAL', True):
            self.assertEqual(self.client.get('/health').status_code, 401)

    def test_authorized_python_executes_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = hs.FileOperationsManager(tmp)
            # Real interpreter and command runner, no venv or package downloads.
            with mock.patch.object(hs, 'file_manager', manager), \
                    mock.patch.object(hs.env_manager, 'get_python_path', return_value=sys.executable):
                r = self.client.post('/api/python/execute', headers=AUTH,
                    json={'script': 'print("python-auth-ok")', 'filename': 'script with spaces.py'})
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.json['stdout'].strip(), 'python-auth-ok')
                self.assertFalse((Path(tmp) / 'script with spaces.py').exists())

    def test_authorized_command_executes(self):
        r = self.client.post('/api/command', headers=AUTH,
                            json={'command': 'printf command-auth-ok', 'use_cache': False})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json['stdout'], 'command-auth-ok')

    def test_real_loopback_http(self):
        import requests
        from werkzeug.serving import make_server
        server = make_server('127.0.0.1', 0, hs.app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f'http://127.0.0.1:{server.server_port}/api/command'
            with requests.Session() as session:
                session.trust_env = False
                self.assertEqual(session.post(url, json={'command': 'printf no'}, timeout=5).status_code, 401)
                r = session.post(url, headers=AUTH, json={'command': 'printf http-ok', 'use_cache': False}, timeout=5)
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.json()['stdout'], 'http-ok')
        finally:
            server.shutdown(); thread.join(5); server.server_close()


class ConfigurationTests(unittest.TestCase):
    def start(self, args=(), env=None):
        clean = {k: v for k, v in os.environ.items() if not k.startswith('HEXSTRIKE_') and k not in ('API_HOST', 'DEBUG_MODE')}
        clean.update(env or {})
        with mock.patch.dict(os.environ, clean, clear=True), mock.patch.object(sys, 'argv', [str(SERVER_PATH), *args]), \
                mock.patch('flask.Flask.run') as run, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                namespace = runpy.run_path(str(SERVER_PATH), run_name='__main__')
                return run, namespace
            except (SystemExit, ValueError):
                run.assert_not_called()
                return run, None

    def test_default_requires_credentials(self):
        run, ns = self.start()
        self.assertIsNone(ns)

    def test_default_bind_with_token(self):
        run, ns = self.start(env={'HEXSTRIKE_API_TOKEN': TOKEN})
        self.assertEqual(run.call_args.kwargs['host'], '127.0.0.1')
        self.assertFalse(run.call_args.kwargs['use_debugger'])
        self.assertFalse(run.call_args.kwargs['use_reloader'])

    def test_remote_explicit_and_protected(self):
        run, ns = self.start(['--host', '0.0.0.0'], {'HEXSTRIKE_API_TOKEN': TOKEN})
        self.assertEqual(run.call_args.kwargs['host'], '0.0.0.0')

    def test_invalid_startups(self):
        for env in ({'HEXSTRIKE_PORT': '0'}, {'HEXSTRIKE_PORT': '65536'}, {'HEXSTRIKE_PORT': 'abc'},
                    {'HEXSTRIKE_API_TOKEN': ' '}, {'HEXSTRIKE_API_TOKEN': 'weak'},
                    {'HEXSTRIKE_HOST': ''}, {'HEXSTRIKE_HOST': 'example.com'},
                    {'HEXSTRIKE_HOST': '0.0.0.0', 'HEXSTRIKE_ALLOW_UNAUTHENTICATED_LOCAL': '1'},
                    {'HEXSTRIKE_ALLOW_UNAUTHENTICATED_LOCAL': 'yes'},
                    {'HEXSTRIKE_COMMAND_TIMEOUT': '0'}, {'HEXSTRIKE_COMMAND_TIMEOUT': '-1'},
                    {'HEXSTRIKE_COMMAND_TIMEOUT': 'abc'}, {'HEXSTRIKE_COMMAND_TIMEOUT': '1.5'},
                    {'HEXSTRIKE_HOST': '0.0.0.0', 'DEBUG_MODE': '1'}):
            with self.subTest(env=env):
                _, ns = self.start(env={'HEXSTRIKE_API_TOKEN': TOKEN, **env})
                self.assertIsNone(ns)

    def test_cli_invalid_ports_timeout_host(self):
        for args in (['--port', '0'], ['--port', '65536'], ['--timeout', '0'], ['--timeout', '-1'],
                     ['--timeout', '1.5'], ['--host', 'example.com'], ['--host', '0.0.0.0', '--debug']):
            with self.subTest(args=args):
                _, ns = self.start(args, {'HEXSTRIKE_API_TOKEN': TOKEN})
                self.assertIsNone(ns)

    def test_host_alias_and_cli_precedence(self):
        run, _ = self.start(env={'HEXSTRIKE_API_TOKEN': TOKEN, 'API_HOST': '::1'})
        self.assertEqual(run.call_args.kwargs['host'], '::1')
        run, _ = self.start(['--host', '127.0.0.2'], {'HEXSTRIKE_API_TOKEN': TOKEN, 'HEXSTRIKE_HOST': '::1'})
        self.assertEqual(run.call_args.kwargs['host'], '127.0.0.2')

    def test_timeout_env_cli_and_dynamic_default(self):
        for args, expected in [((), 7), (['--timeout', '9'], 9)]:
            run, ns = self.start(args, {'HEXSTRIKE_API_TOKEN': TOKEN, 'HEXSTRIKE_COMMAND_TIMEOUT': '7'})
            self.assertEqual(ns['COMMAND_TIMEOUT'], expected)
            self.assertEqual(ns['EnhancedCommandExecutor']('echo ok').timeout, expected)

    def test_token_validation(self):
        for value in ('short', ' '*32, 'a'*31+'\n', 'é'*32, 'a'*515):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                validate_token(value)
        self.assertEqual(validate_token(TOKEN), TOKEN)


class TimeoutTests(unittest.TestCase):
    def setUp(self):
        self.client = hs.app.test_client()
        patch = mock.patch.object(hs, 'API_TOKEN', TOKEN)
        patch.start(); self.addCleanup(patch.stop)

    def test_invalid_request_timeouts_do_not_execute(self):
        with mock.patch.object(hs, 'execute_command') as execute:
            for value in (0, -1, True, False, 1.5, '2', 'abc', [], {}):
                r = self.client.post('/api/command', headers=AUTH, json={'command': 'echo no', 'timeout': value})
                self.assertEqual(r.status_code, 400, repr(value))
            execute.assert_not_called()

    def test_request_timeout_forwarded(self):
        with mock.patch.object(hs, 'execute_command', return_value={'success': True}) as execute:
            for value in (1, 600):
                r = self.client.post('/api/command', headers=AUTH, json={'command': 'echo ok', 'timeout': value})
                self.assertEqual(r.status_code, 200)
                execute.assert_called_with('echo ok', use_cache=True, timeout=value)

    def test_real_timeout_not_cached_and_extended_retry(self):
        # exec replaces the shell so this test does not leave a descendant behind.
        code = 'import time; print("partial", flush=True); time.sleep(1.3); print("complete")'
        command = 'exec ' + shlex.quote(sys.executable) + ' -c ' + shlex.quote(code)
        with mock.patch.object(hs, 'cache', hs.HexStrikeCache()):
            short = hs.execute_command(command, timeout=1)
            self.assertTrue(short['timed_out'])
            retry = hs.execute_command(command, timeout=3)
            self.assertFalse(retry['timed_out'])
            self.assertIn('complete', retry['stdout'])
            with mock.patch.object(hs.EnhancedCommandExecutor, 'execute') as execute:
                hs.execute_command(command, timeout=3)
                execute.assert_not_called()
            again = hs.execute_command(command, timeout=1)
            self.assertTrue(again['timed_out'])

    def test_timed_out_success_never_cached(self):
        with mock.patch.object(hs, 'cache') as cache, \
                mock.patch.object(hs.EnhancedCommandExecutor, 'execute', return_value={'success': True, 'timed_out': True}):
            cache.get.return_value = None
            hs.execute_command('unused')
            cache.set.assert_not_called()
