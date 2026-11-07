#!/usr/bin/env python3
"""Local harness for the dnshelper UI: a mock NS8 API in front of the REAL
Python action code (imageroot/pypkg/dnshelper_lib.py), with a fake DNS host.

    python3 ui/dev/server.py [port]        then open http://127.0.0.1:8099/

State lives in a temporary directory that is removed on exit. Try tokens
containing "bad" (rejected), "readonly" or "nolist" (host limitations).

Environment: DNSHELPER_REAL_BIN=<built helper> shows the real provider list;
CORE_CSS=<core UI dist/css/core.css> gives the shell's styling.
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
STATE = tempfile.mkdtemp(prefix='dnshelper-ui-')
os.environ.update(AGENT_STATE_DIR=STATE, AGENT_TASK_USER='admin', MODULE_ID='dnshelper1',
                  AGENT_ID='module/dnshelper1', DNSHELPER_BIN=os.path.join(HERE, 'fake_helper.py'))
sys.path.insert(0, os.path.join(ROOT, 'imageroot', 'pypkg'))
import dnshelper_lib as lib  # noqa: E402

DIST = os.path.join(HERE, '..', 'dist')
# The shell's global stylesheet (the NS8 core UI's css/core.css). Optional: without it the app renders unstyled.
CORE_CSS = os.environ.get('CORE_CSS', '')
EVENTS, LOCK = [], threading.Lock()

INSTALLED = {'ghcr.io/nethserver/mail': [{'id': 'mail1', 'node': '1', 'module': 'mail', 'ui_name': 'Company mail'}],
             'ghcr.io/nethserver/traefik': [{'id': 'traefik1', 'node': '1', 'module': 'traefik'}],
             'ghcr.io/nethserver/webserver': [{'id': 'webserver1', 'node': '1', 'module': 'webserver'}],
             'ghcr.io/nethserver/dnshelper': [{'id': 'dnshelper1', 'node': '1', 'module': 'dnshelper'}],
             'ghcr.io/danb35/powerdns': [{'id': 'powerdns1', 'node': '1', 'module': 'powerdns'}],
             'ghcr.io/danb35/automx': [{'id': 'automx1', 'node': '1', 'module': 'automx'}]}

# The ns8-powerdns primary that sync-powerdns adopts from. Its zones are also served by
# the fake DNS host (fake_helper.py), so Check credentials works on them.
POWERDNS_ZONES = ['example.net', '2.0.192.in-addr.arpa']


# Which module wrote which record of example.com (the fake DNS host's default
# records), so the Records page shows "by mail1" tags; automx1 is "removed"
# later through POST /dev/module-removed?module=automx1.
SEEDED_OWNERS = {
    'module/mail1': [('@', 'MX', '10 mail.example.com.'), ('@', 'TXT', 'v=spf1 mx -all'),
                     ('mail._domainkey', 'TXT', 'v=DKIM1; k=rsa; p=' + 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A' * 8),
                     ('_dmarc', 'TXT', 'v=DMARC1; p=quarantine')],
    'module/automx1': [('autoconfig', 'CNAME', 'mail.example.com.'),
                       ('_autodiscover._tcp', 'SRV', '0 0 443 mail.example.com.')],
}


def seed_owners():
    for who, recs in SEEDED_OWNERS.items():
        os.environ['AGENT_TASK_USER'] = who
        lib.record_owners('example.com', {'add': [{'name': n, 'type': t, 'data': d} for n, t, d in recs],
                                          'remove': []})
    os.environ['AGENT_TASK_USER'] = 'admin'


class FakeAgent:
    """What dnshelper_lib uses of the NS8 agent package: the cluster's one
    powerdns-api key, the primary's get-provider-config, and event publishing."""
    SD_ERR, SD_WARNING, SD_INFO, SD_DEBUG = '<3>', '<4>', '<6>', '<7>'

    class _Redis:
        def ping(self):
            return True

        def publish(self, channel, message):
            return 0

    def __init__(self):
        self.tasks = self

    def redis_connect(self, **kw):
        return self._Redis()

    def list_service_providers(self, rdb, service, transport='*', filters={}):
        return [{'module_id': 'powerdns1', 'host': '10.5.4.1', 'port': '20004', 'role': 'primary'}]

    def run(self, agent_id, action, data={}, **kw):
        return {'exit_code': 0, 'output': {
            'provider': 'powerdns', 'zones': list(POWERDNS_ZONES),
            'fields': {'api_url': 'http://10.5.4.1:20004', 'api_key': 'pdns-harness-key', 'server_id': 'localhost'}}}


lib._agent = FakeAgent


def other_module(module_id, action, data):
    if action == 'list-domains':
        return [{'domain': 'example.com'}, {'domain': 'example.org'}]
    if action == 'list-routes':
        if data and data.get('expand_list'):
            return [{'host': h, 'instance': 'x'} for h in ('www.example.com', 'cloud.my-shop.net', 'nas.lan', 'nextcloud.example.org')]
        return ['x']
    if action == 'get-configuration' and module_id.startswith('webserver'):
        return {'hostname': 'nas.lan', 'virtualhost': [{'ServerNames': ['blog.example.org', 'shop.my-shop.net']}]}
    if action == 'get-status':
        return {'instance': module_id, 'node': '1', 'node_ui_name': '', 'services': [], 'images': [], 'volumes': []}
    if action == 'get-name':
        return {'name': ''}
    raise KeyError(action)


def validate_input(action, data):
    """Check the payload against the action's validate-input.json, as NS8 does before
    running a task (the UI sends no payload at all for argument-less actions: null).
    Needs the jsonschema package; without it the check is skipped."""
    try:
        from jsonschema import Draft7Validator
    except ImportError:
        return []
    path = os.path.join(ROOT, 'imageroot', 'actions', action, 'validate-input.json')
    if not os.path.exists(path):
        return []
    with open(path) as f:
        schema = json.load(f)
    return [{'parameter': '(root)', 'field': '(root)', 'value': data, 'error': '(root)_invalid_type: ' + e.message}
            for e in Draft7Validator(schema).iter_errors(data)]


def run(kind, module_id, body):
    action, data, event = body['action'], body.get('data'), body['extra']['eventId']
    time.sleep(0.15)  # a task takes a moment
    ev = {'action': action, 'eventId': event, 'type': 'completed', 'output': None}
    try:
        if kind == 'cluster':
            ev['output'] = {'list-installed-modules': lambda: INSTALLED,
                            'list-backup-repositories': lambda: {'repositories': []},
                            'list-backups': lambda: {'backups': []}}[action]()
        elif module_id.startswith('dnshelper') and action in lib.HANDLERS:
            problems = validate_input(action, data)
            if problems:
                ev.update(type='validation-failed', errors=problems, output=None)
            else:
                ev['output'] = lib.HANDLERS[action](data or {})
        else:
            ev['output'] = other_module(module_id, action, data)
    except lib.ActionError as e:
        ev.update(type='validation-failed', errors=[e.entry], output=None)
    except lib.HelperFailure as e:
        ev.update(type='aborted', output={'error': str(e)})
    except Exception as e:  # unknown action, bug: show it as a failed task
        print('harness error', kind, repr(module_id), action, file=sys.stderr)
        traceback.print_exc()
        ev.update(type='aborted', output={'error': repr(e)})
    with LOCK:
        # kept, not handed out once: a dropped response or a second viewer must not lose results
        ev['seq'] = len(EVENTS) + 1
        EVENTS.append(ev)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def send(self, code, body, ctype='application/json'):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path.split('?')[0] == '/api/events':
            after = int((parse_qs(urlparse(self.path).query).get('after') or ['0'])[0])
            with LOCK:
                out = [e for e in EVENTS if e['seq'] > after]
            return self.send(200, out)
        path = self.path.split('?')[0]
        if path == '/':
            return self.send(200, open(os.path.join(HERE, 'harness.html'), 'rb').read(), 'text/html')
        if path == '/cluster-admin/css/core.css' and os.path.isfile(CORE_CSS):
            return self.send(200, open(CORE_CSS, 'rb').read(), 'text/css')
        if path.startswith('/app/'):
            rel = path[len('/app/'):] or 'index.html'
            full = os.path.normpath(os.path.join(DIST, rel))
            if full.startswith(os.path.normpath(DIST)) and os.path.isfile(full):
                ctype = {'.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.json': 'application/json',
                         '.png': 'image/png', '.svg': 'image/svg+xml'}.get(os.path.splitext(full)[1], 'application/octet-stream')
                return self.send(200, open(full, 'rb').read(), ctype)
        self.send(404, {'error': 'not found'})

    def do_POST(self):
        if self.path.startswith('/dev/module-removed'):
            # what events/module-removed/20orphan_records does when the core removes a module
            module = (parse_qs(urlparse(self.path).query).get('module') or [''])[0]
            return self.send(200, {'orphaned': lib.forget_module(module)})
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or b'{}')
        parts = self.path.strip('/').split('/')          # api/module/<id>/tasks | api/cluster/tasks
        if parts[:2] == ['api', 'module'] and parts[-1] == 'tasks':
            kind, module_id = 'module', parts[2]
        elif parts[:2] == ['api', 'cluster'] and parts[-1] == 'tasks':
            kind, module_id = 'cluster', ''
        else:
            return self.send(404, {'error': 'unknown api'})
        threading.Thread(target=run, args=(kind, module_id, body), daemon=True).start()
        self.send(200, {'result': 'ok'})


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    os.environ.setdefault('DNSHELPER_REAL_BIN', '')
    lib.ensure_state()
    seed_owners()
    print(f'state dir {STATE}\nopen http://127.0.0.1:{port}/', flush=True)
    try:
        ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()
    finally:
        shutil.rmtree(STATE, ignore_errors=True)
