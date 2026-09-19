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

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
STATE = tempfile.mkdtemp(prefix='dnshelper-ui-')
os.environ.update(AGENT_STATE_DIR=STATE, AGENT_TASK_USER='admin',
                  DNSHELPER_BIN=os.path.join(HERE, 'fake_helper.py'))
sys.path.insert(0, os.path.join(ROOT, 'imageroot', 'pypkg'))
import dnshelper_lib as lib  # noqa: E402

DIST = os.path.join(HERE, '..', 'dist')
# The shell's global stylesheet (the NS8 core UI's css/core.css). Optional: without it the app renders unstyled.
CORE_CSS = os.environ.get('CORE_CSS', '')
EVENTS, LOCK = [], threading.Lock()

INSTALLED = {'ghcr.io/nethserver/mail': [{'id': 'mail1', 'node': '1', 'module': 'mail', 'ui_name': 'Company mail'}],
             'ghcr.io/nethserver/traefik': [{'id': 'traefik1', 'node': '1', 'module': 'traefik'}],
             'ghcr.io/nethserver/webserver': [{'id': 'webserver1', 'node': '1', 'module': 'webserver'}],
             'ghcr.io/nethserver/dnshelper': [{'id': 'dnshelper1', 'node': '1', 'module': 'dnshelper'}]}


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


def run(kind, module_id, body):
    action, data, event = body['action'], body.get('data'), body['extra']['eventId']
    time.sleep(0.15)  # a task takes a moment
    ev = {'action': action, 'eventId': event, 'type': 'completed', 'output': None}
    try:
        if kind == 'cluster':
            ev['output'] = {'list-installed-modules': lambda: INSTALLED,
                            'list-backup-repositories': lambda: {'repositories': []},
                            'list-backups': lambda: {'backups': []}}[action]()
        elif module_id == 'dnshelper1' and action in lib.HANDLERS:
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
        if self.path == '/api/events':
            with LOCK:
                out, EVENTS[:] = list(EVENTS), []
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
    print(f'state dir {STATE}\nopen http://127.0.0.1:{port}/', flush=True)
    try:
        ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()
    finally:
        shutil.rmtree(STATE, ignore_errors=True)
