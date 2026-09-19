#!/usr/bin/env python3
"""A stand-in for the dnshelper binary, for the UI harness only.

Provider-independent operations (list-providers, registrable-domains) are
forwarded to the real binary when DNSHELPER_REAL_BIN is set, so the UI shows the
real provider list. Everything that would need a DNS host is faked: a token
containing "bad" is rejected, "readonly" gives a host that cannot replace
records, "nolist" one that cannot list zones.
"""
import json
import os
import subprocess
import sys

req = json.load(sys.stdin)
op = req['op']
real = os.environ.get('DNSHELPER_REAL_BIN')

if real and op in ('list-providers', 'registrable-domains'):
    p = subprocess.run([real], input=json.dumps(req), capture_output=True, text=True)
    sys.stdout.write(p.stdout)
    sys.exit(p.returncode)


def fail(code, message):
    json.dump({'ok': False, 'records': [], 'error': {'code': code, 'message': message}}, sys.stdout)
    sys.exit(1)


secret = ' '.join(str(v) for v in (req.get('credentials') or {}).values())
if op != 'list-providers' and 'bad' in secret:
    fail('auth_failed', 'rejected')

caps = {'get_records': True, 'append_records': True, 'set_records': 'readonly' not in secret,
        'delete_records': True, 'list_zones': 'nolist' not in secret}

if op == 'list-zones':
    if not caps['list_zones']:
        fail('unsupported', 'no zone listing')
    json.dump({'ok': True, 'records': [], 'zones': ['example.com', 'example.org', 'my-shop.net', 'unrelated.io']}, sys.stdout)
elif op == 'validate':
    zone = req.get('zone', '')
    if caps['list_zones'] and zone not in ('example.com', 'example.org', 'my-shop.net', 'unrelated.io'):
        fail('zone_not_found', 'not served')
    json.dump({'ok': True, 'records': [], 'capabilities': caps,
               'validation': {'method': 'list-zones' if caps['list_zones'] else 'get-records', 'zone_found': True,
                              'write_test': 'passed' if req.get('write_test') else 'skipped'}}, sys.stdout)
elif op == 'get-records':
    json.dump({'ok': True, 'records': [{'name': '@', 'type': 'TXT', 'ttl': 300, 'data': 'v=spf1 -all'}]}, sys.stdout)
else:
    json.dump({'ok': True, 'records': [], 'changes': {'add': [], 'remove': []}, 'dry_run': bool(req.get('dry_run'))}, sys.stdout)
