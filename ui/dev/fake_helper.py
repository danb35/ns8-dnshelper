#!/usr/bin/env python3
"""A stand-in for the dnshelper binary, for the UI harness only.

The fake DNS host keeps its records in fake-dns.json next to the module state, so
adding and deleting records through the UI shows up in the next listing.

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
elif op in ('get-records', 'append-records', 'set-records', 'delete-records'):
    zone = req.get('zone', '')
    path = os.path.join(os.environ.get('AGENT_STATE_DIR', '/tmp'), 'fake-dns.json')
    try:
        with open(path) as f:
            db = json.load(f)
    except (OSError, ValueError):
        db = {}
    if zone not in db:
        db[zone] = [
            {'name': '@', 'type': 'NS', 'ttl': 86400, 'data': 'ns1.example-dns.net.'},
            {'name': '@', 'type': 'NS', 'ttl': 86400, 'data': 'ns2.example-dns.net.'},
            {'name': '@', 'type': 'SOA', 'ttl': 3600, 'data': 'ns1.example-dns.net. hostmaster.%s. 2026092001 28800 7200 604800 3600' % zone},
            {'name': '@', 'type': 'A', 'ttl': 300, 'data': '192.0.2.10'},
            {'name': '@', 'type': 'MX', 'ttl': 3600, 'data': '10 mail.%s.' % zone},
            {'name': '@', 'type': 'TXT', 'ttl': 300, 'data': 'v=spf1 mx -all'},
            {'name': 'www', 'type': 'CNAME', 'ttl': 3600, 'data': '%s.' % zone},
            {'name': 'mail', 'type': 'A', 'ttl': 300, 'data': '192.0.2.20'},
            {'name': 'mail._domainkey', 'type': 'TXT', 'ttl': 3600,
             'data': 'v=DKIM1; k=rsa; p=' + 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A' * 8},
        ]
    recs = db[zone]

    def matches(r, want):
        return (r['name'] == want.get('name', r['name']) and r['type'] == want.get('type', r['type'])
                and r['data'] == want.get('data', r['data']))

    changes = {'add': [], 'remove': []}
    if op == 'get-records':
        flt = req.get('filter') or {}
        out = [r for r in recs if matches(r, flt)]
        json.dump({'ok': True, 'records': out}, sys.stdout)
        sys.exit(0)
    dry = bool(req.get('dry_run'))
    for want in req.get('records') or []:
        if op in ('append-records', 'set-records'):
            if any(matches(r, want) for r in recs):
                continue
            if want['type'] == 'CNAME' and any(r['name'] == want['name'] for r in recs):
                fail('conflict', 'a CNAME cannot exist next to other records with the same name')
            new = {'name': want['name'], 'type': want['type'], 'ttl': want.get('ttl') or 300, 'data': want['data']}
            changes['add'].append(new)
            if not dry:
                recs.append(new)
        else:
            for r in [r for r in recs if matches(r, want)]:
                if r['type'] == 'SOA' or (r['type'] == 'NS' and r['name'] == '@'):
                    fail('forbidden', 'apex NS and SOA records are never changed')
                changes['remove'].append(r)
                if not dry:
                    recs.remove(r)
    if not dry:
        with open(path, 'w') as f:
            json.dump(db, f)
    json.dump({'ok': True, 'records': recs, 'changes': changes, 'dry_run': dry}, sys.stdout)
else:
    json.dump({'ok': True, 'records': [], 'changes': {'add': [], 'remove': []}, 'dry_run': bool(req.get('dry_run'))}, sys.stdout)
