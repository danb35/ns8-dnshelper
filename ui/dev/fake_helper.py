#!/usr/bin/env python3
"""A stand-in for the dnshelper binary, for the UI harness only.

The fake DNS host keeps its records in fake-dns.json next to the module state, so
adding and deleting records through the UI shows up in the next listing.

Provider-independent operations (list-providers, registrable-domains,
parse-zone, and export-zone of given records) are forwarded to the real binary
when DNSHELPER_REAL_BIN is set, so the UI shows the real provider list and real
zone files. Everything that would need a DNS host is faked: a token
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



def forward(r):
    p = subprocess.run([real], input=json.dumps(r), capture_output=True, text=True)
    sys.stdout.write(p.stdout)
    sys.exit(p.returncode)


if real and (op in ('list-providers', 'registrable-domains', 'parse-zone')
             or (op == 'export-zone' and req.get('records') is not None)):
    forward(req)


def fail(code, message):
    json.dump({'ok': False, 'records': [], 'error': {'code': code, 'message': message}}, sys.stdout)
    sys.exit(1)


secret = ' '.join(str(v) for v in (req.get('credentials') or {}).values())
if op != 'list-providers' and 'bad' in secret:
    fail('auth_failed', 'rejected')

caps = {'get_records': True, 'append_records': True, 'set_records': 'readonly' not in secret,
        'delete_records': True, 'list_zones': 'nolist' not in secret}

ZONES = ['example.com', 'example.org', 'my-shop.net', 'unrelated.io', 'example.net', '2.0.192.in-addr.arpa']

if op == 'list-zones':
    if not caps['list_zones']:
        fail('unsupported', 'no zone listing')
    json.dump({'ok': True, 'records': [], 'zones': ZONES}, sys.stdout)
elif op == 'validate':
    zone = req.get('zone', '')
    if caps['list_zones'] and zone not in ZONES:
        fail('zone_not_found', 'not served')
    json.dump({'ok': True, 'records': [], 'capabilities': caps,
               'validation': {'method': 'list-zones' if caps['list_zones'] else 'get-records', 'zone_found': True,
                              'write_test': 'passed' if req.get('write_test') else 'skipped'}}, sys.stdout)
elif op in ('get-records', 'append-records', 'set-records', 'delete-records', 'apply-changes',
            'diff-records', 'export-zone', 'check-propagation'):
    zone = req.get('zone', '')
    path = os.path.join(os.environ.get('AGENT_STATE_DIR', '/tmp'), 'fake-dns.json')
    try:
        with open(path) as f:
            db = json.load(f)
    except (OSError, ValueError):
        db = {}
    if zone not in db and zone.endswith('.in-addr.arpa'):
        db[zone] = [
            {'name': '@', 'type': 'NS', 'ttl': 86400, 'data': 'ns1.example.net.'},
            {'name': '@', 'type': 'SOA', 'ttl': 3600, 'data': 'ns1.example.net. hostmaster.example.net. 2026110501 10800 3600 604800 3600'},
            {'name': '10', 'type': 'PTR', 'ttl': 3600, 'data': 'www.example.net.'},
            {'name': '20', 'type': 'PTR', 'ttl': 3600, 'data': 'mail.example.net.'},
        ]
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
            {'name': '_dmarc', 'type': 'TXT', 'ttl': 3600, 'data': 'v=DMARC1; p=quarantine'},
            {'name': 'autoconfig', 'type': 'CNAME', 'ttl': 3600, 'data': 'mail.%s.' % zone},
            {'name': '_autodiscover._tcp', 'type': 'SRV', 'ttl': 3600, 'data': '0 0 443 mail.%s.' % zone},
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
    if op == 'export-zone':
        forward(dict(req, records=recs))
    if op == 'check-propagation':
        # two name servers that both serve what the DNS host has
        flt = req.get('filter') or {}
        want = sorted(r['data'] for r in recs if matches(r, flt))
        servers = [{'server': s, 'address': a, 'status': 'same', 'values': want}
                   for s, a in (('ns1.example-dns.net', '198.51.100.53'), ('ns1.example-dns.net', '2001:db8:53::1'),
                                ('ns2.example-dns.net', '203.0.113.53'), ('ns2.example-dns.net', '2001:db8:53::2'))]
        json.dump({'ok': True, 'records': [r for r in recs if matches(r, flt)], 'servers': servers,
                   'servers_from': 'dns'}, sys.stdout)
        sys.exit(0)

    def key(r):
        return (r['name'], r['type'], r['data'].lower().rstrip('.') if r['type'] in ('CNAME', 'MX', 'SRV', 'NS', 'PTR')
                else r['data'])

    def protected(r):
        return r['type'] == 'SOA' or (r['type'] == 'NS' and r['name'] == '@')

    if op == 'diff-records':
        target = [t for t in req.get('records') or [] if not protected(t)]
        have = [r for r in recs if not protected(r)]
        tk = {key(t): t for t in target}
        hk = {key(r): r for r in have}
        if req.get('mode') == 'add':
            changes['add'] = [t for k, t in tk.items() if k not in hk]
        else:
            changes['add'] = [t for k, t in tk.items() if k not in hk or (t.get('ttl') and t['ttl'] != hk[k]['ttl'])]
            changes['remove'] = [r for k, r in hk.items() if k not in tk or (tk[k].get('ttl') and tk[k]['ttl'] != r['ttl'])]
        json.dump({'ok': True, 'records': [], 'changes': changes}, sys.stdout)
        sys.exit(0)
    before = [dict(r) for r in recs]
    dry = bool(req.get('dry_run'))
    if op == 'apply-changes':
        for want in req.get('remove') or []:
            found = [r for r in recs if key(r) == key(want)]
            if not found:
                fail('stale', '%s %s %s is not in the zone; it may have been changed since it was read'
                     % (want['name'], want['type'], want['data']))
            if protected(found[0]):
                fail('forbidden', 'apex NS and SOA records are never changed')
            changes['remove'].append(found[0])
        for want in req.get('add') or []:
            new = {'name': want['name'], 'type': want['type'], 'ttl': want.get('ttl') or 300, 'data': want['data']}
            kept = [r for r in changes['remove'] if key(r) == key(new) and not want.get('ttl')]
            if kept:
                changes['remove'].remove(kept[0])
                continue
            if any(key(r) == key(new) for r in recs if r not in changes['remove']):
                continue
            changes['add'].append(new)
        if not dry and (changes['add'] or changes['remove']):
            for r in changes['remove']:
                recs.remove(r)
            recs.extend(changes['add'])
            with open(path, 'w') as f:
                json.dump(db, f)
        out = {'ok': True, 'records': changes['add'], 'changes': changes, 'dry_run': dry}
        if not dry and (changes['add'] or changes['remove']):
            out['before'] = before
        json.dump(out, sys.stdout)
        sys.exit(0)
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
    out = {'ok': True, 'records': recs, 'changes': changes, 'dry_run': dry}
    if not dry and (changes['add'] or changes['remove']):
        out['before'] = before   # for the zone snapshots, as the real helper reports it
    json.dump(out, sys.stdout)
else:
    json.dump({'ok': True, 'records': [], 'changes': {'add': [], 'remove': []}, 'dry_run': bool(req.get('dry_run'))}, sys.stdout)
