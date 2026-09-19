"""Integration test on a real NS8 node, with a real consumer module and a real
DNS server. Skipped unless NS8_NODE is set. See README.md in this directory.

The module images are built on the node from local storage (build-on-node.sh);
NS8 deletes a module's image when its last instance is removed, so the test
rebuilds them whenever it needs to install again.
"""
import ast
import json
import os
import subprocess
import unittest

NODE = os.environ.get('NS8_NODE')
KEY_FILE = os.environ.get('NS8_SSH_KEY')
DNS_SERVER = os.environ.get('DNS_SERVER')        # host:port of an RFC 2136 server
DNS_KEY_NAME = os.environ.get('DNS_KEY_NAME', 'dnshelper-test')
DNS_KEY = os.environ.get('DNS_KEY')
ZONE = os.environ.get('DNS_ZONE', 'example.test')
WEBDAV_URL = os.environ.get('WEBDAV_URL')        # optional: enables the backup and restore test
WEBDAV_BASEPATH = os.environ.get('WEBDAV_BASEPATH', 'dnshelper-it')

HERE = os.path.dirname(os.path.abspath(__file__))
FIELDS = lambda: {'server': DNS_SERVER, 'key_name': DNS_KEY_NAME, 'key': DNS_KEY}


def ssh(command, stdin=None, check=True):
    args = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10']
    if KEY_FILE:
        args += ['-i', KEY_FILE]
    p = subprocess.run(args + ['root@' + NODE, command], input=stdin, capture_output=True, text=True, timeout=900)
    if check and p.returncode:
        raise AssertionError('%s failed (%d): %s' % (command[:80], p.returncode, (p.stderr or p.stdout)[-500:]))
    return p


def api(target, action, data=None, check=True):
    """Run an action as the cluster admin. Returns (exit code, parsed stdout)."""
    path = action if target == 'cluster' else 'module/%s/%s' % (target, action)
    if data is None and target == 'cluster':
        p = ssh('api-cli run %s' % path, check=False)   # some cluster actions refuse an empty object
    else:
        p = ssh('api-cli run %s --data -' % path, json.dumps(data or {}), check=False)
    try:
        out = json.loads(p.stdout)
    except ValueError:
        out = p.stdout
    if check and p.returncode:
        raise AssertionError('%s failed (%d): %s %s' % (path, p.returncode, p.stderr[-400:], p.stdout[-400:]))
    return p.returncode, out


def redis(*args):
    return ssh('redis-cli ' + ' '.join(args)).stdout.strip()


def add_module(image):
    out = ssh('add-module %s 1' % image).stdout.strip().splitlines()[-1]
    return ast.literal_eval(out)['module_id']


def build_images():
    subprocess.run([os.path.join(HERE, 'build-on-node.sh'), NODE], check=True, capture_output=True)


def image_missing(name):
    return ssh('podman image exists localhost/%s:test' % name, check=False).returncode != 0


def journal(since='-10min'):
    return ssh('journalctl --no-pager -o cat --since "%s"' % since, check=False).stdout


@unittest.skipUnless(NODE and DNS_SERVER and DNS_KEY, 'set NS8_NODE, DNS_SERVER and DNS_KEY')
class NodeIntegration(unittest.TestCase):
    consumer = None
    helper = None

    # ------------------------------------------------------------------ helpers
    @classmethod
    def call(cls, action, data=None):
        """What the consumer module sees when it calls dnshelper."""
        rc, out = api(cls.consumer, 'call-dnshelper', {'action': action, 'data': data or {}})
        assert rc == 0, out
        return out

    @classmethod
    def zone_records(cls):
        """The zone as the DNS server has it, read as admin."""
        return api(cls.helper, 'get-records', {'zone': ZONE})[1]['records']

    @classmethod
    def tearDownClass(cls):
        # best effort: leave the node as it was found
        try:
            _, backups = api('cluster', 'list-backups', check=False)
            for b in backups.get('backups', []) if isinstance(backups, dict) else []:
                if b['name'] == 'dnshelper-it':
                    api('cluster', 'remove-backup', {'id': b['id']}, check=False)
            _, repos = api('cluster', 'list-backup-repositories', check=False)
            for r in repos.get('repositories', []) if isinstance(repos, dict) else []:
                if r['name'] == 'dnshelper-it-repo':
                    api('cluster', 'remove-backup-repository', {'id': r['id']}, check=False)
            _, mods = api('cluster', 'list-installed-modules', check=False)
            for group in (mods.values() if isinstance(mods, dict) else []):
                for m in group:
                    if m['id'].startswith(('dnshelper', 'dnsconsumer')):
                        ssh('remove-module --no-preserve %s' % m['id'])
        except Exception as ex:   # never mask the real test failure
            print('CLEANUP INCOMPLETE, check the node for dnshelper*/dnsconsumer* modules:', ex)

    # ------------------------------------------------------------------ tests
    def test_01_consumer_installed_first_is_granted_the_role_when_dnshelper_arrives(self):
        build_images()
        cls = type(self)
        cls.consumer = add_module('localhost/dnsconsumer:test')
        self.assertEqual(redis('HGETALL roles/module/' + cls.consumer), '')   # nothing to grant yet
        cls.helper = add_module('localhost/dnshelper:test')
        roles = redis('HGETALL roles/module/' + cls.consumer).split()
        self.assertEqual(roles, ['module/' + cls.helper, 'dnswriter'])
        self.assertEqual(sorted(redis('SMEMBERS module/%s/roles/dnswriter' % cls.helper).split()),
                         ['append-records', 'delete-records', 'get-records', 'has-zone', 'list-zones', 'set-records'])
        self.assertEqual(sorted(redis('SMEMBERS module/%s/roles/dnsreader' % cls.helper).split()),
                         ['get-records', 'has-zone', 'list-zones'])
        self.assertEqual(redis('HGET module/%s/srv/api/dnshelper api' % cls.helper), 'actions')

    def test_02_configure_against_a_real_dns_server(self):
        _, valid = api(self.helper, 'validate-zone', {'zone': ZONE, 'provider': 'rfc2136', 'fields': FIELDS(), 'write_test': True})
        self.assertEqual(valid['validation']['write_test'], 'passed')
        _, cred = api(self.helper, 'add-credential', {'name': 'Lab', 'provider': 'rfc2136', 'fields': FIELDS()})
        api(self.helper, 'add-zone', {'zone': ZONE, 'credential': cred['id']})
        config = api(self.helper, 'get-configuration')[1]
        self.assertNotIn(DNS_KEY, json.dumps(config))
        self.assertEqual(config['credentials'][0]['secrets_set'], ['key'])
        state = '/home/%s/.config/state' % self.helper
        modes = ssh("stat -c '%%a %%n' %s/zones.json %s/policy.json %s/credentials %s/credentials/*.json" % ((state,) * 4)).stdout
        self.assertEqual(sorted(l.split()[0] for l in modes.splitlines()), ['600', '600', '600', '700'])

    def test_03_a_module_is_refused_everything_until_a_rule_allows_it(self):
        seen = self.call('has-zone', {'name': 'mail.' + ZONE})
        self.assertTrue(seen['present'])
        self.assertEqual((seen['exit_code'], seen['output']['managed'], seen['output']['allowed']), (0, True, False))
        self.assertEqual(self.call('list-zones')['output']['zones'], [])
        denied = self.call('append-records', {'zone': ZONE, 'records': [{'name': '_it', 'type': 'TXT', 'data': 'x'}]})
        self.assertEqual((denied['exit_code'], denied['output'][0]['error']), (2, 'not_permitted'))
        # actions outside its role never reach dnshelper: the api-server says 403
        for action, data in (('set-policy', {'rules': []}), ('get-configuration', {}), ('validate-zone', {'zone': ZONE})):
            refused = self.call(action, data)
            self.assertIn('403', refused.get('refused', ''), action)

    def test_04_rules_limit_names_and_types_and_the_dns_server_really_changes(self):
        api(self.helper, 'set-policy', {'rules': [
            {'caller': 'module/' + self.consumer, 'zone': ZONE, 'access': 'write', 'names': ['_it*', '*._domainkey'], 'types': ['TXT']},
            {'caller': 'module/ghost9', 'zone': ZONE, 'access': 'read'}]})
        self.assertTrue(self.call('has-zone', {'name': ZONE})['output']['allowed'])

        ok = self.call('append-records', {'zone': ZONE, 'records': [{'name': '_it', 'type': 'TXT', 'ttl': 120, 'data': 'from the consumer'}]})
        self.assertEqual(ok['exit_code'], 0)
        self.assertIn(('_it', 'TXT', 'from the consumer'), [(r['name'], r['type'], r['data']) for r in self.zone_records()])

        before = self.zone_records()
        for rec in ({'name': 'www', 'type': 'A', 'data': '192.0.2.1'}, {'name': '_it', 'type': 'A', 'data': '192.0.2.1'}):
            r = self.call('append-records', {'zone': ZONE, 'records': [rec]})
            self.assertEqual((r['exit_code'], r['output'][0]['error']), (2, 'not_permitted'), rec)
        self.assertEqual(self.zone_records(), before, 'a refused request must not change the zone')

        seen = self.call('get-records', {'zone': ZONE})['output']['records']
        self.assertEqual([r['name'] for r in seen], ['_it'], 'the consumer must only see records its rule covers')
        self.assertTrue(any(r['name'] == 'keep' for r in self.zone_records()))
        self.call('delete-records', {'zone': ZONE, 'records': [{'name': '_it', 'type': 'TXT', 'data': 'from the consumer'}]})

    def test_05_dkim_key_rotation_as_a_mail_module_would_do_it(self):
        old = 'v=DKIM1; k=rsa; p=' + 'OLDKEY0123456789' * 26
        new = 'v=DKIM1; k=rsa; p=' + 'NEWKEY0123456789' * 26
        rec = lambda data: {'name': 'mail._domainkey', 'type': 'TXT', 'data': data}
        self.assertEqual(self.call('append-records', {'zone': ZONE, 'records': [rec(old)]})['exit_code'], 0)
        dry = self.call('set-records', {'zone': ZONE, 'dry_run': True, 'replace_prefixes': ['v=DKIM1'], 'records': [rec(new)]})
        self.assertTrue(dry['output']['dry_run'])
        self.assertEqual([r['data'] for r in self.zone_records() if r['name'] == 'mail._domainkey'], [old])
        real = self.call('set-records', {'zone': ZONE, 'replace_prefixes': ['v=DKIM1'], 'records': [rec(new)]})
        self.assertEqual(real['exit_code'], 0)
        self.assertEqual([r['data'] for r in self.zone_records() if r['name'] == 'mail._domainkey'], [new])
        # a delete without a type needs a rule with type *: refused
        no_type = self.call('delete-records', {'zone': ZONE, 'records': [{'name': 'mail._domainkey'}]})
        self.assertEqual((no_type['exit_code'], no_type['output'][0]['error']), (2, 'not_permitted'))
        self.assertEqual(self.call('delete-records', {'zone': ZONE, 'records': [rec(new)]})['exit_code'], 0)
        self.assertEqual([r for r in self.zone_records() if r['name'] == 'mail._domainkey'], [])

    def test_06_audit_lines_in_the_journal_and_the_zone_event(self):
        log = journal()
        self.assertIn('dnshelper audit: caller="module/%s" action="append-records" result="ok"' % self.consumer, log)
        self.assertIn('action="append-records" result="rejected" error="not_permitted"', log)
        self.assertNotIn(DNS_KEY[:16], log, 'the TSIG key must never be logged')
        # the event, seen by a real subscriber
        cid = api(self.helper, 'get-configuration')[1]['zones'][0]['credential']
        payload = json.dumps({'zone': ZONE, 'credential': cid})
        out = ssh("(timeout 20 redis-cli PSUBSCRIBE 'module/%s/event/*' > /tmp/dnshelper-it-events &) ; sleep 2; "
                  "echo '%s' | api-cli run module/%s/update-zone --data - >/dev/null; sleep 3; cat /tmp/dnshelper-it-events; rm -f /tmp/dnshelper-it-events"
                  % (self.helper, payload, self.helper)).stdout
        self.assertIn('module/%s/event/service-dnshelper-changed' % self.helper, out)
        self.assertIn('"key": "module/%s/srv/api/dnshelper"' % self.helper, out)

    @unittest.skipUnless(WEBDAV_URL, 'set WEBDAV_URL to a WebDAV server (base path must exist) to test backup and restore')
    def test_07_real_backup_and_restore_into_a_new_instance(self):
        conf = 'type = webdav\nurl = %s\nvendor = other\n' % WEBDAV_URL
        _, repo = api('cluster', 'add-backup-repository', {'provider': 'rclone', 'name': 'dnshelper-it-repo', 'url': '', 'password': '',
                                                          'parameters': {'rclone_conf_secret': conf, 'basepath': WEBDAV_BASEPATH}})
        _, backup_id = api('cluster', 'add-backup', {'name': 'dnshelper-it', 'repository': repo['id'], 'schedule': 'daily',
                                                     'schedule_hint': {}, 'retention': 3, 'instances': [self.helper], 'enabled': True})
        api('cluster', 'run-backup', {'id': backup_id})
        listed = api('cluster', 'list-backups')[1]['backups']
        inst = [b for b in listed if b['id'] == backup_id][0]['instances'][0]
        self.assertTrue(inst['status']['success'], inst)
        self.assertGreaterEqual(inst['status']['total_file_count'], 5)

        _, restored = api('cluster', 'restore-module', {'repository': repo['id'], 'path': inst['repository_path'],
                                                        'snapshot': '', 'node': 1, 'replace': False})
        new = restored['module_id']
        self.assertNotEqual(new, self.helper)
        config = api(new, 'get-configuration')[1]
        self.assertEqual((config['zones'][0]['zone'], config['credentials'][0]['secrets_set']), (ZONE, ['key']))
        self.assertEqual(sorted(r['caller'] for r in api(new, 'get-policy')[1]['rules']), sorted(['module/ghost9', 'module/' + self.consumer]))
        # the restored secret still opens the real DNS server (validate + a write test)
        valid = api(new, 'validate-zone', {'zone': ZONE, 'write_test': True})[1]
        self.assertEqual(valid['validation']['write_test'], 'passed')
        log = journal('-5min')
        self.assertIn('dnshelper: restored 1 zone(s), 1 credential(s), 2 policy rule(s)', log)
        self.assertIn('policy refers to module/ghost9, which does not exist in this cluster', log)
        state = '/home/%s/.config/state' % new
        modes = ssh("stat -c '%%a' %s/zones.json %s/policy.json %s/credentials %s/credentials/*.json" % ((state,) * 4)).stdout.split()
        self.assertEqual(sorted(modes), ['600', '600', '600', '700'])
        self.assertEqual(redis('SCARD module/%s/roles/dnswriter' % new), '6')
        self.assertEqual(redis('HGET module/%s/srv/api/dnshelper api' % new), 'actions')
        ssh('remove-module --no-preserve %s' % new)

    def test_08_removing_dnshelper_is_seen_by_the_consumer_and_reinstalling_restores_access(self):
        ssh('remove-module --no-preserve %s' % self.helper)
        self.assertEqual(redis('GET cluster/default_instance/dnshelper'), '')
        self.assertEqual(redis('HGETALL roles/module/' + self.consumer), '')
        self.assertIn('dnshelper@cluster:dnswriter', redis('SMEMBERS cluster/authorizations/module/' + self.consumer))
        rc, out = api(self.consumer, 'call-dnshelper', {'action': 'has-zone', 'data': {'name': ZONE}})
        self.assertEqual(out, {'present': False})
        if image_missing('dnshelper'):
            build_images()
        type(self).helper = add_module('localhost/dnshelper:test')
        self.assertEqual(redis('HGETALL roles/module/' + self.consumer).split(), ['module/' + self.helper, 'dnswriter'])
        self.assertEqual(self.call('has-zone', {'name': ZONE})['output'], {'allowed': False, 'managed': False, 'zone': None})


if __name__ == '__main__':
    unittest.main()
