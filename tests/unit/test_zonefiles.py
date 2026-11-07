"""Zone file export and import planning (DESIGN.md, Records editor)."""
import json
import os
import unittest
from unittest import mock

from test_dnshelper_lib import SECRET, Base, as_module, lib

A1 = {'name': 'www', 'type': 'A', 'ttl': 300, 'data': '192.0.2.1'}


class ZoneFileTests(Base):
    def setUp(self):
        super().setUp()
        lib.add_zone({'zone': 'example.com', 'credential': self.add_cred()})

    def test_export_reads_the_zone(self):
        self.respond({'export-zone': {'ok': True, 'records': [], 'text': '$ORIGIN example.com.\n'}})
        out = lib.export_zone({'zone': 'example.com'})
        self.assertEqual((out['filename'], out['text']), ('example.com.zone', '$ORIGIN example.com.\n'))
        req = self.calls()[-1]['req']
        self.assertEqual(req['op'], 'export-zone')
        self.assertNotIn('records', req)

    def test_export_of_a_snapshot_needs_no_provider(self):
        self.respond({'get-records': {'ok': True, 'records': [A1]},
                      'export-zone': {'ok': True, 'records': [], 'text': 'x'}})
        sid = lib.create_snapshot({'zone': 'example.com'})['id']
        out = lib.export_zone({'zone': 'example.com', 'snapshot': sid})
        self.assertEqual(out['filename'], 'example.com-%s.zone' % sid)
        req = self.calls()[-1]['req']
        self.assertEqual(req['records'], [A1])
        self.assertNotIn('credentials', req)

    def test_import_plans_without_writing(self):
        self.respond({
            'parse-zone': {'ok': True, 'records': [A1], 'skipped': [{'name': '@', 'type': 'SOA', 'reason': 'r'}]},
            'diff-records': {'ok': True, 'records': [], 'changes': {'add': [A1], 'remove': []}}})
        out = lib.import_zone({'zone': 'example.com', 'text': 'www 300 IN A 192.0.2.1\n'})
        self.assertEqual((out['parsed'], out['add'], out['remove'], len(out['skipped'])), (1, [A1], [], 1))
        parse, diff = [c['req'] for c in self.calls()[-2:]]
        self.assertEqual(parse['op'], 'parse-zone')
        self.assertNotIn('credentials', parse)        # parsing never sees the credential
        self.assertNotIn(SECRET, json.dumps(parse))
        self.assertEqual((diff['op'], diff['mode'], diff['records']), ('diff-records', 'add', [A1]))
        self.assertEqual([c['req']['op'] for c in self.calls()].count('apply-changes'), 0)

    def test_import_replace_mode(self):
        self.respond({'parse-zone': {'ok': True, 'records': [], 'skipped': []},
                      'diff-records': {'ok': True, 'records': [], 'changes': {'add': [], 'remove': [A1]}}})
        out = lib.import_zone({'zone': 'example.com', 'text': '', 'mode': 'replace'})
        self.assertEqual(out['remove'], [A1])
        self.assertNotIn('mode', self.calls()[-1]['req'])

    def test_a_bad_file_is_a_validation_error(self):
        self.respond({'parse-zone': {'ok': False, 'records': [],
                                     'error': {'code': 'invalid_request', 'message': 'zone file: bad'}}})
        self.assertRejects(lib.import_zone, {'zone': 'example.com', 'text': 'x'}, 'invalid_request')

    def test_modules_cannot_use_zone_files(self):
        with as_module('mail1'):
            self.assertRejects(lib.export_zone, {'zone': 'example.com'}, 'not_permitted')
            self.assertRejects(lib.import_zone, {'zone': 'example.com', 'text': ''}, 'not_permitted')
        self.assertRejects(lib.export_zone, {'zone': 'other.org'}, 'zone_not_found')


@unittest.skipUnless(os.environ.get('DNSHELPER_REAL_BIN'), 'set DNSHELPER_REAL_BIN to the built helper')
class RealZoneFileTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {'DNSHELPER_BIN': os.environ['DNSHELPER_REAL_BIN'],
                                               'AGENT_STATE_DIR': '/nonexistent-but-unused'})
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_helper(self, req):
        with mock.patch.object(lib, '_state_dir', return_value='/tmp'):
            return lib.call_helper(req)

    def test_parse_and_export_round_trip(self):
        text = '$TTL 600\n@ IN SOA a. b. 1 2 3 4 5\nwww IN CNAME web.example.net.\nq IN TXT "say \\"hi\\""\n'
        parsed = self.run_helper({'op': 'parse-zone', 'zone': 'example.com', 'text': text})
        got = {(r['name'], r['type']): r['data'] for r in parsed['records']}
        self.assertEqual(got, {('www', 'CNAME'): 'web.example.net.', ('q', 'TXT'): 'say "hi"'})
        self.assertEqual(parsed['skipped'][0]['type'], 'SOA')
        out = self.run_helper({'op': 'export-zone', 'zone': 'example.com', 'records': parsed['records']})
        self.assertIn('q\t600\tIN\tTXT\t"say \\"hi\\""', out['text'])


class PropagationTests(Base):
    def setUp(self):
        super().setUp()
        lib.add_zone({'zone': 'example.com', 'credential': self.add_cred()})

    def test_check_propagation_passes_name_and_type(self):
        self.respond({'check-propagation': {'ok': True, 'records': [A1], 'servers_from': 'dns', 'servers': [
            {'server': 'ns1.example.net', 'address': '192.0.2.53', 'status': 'same', 'values': ['192.0.2.1']}]}})
        out = lib.check_propagation({'zone': 'example.com', 'name': 'www', 'type': 'a'})
        self.assertEqual((out['type'], out['servers'][0]['status'], out['servers_from']), ('A', 'same', 'dns'))
        self.assertEqual(self.calls()[-1]['req']['filter'], {'name': 'www', 'type': 'a'})

    def test_modules_cannot_check(self):
        with as_module('mail1'):
            self.assertRejects(lib.check_propagation, {'zone': 'example.com', 'name': 'www', 'type': 'A'},
                               'not_permitted')
