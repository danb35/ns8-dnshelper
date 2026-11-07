"""Which module wrote which record (DESIGN.md, Records editor)."""
import os
import unittest
from unittest import mock

from test_dnshelper_lib import Base, as_module, lib

DKIM = {'name': 'sel._domainkey', 'type': 'TXT', 'ttl': 300, 'data': 'v=DKIM1; p=x'}
MX = {'name': '@', 'type': 'MX', 'ttl': 300, 'data': '10 Mail.Example.com.'}
A = {'name': 'www', 'type': 'A', 'ttl': 300, 'data': '192.0.2.1'}


def written(add=(), remove=()):
    return {'ok': True, 'records': list(add), 'before': [A],
            'changes': {'add': list(add), 'remove': list(remove)}}


class OwnerTests(Base):
    def setUp(self):
        super().setUp()
        lib.add_zone({'zone': 'example.com', 'credential': self.add_cred()})

    def owners(self):
        return lib.list_owners({'zone': 'example.com'})['owners']

    def module_write(self, action, fn, data, response):
        self.respond({action: response})
        with as_module('mail1'), mock.patch.object(lib, '_require_access'):
            fn(data)

    def test_a_module_write_records_its_owner(self):
        self.module_write('append-records', lib.append_records,
                          {'zone': 'example.com', 'records': [DKIM, MX]}, written(add=[DKIM, MX]))
        got = {(o['name'], o['type']): o['callers'] for o in self.owners()}
        self.assertEqual(got, {('sel._domainkey', 'TXT'): ['module/mail1'], ('@', 'MX'): ['module/mail1']})
        path = os.path.join(self.state, 'owners', 'example.com.json')
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_an_administrator_write_has_no_owner_and_a_removal_forgets(self):
        self.module_write('append-records', lib.append_records,
                          {'zone': 'example.com', 'records': [DKIM]}, written(add=[DKIM]))
        # the administrator edits the module's record: it is no longer the module's
        new = dict(DKIM, data='v=DKIM1; p=y')
        self.respond({'apply-changes': written(add=[new], remove=[DKIM])})
        lib.apply_changes({'zone': 'example.com', 'remove': [DKIM], 'add': [new]})
        self.assertEqual(self.owners(), [])

    def test_host_names_match_without_case_or_final_dot(self):
        self.module_write('append-records', lib.append_records,
                          {'zone': 'example.com', 'records': [MX]}, written(add=[MX]))
        self.module_write('delete-records', lib.delete_records,
                          {'zone': 'example.com', 'records': [MX]},
                          written(remove=[dict(MX, data='10 mail.example.com')]))
        self.assertEqual(self.owners(), [])

    def test_a_failed_or_dry_write_changes_nothing(self):
        self.module_write('append-records', lib.append_records,
                          {'zone': 'example.com', 'records': [DKIM]},
                          {'ok': True, 'dry_run': True, 'records': [], 'changes': {'add': [DKIM], 'remove': []}})
        self.respond({'append-records': {'ok': False, 'records': [], 'before': [A],
                                         'error': {'code': 'provider_error', 'message': 'm'}}})
        with as_module('mail1'), mock.patch.object(lib, '_require_access'), self.assertRaises(lib.HelperFailure):
            lib.append_records({'zone': 'example.com', 'records': [DKIM]})
        self.assertEqual(self.owners(), [])

    def test_removing_the_zone_removes_its_owners(self):
        self.module_write('append-records', lib.append_records,
                          {'zone': 'example.com', 'records': [DKIM]}, written(add=[DKIM]))
        lib.remove_zone({'zone': 'example.com'})
        self.assertFalse(os.path.exists(os.path.join(self.state, 'owners', 'example.com.json')))

    def test_a_module_asking_for_an_existing_record_claims_it(self):
        self.module_write('append-records', lib.append_records,
                          {'zone': 'example.com', 'records': [DKIM]}, written(add=[DKIM]))
        # a moved copy writes the same record: nothing changes at the host
        self.respond({'append-records': {'ok': True, 'records': [], 'before': [A, DKIM],
                                         'changes': {'add': [], 'remove': []}}})
        with as_module('mail2'), mock.patch.object(lib, '_require_access'):
            lib.append_records({'zone': 'example.com', 'records': [DKIM]})
        self.assertEqual(self.owners()[0]['callers'], ['module/mail1', 'module/mail2'])

    def test_removing_a_module_orphans_only_what_no_one_else_wrote(self):
        self.module_write('append-records', lib.append_records,
                          {'zone': 'example.com', 'records': [DKIM, MX]}, written(add=[DKIM, MX]))
        self.respond({'append-records': {'ok': True, 'records': [], 'before': [A, DKIM, MX],
                                         'changes': {'add': [], 'remove': []}}})
        with as_module('mail2'), mock.patch.object(lib, '_require_access'):
            lib.append_records({'zone': 'example.com', 'records': [MX]})
        self.assertEqual(lib.forget_module('mail1'), {'example.com': 1})
        got = {o['type']: (o['callers'], o['removed']) for o in self.owners()}
        self.assertEqual(got['TXT'], ([], ['module/mail1']))            # orphaned
        self.assertEqual(got['MX'], (['module/mail2'], ['module/mail1']))  # still mail2's
        self.assertEqual(lib.forget_module('nobody1'), {})

    def test_the_administrator_keeps_orphaned_records(self):
        self.module_write('append-records', lib.append_records,
                          {'zone': 'example.com', 'records': [DKIM]}, written(add=[DKIM]))
        lib.forget_module('mail1')
        out = lib.release_records({'zone': 'example.com', 'records': [{'name': DKIM['name'], 'type': 'TXT',
                                                                       'data': DKIM['data']}]})
        self.assertEqual(out, {'released': 1})
        self.assertEqual(self.owners(), [])

    def test_an_old_owners_file_is_read(self):
        lib.ensure_state()
        with open(os.path.join(self.state, 'owners', 'example.com.json'), 'w') as f:
            f.write('{"records": {"x": {"name": "@", "type": "MX", "data": "10 m.", "caller": "module/mail1", '
                    '"time": "t"}}}')
        self.assertEqual(self.owners()[0]['callers'], ['module/mail1'])
        self.assertEqual(lib.forget_module('mail1'), {'example.com': 1})

    def test_modules_cannot_list_owners(self):
        with as_module('mail1'):
            self.assertRejects(lib.list_owners, {'zone': 'example.com'}, 'not_permitted')
            self.assertRejects(lib.release_records, {'zone': 'example.com', 'records': []}, 'not_permitted')

    def test_restore_drops_an_unreadable_owners_file(self):
        lib.ensure_state()
        with open(os.path.join(self.state, 'owners', 'example.com.json'), 'w') as f:
            f.write('{bad')
        summary, warnings = lib.check_restored_state()
        self.assertTrue(any('owners' in w for w in warnings), warnings)
        self.assertEqual(self.owners(), [])
        self.assertTrue(os.path.isdir(os.path.join(self.state, 'owners')))


if __name__ == '__main__':
    unittest.main()
