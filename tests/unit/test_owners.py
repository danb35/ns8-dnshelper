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
        got = {(o['name'], o['type']): o['caller'] for o in self.owners()}
        self.assertEqual(got, {('sel._domainkey', 'TXT'): 'module/mail1', ('@', 'MX'): 'module/mail1'})
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

    def test_modules_cannot_list_owners(self):
        with as_module('mail1'):
            self.assertRejects(lib.list_owners, {'zone': 'example.com'}, 'not_permitted')

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
