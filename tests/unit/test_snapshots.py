"""Zone snapshots: taken from the helper's pre-write read, retention, revert diff.

See DESIGN.md, Records editor: Snapshots and revert.
"""
import datetime
import json
import os
import unittest
from unittest import mock

from test_dnshelper_lib import ActionRunner, Base, as_module, lib, load

A1 = {'name': 'www', 'type': 'A', 'ttl': 300, 'data': '192.0.2.1'}
A2 = {'name': 'www', 'type': 'A', 'ttl': 300, 'data': '192.0.2.2'}
TXT = {'name': '@', 'type': 'TXT', 'ttl': 300, 'data': 'v=spf1 -all'}


def written(before, add=(), remove=()):
    return {'ok': True, 'records': list(add), 'before': before,
            'changes': {'add': list(add), 'remove': list(remove)}}


class SnapshotRunTests(ActionRunner):
    def test_configure_module_without_payload(self):
        code, out, err, _ = self.run_action('configure-module', None)
        self.assertEqual(code, 0, err)
        self.assertIn('action="configure-module"', err)


class SnapshotTests(Base):
    def setUp(self):
        super().setUp()
        lib.add_zone({'zone': 'example.com', 'credential': self.add_cred()})

    def snaps(self, zone='example.com'):
        return lib.list_snapshots({'zone': zone})['snapshots']

    def test_a_write_keeps_the_zone_as_it_was_before(self):
        self.respond({'append-records': written([A1], add=[TXT])})
        lib.append_records({'zone': 'example.com', 'records': [TXT]})
        (s,) = self.snaps()
        self.assertEqual((s['kind'], s['action'], s['records']), ('auto', 'append-records', 1))
        self.assertEqual(s['changes'][0]['add'], [TXT])
        self.assertEqual(s['changes'][0]['result'], 'ok')
        full = lib.get_snapshot({'zone': 'example.com', 'id': s['id']})['snapshot']
        self.assertEqual(full['records'], [A1])
        path = os.path.join(self.state, 'snapshots', 'example.com', s['id'] + '.json')
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_no_write_no_snapshot(self):
        # dry run or nothing to change: the helper reports no "before"
        self.respond({'set-records': {'ok': True, 'dry_run': True, 'records': [],
                                      'changes': {'add': [TXT], 'remove': []}}})
        lib.set_records({'zone': 'example.com', 'records': [TXT], 'dry_run': True})
        self.assertEqual(self.snaps(), [])

    def test_a_failed_write_still_keeps_a_snapshot(self):
        self.respond({'apply-changes': {'ok': False, 'records': [], 'before': [A1],
                                        'error': {'code': 'provider_error', 'message': 'halfway'}}})
        with self.assertRaises(lib.HelperFailure):
            lib.apply_changes({'zone': 'example.com', 'remove': [A1], 'add': [A2], 'label': 'retarget'})
        (s,) = self.snaps()
        c = s['changes'][0]
        self.assertEqual((c['result'], c['add'], c['remove'], c['label']), ('failed', [A2], [A1], 'retarget'))

    def test_an_unchanged_zone_adds_the_change_to_the_latest_snapshot(self):
        self.respond({'get-records': {'ok': True, 'records': [A1]}})
        lib.create_snapshot({'zone': 'example.com', 'label': 'start'})
        self.respond({'append-records': written([A1], add=[TXT])})
        lib.append_records({'zone': 'example.com', 'records': [TXT]})
        (s,) = self.snaps()
        self.assertEqual((s['kind'], s['label'], len(s['changes'])), ('manual', 'start', 1))
        # the zone has changed since: the next write gets a snapshot of its own
        self.respond({'delete-records': written([A1, TXT], remove=[TXT])})
        lib.delete_records({'zone': 'example.com', 'records': [TXT]})
        self.assertEqual(len(self.snaps()), 2)

    def test_retention_by_count_and_age_keeps_the_latest(self):
        lib.configure_module({'snapshot_max_count': 3})
        for i in range(5):
            self.respond({'append-records': written([dict(A1, data='192.0.2.%d' % i)], add=[TXT])})
            lib.append_records({'zone': 'example.com', 'records': [TXT]})
        ids = [s['id'] for s in self.snaps()]
        self.assertEqual(len(ids), 3)
        # make everything old: only the latest survives for a managed zone
        later = lib._now() + datetime.timedelta(days=91)
        with mock.patch.object(lib, '_now', return_value=later):
            lib.prune_snapshots('example.com', managed=True)
        self.assertEqual([s['id'] for s in self.snaps()], ids[:1])

    def test_removing_a_zone_removes_its_snapshots(self):
        self.respond({'get-records': {'ok': True, 'records': [A1]}})
        lib.create_snapshot({'zone': 'example.com'})
        self.assertEqual(lib.get_configuration({})['zones'][0]['snapshots'], 1)
        lib.remove_zone({'zone': 'example.com'})
        self.assertFalse(os.path.exists(os.path.join(self.state, 'snapshots', 'example.com')))

    def test_snapshots_of_a_zone_no_longer_managed_age_out_completely(self):
        self.respond({'get-records': {'ok': True, 'records': [A1]}})
        lib.create_snapshot({'zone': 'example.com'})
        # as sync-powerdns does: the zone goes, its snapshots stay
        with lib._ConfigLock():
            lib._save_zones({})
        lib.prune_orphan_snapshots()
        self.assertTrue(lib._snapshot_ids('example.com'))
        later = lib._now() + datetime.timedelta(days=91)
        with mock.patch.object(lib, '_now', return_value=later):
            lib.prune_orphan_snapshots()
        self.assertEqual(lib._snapshot_ids('example.com'), [])
        self.assertFalse(os.path.exists(os.path.join(self.state, 'snapshots', 'example.com')))

    def test_diff_reports_who_changed_each_record_since(self):
        self.respond({'get-records': {'ok': True, 'records': [A1]}})
        sid = lib.create_snapshot({'zone': 'example.com'})['id']
        self.respond({'append-records': written([A1], add=[TXT])})
        # a module's write (its policy is not what this test is about)
        with as_module('mail1'), mock.patch.object(lib, '_require_access'):
            lib.append_records({'zone': 'example.com', 'records': [TXT]})
        self.respond({'diff-records': {'ok': True, 'records': [],
                                       'changes': {'add': [], 'remove': [TXT]}}})
        out = lib.diff_snapshot({'zone': 'example.com', 'id': sid})
        self.assertEqual(out['remove'], [{'record': TXT, 'changed_by': ['module/mail1']}])
        self.assertEqual(self.calls()[-1]['req']['records'], [A1])

    def test_modules_cannot_use_snapshots(self):
        with as_module('mail1'):
            for fn, data in ((lib.list_snapshots, {'zone': 'example.com'}),
                             (lib.create_snapshot, {'zone': 'example.com'}),
                             (lib.diff_snapshot, {'zone': 'example.com', 'id': '20261106T101500.000000Z'})):
                self.assertRejects(fn, data, 'not_permitted')

    def test_ids_are_checked(self):
        self.assertRejects(lib.get_snapshot, {'zone': 'example.com', 'id': '../../zones'}, 'invalid_snapshot_id')
        self.assertRejects(lib.delete_snapshot, {'zone': 'example.com', 'id': '20261106T101500.000000Z'},
                           'snapshot_not_found')
        self.assertRejects(lib.list_snapshots, {'zone': 'other.org'}, 'zone_not_found')

    def test_delete_snapshot(self):
        self.respond({'get-records': {'ok': True, 'records': [A1]}})
        sid = lib.create_snapshot({'zone': 'example.com'})['id']
        lib.delete_snapshot({'zone': 'example.com', 'id': sid})
        self.assertEqual(self.snaps(), [])

    def test_settings(self):
        self.assertEqual(lib.get_configuration({})['settings'],
                         {'snapshot_max_count': 50, 'snapshot_max_age_days': 90})
        lib.configure_module(None)  # the UI may send no payload
        lib.configure_module({'snapshot_max_age_days': 30})
        self.assertEqual(lib.load_settings(), {'snapshot_max_count': 50, 'snapshot_max_age_days': 30})
        self.assertEqual(load(os.path.join(self.state, 'settings.json'))['snapshot_max_age_days'], 30)

    def test_restore_drops_unreadable_snapshots(self):
        self.respond({'get-records': {'ok': True, 'records': [A1]}})
        lib.create_snapshot({'zone': 'example.com'})
        d = os.path.join(self.state, 'snapshots', 'example.com')
        with open(os.path.join(d, '20200101T000000.000000Z.json'), 'w') as f:
            f.write('{broken')
        with open(os.path.join(self.state, 'settings.json'), 'w') as f:
            f.write('[]')
        summary, warnings = lib.check_restored_state()
        self.assertEqual(summary['snapshots'], 1)
        self.assertTrue(any('unreadable snapshot' in w for w in warnings), warnings)
        self.assertTrue(any('settings.json' in w for w in warnings), warnings)
        self.assertEqual(lib.load_settings()['snapshot_max_count'], 50)


if __name__ == '__main__':
    unittest.main()
