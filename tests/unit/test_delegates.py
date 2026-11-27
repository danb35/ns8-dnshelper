"""Delegated zones: a module that adds credentials and zones of its own
(DESIGN.md, Delegated access, phase 2)."""
import json
import os
import unittest
from unittest import mock

from test_dnshelper_lib import CHANGES, SECRET, ActionRunner, as_module, lib, load

FIELDS = {'api_token': SECRET}


class DelegateTests(ActionRunner):
    def setUp(self):
        super().setUp()
        self.admin_cred = self.add_cred(name='Admin')
        lib.add_zone({'zone': 'admin.com', 'credential': self.admin_cred})
        lib.configure_module({'delegates': ['dnsapi1']})
        self.respond({'get-records': {'ok': True, 'records': [
            {'name': 'www', 'type': 'A', 'ttl': 300, 'data': '192.0.2.1'}]},
            'append-records': CHANGES, 'apply-changes': CHANGES,
            'validate': {'ok': True, 'validation': {}, 'capabilities': {}},
            'list-zones': {'ok': True, 'zones': ['customer.com']}})

    def delegate_adds(self, zone='customer.com', module='dnsapi1'):
        with as_module(module):
            cid = lib.add_credential({'name': zone, 'provider': 'cloudflare', 'fields': FIELDS})['id']
            lib.add_zone({'zone': zone, 'credential': cid})
        return cid

    # ------------------------------------------------------------ the setting

    def test_delegates_setting_is_normalized_and_validated(self):
        with mock.patch.dict(os.environ, {'MODULE_ID': 'dnshelper1'}):
            lib.configure_module({'delegates': ['module/DNSapi2', 'dnsapi1', 'dnsapi1']})
            self.assertEqual(lib.load_settings()['delegates'], ['dnsapi1', 'dnsapi2'])
            self.assertEqual(lib.get_configuration({})['settings']['delegates'], ['dnsapi1', 'dnsapi2'])
            self.assertRejects(lib.configure_module, {'delegates': ['bad id']}, 'invalid_module_id', 'delegates')
            self.assertRejects(lib.configure_module, {'delegates': ['dnshelper1']}, 'invalid_module_id')
            lib.configure_module({'snapshot_max_count': 5})   # other settings keep the delegates
            self.assertEqual(lib.load_settings()['delegates'], ['dnsapi1', 'dnsapi2'])
            lib.configure_module({'delegates': []})
            self.assertEqual(lib.load_settings()['delegates'], [])

    def test_list_snapshots_settings_leave_the_delegates_out(self):
        self.assertEqual(set(lib.list_snapshots({'zone': 'admin.com'})['settings']),
                         {'snapshot_max_count', 'snapshot_max_age_days'})

    def test_a_module_not_in_delegates_is_refused_everything(self):
        cid = self.delegate_adds()
        calls = [
            (lib.add_credential, {'name': 'x', 'provider': 'cloudflare', 'fields': FIELDS}),
            (lib.update_credential, {'id': cid, 'name': 'y'}),
            (lib.remove_credential, {'id': cid}),
            (lib.add_zone, {'zone': 'new.com', 'credential': cid}),
            (lib.update_zone, {'zone': 'customer.com', 'credential': cid}),
            (lib.remove_zone, {'zone': 'customer.com'}),
            (lib.validate_zone, {'zone': 'x.com', 'provider': 'cloudflare', 'fields': FIELDS}),
            (lib.list_provider_zones, {'provider': 'cloudflare', 'fields': FIELDS}),
        ]
        with as_module('mail1'):
            for fn, data in calls:
                self.assertRejects(fn, data, 'not_permitted')
        lib.configure_module({'delegates': []})   # removed from the setting: refused too
        with as_module('dnsapi1'):
            for fn, data in calls:
                self.assertRejects(fn, data, 'not_permitted')
            self.assertEqual(lib.list_zones({})['zones'], [])
            self.assertRejects(lib.get_records, {'zone': 'customer.com'}, 'not_permitted')

    # ------------------------------------------------------------ what a delegate may do

    def test_a_delegates_credential_is_marked_and_its_zone_is_writable_without_a_rule(self):
        cid = self.delegate_adds()
        cred = load(os.path.join(self.state, 'credentials', cid + '.json'))
        self.assertEqual(cred['delegated_to'], 'module/dnsapi1')
        self.assertEqual(cred['fields'], FIELDS)
        with as_module('dnsapi1'):
            self.assertEqual(lib.list_zones({})['zones'], [{
                'zone': 'customer.com', 'credential': cid, 'provider': 'cloudflare', 'delegated': True,
                'access': 'write', 'full': True}])
            hz = lib.has_zone({'name': 'www.customer.com', 'records': [{'name': 'www.customer.com', 'type': 'A'}]})
            self.assertEqual((hz['allowed'], hz['delegated'], hz['access'], hz['full']), (True, True, 'write', True))
            self.assertEqual(hz['records'][0]['write'], True)
            lib.append_records({'zone': 'customer.com', 'records': [{'name': 'www', 'type': 'A', 'data': '192.0.2.9'}],
                                'on_behalf_of': 't1:k1'})
            self.assertEqual(len(lib.get_records({'zone': 'customer.com'})['records']), 1)
            # the administrator's zone is still default deny
            self.assertRejects(lib.get_records, {'zone': 'admin.com'}, 'not_permitted')
            self.assertEqual(lib.has_zone({'name': 'admin.com'})['delegated'], False)
        # another module gets nothing from the delegation
        with as_module('mail1'):
            self.assertEqual(lib.list_zones({})['zones'], [])
            self.assertRejects(lib.append_records, {'zone': 'customer.com', 'records': [
                {'name': 'www', 'type': 'A', 'data': '192.0.2.9'}]}, 'not_permitted')

    def test_the_safety_rails_still_apply_in_a_delegated_zone(self):
        self.delegate_adds()
        self.respond({'append-records': {'ok': False, 'error': {'code': 'forbidden', 'message': 'SOA'}}})
        with as_module('dnsapi1'):
            self.assertRejects(lib.append_records, {'zone': 'customer.com', 'records': [
                {'name': '@', 'type': 'SOA', 'data': 'x'}]}, 'forbidden')

    def test_a_delegate_may_change_and_remove_only_its_own(self):
        own = self.delegate_adds()
        lib.configure_module({'delegates': ['dnsapi1', 'dnsapi2']})
        other = self.delegate_adds('other.net', module='dnsapi2')
        with as_module('dnsapi1'):
            lib.update_credential({'id': own, 'name': 'renamed', 'fields': {'api_token': 'NEW'}})
            for fn, data in [
                    (lib.update_credential, {'id': other, 'name': 'x'}),
                    (lib.update_credential, {'id': self.admin_cred, 'name': 'x'}),
                    (lib.remove_credential, {'id': other}),
                    (lib.remove_credential, {'id': self.admin_cred}),
                    (lib.add_zone, {'zone': 'new.com', 'credential': self.admin_cred}),
                    (lib.add_zone, {'zone': 'new.com', 'credential': other}),
                    (lib.update_zone, {'zone': 'customer.com', 'credential': other}),
                    (lib.update_zone, {'zone': 'other.net', 'credential': own}),
                    (lib.update_zone, {'zone': 'admin.com', 'credential': own}),
                    (lib.update_zone, {'zone': 'missing.com', 'credential': own}),
                    (lib.remove_zone, {'zone': 'other.net'}),
                    (lib.remove_zone, {'zone': 'admin.com'}),
                    (lib.remove_zone, {'zone': 'missing.com'}),
                    (lib.validate_zone, {'zone': 'admin.com'}),
                    (lib.validate_zone, {'zone': 'other.net'}),
                    (lib.validate_zone, {'zone': 'x.com', 'credential': self.admin_cred}),
                    (lib.list_provider_zones, {'credential': self.admin_cred}),
                    (lib.list_provider_zones, {'credential': other})]:
                self.assertRejects(fn, data, 'not_permitted')
            self.assertRejects(lib.add_zone, {'zone': 'admin.com', 'credential': own}, 'zone_already_configured')
            self.assertRejects(lib.remove_credential, {'id': own}, 'credential_in_use')
            lib.validate_zone({'zone': 'customer.com'})
            lib.validate_zone({'zone': 'x.com', 'credential': own})
            lib.validate_zone({'zone': 'x.com', 'provider': 'cloudflare', 'fields': FIELDS})
            self.assertEqual(lib.list_provider_zones({'credential': own})['zones'], ['customer.com'])
            lib.remove_zone({'zone': 'customer.com'})
            lib.remove_credential({'id': own})
        self.assertEqual(sorted(lib._load_zones()), ['admin.com', 'other.net'])
        self.assertFalse(os.path.exists(os.path.join(self.state, 'credentials', own + '.json')))
        self.assertEqual(load(os.path.join(self.state, 'credentials', self.admin_cred + '.json'))['name'], 'Admin')

    def test_a_delegate_may_not_add_a_zone_inside_or_around_another(self):
        cid = self.delegate_adds()
        with as_module('dnsapi1'):
            self.assertRejects(lib.add_zone, {'zone': 'shop.admin.com', 'credential': cid}, 'zone_overlaps')
            lib.add_zone({'zone': 'shop.customer.com', 'credential': cid})   # inside its own: allowed
        lib.add_zone({'zone': 'b.admin.com', 'credential': self.admin_cred})   # the administrator may

    def test_the_marker_cannot_be_forged_through_the_input(self):
        # add-credential's schema has no delegated_to; even if it came through, the caller decides
        cid = lib.add_credential({'name': 'x', 'provider': 'cloudflare', 'fields': FIELDS,
                                  'delegated_to': 'module/dnsapi1'})['id']
        self.assertNotIn('delegated_to', load(os.path.join(self.state, 'credentials', cid + '.json')))

    # ------------------------------------------------------------ the administrator

    def test_the_administrator_sees_removes_but_does_not_edit_delegated_objects(self):
        cid = self.delegate_adds()
        cfg = lib.get_configuration({})
        self.assertEqual({c['id']: c['delegated_to'] for c in cfg['credentials']},
                         {cid: 'module/dnsapi1', self.admin_cred: ''})
        self.assertEqual({z['zone']: z['delegated_to'] for z in cfg['zones']},
                         {'customer.com': 'module/dnsapi1', 'admin.com': ''})
        self.assertNotIn(SECRET, json.dumps(cfg))
        self.assertRejects(lib.update_credential, {'id': cid, 'name': 'x'}, 'delegated', 'id')
        self.assertRejects(lib.update_zone, {'zone': 'customer.com', 'credential': self.admin_cred}, 'delegated')
        self.assertRejects(lib.update_zone, {'zone': 'admin.com', 'credential': cid}, 'delegated', 'credential')
        self.assertRejects(lib.add_zone, {'zone': 'new.com', 'credential': cid}, 'delegated')
        lib.validate_zone({'zone': 'customer.com'})
        lib.remove_zone({'zone': 'customer.com'})
        lib.remove_credential({'id': cid})

    def test_take_over(self):
        cid = self.delegate_adds()
        self.assertRejects(lib.take_over_credential, {'id': self.admin_cred}, 'not_delegated')
        with as_module('dnsapi1'):
            self.assertRejects(lib.take_over_credential, {'id': cid}, 'not_permitted')
        self.assertEqual(lib.take_over_credential({'id': cid}),
                         {'id': cid, 'delegated_to': 'module/dnsapi1', 'zones': ['customer.com']})
        self.assertNotIn('delegated_to', load(os.path.join(self.state, 'credentials', cid + '.json')))
        lib.update_credential({'id': cid, 'name': 'mine now'})
        with as_module('dnsapi1'):
            self.assertEqual(lib.list_zones({})['zones'], [])
            self.assertRejects(lib.remove_zone, {'zone': 'customer.com'}, 'not_permitted')
            self.assertRejects(lib.get_records, {'zone': 'customer.com'}, 'not_permitted')

    def test_take_over_through_run_is_audited_and_publishes_the_change(self):
        cid = self.delegate_adds()
        with mock.patch.dict(os.environ, {'MODULE_ID': 'dnshelper1', 'AGENT_ID': 'module/dnshelper1'}):
            code, out, err, agent = self.run_action('take-over-credential', {'id': cid})
        self.assertEqual(code, 0)
        self.assertIn('action="take-over-credential"', err)
        self.assertIn('id="%s"' % cid, err)
        agent.redis.publish.assert_called_once()

    def test_a_removed_delegate_leaves_its_objects_to_the_administrator(self):
        cid = self.delegate_adds()
        self.assertEqual(lib.forget_delegate('mail1'), {})
        self.assertEqual(lib.forget_delegate('dnsapi1'), {cid: ['customer.com']})
        self.assertEqual(lib.get_configuration({})['zones'][1]['delegated_to'], '')
        self.assertEqual(sorted(lib._load_zones()), ['admin.com', 'customer.com'])
        lib.update_credential({'id': cid, 'name': 'editable now'})

    def test_restore_accepts_the_marker_and_warns_about_missing_delegates(self):
        cid = self.delegate_adds()
        summary, warnings = lib.check_restored_state(lambda m: m != 'dnsapi1')
        self.assertEqual(summary['credentials'], 2)
        self.assertTrue(any(cid in w and 'module/dnsapi1' in w for w in warnings), warnings)
        self.assertTrue(any('delegates setting lists dnsapi1' in w for w in warnings), warnings)
        _, warnings = lib.check_restored_state(lambda m: True)
        self.assertEqual(warnings, [])


class SchemaTests(unittest.TestCase):
    ACTIONS = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'imageroot', 'actions')

    def test_grants_define_dnszoneadmin(self):
        with open(os.path.join(self.ACTIONS, 'create-module', '30grants')) as f:
            text = f.read()
        self.assertIn('roles/dnszoneadmin', text)
        for a in ('add-credential', 'remove-zone', 'validate-zone', 'list-provider-zones'):
            self.assertIn('    %s\n' % a, text)
        self.assertNotIn('take-over-credential', text)

    def test_add_credential_schema_has_no_marker(self):
        schema = load(os.path.join(self.ACTIONS, 'add-credential', 'validate-input.json'))
        self.assertFalse(schema['additionalProperties'])
        self.assertNotIn('delegated_to', schema['properties'])


if __name__ == '__main__':
    unittest.main()
