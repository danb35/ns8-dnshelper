import io
import json
import os
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', '..', 'imageroot', 'pypkg'))
import dnshelper_lib as lib  # noqa: E402


def load(path):
    with open(path) as f:
        return json.load(f)


SECRET = 'S3CRET-TOKEN-VALUE'

PROVIDERS = {'ok': True, 'records': [], 'providers': [{
    'name': 'cloudflare', 'label': 'Cloudflare', 'types': ['A', 'TXT'],
    'fields': [
        {'name': 'api_token', 'label': 'API token', 'secret': True, 'required': True},
        {'name': 'zone_token', 'label': 'Zone token', 'secret': True, 'required': False},
        {'name': 'account', 'label': 'Account', 'secret': False, 'required': False},
    ]}]}
CHANGES = {'ok': True, 'dry_run': True, 'records': [],
           'changes': {'add': [{'name': '@', 'type': 'TXT', 'ttl': 0, 'data': 'x'}], 'remove': []}}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.tmp.name, 'state')
        os.makedirs(self.state)
        self.log = os.path.join(self.tmp.name, 'log')
        self.responses = os.path.join(self.tmp.name, 'responses.json')
        self.respond({'list-providers': PROVIDERS})
        env = {'AGENT_STATE_DIR': self.state, 'DNSHELPER_BIN': os.path.join(HERE, 'stub_helper.py'),
               'STUB_LOG': self.log, 'STUB_RESPONSES': self.responses}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def respond(self, mapping):
        current = {}
        if os.path.exists(self.responses):
            with open(self.responses) as f:
                current = json.load(f)
        current.update(mapping)
        with open(self.responses, 'w') as f:
            json.dump(current, f)

    def calls(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log) as f:
            return [json.loads(line) for line in f]

    def add_cred(self, **kw):
        data = {'name': 'CF', 'provider': 'cloudflare', 'fields': {'api_token': SECRET}}
        data.update(kw)
        return lib.add_credential(data)['id']

    def assertRejects(self, fn, data, error, field=None):
        with self.assertRaises(lib.ActionError) as cm:
            fn(data)
        self.assertEqual(cm.exception.entry['error'], error)
        if field:
            self.assertEqual(cm.exception.entry['field'], field)
        self.assertNotIn(SECRET, json.dumps(cm.exception.entry))


class CredentialTests(Base):
    def test_credential_file_is_private_and_holds_the_secret(self):
        cid = self.add_cred()
        path = os.path.join(self.state, 'credentials', cid + '.json')
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode), 0o700)
        self.assertEqual(load(path)['fields']['api_token'], SECRET)
        self.assertEqual([f for f in os.listdir(os.path.dirname(path)) if f.endswith('.tmp')], [])

    def test_secret_is_not_written_to_environment_state(self):
        self.add_cred()
        self.assertFalse(os.path.exists(os.path.join(self.state, 'environment')))

    def test_add_validates_against_the_provider_schema(self):
        self.assertRejects(lib.add_credential, {'name': 'x', 'provider': 'nope', 'fields': {}}, 'unknown_provider')
        self.assertRejects(lib.add_credential, {'name': 'x', 'provider': 'cloudflare', 'fields': {}},
                           'required', 'fields.api_token')
        self.assertRejects(lib.add_credential,
                           {'name': 'x', 'provider': 'cloudflare', 'fields': {'api_token': SECRET, 'bogus': '1'}},
                           'unknown_field')

    def test_get_configuration_never_returns_secrets(self):
        cid = self.add_cred(fields={'api_token': SECRET, 'account': 'acme'})
        cfg = lib.get_configuration({})
        self.assertNotIn(SECRET, json.dumps(cfg))
        self.assertEqual(cfg['credentials'], [{
            'id': cid, 'name': 'CF', 'provider': 'cloudflare',
            'values': {'account': 'acme'}, 'secrets_set': ['api_token']}])

    def test_update_blank_secret_keeps_and_new_secret_replaces(self):
        cid = self.add_cred(fields={'api_token': SECRET, 'account': 'acme'})
        path = os.path.join(self.state, 'credentials', cid + '.json')
        lib.update_credential({'id': cid, 'name': 'Renamed', 'fields': {'api_token': '', 'account': ''}})
        stored = load(path)
        self.assertEqual(stored['name'], 'Renamed')
        self.assertEqual(stored['fields'], {'api_token': SECRET})  # secret kept, blank non-secret removed
        lib.update_credential({'id': cid, 'fields': {'api_token': 'rotated'}})
        self.assertEqual(load(path)['fields']['api_token'], 'rotated')

    def test_update_cannot_leave_a_required_field_empty(self):
        cid = self.add_cred()
        os.chmod(self.state, 0o700)
        path = os.path.join(self.state, 'credentials', cid + '.json')
        stored = load(path)
        stored['fields'].pop('api_token')
        with open(path, 'w') as f:
            json.dump(stored, f)
        self.assertRejects(lib.update_credential, {'id': cid, 'fields': {'api_token': ''}}, 'required')

    def test_ids_cannot_escape_the_directory(self):
        self.assertRejects(lib.remove_credential, {'id': '../zones'}, 'invalid_credential_id')

    def test_remove_refuses_while_a_zone_uses_it(self):
        cid = self.add_cred()
        lib.add_zone({'zone': 'example.com', 'credential': cid})
        self.assertRejects(lib.remove_credential, {'id': cid}, 'credential_in_use')
        lib.remove_zone({'zone': 'example.com'})
        lib.remove_credential({'id': cid})
        self.assertEqual(lib.get_configuration({})['credentials'], [])


class ZoneTests(Base):
    def test_add_update_remove(self):
        a, b = self.add_cred(), self.add_cred()
        lib.add_zone({'zone': 'Example.COM.', 'credential': a})
        self.assertRejects(lib.add_zone, {'zone': 'example.com', 'credential': a}, 'zone_already_configured')
        self.assertRejects(lib.add_zone, {'zone': 'example.org', 'credential': 'cnone'}, 'credential_not_found')
        lib.update_zone({'zone': 'example.com', 'credential': b})
        self.assertEqual(lib.list_zones({})['zones'],
                         [{'zone': 'example.com', 'credential': b, 'provider': 'cloudflare'}])
        lib.remove_zone({'zone': 'example.com'})
        self.assertRejects(lib.remove_zone, {'zone': 'example.com'}, 'zone_not_found')

    def test_invalid_zone_names(self):
        cid = self.add_cred()
        for z in ('localhost', '../x.com', 'a b.com', 'x/y.com', ''):
            self.assertRejects(lib.add_zone, {'zone': z, 'credential': cid}, 'invalid_zone')

    def test_has_zone_finds_the_longest_containing_zone(self):
        cid = self.add_cred()
        for z in ('example.com', 'sub.example.com'):
            lib.add_zone({'zone': z, 'credential': cid})
        self.assertEqual(lib.has_zone({'name': 'mail.example.com'}), {'managed': True, 'zone': 'example.com', 'allowed': True})
        self.assertEqual(lib.has_zone({'name': 'a.SUB.example.com.'}), {'managed': True, 'zone': 'sub.example.com', 'allowed': True})
        self.assertEqual(lib.has_zone({'name': 'example.com'}), {'managed': True, 'zone': 'example.com', 'allowed': True})
        self.assertEqual(lib.has_zone({'name': 'notexample.com'}), {'managed': False, 'zone': None, 'allowed': False})

    def test_zones_file_is_private(self):
        lib.add_zone({'zone': 'example.com', 'credential': self.add_cred()})
        mode = stat.S_IMODE(os.stat(os.path.join(self.state, 'zones.json')).st_mode)
        self.assertEqual(mode, 0o600)


class HelperCallTests(Base):
    def setUp(self):
        super().setUp()
        self.cid = self.add_cred()
        lib.add_zone({'zone': 'example.com', 'credential': self.cid})
        os.unlink(self.log) if os.path.exists(self.log) else None

    def last(self):
        return self.calls()[-1]

    def test_credentials_travel_on_stdin_only(self):
        self.respond({'get-records': {'ok': True, 'records': []}})
        lib.get_records({'zone': 'example.com'})
        call = self.last()
        self.assertEqual(call['req']['credentials'], {'api_token': SECRET})
        self.assertEqual(call['req']['provider'], 'cloudflare')
        self.assertNotIn(SECRET, json.dumps(call['argv']))
        self.assertNotIn(SECRET, json.dumps({k: v for k, v in call['env'].items()
                                             if k not in ('STUB_LOG', 'STUB_RESPONSES')}))

    def test_locking_is_enabled_under_the_state_dir(self):
        self.respond({'get-records': {'ok': True, 'records': []}})
        lib.get_records({'zone': 'example.com'})
        argv = self.last()['argv']
        self.assertEqual(argv[argv.index('-lock-dir') + 1], os.path.join(self.state, 'locks'))

    def test_the_session_token_cache_is_under_the_state_dir_but_not_backed_up(self):
        self.respond({'get-records': {'ok': True, 'records': []}})
        lib.get_records({'zone': 'example.com'})
        argv = self.last()['argv']
        self.assertEqual(argv[argv.index('-cache-dir') + 1], os.path.join(self.state, 'cache'))
        with open(os.path.join(os.path.dirname(lib.__file__), '..', 'etc', 'state-include.conf')) as f:
            self.assertNotIn('cache', f.read())

    def test_unconfigured_zone(self):
        self.assertRejects(lib.get_records, {'zone': 'other.org'}, 'zone_not_found', 'zone')
        self.assertEqual(self.calls(), [])

    def test_change_operations_pass_options_through(self):
        self.respond({'set-records': CHANGES})
        out = lib.set_records({
            'zone': 'example.com', 'dry_run': True, 'mode': 'merge', 'replace_prefixes': ['v=spf1'],
            'records': [{'name': '@', 'type': 'TXT', 'data': 'v=spf1 -all'}]})
        req = self.last()['req']
        self.assertEqual((req['op'], req['dry_run'], req['mode'], req['replace_prefixes']),
                         ('set-records', True, 'merge', ['v=spf1']))
        self.assertTrue(out['dry_run'])
        self.assertEqual(out['changes']['add'][0]['data'], 'x')

    def test_get_records_filter(self):
        self.respond({'get-records': {'ok': True, 'records': []}})
        lib.get_records({'zone': 'example.com', 'type': 'TXT'})
        self.assertEqual(self.last()['req']['filter'], {'type': 'TXT'})

    def test_user_fixable_helper_errors_become_validation_errors(self):
        for code, field in (('conflict', 'records'), ('auth_failed', 'credentials'), ('forbidden', 'records')):
            self.respond({'append-records': {'ok': False, 'records': [], 'error': {'code': code, 'message': 'm'}}})
            with self.assertRaises(lib.ActionError) as cm:
                lib.append_records({'zone': 'example.com', 'records': []})
            self.assertEqual((cm.exception.entry['error'], cm.exception.entry['field']), (code, field))

    def test_other_helper_errors_are_failures(self):
        self.respond({'append-records': {'ok': False, 'records': [], 'error': {'code': 'timeout', 'message': 'slow'}}})
        with self.assertRaises(lib.HelperFailure):
            lib.append_records({'zone': 'example.com', 'records': []})

    def test_unparseable_helper_output_never_surfaces(self):
        self.respond({'get-records': 'boom ' + SECRET})
        with self.assertRaises(lib.HelperFailure) as cm:
            lib.get_records({'zone': 'example.com'})
        self.assertNotIn(SECRET, str(cm.exception))

    def test_missing_binary_is_a_failure(self):
        with mock.patch.dict(os.environ, {'DNSHELPER_BIN': '/nonexistent/dnshelper'}):
            with self.assertRaises(lib.HelperFailure):
                lib.list_providers({})

    def test_validate_zone_variants(self):
        ok = {'ok': True, 'records': [], 'capabilities': {'get_records': True},
              'validation': {'method': 'get-records', 'zone_found': True, 'write_test': 'skipped'}}
        self.respond({'validate': ok})
        self.assertTrue(lib.validate_zone({'zone': 'example.com'})['valid'])          # configured
        self.assertEqual(self.last()['req']['credentials'], {'api_token': SECRET})
        lib.validate_zone({'zone': 'new.org', 'credential': self.cid, 'write_test': True})  # stored credential
        self.assertTrue(self.last()['req']['write_test'])
        before = json.dumps(lib.get_configuration({}), sort_keys=True)
        lib.validate_zone({'zone': 'new.org', 'provider': 'cloudflare', 'fields': {'api_token': 'inline'}})
        self.assertEqual(self.last()['req']['credentials'], {'api_token': 'inline'})   # inline, nothing saved
        self.assertEqual(json.dumps(lib.get_configuration({}), sort_keys=True), before)
        self.assertEqual(lib.list_zones({})['zones'][0]['zone'], 'example.com')


class ActionRunner(Base):
    def run_action(self, action, data):
        agent = types.ModuleType('agent')
        agent.SD_ERR, agent.SD_INFO, agent.SD_WARNING = '<3>', '<6>', '<4>'
        agent.set_status = mock.Mock()
        agent.redis = mock.Mock()
        agent.redis_connect = mock.Mock(return_value=agent.redis)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(sys.modules, {'agent': agent}), \
                mock.patch.object(sys, 'stdin', io.StringIO(json.dumps(data))), \
                mock.patch.object(sys, 'stdout', out), mock.patch.object(sys, 'stderr', err):
            try:
                lib.run(action)
                code = 0
            except SystemExit as e:
                code = e.code
        self.agent = agent
        return code, out.getvalue(), err.getvalue(), agent



class ImportTests(Base):
    def test_list_provider_zones_variants(self):
        self.respond({'list-zones': {'ok': True, 'records': [], 'zones': ['a.com', 'b.org']}})
        cid = self.add_cred()
        self.assertEqual(lib.list_provider_zones({'credential': cid}), {'supported': True, 'zones': ['a.com', 'b.org']})
        req = self.calls()[-1]['req']
        self.assertEqual((req['op'], req['credentials'], 'zone' in req), ('list-zones', {'api_token': SECRET}, False))
        lib.list_provider_zones({'provider': 'cloudflare', 'fields': {'api_token': 'inline'}})
        self.assertEqual(self.calls()[-1]['req']['credentials'], {'api_token': 'inline'})
        self.assertEqual(lib.get_configuration({})['credentials'][0]['id'], cid)   # nothing was saved for the inline one
        self.assertEqual(len(lib.get_configuration({})['credentials']), 1)

    def test_provider_that_cannot_list_zones_is_not_an_error(self):
        self.respond({'list-zones': {'ok': False, 'records': [], 'error': {'code': 'unsupported', 'message': 'x'}}})
        cid = self.add_cred()
        self.assertEqual(lib.list_provider_zones({'credential': cid}), {'supported': False, 'zones': []})

    def test_bad_credentials_are_still_reported(self):
        self.respond({'list-zones': {'ok': False, 'records': [], 'error': {'code': 'auth_failed', 'message': 'x'}}})
        self.assertRejects(lib.list_provider_zones, {'credential': self.add_cred()}, 'auth_failed', 'credentials')

    def test_suggest_zones_marks_managed_ones(self):
        cid = self.add_cred()
        lib.add_zone({'zone': 'example.com', 'credential': cid})
        self.respond({'registrable-domains': {'ok': True, 'records': [], 'candidates': [
            {'zone': 'example.com', 'names': ['mail.example.com']},
            {'zone': 'shop.example.com', 'names': ['shop.example.com']},
            {'zone': 'other.org', 'names': ['www.other.org']}]}})
        out = lib.suggest_zones({'names': ['mail.example.com', 'shop.example.com', 'www.other.org']})['candidates']
        self.assertEqual([(c['zone'], c['managed'], c['managed_zone']) for c in out],
                         [('example.com', True, 'example.com'), ('shop.example.com', True, 'example.com'), ('other.org', False, None)])
        self.assertEqual(self.calls()[-1]['req']['names'], ['mail.example.com', 'shop.example.com', 'www.other.org'])


class RunTests(ActionRunner):
    def test_success_prints_json(self):
        code, out, _, agent = self.run_action('has-zone', {'name': 'x.example.com'})
        self.assertEqual((code, json.loads(out)), (0, {'managed': False, 'zone': None, 'allowed': False}))
        agent.set_status.assert_not_called()

    def test_validation_failure_protocol(self):
        code, out, _, agent = self.run_action('remove-zone', {'zone': 'example.com'})
        self.assertEqual(code, 2)
        agent.set_status.assert_called_once_with('validation-failed')
        self.assertEqual(json.loads(out)[0]['error'], 'zone_not_found')

    def test_helper_failure_exits_nonzero_with_journal_prefix(self):
        with mock.patch.dict(os.environ, {'DNSHELPER_BIN': '/nonexistent'}):
            code, out, err, _ = self.run_action('list-providers', {})
        self.assertEqual((code, out), (1, ''))
        self.assertTrue(err.startswith('<3>'))

    def test_every_action_has_a_handler_and_a_step(self):
        actions = os.path.join(HERE, '..', '..', 'imageroot', 'actions')
        for name in os.listdir(actions):
            if name in ('configure-module', 'create-module', 'restore-module'):   # lifecycle actions
                continue
            self.assertIn(name, lib.HANDLERS)
            self.assertTrue(os.access(os.path.join(actions, name, '10run'), os.X_OK), name)
        for name in lib.HANDLERS:
            self.assertTrue(os.path.isdir(os.path.join(actions, name)), name)


def as_module(module_id):
    return mock.patch.dict(os.environ, {'AGENT_TASK_USER': 'module/' + module_id})


class PolicyTests(Base):
    def setUp(self):
        super().setUp()
        self.cid = self.add_cred()
        for z in ('example.com', 'other.org'):
            lib.add_zone({'zone': z, 'credential': self.cid})
        self.respond({'get-records': {'ok': True, 'records': [
            {'name': '@', 'type': 'TXT', 'ttl': 300, 'data': 'v=spf1 -all'},
            {'name': 'mail._domainkey', 'type': 'TXT', 'ttl': 300, 'data': 'k'},
            {'name': 'www', 'type': 'A', 'ttl': 300, 'data': '192.0.2.1'}]},
            'append-records': CHANGES, 'set-records': CHANGES, 'delete-records': CHANGES})
        if os.path.exists(self.log):
            os.unlink(self.log)

    def rule(self, **kw):
        r = {'caller': 'module/mail1', 'zones': ['example.com'], 'access': 'write',
             'names': ['@', '*._domainkey'], 'types': ['TXT', 'MX']}
        r.update(kw)
        return r

    def txt(self, name, data='x', typ='TXT'):
        return {'name': name, 'type': typ, 'data': data}

    def test_policy_round_trip_and_normalization(self):
        lib.set_policy({'rules': [{'caller': 'Module/Mail1', 'zone': 'Example.COM.', 'access': 'read',
                                   'names': ['WWW'], 'types': ['txt']}, {'caller': 'module/x*', 'zone': '*', 'access': 'write'}]})
        self.assertEqual(lib.get_policy({})['rules'], [
            {'caller': 'module/mail1', 'zones': ['example.com'], 'access': 'read', 'names': ['www'], 'types': ['TXT']},
            {'caller': 'module/x*', 'zones': ['*'], 'access': 'write', 'names': ['*'], 'types': ['*']}])
        mode = stat.S_IMODE(os.stat(os.path.join(self.state, 'policy.json')).st_mode)
        self.assertEqual(mode, 0o600)

    def test_a_rule_can_name_several_zones(self):
        lib.set_policy({'rules': [
            {'caller': 'module/web1', 'zones': ['Example.com.', 'other.org', 'example.com'], 'access': 'write',
             'names': ['*'], 'types': ['CNAME']}]})
        self.assertEqual(lib.get_policy({})['rules'][0]['zones'], ['example.com', 'other.org'])  # normalized, deduplicated
        cname = {'name': 'www', 'type': 'CNAME', 'data': 'h.example.com.'}
        with as_module('web1'):
            for zone in ('example.com', 'other.org'):
                lib.append_records({'zone': zone, 'records': [cname]})
            self.assertEqual(sorted(z['zone'] for z in lib.list_zones({})['zones']), ['example.com', 'other.org'])
        lib.add_zone({'zone': 'third.net', 'credential': self.cid})
        with as_module('web1'):
            self.assertRejects(lib.append_records, {'zone': 'third.net', 'records': [cname]}, 'not_permitted', 'zone')

    def test_all_zones_absorbs_the_rest_of_the_list(self):
        lib.set_policy({'rules': [{'caller': 'module/x1', 'zones': ['example.com', '*'], 'access': 'read'}]})
        self.assertEqual(lib.get_policy({})['rules'][0]['zones'], ['*'])

    def test_a_rule_stored_with_one_zone_still_applies(self):
        # the format before a rule could name several zones
        lib._write_private(lib._policy_path(), {'rules': [
            {'caller': 'module/web1', 'zone': 'example.com', 'access': 'write', 'names': ['*'], 'types': ['*']}]})
        self.assertEqual(lib.get_policy({})['rules'][0]['zones'], ['example.com'])
        self.assertNotIn('zone', lib.get_policy({})['rules'][0])
        with as_module('web1'):
            lib.append_records({'zone': 'example.com', 'records': [self.txt('a')]})
            self.assertRejects(lib.append_records, {'zone': 'other.org', 'records': [self.txt('a')]}, 'not_permitted', 'zone')
        # saving the table again writes the new format
        lib.set_policy({'rules': lib.get_policy({})['rules']})
        self.assertEqual(lib._load_rules()[0]['zones'], ['example.com'])

    def test_zone_and_zones_are_exclusive_and_one_is_needed(self):
        for bad in ({'zone': 'example.com', 'zones': ['example.com']}, {}, {'zones': []}, {'zones': ['not a zone']}):
            with self.assertRaises(lib.ActionError):
                lib.set_policy({'rules': [dict({'caller': 'module/x1', 'access': 'read'}, **bad)]})

    def test_policy_validation(self):
        bad = [({'caller': 'admin'}, 'invalid_caller'), ({'caller': 'module/../x'}, 'invalid_caller'),
               ({'access': 'root'}, 'invalid_access'), ({'names': ['a b']}, 'invalid_name_pattern'),
               ({'types': ['T X']}, 'invalid_type'), ({'zones': ['nodots']}, 'invalid_zone')]
        for change, error in bad:
            with self.assertRaises(lib.ActionError) as cm:
                lib.set_policy({'rules': [self.rule(**change)]})
            self.assertEqual(cm.exception.entry['error'], error, change)

    def test_modules_are_denied_by_default(self):
        with as_module('mail1'):
            self.assertRejects(lib.get_records, {'zone': 'example.com'}, 'not_permitted')
            self.assertRejects(lib.append_records, {'zone': 'example.com', 'records': [self.txt('@')]}, 'not_permitted')
            self.assertEqual(lib.list_zones({})['zones'], [])
            self.assertEqual(lib.has_zone({'name': 'example.com'}), {'managed': True, 'zone': 'example.com', 'allowed': False})
        self.assertEqual(self.calls(), [])  # nothing reached the provider

    def test_administrators_are_not_restricted(self):
        for user in ('', 'admin'):
            with mock.patch.dict(os.environ, {'AGENT_TASK_USER': user}):
                lib.append_records({'zone': 'example.com', 'records': [self.txt('anything')]})
                self.assertEqual(len(lib.list_zones({})['zones']), 2)

    def test_write_rule_limits_names_types_and_zone(self):
        lib.set_policy({'rules': [self.rule()]})
        with as_module('mail1'):
            lib.append_records({'zone': 'example.com', 'records': [self.txt('@'), self.txt('mail._domainkey'),
                                                                   {'name': '@', 'type': 'mx', 'data': '10 m.example.com.'}]})
            for rec in (self.txt('www'), self.txt('@', typ='A'), self.txt('_domainkey'), self.txt('a.b')):
                self.assertRejects(lib.set_records, {'zone': 'example.com', 'records': [rec]}, 'not_permitted', 'records')
            self.assertRejects(lib.append_records, {'zone': 'other.org', 'records': [self.txt('@')]}, 'not_permitted', 'zone')
        self.assertEqual(len(self.calls()), 1)  # only the permitted request got through

    def test_web_preset_allows_cname_with_any_name_and_nothing_else(self):
        # the "Web server or service" preset of the Access page
        lib.set_policy({'rules': [self.rule(caller='module/sogo1', names=['*'], types=['CNAME'])]})
        cname = {'name': 'mail', 'type': 'CNAME', 'data': 'host.example.com.'}
        with as_module('sogo1'):
            lib.append_records({'zone': 'example.com', 'records': [cname, dict(cname, name='a.b')]})
            lib.delete_records({'zone': 'example.com', 'records': [cname]})
            for rec in (self.txt('mail'), self.txt('@', typ='A'), self.txt('mail', typ='MX')):
                self.assertRejects(lib.append_records, {'zone': 'example.com', 'records': [rec]}, 'not_permitted', 'records')
            self.assertRejects(lib.delete_records, {'zone': 'example.com', 'records': [{'name': 'mail'}]}, 'not_permitted')
            self.assertRejects(lib.append_records, {'zone': 'other.org', 'records': [cname]}, 'not_permitted', 'zone')

    def test_one_forbidden_record_refuses_the_whole_request(self):
        lib.set_policy({'rules': [self.rule()]})
        with as_module('mail1'):
            self.assertRejects(lib.append_records, {'zone': 'example.com', 'records': [self.txt('@'), self.txt('www')]},
                               'not_permitted')
        self.assertEqual(self.calls(), [])

    def test_delete_without_type_needs_a_wildcard_type_rule(self):
        lib.set_policy({'rules': [self.rule()]})
        with as_module('mail1'):
            self.assertRejects(lib.delete_records, {'zone': 'example.com', 'records': [{'name': '@'}]}, 'not_permitted')
        lib.set_policy({'rules': [self.rule(types=['*'])]})
        with as_module('mail1'):
            lib.delete_records({'zone': 'example.com', 'records': [{'name': '@'}]})

    def test_read_rule_reads_but_cannot_write_and_reads_are_filtered(self):
        lib.set_policy({'rules': [self.rule(access='read')]})
        with as_module('mail1'):
            names = [r['name'] for r in lib.get_records({'zone': 'example.com'})['records']]
            self.assertEqual(sorted(names), ['@', 'mail._domainkey'])   # 'www' A is not covered
            self.assertRejects(lib.append_records, {'zone': 'example.com', 'records': [self.txt('@')]}, 'not_permitted')
            self.assertRejects(lib.get_records, {'zone': 'other.org'}, 'not_permitted')

    def test_rules_apply_per_caller_with_wildcards(self):
        lib.set_policy({'rules': [self.rule(caller='module/traefik*', zones=['*'], names=['_acme-challenge', '_acme-challenge.*'], types=['TXT'])]})
        with as_module('traefik2'):
            lib.append_records({'zone': 'other.org', 'records': [self.txt('_acme-challenge.www')]})
            self.assertRejects(lib.append_records, {'zone': 'other.org', 'records': [self.txt('www')]}, 'not_permitted')
        with as_module('mail1'):
            self.assertRejects(lib.append_records, {'zone': 'other.org', 'records': [self.txt('_acme-challenge')]}, 'not_permitted')

    def test_has_zone_and_list_zones_reflect_the_rules(self):
        lib.set_policy({'rules': [self.rule()]})
        with as_module('mail1'):
            self.assertTrue(lib.has_zone({'name': 'mail.example.com'})['allowed'])
            self.assertFalse(lib.has_zone({'name': 'x.other.org'})['allowed'])
            self.assertEqual([z['zone'] for z in lib.list_zones({})['zones']], ['example.com'])


class AuditAndEventTests(ActionRunner):
    def test_audit_line_for_a_module_change(self):
        self.respond({'append-records': CHANGES})
        cid = self.add_cred()
        lib.add_zone({'zone': 'example.com', 'credential': cid})
        lib.set_policy({'rules': [{'caller': 'module/mail1', 'zone': 'example.com', 'access': 'write'}]})
        with as_module('mail1'):
            code, out, err, _ = self.run_action('append-records', {
                'zone': 'example.com', 'records': [{'name': '@', 'type': 'TXT', 'data': 'x'}]})
        self.assertEqual(code, 0)
        self.assertTrue(err.startswith('<6>dnshelper audit: '), err)
        for want in ('caller="module/mail1"', 'action="append-records"', 'result="ok"', 'zone="example.com"', '"@ TXT x"'):
            self.assertIn(want, err)
        self.assertNotIn(SECRET, err)

    def test_denials_and_module_reads_are_logged_and_reads_by_humans_are_not(self):
        with as_module('mail1'):
            code, _, err, _ = self.run_action('get-records', {'zone': 'example.com'})
        self.assertEqual(code, 2)
        self.assertIn('result="rejected"', err)
        self.assertIn('error="not_permitted"', err)
        code, _, err, _ = self.run_action('list-zones', {})
        self.assertEqual(err, '')

    def test_admin_changes_are_logged_without_credentials(self):
        code, out, err, _ = self.run_action('add-credential', {
            'name': 'Prod', 'provider': 'cloudflare', 'fields': {'api_token': SECRET}})
        self.assertEqual(code, 0)
        self.assertIn('action="add-credential"', err)
        self.assertIn('provider="cloudflare"', err)
        self.assertNotIn(SECRET, err)
        self.assertNotIn(SECRET, out.replace(json.loads(out)['id'], ''))

    def test_zone_changes_publish_the_service_event(self):
        cid = self.add_cred()
        with mock.patch.dict(os.environ, {'MODULE_ID': 'dnshelper1', 'AGENT_ID': 'module/dnshelper1', 'MODULE_UUID': 'u-1'}):
            code, _, _, agent = self.run_action('add-zone', {'zone': 'example.com', 'credential': cid})
            self.assertEqual(code, 0)
            channel, payload = agent.redis.publish.call_args[0]
            self.assertEqual(channel, 'module/dnshelper1/event/service-dnshelper-changed')
            self.assertEqual(json.loads(payload), {'key': 'module/dnshelper1/srv/api/dnshelper',
                                                   'module_id': 'dnshelper1', 'module_uuid': 'u-1'})
            agent.redis_connect.assert_called_with(privileged=True)
            # A failed action, and an unrelated one, raise nothing.
            _, _, _, agent = self.run_action('add-zone', {'zone': 'example.com', 'credential': cid})
            agent.redis.publish.assert_not_called()
            _, _, _, agent = self.run_action('list-zones', {})
            agent.redis.publish.assert_not_called()

    def test_a_failing_publish_does_not_fail_the_action(self):
        cid = self.add_cred()
        with mock.patch.dict(os.environ, {'MODULE_ID': 'dnshelper1', 'AGENT_ID': 'module/dnshelper1'}):
            with mock.patch('dnshelper_lib._publish_change', wraps=lib._publish_change):
                agent_stub = types.ModuleType('agent')
                agent_stub.SD_INFO, agent_stub.SD_WARNING, agent_stub.SD_ERR = '<6>', '<4>', '<3>'
                agent_stub.set_status = mock.Mock()
                agent_stub.redis_connect = mock.Mock(side_effect=RuntimeError('redis down'))
                err = io.StringIO()
                with mock.patch.dict(sys.modules, {'agent': agent_stub}), \
                        mock.patch.object(sys, 'stdin', io.StringIO(json.dumps({'zone': 'example.com', 'credential': cid}))), \
                        mock.patch.object(sys, 'stdout', io.StringIO()), mock.patch.object(sys, 'stderr', err):
                    lib.run('add-zone')
                self.assertIn('cannot publish', err.getvalue())
        self.assertEqual(len(lib.list_zones({})['zones']), 1)


class InputSchemaTests(unittest.TestCase):
    def test_actions_without_arguments_accept_the_empty_payload_the_ui_sends(self):
        """The admin UI calls an argument-less action with no payload at all, which
        NS8 validates as null. A schema that only allows an object then fails on a
        real node ("Expected: object, given: null") while api-cli with {} passes."""
        actions = os.path.join(HERE, '..', '..', 'imageroot', 'actions')
        seen = []
        for name in sorted(os.listdir(actions)):
            path = os.path.join(actions, name, 'validate-input.json')
            if not os.path.exists(path):
                continue
            schema = load(path)
            if not schema.get('required') and not schema.get('properties'):
                seen.append(name)
                types = schema['type'] if isinstance(schema['type'], list) else [schema['type']]
                self.assertIn('null', types, name)
                self.assertIn('object', types, name)
        self.assertIn('list-providers', seen)
        self.assertIn('list-zones', seen)


class ModuleScriptTests(unittest.TestCase):
    root = os.path.join(HERE, '..', '..', 'imageroot', 'actions', 'create-module')

    def test_role_scripts_only_name_real_actions(self):
        with open(os.path.join(self.root, '30grants')) as f:
            text = f.read()
        import re
        arrays = {m.group(1): m.group(2).split() for m in re.finditer(r'(\w+)=\(\s*([^)]*)\)', text)}
        actions = os.path.join(HERE, '..', '..', 'imageroot', 'actions')
        for name in arrays['reader_actions'] + arrays['writer_actions']:
            self.assertTrue(os.path.isdir(os.path.join(actions, name)), name)
        # Modules must never be able to reach the administration actions.
        for admin in ('set-policy', 'get-policy', 'add-zone', 'add-credential', 'update-credential', 'validate-zone',
                      'remove-zone', 'update-zone', 'remove-credential', 'get-configuration', 'list-providers'):
            self.assertNotIn(admin, arrays['reader_actions'] + arrays['writer_actions'])
        self.assertIn('roles/dnsreader', text)
        self.assertIn('roles/dnswriter" "${reader_actions[@]}" "${writer_actions[@]}"', text)

    def test_scripts_parse(self):
        import subprocess
        subprocess.run(['bash', '-n', os.path.join(self.root, '30grants')], check=True)
        with open(os.path.join(self.root, '50register_service')) as f:
            compile(f.read(), '50register_service', 'exec')
        for n in os.listdir(self.root):
            self.assertTrue(os.access(os.path.join(self.root, n), os.X_OK), n)


@unittest.skipUnless(os.environ.get('DNSHELPER_REAL_BIN'), 'set DNSHELPER_REAL_BIN to the built helper')
class RealHelperTests(unittest.TestCase):
    """The same plumbing against the real Go binary. No network is touched:
    every case is decided by the helper before it contacts a provider."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {'AGENT_STATE_DIR': self.tmp.name,
                                               'DNSHELPER_BIN': os.environ['DNSHELPER_REAL_BIN']})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_list_providers_matches_the_schema_the_library_expects(self):
        names = {p['name'] for p in lib.list_providers({})['providers']}
        self.assertEqual(names, {'cloudflare', 'corenetworks', 'digitalocean', 'godaddy', 'hetzner', 'linode', 'namedotcom', 'porkbun', 'rfc2136', 'route53'})

    def test_credential_lifecycle_with_defaults(self):
        cid = lib.add_credential({'name': 'bind', 'provider': 'rfc2136',
                                  'fields': {'server': 'ns.example.com:53', 'key_name': 'k', 'key': 'c2VjcmV0'}})['id']
        stored = load(os.path.join(self.tmp.name, 'credentials', cid + '.json'))
        self.assertEqual(stored['fields']['key_alg'], 'hmac-sha256')   # default filled in
        cfg = lib.get_configuration({})['credentials'][0]
        self.assertEqual(cfg['secrets_set'], ['key'])
        self.assertNotIn('c2VjcmV0', json.dumps(cfg))

    def test_missing_field_is_reported_by_field(self):
        with self.assertRaises(lib.ActionError) as cm:
            lib.add_credential({'name': 'x', 'provider': 'hetzner', 'fields': {}})
        self.assertEqual(cm.exception.entry['field'], 'fields.api_token')


if __name__ == '__main__':
    unittest.main()
