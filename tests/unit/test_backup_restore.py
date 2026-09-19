import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_dnshelper_lib import Base, PROVIDERS, SECRET, HERE, lib, load

ROOT = os.path.join(HERE, '..', '..')
INCLUDE = os.path.join(ROOT, 'imageroot', 'etc', 'state-include.conf')
DUMP_STATE = os.path.join(ROOT, 'imageroot', 'bin', 'module-dump-state')


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class EnsureStateTests(Base):
    def test_creates_a_complete_private_empty_state(self):
        lib.ensure_state()
        self.assertEqual(load(os.path.join(self.state, 'zones.json')), {'zones': {}})
        self.assertEqual(load(os.path.join(self.state, 'policy.json')), {'rules': []})
        self.assertEqual(mode(os.path.join(self.state, 'credentials')), 0o700)
        self.assertEqual(mode(os.path.join(self.state, 'zones.json')), 0o600)
        self.assertEqual(mode(os.path.join(self.state, 'policy.json')), 0o600)

    def test_never_overwrites_existing_state(self):
        cid = self.add_cred()
        lib.add_zone({'zone': 'example.com', 'credential': cid})
        lib.set_policy({'rules': [{'caller': 'module/a1', 'zone': 'example.com', 'access': 'read'}]})
        lib.ensure_state()
        self.assertEqual(len(lib.list_zones({})['zones']), 1)
        self.assertEqual(len(lib.get_policy({})['rules']), 1)
        self.assertEqual(len(lib.get_configuration({})['credentials']), 1)

    def test_every_path_in_the_include_file_exists_afterwards(self):
        lib.ensure_state()
        with open(INCLUDE) as f:
            paths = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        self.assertTrue(paths)
        for p in paths:
            self.assertTrue(p.startswith('state/'), p)
            self.assertTrue(os.path.exists(os.path.join(self.tmp.name, p)), p)

    def test_scripts_run_and_are_executable(self):
        subprocess.run([sys.executable, DUMP_STATE], check=True, env=dict(os.environ))
        self.assertTrue(os.path.exists(os.path.join(self.state, 'policy.json')))
        for rel in ('bin/module-dump-state', 'actions/restore-module/50check_state', 'actions/create-module/10init_state'):
            self.assertTrue(os.access(os.path.join(ROOT, 'imageroot', rel), os.X_OK), rel)
        for rel in ('actions/restore-module/50check_state', 'actions/create-module/10init_state'):
            with open(os.path.join(ROOT, 'imageroot', rel)) as f:
                compile(f.read(), rel, 'exec')


class CheckRestoredStateTests(Base):
    def setUp(self):
        super().setUp()
        self.cid = self.add_cred()
        lib.add_zone({'zone': 'example.com', 'credential': self.cid})
        lib.set_policy({'rules': [{'caller': 'module/mail1', 'zone': 'example.com', 'access': 'write'}]})

    def test_healthy_state_summary_and_no_warnings(self):
        summary, warnings = lib.check_restored_state(lambda m: True)
        self.assertEqual(summary, {'zones': 1, 'credentials': 1, 'rules': 1})
        self.assertEqual(warnings, [])

    def test_permissions_are_repaired(self):
        path = os.path.join(self.state, 'credentials', self.cid + '.json')
        os.chmod(path, 0o644)
        os.chmod(os.path.join(self.state, 'credentials'), 0o755)
        os.chmod(os.path.join(self.state, 'policy.json'), 0o644)
        lib.check_restored_state()
        self.assertEqual(mode(path), 0o600)
        self.assertEqual(mode(os.path.join(self.state, 'credentials')), 0o700)
        self.assertEqual(mode(os.path.join(self.state, 'policy.json')), 0o600)

    def test_corrupt_files_fail_the_restore_without_echoing_contents(self):
        for rel, content in (('zones.json', '{not json ' + SECRET), ('policy.json', '[]'), ('zones.json', '{"zones": []}'),
                             ('credentials/%s.json' % self.cid, '{"name": 1}')):
            keep = os.path.join(self.state, rel)
            with open(keep) as f:
                original = f.read()
            with open(keep, 'w') as f:
                f.write(content)
            with self.assertRaises(lib.StateError) as cm:
                lib.check_restored_state()
            self.assertNotIn(SECRET, str(cm.exception))
            with open(keep, 'w') as f:
                f.write(original)
        lib.check_restored_state()   # and it works again once repaired

    def test_dangling_and_odd_things_are_warnings_not_failures(self):
        os.unlink(os.path.join(self.state, 'credentials', self.cid + '.json'))
        with open(os.path.join(self.state, 'credentials', 'notes.txt'), 'w') as f:
            f.write('x')
        with open(os.path.join(self.state, 'credentials', 'c1.json.99.tmp'), 'w') as f:
            f.write('{')
        summary, warnings = lib.check_restored_state(lambda m: False)
        text = '\n'.join(warnings)
        self.assertIn('refers to missing credential', text)
        self.assertIn('notes.txt', text)
        self.assertIn('module/mail1, which does not exist', text)
        self.assertFalse(os.path.exists(os.path.join(self.state, 'credentials', 'c1.json.99.tmp')))

    def test_unknown_provider_and_invalid_rule_are_warned_about(self):
        path = os.path.join(self.state, 'credentials', self.cid + '.json')
        cred = load(path)
        cred['provider'] = 'removedprovider'
        with open(path, 'w') as f:
            json.dump(cred, f)
        with open(os.path.join(self.state, 'policy.json'), 'w') as f:
            json.dump({'rules': [{'caller': 'nope'}]}, f)
        _, warnings = lib.check_restored_state()
        text = '\n'.join(warnings)
        self.assertIn('removedprovider', text)
        self.assertIn('invalid rule', text)

    def test_wildcard_callers_are_not_looked_up(self):
        lib.set_policy({'rules': [{'caller': 'module/traefik*', 'zone': '*', 'access': 'write'}]})
        seen = []
        lib.check_restored_state(lambda m: seen.append(m) or False)
        self.assertEqual(seen, [])


@unittest.skipUnless(shutil.which('restic'), 'restic is not installed')
class ResticRoundTripTests(Base):
    """Back up with the repository's real state-include.conf, exactly as
    module-backup does (workdir holding state/, --files-from), and restore the
    way the core 10restore step does, into a freshly created module."""

    def setUp(self):
        super().setUp()
        self.repo = os.path.join(self.tmp.name, 'repo')
        self.restic_env = dict(os.environ, RESTIC_PASSWORD='test-only', RESTIC_REPOSITORY=self.repo)
        subprocess.run(['restic', 'init', '-q'], check=True, env=self.restic_env, capture_output=True)

    def restic(self, cwd, *args):
        return subprocess.run(['restic', *args], cwd=cwd, env=self.restic_env, capture_output=True, text=True)

    def backup(self, workdir):
        with mock.patch.dict(os.environ, {'AGENT_STATE_DIR': os.path.join(workdir, 'state')}):
            subprocess.run([sys.executable, DUMP_STATE], check=True)   # module-dump-state
        p = self.restic(workdir, 'backup', '--no-scan', 'state/environment', '--files-from=' + INCLUDE)
        self.assertEqual(p.returncode, 0, p.stderr)

    def restore_into_new_module(self):
        workdir = tempfile.mkdtemp(dir=self.tmp.name)
        state = os.path.join(workdir, 'state')
        os.makedirs(state)
        with open(os.path.join(state, 'environment'), 'w') as f:
            f.write('NEW=1\n')
        with mock.patch.dict(os.environ, {'AGENT_STATE_DIR': state}):
            lib.ensure_state()                                       # create-module/10init_state
        p = self.restic(workdir, 'restore', 'latest', '--target', '.', '--exclude', 'state/environment')
        self.assertEqual(p.returncode, 0, p.stderr)
        return workdir, state

    def test_full_configuration_survives_a_backup_and_restore(self):
        cid = self.add_cred(fields={'api_token': SECRET, 'account': 'acme'})
        lib.add_zone({'zone': 'example.com', 'credential': cid})
        lib.set_policy({'rules': [{'caller': 'module/mail1', 'zone': 'example.com', 'access': 'write',
                                   'names': ['_domainkey', '*._domainkey'], 'types': ['TXT']}]})
        with open(os.path.join(self.state, 'environment'), 'w') as f:
            f.write('OLD=1\n')
        with open(os.path.join(self.state, '.module-backup.lock'), 'w'):
            pass
        before = {'config': lib.get_configuration({}), 'policy': lib.get_policy({}), 'zones': lib.list_zones({})}
        self.backup(self.tmp.name)

        # Locks and other state files that are not listed must stay out of the backup.
        listing = self.restic(self.tmp.name, 'ls', 'latest').stdout
        self.assertNotIn('.module-backup.lock', listing)
        self.assertNotIn('locks', listing)

        workdir, state = self.restore_into_new_module()
        with mock.patch.dict(os.environ, {'AGENT_STATE_DIR': state}):
            summary, warnings = lib.check_restored_state(lambda m: True)
            self.assertEqual((summary, warnings), ({'zones': 1, 'credentials': 1, 'rules': 1}, []))
            after = {'config': lib.get_configuration({}), 'policy': lib.get_policy({}), 'zones': lib.list_zones({})}
            self.assertEqual(after, before)
            cred = load(os.path.join(state, 'credentials', cid + '.json'))
            self.assertEqual(cred['fields']['api_token'], SECRET)    # usable after restore
            self.assertEqual(mode(os.path.join(state, 'credentials', cid + '.json')), 0o600)
            self.assertEqual(mode(os.path.join(state, 'credentials')), 0o700)
            self.assertEqual(mode(os.path.join(state, 'policy.json')), 0o600)
        with open(os.path.join(state, 'environment')) as f:
            self.assertEqual(f.read(), 'NEW=1\n')                    # core's file is not overwritten

    def test_unconfigured_module_backs_up_and_restores_empty(self):
        with open(os.path.join(self.state, 'environment'), 'w') as f:
            f.write('OLD=1\n')
        self.backup(self.tmp.name)       # dump-state creates the empty state, so nothing is missing
        workdir, state = self.restore_into_new_module()
        with mock.patch.dict(os.environ, {'AGENT_STATE_DIR': state}):
            summary, warnings = lib.check_restored_state()
            self.assertEqual((summary, warnings), ({'zones': 0, 'credentials': 0, 'rules': 0}, []))

    def test_restore_replaces_what_the_new_module_started_with(self):
        cid = self.add_cred()
        lib.add_zone({'zone': 'example.com', 'credential': cid})
        with open(os.path.join(self.state, 'environment'), 'w') as f:
            f.write('OLD=1\n')
        self.backup(self.tmp.name)
        workdir, state = self.restore_into_new_module()
        with mock.patch.dict(os.environ, {'AGENT_STATE_DIR': state}):
            # the new module's own empty files were overwritten, not merged
            self.assertEqual([z['zone'] for z in lib.list_zones({})['zones']], ['example.com'])


if __name__ == '__main__':
    unittest.main()
