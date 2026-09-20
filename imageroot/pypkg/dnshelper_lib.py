#
# Copyright (C) 2026 dnshelper contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""Shared code for the dnshelper action steps.

Configuration lives in the module state directory, never in Redis or in
state/environment (both readable by other modules):

  state/zones.json            {"zones": {"example.com": {"credential": "<id>"}}}
  state/credentials/<id>.json {"name", "provider", "fields": {...}}  mode 0600

Credentials are separate objects so that one token can serve many zones and be
rotated in one place. They reach the Go helper on its stdin only.

Callers: the api-server sets AGENT_TASK_USER to "module/<id>" for a task started
by another module, and to the user name for a human. Roles (created in
create-module/30grants) only say which actions a module may call. What it may
change is decided by the policy table in state/policy.json, default deny.
Human administrators are not restricted by it.

  state/policy.json           {"rules": [{"caller", "zone", "access", "names", "types"}]}
"""

import fcntl
import fnmatch
import json
import os
import re
import secrets
import subprocess
import sys

ZONE_RE = re.compile(r'^[a-z0-9_]([a-z0-9._-]*[a-z0-9_])?\.[a-z0-9_-]*[a-z0-9_]$')
ID_RE = re.compile(r'^[a-z0-9-]{1,40}$')

# helper error code -> field the UI should mark
_CODE_FIELD = {
    'auth_failed': 'credentials',
    'zone_not_found': 'zone',
    'unsupported': 'provider',
}
_USER_FIXABLE = {'invalid_request', 'conflict', 'forbidden', 'zone_not_found',
                 'auth_failed', 'unsupported', 'unknown_provider'}


class ActionError(Exception):
    """A problem the caller can fix; reported as an NS8 validation failure."""

    def __init__(self, field, error, value='', message=''):
        super().__init__(error)
        self.entry = {'field': field, 'parameter': field, 'value': value, 'error': error}
        if message:
            self.entry['message'] = message


class HelperFailure(Exception):
    """The helper failed for a reason the caller cannot fix (timeout, provider outage)."""


# ---------------------------------------------------------------- paths

def _state_dir():
    return os.environ['AGENT_STATE_DIR']


def _zones_path():
    return os.path.join(_state_dir(), 'zones.json')


def _policy_path():
    return os.path.join(_state_dir(), 'policy.json')


def _cred_dir():
    return os.path.join(_state_dir(), 'credentials')


def _cred_path(cred_id):
    if not ID_RE.match(cred_id):
        raise ActionError('id', 'invalid_credential_id', cred_id)
    return os.path.join(_cred_dir(), cred_id + '.json')


# ---------------------------------------------------------------- storage

def _write_private(path, obj):
    """Atomically write obj as JSON, readable by the module user only."""
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    tmp = '%s.%d.tmp' % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(obj, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


class _ConfigLock:
    """Serializes read-modify-write of the configuration files."""

    def __enter__(self):
        os.makedirs(_state_dir(), exist_ok=True)
        self.f = open(os.path.join(_state_dir(), 'config.lock'), 'w')
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        self.f.close()


def _load_zones():
    return _read_json(_zones_path(), {'zones': {}})['zones']


def _save_zones(zones):
    _write_private(_zones_path(), {'zones': zones})


def _load_credential(cred_id):
    cred = _read_json(_cred_path(cred_id), None)
    if cred is None:
        raise ActionError('credential', 'credential_not_found', cred_id)
    return cred


def normalize_zone(zone):
    z = zone.strip().lower().rstrip('.')
    if not ZONE_RE.match(z) or len(z) > 253:
        raise ActionError('zone', 'invalid_zone', zone)
    return z


# ---------------------------------------------------------------- helper

def _helper_path():
    return os.environ.get('DNSHELPER_BIN') or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', 'bin', 'dnshelper')


def call_helper(request):
    """Run the Go helper. Credentials go on stdin only, never argv or env."""
    lock_dir = os.path.join(_state_dir(), 'locks')
    try:
        p = subprocess.run(
            [_helper_path(), '-lock-dir', lock_dir, '-timeout', '120s'],
            input=json.dumps(request), capture_output=True, text=True, timeout=150)
        resp = json.loads(p.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        # Say nothing about the cause: the request holds credentials.
        raise HelperFailure('the dnshelper binary could not be run')
    if resp.get('ok'):
        return resp
    err = resp.get('error') or {}
    code, message = err.get('code', 'provider_error'), err.get('message', '')
    if code in _USER_FIXABLE:
        raise ActionError(_CODE_FIELD.get(code, 'records'), code, message=message)
    raise HelperFailure('%s: %s' % (code, message))


def _providers():
    return {p['name']: p for p in call_helper({'op': 'list-providers'})['providers']}


def _check_fields(provider, fields, creating):
    """Validate credential fields against the provider schema.

    Returns the fields with defaults filled in. Secrets are never echoed.
    """
    info = _providers().get(provider)
    if info is None:
        raise ActionError('provider', 'unknown_provider', provider)
    known = {f['name']: f for f in info['fields']}
    for name in fields:
        if name not in known:
            raise ActionError('fields', 'unknown_field', name)
    out = dict(fields)
    for name, f in known.items():
        if not out.get(name) and f.get('default') and creating:
            out[name] = f['default']
        if creating and f['required'] and not out.get(name):
            raise ActionError('fields.' + name, 'required')
    return out, known


# ---------------------------------------------------------------- policy

CALLER_RE = re.compile(r'^module/[a-z0-9_*?-]+$')
NAME_PATTERN_RE = re.compile(r'^[a-z0-9@_.*?-]+$')
TYPE_RE = re.compile(r'^([A-Z0-9]+|\*)$')
MAX_RULES = 200
MAX_RULE_ZONES = 200


def caller():
    return os.environ.get('AGENT_TASK_USER', '')


def _restricted():
    """Module callers are bound by the policy table; humans are not."""
    return caller().startswith('module/')


def _load_rules():
    """The stored rules. Rules saved before a rule could name several zones hold
    a single 'zone'; they are read as a list of one."""
    rules = _read_json(_policy_path(), {'rules': []})['rules']
    return [r if 'zones' in r else dict({k: v for k, v in r.items() if k != 'zone'}, zones=[r['zone']])
            for r in rules]


def _normalize_zones(r, i):
    """The zones of rule number i as a list of zone names, or ['*'] for all."""
    if 'zones' in r and 'zone' in r:
        raise ActionError('rules.%d.zones' % i, 'invalid_request', message='give zones, not zone and zones')
    zones = r['zones'] if 'zones' in r else [r.get('zone', '')]
    if not isinstance(zones, list) or not zones or len(zones) > MAX_RULE_ZONES:
        raise ActionError('rules.%d.zones' % i, 'required' if not zones else 'invalid_request')
    out = []
    for z in zones:
        z = '*' if z == '*' else normalize_zone(z)
        if z not in out:
            out.append(z)
    return ['*'] if '*' in out else out


def _normalize_rules(rules):
    if len(rules) > MAX_RULES:
        raise ActionError('rules', 'too_many_rules')
    out = []
    for i, r in enumerate(rules):
        who = str(r.get('caller', '')).strip().lower()
        if not CALLER_RE.match(who):
            raise ActionError('rules.%d.caller' % i, 'invalid_caller', who)
        zones = _normalize_zones(r, i)
        if r.get('access') not in ('read', 'write'):
            raise ActionError('rules.%d.access' % i, 'invalid_access')
        names = [str(n).strip().lower() for n in r.get('names', ['*'])] or ['*']
        for n in names:
            if not NAME_PATTERN_RE.match(n):
                raise ActionError('rules.%d.names' % i, 'invalid_name_pattern', n)
        types = [str(t).strip().upper() for t in r.get('types', ['*'])] or ['*']
        for t in types:
            if not TYPE_RE.match(t):
                raise ActionError('rules.%d.types' % i, 'invalid_type', t)
        out.append({'caller': who, 'zones': zones, 'access': r['access'],
                    'names': names, 'types': types})
    return out


def _rules_for(zone):
    """The rules that apply to the current caller in zone."""
    who = caller().lower()
    return [r for r in _load_rules()
            if fnmatch.fnmatchcase(who, r['caller']) and ('*' in r['zones'] or zone in r['zones'])]


def _covers(rule, name, rtype):
    """Does rule cover the record (name, rtype)? rtype None means "any type"."""
    n = name.strip().lower().rstrip('.') or '@'
    if not any(fnmatch.fnmatchcase(n, p) for p in rule['names']):
        return False
    if '*' in rule['types']:
        return True
    return rtype is not None and rtype.upper() in rule['types']


def _may(rules, name, rtype, write):
    return any((r['access'] == 'write' or not write) and _covers(r, name, rtype) for r in rules)


def _require_access(zone, records):
    """Refuse a change the caller's rules do not cover."""
    if not _restricted():
        return
    rules = _rules_for(zone)
    if not any(r['access'] == 'write' for r in rules):
        raise ActionError('zone', 'not_permitted', zone, 'this module may not change zone %s' % zone)
    for r in records:
        if not _may(rules, r['name'], r.get('type'), write=True):
            what = r['name'] + (' ' + r['type'] if r.get('type') else '')
            raise ActionError('records', 'not_permitted', what,
                              'the policy does not let this module change %s in %s' % (what, zone))


def get_policy(data):
    return {'rules': _load_rules()}


def set_policy(data):
    rules = _normalize_rules(data['rules'])
    with _ConfigLock():
        _write_private(_policy_path(), {'rules': rules})
    return {}


# ---------------------------------------------------------------- actions

def list_providers(data):
    return {'providers': call_helper({'op': 'list-providers'})['providers']}


def add_credential(data):
    fields, _ = _check_fields(data['provider'], data['fields'], creating=True)
    cred_id = 'c' + secrets.token_hex(4)
    with _ConfigLock():
        _write_private(_cred_path(cred_id), {
            'name': data['name'], 'provider': data['provider'],
            'fields': {k: v for k, v in fields.items() if v != ''}})
    return {'id': cred_id}


def update_credential(data):
    with _ConfigLock():
        cred = _load_credential(data['id'])
        _, known = _check_fields(cred['provider'], data.get('fields', {}), creating=False)
        if 'name' in data:
            cred['name'] = data['name']
        for name, value in data.get('fields', {}).items():
            if value == '' and known[name]['secret']:
                continue  # blank secret means keep
            if value == '':
                cred['fields'].pop(name, None)
            else:
                cred['fields'][name] = value
        for name, f in known.items():
            if f['required'] and not cred['fields'].get(name):
                raise ActionError('fields.' + name, 'required')
        _write_private(_cred_path(data['id']), cred)
    return {}


def remove_credential(data):
    with _ConfigLock():
        _load_credential(data['id'])
        users = sorted(z for z, v in _load_zones().items() if v['credential'] == data['id'])
        if users:
            raise ActionError('id', 'credential_in_use', data['id'], ', '.join(users))
        os.unlink(_cred_path(data['id']))
    return {}


def add_zone(data):
    zone = normalize_zone(data['zone'])
    with _ConfigLock():
        _load_credential(data['credential'])
        zones = _load_zones()
        if zone in zones:
            raise ActionError('zone', 'zone_already_configured', zone)
        zones[zone] = {'credential': data['credential']}
        _save_zones(zones)
    return {}


def update_zone(data):
    zone = normalize_zone(data['zone'])
    with _ConfigLock():
        _load_credential(data['credential'])
        zones = _load_zones()
        if zone not in zones:
            raise ActionError('zone', 'zone_not_found', zone)
        zones[zone] = {'credential': data['credential']}
        _save_zones(zones)
    return {}


def remove_zone(data):
    zone = normalize_zone(data['zone'])
    with _ConfigLock():
        zones = _load_zones()
        if zone not in zones:
            raise ActionError('zone', 'zone_not_found', zone)
        del zones[zone]
        _save_zones(zones)
    return {}


def get_configuration(data):
    providers = _providers()
    creds = []
    if os.path.isdir(_cred_dir()):
        for fn in sorted(os.listdir(_cred_dir())):
            if not fn.endswith('.json'):
                continue
            cred = _read_json(os.path.join(_cred_dir(), fn), None)
            if cred is None:
                continue
            known = {f['name']: f for f in providers.get(cred['provider'], {}).get('fields', [])}
            secret = {n for n, f in known.items() if f['secret']}
            creds.append({
                'id': fn[:-len('.json')],
                'name': cred['name'],
                'provider': cred['provider'],
                'values': {k: v for k, v in cred['fields'].items() if k not in secret and k in known},
                'secrets_set': sorted(k for k, v in cred['fields'].items() if k in secret and v),
            })
    zones = [{'zone': z, 'credential': v['credential']} for z, v in sorted(_load_zones().items())]
    return {'credentials': creds, 'zones': zones}


def list_zones(data):
    zones = _load_zones()
    out = []
    for z, v in sorted(zones.items()):
        if _restricted() and not _rules_for(z):
            continue
        cred = _read_json(_cred_path(v['credential']), None)
        out.append({'zone': z, 'credential': v['credential'],
                    'provider': cred['provider'] if cred else None})
    return {'zones': out}


def has_zone(data):
    name = data['name'].strip().lower().rstrip('.')
    best = None
    for z in _load_zones():
        if (name == z or name.endswith('.' + z)) and (best is None or len(z) > len(best)):
            best = z
    allowed = best is not None and (not _restricted() or bool(_rules_for(best)))
    return {'managed': best is not None, 'zone': best, 'allowed': allowed}


def _zone_request(zone):
    zone = normalize_zone(zone)
    entry = _load_zones().get(zone)
    if entry is None:
        raise ActionError('zone', 'zone_not_found', zone)
    cred = _load_credential(entry['credential'])
    return {'provider': cred['provider'], 'zone': zone, 'credentials': cred['fields']}


def validate_zone(data):
    if 'provider' in data:
        zone = normalize_zone(data['zone'])
        fields, _ = _check_fields(data['provider'], data['fields'], creating=True)
        req = {'provider': data['provider'], 'zone': zone, 'credentials': fields}
    elif 'credential' in data:
        zone = normalize_zone(data['zone'])
        cred = _load_credential(data['credential'])
        req = {'provider': cred['provider'], 'zone': zone, 'credentials': cred['fields']}
    else:
        req = _zone_request(data['zone'])
    req.update(op='validate', write_test=bool(data.get('write_test')))
    resp = call_helper(req)
    return {'valid': True, 'validation': resp['validation'], 'capabilities': resp['capabilities']}


def list_provider_zones(data):
    """The zones a credential can see at the DNS host, for the "add zone" wizard.

    Not every provider package can list zones: then supported is false and the
    wizard asks for the name instead.
    """
    if 'provider' in data:
        fields, _ = _check_fields(data['provider'], data['fields'], creating=True)
        req = {'provider': data['provider'], 'credentials': fields}
    else:
        cred = _load_credential(data['credential'])
        req = {'provider': cred['provider'], 'credentials': cred['fields']}
    req['op'] = 'list-zones'
    try:
        zones = call_helper(req)['zones']
    except ActionError as e:
        if e.entry['error'] == 'unsupported':
            return {'supported': False, 'zones': []}
        raise
    return {'supported': True, 'zones': zones}


def suggest_zones(data):
    """Reduce host names (collected by the UI from the mail, web server and
    Traefik modules) to the registrable domains that would be candidate zones,
    and say which are already managed. Candidates only: a mail domain is not
    necessarily a DNS zone the administrator can manage."""
    resp = call_helper({'op': 'registrable-domains', 'names': data['names']})
    managed = _load_zones()
    out = []
    for c in resp.get('candidates', []):
        owner = next((z for z in managed if c['zone'] == z or c['zone'].endswith('.' + z)), None)
        out.append({'zone': c['zone'], 'names': c['names'], 'managed': owner is not None, 'managed_zone': owner})
    return {'candidates': out}


def get_records(data):
    zone = normalize_zone(data['zone'])
    rules = _rules_for(zone) if _restricted() else None
    if rules is not None and not rules:
        raise ActionError('zone', 'not_permitted', zone, 'this module may not read zone %s' % zone)
    req = _zone_request(zone)
    req['op'] = 'get-records'
    flt = {k: data[k] for k in ('name', 'type') if k in data}
    if flt:
        req['filter'] = flt
    records = call_helper(req)['records']
    if rules is not None:
        records = [r for r in records if _may(rules, r['name'], r['type'], write=False)]
    return {'records': records}


def _change(op):
    def handler(data):
        _require_access(normalize_zone(data['zone']), data['records'])
        req = _zone_request(data['zone'])
        req.update(op=op, records=data['records'], dry_run=bool(data.get('dry_run')))
        for k in ('mode', 'replace_prefixes'):
            if k in data:
                req[k] = data[k]
        resp = call_helper(req)
        return {'dry_run': bool(resp.get('dry_run')), 'changes': resp['changes'], 'records': resp['records']}
    return handler


append_records = _change('append-records')
set_records = _change('set-records')
delete_records = _change('delete-records')

HANDLERS = {
    'list-providers': list_providers,
    'add-credential': add_credential,
    'update-credential': update_credential,
    'remove-credential': remove_credential,
    'add-zone': add_zone,
    'update-zone': update_zone,
    'remove-zone': remove_zone,
    'get-configuration': get_configuration,
    'list-zones': list_zones,
    'get-policy': get_policy,
    'set-policy': set_policy,
    'has-zone': has_zone,
    'validate-zone': validate_zone,
    'list-provider-zones': list_provider_zones,
    'suggest-zones': suggest_zones,
    'get-records': get_records,
    'append-records': append_records,
    'set-records': set_records,
    'delete-records': delete_records,
}


# ---------------------------------------------------------------- backup and restore

class StateError(Exception):
    """The module state is unusable (for instance corrupt after a restore)."""


def ensure_state():
    """Create the state layout listed in etc/state-include.conf if it is missing.

    Every listed path always exists, whatever the restic version does with a
    missing one, and a module that has not been configured yet still has a
    complete (empty) state to back up.
    """
    with _ConfigLock():
        os.makedirs(_cred_dir(), mode=0o700, exist_ok=True)
        os.chmod(_cred_dir(), 0o700)
        if not os.path.exists(_zones_path()):
            _save_zones({})
        if not os.path.exists(_policy_path()):
            _write_private(_policy_path(), {'rules': []})


def _parse(path, kind):
    try:
        with open(path) as f:
            obj = json.load(f)
    except (OSError, ValueError):
        raise StateError('%s is missing or is not valid JSON' % os.path.basename(path))
    if not isinstance(obj, dict) or not isinstance(obj.get(kind), (dict, list)):
        raise StateError('%s has an unexpected structure' % os.path.basename(path))
    return obj


def check_restored_state(module_exists=None):
    """Validate and repair the state after a restore.

    Returns (summary, warnings). Raises StateError when a file cannot be used
    at all: better to fail the restore loudly than to run with half a
    configuration. Semantic oddities (a zone whose credential is missing, a
    policy rule for a module that does not exist here) are warnings, because the
    administrator can fix them and must not lose the rest.

    module_exists: optional callable(module_id) -> bool, to check policy callers.
    """
    ensure_state()
    warnings = []

    zones = _parse(_zones_path(), 'zones')['zones']
    if not isinstance(zones, dict) or not all(isinstance(v, dict) and isinstance(v.get('credential'), str)
                                              for v in zones.values()):
        raise StateError('zones.json has an unexpected structure')
    rules = _parse(_policy_path(), 'rules')['rules']
    if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
        raise StateError('policy.json has an unexpected structure')

    creds = {}
    for fn in sorted(os.listdir(_cred_dir())):
        path = os.path.join(_cred_dir(), fn)
        if fn.endswith('.tmp'):
            os.unlink(path)          # left by an interrupted write
            continue
        if not fn.endswith('.json') or not ID_RE.match(fn[:-len('.json')]):
            warnings.append('ignoring unexpected file credentials/%s' % fn)
            continue
        try:
            with open(path) as f:
                cred = json.load(f)
        except (OSError, ValueError):
            raise StateError('credentials/%s is not valid JSON' % fn)
        if not (isinstance(cred, dict) and isinstance(cred.get('name'), str) and isinstance(cred.get('provider'), str)
                and isinstance(cred.get('fields'), dict)):
            raise StateError('credentials/%s has an unexpected structure' % fn)
        creds[fn[:-len('.json')]] = cred
        os.chmod(path, 0o600)
    os.chmod(_cred_dir(), 0o700)
    for path in (_zones_path(), _policy_path()):
        os.chmod(path, 0o600)

    try:
        known = set(_providers())
    except (HelperFailure, ActionError):
        known = None
    if known is not None:
        for cid, cred in sorted(creds.items()):
            if cred['provider'] not in known:
                warnings.append('credential %s uses provider %s, which this version does not support'
                                % (cid, cred['provider']))
    for z, v in sorted(zones.items()):
        if v['credential'] not in creds:
            warnings.append('zone %s refers to missing credential %s' % (z, v['credential']))
    try:
        _normalize_rules(rules)
    except ActionError as e:
        warnings.append('policy has an invalid rule (%s): fix it with set-policy' % e.entry['error'])
    if module_exists is not None:
        for who in sorted({r.get('caller', '') for r in rules if isinstance(r.get('caller'), str)}):
            if who.startswith('module/') and not re.search(r'[*?]', who) and module_exists(who[len('module/'):]) is False:
                warnings.append('policy refers to %s, which does not exist in this cluster' % who)

    summary = {'zones': len(zones), 'credentials': len(creds), 'rules': len(rules)}
    return summary, warnings


# ---------------------------------------------------------------- audit, events

# Actions that change something. Every call by another module is logged too.
MUTATING = {'add-credential', 'update-credential', 'remove-credential', 'add-zone', 'update-zone',
            'remove-zone', 'set-policy', 'append-records', 'set-records', 'delete-records'}
ZONE_ACTIONS = {'add-zone', 'update-zone', 'remove-zone'}
EVENT = 'service-dnshelper-changed'


def _brief(rec):
    return '%s %s %s' % (rec['name'], rec['type'], rec['data'][:80])


def audit_line(action, data, result, outcome, error=None):
    """One journal line: who did what to which zone, and what changed.

    Built only from a whitelist of fields: never a credential field, and no
    provider message.
    """
    f = [('caller', caller() or '-'), ('action', action), ('result', outcome)]
    if error:
        f.append(('error', error))
    for key in ('zone', 'id', 'credential', 'provider', 'name'):
        if isinstance(data.get(key), str):
            f.append((key, data[key]))
    if 'dry_run' in data:
        f.append(('dry_run', bool(data['dry_run'])))
    if action == 'set-policy':
        f.append(('rules', len(data.get('rules', []))))
    if result and 'changes' in result:
        f.append(('add', [_brief(r) for r in result['changes']['add']]))
        f.append(('remove', [_brief(r) for r in result['changes']['remove']]))
    elif action in ('append-records', 'set-records', 'delete-records'):
        f.append(('requested', [_brief({'name': r['name'], 'type': r.get('type', '*'), 'data': r.get('data', '')})
                                for r in data.get('records', [])]))
    return 'dnshelper audit: ' + ' '.join(
        '%s=%s' % (k, v if isinstance(v, (int, bool)) else json.dumps(v)) for k, v in f)


def _audit(agent, action, data, result, outcome, error=None):
    if action in MUTATING or caller().startswith('module/'):
        print(agent.SD_INFO + audit_line(action, data, result, outcome, error), file=sys.stderr)


def _publish_change(agent):
    """Tell listeners the set of managed zones changed. Best effort."""
    module_id = os.environ['MODULE_ID']
    payload = {'key': 'module/%s/srv/api/dnshelper' % module_id, 'module_id': module_id,
               'module_uuid': os.environ.get('MODULE_UUID', '')}
    try:
        agent.redis_connect(privileged=True).publish(
            '%s/event/%s' % (os.environ['AGENT_ID'], EVENT), json.dumps(payload))
    except Exception:
        print(agent.SD_WARNING + 'dnshelper: cannot publish %s' % EVENT, file=sys.stderr)


def run(action):
    """Entry point of an action step: JSON on stdin, JSON on stdout."""
    import agent  # only present on a node

    data = json.load(sys.stdin)
    try:
        result = HANDLERS[action](data)
    except ActionError as e:
        _audit(agent, action, data, None, 'rejected', e.entry['error'])
        agent.set_status('validation-failed')
        json.dump([e.entry], fp=sys.stdout)
        sys.exit(2)
    except HelperFailure as e:
        _audit(agent, action, data, None, 'failed')
        print(agent.SD_ERR + str(e), file=sys.stderr)
        sys.exit(1)
    _audit(agent, action, data, result, 'ok')
    if action in ZONE_ACTIONS:
        _publish_change(agent)
    json.dump(result, fp=sys.stdout)
