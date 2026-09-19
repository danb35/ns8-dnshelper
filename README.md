# ns8-dnshelper

Helper module for [NethServer 8](https://nethserver.github.io/ns8-core/) that lets other
modules create, edit and remove DNS records through DNS hosts' APIs, using
[libdns](https://github.com/libdns/libdns). See [DESIGN.md](DESIGN.md) for the full design
and the build order.

## Status

Build order steps 1-7 are done. The module, its Go helper, actions, credential store, roles,
policy, audit log, backup and restore, and the admin UI exist, and a real consumer module has
been tested against them on a real NS8 3.22.0 node with a real DNS server (see
[tests/integration](tests/integration/README.md)). What has **not** been done: rendering the UI in
the real NS8 admin shell (the UI files are verified to be delivered and served, and every screen
was exercised in a local harness, `ui/dev`), and running `build-images.sh` itself (the test builds
the same image layout with podman).

## Actions

Each action has `validate-input.json` and `validate-output.json` under `imageroot/actions/<action>/`.

| Group | Actions |
|---|---|
| Admin | `list-providers`, `list-provider-zones`, `suggest-zones`, `add-credential`, `update-credential`, `remove-credential`, `add-zone`, `update-zone`, `remove-zone`, `validate-zone`, `get-policy`, `set-policy` |
| Consumer | `list-zones`, `has-zone`, `get-records`, `append-records`, `set-records`, `delete-records` |
| UI convention | `configure-module` (no settings yet), `get-configuration` |

`has-zone` takes a zone or a host name (`mail.example.com`) and returns the longest managed
zone containing it. `validate-zone` checks a saved zone, a zone with a saved credential, or a
zone with inline provider fields, so a wizard can validate before saving anything.
`validate-zone` is read-only unless `write_test` is set.

## Using dnshelper from another module

**1. Get the role.** In the consumer's `build-images.sh`:

```bash
--label="org.nethserver.authorizations=dnshelper@cluster:dnswriter"
```

`dnsreader` allows `get-records`, `list-zones` and `has-zone`; `dnswriter` adds `append-records`,
`set-records` and `delete-records`. `@cluster` means the default dnshelper instance of the
cluster (`@node` and `@any` work too). The grant also reaches consumers installed *before*
dnshelper: ns8-core stores each module's authorizations and re-applies them after every
`add-module` (`cluster.grants.refresh_permissions`).

**2. Check that dnshelper is there and covers the name.** The role is granted on the cluster's
*default* dnshelper instance (the first one installed, `cluster/default_instance/dnshelper`), so
that is the one to call if a cluster ever has more than one.

```python
rdb = agent.redis_connect(use_replica=True)
if not agent.list_service_providers(rdb, 'dnshelper'):   # module absent
    ...
r = agent.tasks.run(agent_id='module/dnshelper1', action='has-zone', data={'name': 'mail.example.com'})
r['output']   # {"managed": true, "zone": "example.com", "allowed": true}
```

**3. Change records.** `data=` verified against ns8-core `agent/tasks/run.py`.

```python
r = agent.tasks.run(agent_id='module/dnshelper1', action='append-records', data={
    'zone': 'example.com',
    'records': [{'name': 'mail._domainkey', 'type': 'TXT', 'data': 'v=DKIM1; k=rsa; p=...'}]})
agent.assert_exp(r['exit_code'] == 0)
```

User-fixable problems (conflict, forbidden, `not_permitted`, bad credentials, unknown zone) are
reported as NS8 `validation-failed` with an `error` code and a `message`; provider outages and
timeouts fail the step with a journal message.

### What a module may touch: the policy table

Roles are module-wide, so they only decide which actions a module can call. Which zones, record
names and types it may change is the policy table (`get-policy`, `set-policy`, stored in
`state/policy.json`). It is **default deny** for modules: until an administrator adds a rule, a
module with the role can call the actions but is refused everything.

```json
{"rules": [
  {"caller": "module/mail1", "zone": "example.com", "access": "write",
   "names": ["@", "*._domainkey"], "types": ["TXT", "MX"]},
  {"caller": "module/traefik*", "zone": "*", "access": "write",
   "names": ["_acme-challenge", "_acme-challenge.*"], "types": ["TXT"]}
]}
```

- `caller` is `module/<id>`, with `*` and `?` wildcards. `zone` is a managed zone or `*`.
- `access` is `read` or `write` (write implies read). Names are relative to the zone and matched
  with glob patterns; `names` and `types` default to `*`.
- A request with any record the rules do not cover is refused as a whole, before the provider is
  contacted. A delete without a `type` needs a rule with type `*`.
- `get-records` returns only the records a rule covers; `list-zones` only zones with a rule;
  `has-zone` says `allowed`.
- Administrators (any caller that is not `module/...`, seen as `AGENT_TASK_USER`) are not
  restricted by the policy.

### Audit log and events

Every change, and every call by another module, writes one line to the module's journal, for
example `dnshelper audit: caller="module/mail1" action="append-records" result="ok"
zone="example.com" add=["mail._domainkey TXT v=DKIM1..."] remove=[]`. Refusals are logged with
`result="rejected"` and the error code. Credentials and provider messages never appear.

Adding, changing or removing a zone publishes `service-dnshelper-changed` on
`module/<id>/event/`, with `{"key", "module_id", "module_uuid"}` as payload. The service key is
`module/<id>/srv/api/dnshelper`.

## Credentials

Credentials are separate objects; a zone references one. They are never stored in
`state/environment` or Redis. They live in `state/credentials/<id>.json` (directory 0700, files
0600, written atomically) and reach the helper on stdin only. `get-configuration` reports only
which secret fields are set; on update an empty secret field means "keep". Use zone-scoped,
least-privilege tokens.

## Backup and restore

**What is backed up** (`imageroot/etc/state-include.conf`): `state/zones.json`,
`state/policy.json` and `state/credentials/`. Lock files are not. The core adds
`state/environment` itself; dnshelper keeps nothing in it.

**Decision: credentials are included.** Without them a restored module cannot manage any zone,
and the operator would have to re-enter every token. The cost is that provider tokens sit in the
backup. They are protected by the backup destination's encryption (NS8 backups are Restic
repositories encrypted with the destination's key), which is the same protection the rest of the
module state gets; encrypting them again with a key stored next to them would add nothing. The
mitigation is the token itself: create zone-scoped, least-privilege tokens, and rotate them if a
backup destination is ever exposed.

**Backup.** `module-backup` runs `bin/module-dump-state` first. There is nothing to dump (all
state is in atomically written plain files), so it only makes sure every listed path exists: a
module that has not been configured yet still backs up cleanly, whatever the Restic version does
with a missing path. `create-module/10init_state` creates the same empty state at install.

**Restore.** The core `10restore` step puts the files back into the state directory (Restic
keeps their modes) and `restore-module/50check_state` then:

- fails the restore if `zones.json`, `policy.json` or a credential file is missing, is not valid
  JSON, or has the wrong structure (the message names the file, never its contents);
- enforces the modes again (files 0600, `credentials/` 0700) and removes leftover `.tmp` files;
- warns (journal, `<4>` level) about a zone whose credential is missing, a provider this version
  no longer supports, an invalid policy rule, and policy rules for a `module/<id>` that does not
  exist in this cluster;
- logs a one-line summary and publishes `service-dnshelper-changed`.

Restoring under a different module id works: `create-module` runs first for the new instance and
creates its roles and service key. Policy callers such as `module/mail1` are matched by id, so
after restoring into a cluster where the consumer has another id, fix the policy with
`set-policy`; the restore warns about exactly this.

## The `dnshelper` binary

One JSON request on stdin, one JSON response on stdout, exit status 0 only when `"ok": true`.
Credentials are accepted on stdin only. The contract is in
[helper/internal/contract/contract.go](helper/internal/contract/contract.go).

```bash
echo '{"op":"list-providers"}' | helper/dnshelper
```

Operations: `list-providers`, `capabilities`, `validate`, `list-zones`, `get-records`,
`append-records`, `set-records`, `delete-records`, and `registrable-domains` (reduces host names to
the registrable domains containing them, with the public suffix list; needs no provider). Records are `{"name","type","ttl","data"}` with names relative
to the zone (`@` for the apex) and TXT data as one plain, unquoted string of any length.

Behaviour worth knowing:

- Every change reads the zone first and refuses results that would be invalid: a CNAME at the
  apex or next to other data, several CNAMEs at one name, an SRV/MX target that is a CNAME.
- Apex NS and any SOA record are never changed. Deleting everything at the apex is refused.
- `dry_run` returns the `changes` that would be made and writes nothing.
- `set-records` defaults to `"mode": "merge"`: existing members of an RRset are kept, so setting
  an SPF record does not delete site-verification TXT records. `replace_prefixes`
  (e.g. `["v=spf1"]`) names the existing values to replace. `"mode": "rrset"` is the raw libdns
  behaviour where the input becomes the only members of the RRset.
- Deletes are exact (name, type, value, and TTL if given). They are resolved against the zone and
  the provider is handed its own records back, so provider record IDs are preserved.
- `set-records` is applied as a delete followed by an append (with the removed records put back
  if the append fails), not as libdns `SetRecords`, whose behaviour differs between provider
  packages. Every delete is verified by re-reading the zone, so a provider that reports success
  but deletes nothing is caught.
- Changes to one zone are serialized with `flock` under `-lock-dir`.
- Errors are `{"code","message"}`. Provider error text has the supplied credentials scrubbed.

Build and test (Go 1.27, Python 3):

```bash
cd helper && go test ./... && go build -o dnshelper ./cmd/dnshelper && cd ..
DNSHELPER_REAL_BIN=$PWD/helper/dnshelper python3 -m unittest discover -s tests/unit
```

`build-images.sh` is written to build a static (`CGO_ENABLED=0`) binary into
`imageroot/bin/dnshelper` and run the Go tests first. It has not been run yet: it needs buildah,
which the test node lacks. The integration test assembles the same image layout with podman
(`tests/integration/build-on-node.sh`).

Supported providers today: Cloudflare, Hetzner (Cloud DNS API), RFC 2136. All three have been
tested live: Cloudflare and Hetzner against real zones, RFC 2136 against a local BIND (see
[helper/testdata/bind](helper/testdata/bind/README.md)). The live tests are in
`helper/internal/app/live_test.go`, skipped unless a provider's variables are set (never put
tokens or keys in a file). They found these provider-package quirks, handled in
`registry/providers.go`, `registry/hetzner.go`, `dnsops` and the registry's `TXTForbidden`:

- Cloudflare returns long TXT values with `" "` between strings and only deletes them when the
  outer quotes are present (a small adapter fixes the delete).
- Cloudflare's `SetRecords` fails on multi-member RRsets, hence set-records is delete + append.
- Cloudflare and RFC 2136 do not round-trip TXT values containing `"` or `\`, so those are refused.
- The libdns Hetzner package v1 talks to the retired DNS Console API (`dns.hetzner.com` now
  redirects and answers with HTML); v2 uses the Cloud DNS API and needs a Hetzner Cloud API
  token. v2 neither chunks nor escapes TXT values, which the API demands, so an adapter encodes
  them on write and decodes them on read. A TXT value beginning or ending with `"` is refused.
- Hetzner API actions take 8-15 seconds each; the helper's overall timeout is 120 s. Its RRsets
  share one TTL, so appending a record with a different explicit TTL to an existing RRset can be
  rejected by the provider.
- An RFC 2136 zone transfer lists the SOA twice; repeats are dropped.
- RFC 2136 reading needs AXFR allowed for the TSIG key; a zone the server does not serve is
  reported as `auth_failed`.

## Admin UI

Vue 2 with Carbon and `ns8-ui-lib`, in `ui/`. Three pages besides About:

- **Status**: number of managed zones and access rules with shortcuts, instance and node, backup,
  and a card that opens the system logs filtered on `dnshelper audit`.
- **Zones**: managed zones (check credentials, change a zone's credential, remove) and the
  credentials they use (edit, delete; a credential still used by a zone cannot be deleted).
  *Add zone* is a wizard: pick a DNS host, enter its credential (or reuse a saved one), choose the
  zone from the ones that credential can manage or type it, and review what dnshelper can do
  there, with an optional write test, before anything is saved. *Find zones used by my modules*
  suggests zones from the mail, web server and Traefik modules' host names; these are candidates
  only. Secrets are never shown again after saving: an empty secret field means "keep".
- **Access**: the policy table (which module may change which record names and types), with
  presets for a mail server and for ACME DNS-01, and the authorization label a consumer module
  needs.

```bash
cd ui && yarn install && NODE_OPTIONS=--openssl-legacy-provider yarn build
```

The UI only runs inside the NS8 admin shell. To look at it without a node, `ui/dev` is a harness:
a fake shell around the built UI, backed by the real Python actions and a fake DNS host (see
[ui/dev/README.md](ui/dev/README.md)). Everything has been exercised there, and the node serves
the extracted files, but it has not been rendered in a real shell. Only `en/translation.json` is
edited by hand; the other languages are managed by Weblate.

## Development

Agent guidance for this repository is in [AGENTS.md](AGENTS.md); the NethServer module skill it
relies on is vendored in [.claude/skills/](.claude/skills/).

## Testing on a node

`tests/integration/` is a re-runnable test on a real node: it installs dnshelper and a minimal
consumer module, uses a real DNS server, and covers role grants, default deny, policy scoping,
audit lines, a real backup and restore, and removal. See
[tests/integration/README.md](tests/integration/README.md).

The Robot suite in `tests/` is the smoke test that CI runs (`test-module.sh`):

```bash
./test-module.sh <NODE_ADDR> ghcr.io/nethserver/dnshelper:latest
```
