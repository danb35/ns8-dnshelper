# ns8-dnshelper

Helper module for [NethServer 8](https://nethserver.github.io/ns8-core/) that lets other
modules create, edit and remove DNS records through DNS hosts' APIs, using
[libdns](https://github.com/libdns/libdns). See [DESIGN.md](DESIGN.md) for the full design
and the build order.

## Status

The latest release is [0.2.0](https://github.com/danb35/ns8-dnshelper/releases/tag/0.2.0) (the first
was [0.1.0](https://github.com/danb35/ns8-dnshelper/releases/tag/0.1.0)); see the
[releases](https://github.com/danb35/ns8-dnshelper/releases) for what changed. Every step of the
build order in [DESIGN.md](DESIGN.md) is implemented: the module, its Go helper, actions,
credential store, roles, policy, audit log, backup and restore, and the admin UI.

What has been checked, and where:

- A real consumer module was tested against dnshelper on a real NS8 3.22.0 node with a real DNS
  server (see [tests/integration](tests/integration/README.md); it needs a node and is not part of
  CI).
- The admin UI has been used in the real NS8 admin shell.
- The providers were tested live against real zones (see [Providers](#providers)).
- CI builds and publishes the image with `build-images.sh`, runs the Go tests, and runs the
  module's Robot Framework tests on Rocky Linux 9 and Debian 13.

Known gaps: the French, German, Italian, Spanish and Portuguese translations were written without
a native-speaker review, and the Basque (`eu`) locale still carries the template's placeholder text.

## Install

Instantiate the module with:

    add-module ghcr.io/danb35/dnshelper:latest 1

The output of the command will return the instance name.
Output example:

    {"module_id": "dnshelper1", "image_name": "dnshelper", "image_url": "ghcr.io/danb35/dnshelper:latest"}

To install a particular release instead of the newest build, use its tag in place of `latest`, for
example `ghcr.io/danb35/dnshelper:0.1.1`.

Then open the module's page in the NS8 admin UI to add credentials and zones.

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

### The consumer actions in detail

A record is `{"name", "type", "ttl", "data"}`. `name` is relative to the zone (`@` for the apex);
`ttl` is optional (0 or omitted means "unspecified": kept when merging, and the provider's default
otherwise; providers with a minimum raise a shorter TTL). `data` is the value in libdns text form:
TXT is one plain, unquoted string of any length, MX is `"priority target"` and SRV is
`"priority weight port target"`. The exact schemas are `imageroot/actions/<action>/validate-*.json`.

| Action | Input | Output |
|---|---|---|
| `has-zone` | `name`: a zone or a host name | `{"managed", "zone", "allowed"}`; `zone` is the longest managed zone containing the name, `allowed` is whether the caller has any rule for it |
| `list-zones` | none | `{"zones": [{"zone", "credential", "provider"}]}`, only the zones the caller has a rule for |
| `get-records` | `zone`; optional `name`, `type` filters | `{"records": [...]}`, only records the caller's rules cover |
| `append-records` | `zone`, `records`, optional `dry_run` | `{"dry_run", "changes": {"add", "remove"}, "records"}`; adds records, never removes; adding one that already exists is not an error |
| `set-records` | `zone`, `records`, optional `dry_run`, `mode`, `replace_prefixes` | as above; see below |
| `delete-records` | `zone`, `records` (only `name` required), optional `dry_run` | as above; removes the records that match |

- `set-records` defaults to `"mode": "merge"`: it keeps the other members of an RRset, so setting an
  SPF record does not delete site-verification TXT records. `replace_prefixes` (for example
  `["v=spf1"]`) names existing values to replace. `"mode": "rrset"` makes the input the only
  members of each `(name, type)` set. Use merge to rotate a DKIM key: the old value is replaced,
  the rest kept.
- `delete-records` matches exactly on name, type, value and TTL, where a `type`, `ttl` or `data` you
  leave out matches anything. Leaving the type out therefore needs an access rule with type `*`.
  A provider that raised a TTL on write stores a different one, so leave the TTL out.
- `dry_run` returns `changes` and writes nothing, for a preview or a permission check.
- A change is refused as a whole, before any provider call, if the access rules do not cover every
  record. dnshelper also refuses results that would be invalid (a CNAME at the apex or beside other
  records, an SRV or MX target that is a CNAME) and never changes apex NS or SOA records.
- Errors a caller can act on come back as NS8 validation failures whose `error` is one of
  `not_permitted`, `zone_not_found`, `conflict`, `forbidden`, `auth_failed`, `unsupported`,
  `invalid_request` or `unknown_provider`. Timeouts and provider outages fail the step instead.
- Speed: every call reads the zone first. Most providers answer in a second or two, Hetzner takes 8
  to 15 seconds per API call, and the helper gives up after 120 seconds. Do not call in a tight loop.
- Which record types work, and which values a provider refuses (for example `"` and `\` in TXT on
  some), depends on the DNS host: see [Providers](#providers).
- A working consumer is `tests/integration/consumer/`: its `call-dnshelper` action finds dnshelper
  the way step 2 does and reports what came back. `tests/integration/test_node.py` shows the calls
  and their results on a real node.

### What a module may touch: the policy table

Roles are module-wide, so they only decide which actions a module can call. Which zones, record
names and types it may change is the policy table (`get-policy`, `set-policy`, stored in
`state/policy.json`). It is **default deny** for modules: until an administrator adds a rule, a
module with the role can call the actions but is refused everything.

```json
{"rules": [
  {"caller": "module/mail1", "zones": ["example.com", "example.org"], "access": "write",
   "names": ["@", "*._domainkey"], "types": ["TXT", "MX"]},
  {"caller": "module/traefik*", "zones": ["*"], "access": "write",
   "names": ["_acme-challenge", "_acme-challenge.*"], "types": ["TXT"]}
]}
```

- `caller` is `module/<id>`, with `*` and `?` wildcards. `zones` is a list of managed zones, or `["*"]` for all of them. Rules saved with a single `zone` (the earlier format, still accepted by `set-policy`) are read as a list of one, and `get-policy` always returns `zones`.
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

A provider that limits logins (Core-Networks) makes the helper keep the short-lived session token it
receives in `state/cache` (directory 0700, files 0600), so that each call does not log in again. The
token is derived from the credential, is not part of the backup, and expires within the hour.

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

## Providers

Supported providers today: Cloudflare, Core-Networks (core-networks.de, new in 0.2.0), GoDaddy, Hetzner (Cloud DNS API), name.com and
RFC 2136. All have been tested live: Cloudflare, Core-Networks, GoDaddy, Hetzner and name.com against
real zones, RFC 2136 against a local BIND (see [helper/testdata/bind](helper/testdata/bind/README.md)).

| Provider | Credentials | Record types | Zones listed in the wizard |
|---|---|---|---|
| Cloudflare | API token with Zone:DNS:Edit, and a Zone:Read token if the first is scoped to one zone | A, AAAA, CAA, CNAME, MX, NS, SRV, TXT | Yes |
| Core-Networks ([core-networks.de](https://www.core-networks.de/)) | Login and password of an API account (made under API user accounts in the Core-Networks web interface; not the login of the web interface) | A, AAAA, CAA, CNAME, MX, NS, SRV, TXT | Yes (master zones) |
| GoDaddy | Personal access token (PAT) from developer.godaddy.com with the domain and DNS scopes. The older **classic** API key and secret still work but GoDaddy is deprecating them; give one or the other | A, AAAA, CNAME, MX, NS, SRV, TXT | Yes; type the zone if the credential may not list domains |
| Hetzner | Hetzner Cloud API token with read and write | A, AAAA, CNAME, MX, NS, SRV, TXT | Yes |
| name.com | User name and API token, made under Account Settings > API Tokens | A, AAAA, CNAME, MX, NS, SRV, TXT | Yes |
| RFC 2136 | Server address, TSIG key name, algorithm and key | A, AAAA, CAA, CNAME, HTTPS, MX, NS, SRV, SVCB, TXT | No: type the zone |

The record types are those the provider package is tested or documented to handle; the wizard
shows what dnshelper can do for a zone once its credentials are checked. Prefer tokens limited to
the zones you need.

What to know about each provider:

- **Cloudflare**: HTTPS and SVCB records are not supported. TXT values containing `"` or `\` are
  refused.
- **Core-Networks**: TTLs under 60 seconds are raised to 60, and a record without a TTL gets 1800.
  The service limits how often one can log in, so dnshelper keeps the session token (valid for an
  hour) between calls; see [Credentials](#credentials). Every change is committed to the name
  servers at once. TXT values, including ones with `"` or `\`, are stored as written.
- **GoDaddy**: TTLs under 600 seconds are raised to 600. The API allows about 60 requests a minute
  and dnshelper waits and retries when it is exceeded. A credential that is not allowed to list
  domains needs the zone name typed in.
- **Hetzner**: uses the Cloud DNS API (zones in the Hetzner Console), not the retired DNS Console
  API. Each API action takes 8 to 15 seconds. A TXT value beginning or ending with `"` is refused.
- **name.com**: TTLs under 300 seconds are raised to 300. TXT values containing `"` or `\` are
  refused.
- **RFC 2136**: reading a zone needs zone transfer (AXFR) to be allowed for the TSIG key. TXT values
  containing `"` or `\` are refused.

A provider that raises a TTL stores a different one from the one asked for, so an exact delete that
states the old TTL will not match: leave the TTL out, or use the value as read back.

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

`build-images.sh` builds a static (`CGO_ENABLED=0`) binary into `imageroot/bin/dnshelper`, running
the Go tests first, and the CI publish workflow uses it. The integration test assembles the same
image layout with podman (`tests/integration/build-on-node.sh`), which lets it run on a node that
has no buildah.

The providers, their credentials and their limits are described under [Providers](#providers). The
live tests are in `helper/internal/app/live_test.go`, skipped unless a provider's variables are set
(never put tokens or keys in a file). They found these provider-package quirks, handled in
`registry/providers.go`, `registry/hetzner.go`, `registry/godaddy.go`, `registry/namedotcom.go`,
`dnsops` and the registry's `TXTForbidden`:

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
- The libdns GoDaddy package cannot be used for writing: its append PUTs a single record and so
  replaces the whole `(type, name)` set, its delete removes the whole set whatever the value, and
  it drops MX priorities and cannot write SRV records. `registry/godaddy.go` talks to the GoDaddy
  API itself, reading the zone and rewriting the affected sets. It sends a personal access token
  as a Bearer token (or, for the legacy credential, `sso-key key:secret`) to the v1 endpoints,
  which accept both, and lists the account's active domains (`GET /v1/domains`), so the wizard can
  offer them; a credential refused the list falls back to typing the zone name. GoDaddy accepts no
  TTL under 600 seconds (shorter or unset TTLs are raised) and allows about 60 requests a minute (a
  429 answer is retried). GoDaddy also serves an apex A record whose value is a placeholder text,
  not an address; it is passed through as is.
- name.com accepts no TTL under 300 seconds, so an adapter raises shorter or unset ones. It reads a
  TXT value as zone-file text: `"` and `\` do not round-trip and are refused.
- Core-Networks has no libdns package; `registry/corenetworks.go` talks to the API. It differs from
  the others in these ways, all verified against a live zone: a login gives a one hour token and
  logins are rate limited (429), so the token is cached in `-cache-dir`; changes are held in a
  database until an explicit `commit`, which follows every change; a delete removes everything the
  posted partial record matches and an empty one wipes the zone, so only complete records read from
  the zone are ever sent; there is no update (a set is delete and add); TTLs below 60 are refused
  and none means 1800; a TXT value is read as zone-file text, so plain text (even 600 characters, the
  service splits it) is sent as it is but a value with `"` or `\` is sent as quoted, escaped strings
  (sent raw it is split at every space and loses backslashes), and values entered with quotes are
  decoded when read; the same record with another TTL becomes a second record.
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
  presets for a mail server, for ACME DNS-01 and for a web server or service (CNAME records with
  any name, for modules such as the web server, SOGo or Grafana that publish a name for their own
  FQDN), and the authorization label a consumer module
  needs.

```bash
cd ui && yarn install && NODE_OPTIONS=--openssl-legacy-provider yarn build
```

The UI only runs inside the NS8 admin shell. To look at it without a node, `ui/dev` is a harness:
a fake shell around the built UI, backed by the real Python actions and a fake DNS host (see
[ui/dev/README.md](ui/dev/README.md)). English is the source language in
`ui/public/i18n/en/translation.json`; the other languages were translated from it and have not
been reviewed by native speakers.

## Acknowledgements

Thanks to Marko for providing a test domain and credentials, which made it possible to build and
test the Core-Networks provider against the live service.

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
./test-module.sh <NODE_ADDR> ghcr.io/danb35/dnshelper:latest
```
