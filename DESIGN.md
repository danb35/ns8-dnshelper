# ns8-dnshelper: design brief

Helper module for NethServer 8 (NS8) that lets other modules create, edit and remove DNS
records through DNS hosts' APIs. Built on Go `libdns` (github.com/libdns/libdns, v1.x).
Status: build order steps 1-7 done (scaffold, Go helper, actions + credential store, roles/policy/audit, backup/restore, UI, node integration test); adoption of ns8-powerdns zones implemented, not yet tested against a live primary; see README. Items marked **VERIFY** were not confirmed from docs.

## Requirements (from the owner)

1. Extend the NS8 API (module actions) so other modules can: check the module is present,
   check whether it manages a zone, and set / append / edit / delete records.
2. Admin web UI: add zones; per zone choose a DNS provider and credentials; validate the
   credentials against provider and zone.
   - Bonus: read zones already configured in the web server / mail modules.
3. Store credentials securely.
4. Must handle at least CNAME and arbitrary TXT (SPF, DKIM); SRV desirable.
5. Suggest further appropriate goals (see below).

## Architecture

- Rootless NS8 module. Repo is a copy of the ns8-kickstart template (rename kickstart -> dnshelper;
  module names must not end in a digit). Decide whether a long-running service is needed at all;
  probably not, since everything is on-demand actions.
- The API is the module agent's actions. Consumers call
  `agent.tasks.run(agent_id='module/dnshelper1', action=..., data=...)` from their own action
  steps (module agents cannot LPUSH tasks directly; this goes through the api-server with the
  module's Redis credentials). Verified 2026-09-19 in ns8-core `agent/tasks/run.py`: `run(agent_id, action, data={}, **kwargs)`.
- DNS work is done by a static Go binary `dnshelper` (CGO_ENABLED=0) shipped under `imageroot/`,
  invoked by action steps. Input JSON on stdin (zone, provider, credentials, records), output JSON
  on stdout. Credentials never appear in argv or environment. Python steps do validation and NS8
  plumbing. Alternative: run the binary in a container (isolation) instead of on the host.
- Provider adapters: a curated registry (name -> constructor + credential field schema).
  Do not reflect over libdns provider structs; field names vary. Type-assert the optional
  interfaces (RecordGetter/Appender/Setter/Deleter, ZoneLister) and report capabilities.

## Actions

| Group | Actions |
|---|---|
| UI convention | `configure-module`, `get-configuration` |
| Admin | `add-zone`, `update-zone`, `remove-zone`, `validate-zone`, `list-providers`, `sync-powerdns` |
| Consumer API | `list-zones`, `has-zone`, `get-records`, `append-records`, `set-records`, `delete-records` |

Each action: `validate-input.json` and `validate-output.json` (NS8 validation framework).
Record types in the API map to libdns v1 types: CNAME, TXT, SRV, Address (A/AAAA), MX, NS, CAA,
ServiceBinding, plus generic RR.

Presence check: register a service-provider entry (Redis `module/<id>/srv/...` hash) so consumers
can use `agent.list_service_providers()` / the base `list-service-providers` action; raise a
change event when zones change (follow the documented event naming convention).

## libdns semantics to respect

- `SetRecords` makes the input the ONLY members of each (name, type) RRset. Setting an SPF TXT at
  the apex would delete other apex TXT records (site verification etc.). Prefer read-merge-set,
  or `AppendRecords`. Offer a dry-run / preview.
- `DeleteRecords` only removes exact matches (name, type, TTL, value) unless type/TTL/value are
  left empty.
- CNAME: adding one where other records exist may fail, leave the zone invalid, or delete the
  others. Read first and refuse conflicts.
- SRV target must not point at a CNAME.
- TXT: whole value as one unquoted, unescaped string; provider package handles quoting and
  255-byte chunking. Test long DKIM keys per provider.
- Names are relative to the zone ("@" for apex). Use `libdns.RelativeName` / `AbsoluteName`.
- libdns assumes only this code manipulates the zone and gives no locking: serialize per zone
  (flock).
- Providers are community-maintained; each may lack record types. Show a capability matrix.
- Many provider packages are separate Go modules; some may still target the old (v0.x) API.
  Checked 2026-09-19: cloudflare v0.2.2, hetzner v1.0.0, rfc2136 v1.0.1, route53 v1.6.2 and gandi v1.1.0
  all require libdns v1.x (a provider's own 0.x version number does not mean the old API).
  Cloudflare does not handle HTTPS/SVCB records. Later live testing found that libdns/hetzner v1
  targets a retired API; use `github.com/libdns/hetzner/v2` (Hetzner Cloud DNS API).
  2026-09-25: `libdns/gandi` v1.1.0 is not used either (its SetRecords appends to the record set
  and TXT values do not round-trip); `registry/gandi.go` talks to the LiveDNS API itself. Nor is
  `libdns/desec` v1.1.1 (long TXT values misread, prints to stdout); `registry/desec.go` does the
  same, sharing the record-set logic in `registry/rrset.go`.
  `libdns/powerdns` v0.1.4 (pre-release libdns API) is not used either; `registry/powerdns.go`
  uses the same shared logic, tested against PowerDNS 4.9 and 5.0 in Docker. `libdns/googleclouddns`
  v1.2.0 wants the key as a file path; `registry/googleclouddns.go` signs its own token request.
  `libdns/ionos` v1.2.0 (pre-release libdns API, TXT sent as plain text, which IONOS mangles) is
  replaced by `registry/ionos.go`. 2026-09-28: `libdns/ovh` v1.1.0 only knows OVH's older
  application-key login, not OAuth2 service accounts; `registry/ovh.go` talks to the API itself and
  takes either.
- 2026-09-23: live SRV creation through Cloudflare (a real `0 0 443 <target>` record, for
  ns8-automx) failed with a 400 from Cloudflare's own API ("weight is a required data field").
  Root cause: `libdns/cloudflare` v0.2.2 serializes SRV priority/weight/port as plain (non-pointer)
  ints with `omitempty`, so a legitimately zero value -- the common case for SRV -- is dropped from
  the request instead of sent as an explicit 0. Auditing every provider for the same mistake found
  the identical pattern in `libdns/namedotcom` v0.9.0's SRV/MX priority field. 2026-09-30, both
  confirmed live: name.com rejects a zero SRV/MX priority ("Priority is required"), and Cloudflare
  also rejects an MX record with preference 0 ("priority is a required field"), the same mistake on
  its top-level `priority` field.
  Both patched locally (vendored copies under `helper/internal/vendored/`) rather than upstream;
  see [issue #19](https://github.com/danb35/ns8-dnshelper/issues/19) and the README's Providers
  section. The other four providers were checked and don't have this problem, for two different
  reasons: GoDaddy already uses pointer ints; Core-Networks, Hetzner and RFC 2136 send the whole
  record value as one opaque string, so there's no separate field for `omitempty` to drop.

## Adding a provider

Checklist, in addition to the usual live test against a real zone (README's Providers section):

- **Zero-value check (issue [#19](https://github.com/danb35/ns8-dnshelper/issues/19)).** Before
  trusting a new provider package with SRV (or anything else with a numeric sub-field that's
  routinely 0 -- SRV priority/weight, HTTPS/SVCB priority, a null MX's preference), read how it
  marshals that record type to the wire. If it's JSON and the field is a plain, non-pointer numeric
  type tagged `omitempty`, a legitimately-zero value (SRV priority 0, weight 0 -- the common case,
  and what this project's own `_autodiscover._tcp` record uses) gets silently dropped instead of
  sent as an explicit 0, and the provider's API then answers "field required" for a field that
  *was* given, just given as zero. This bit both `libdns/cloudflare` and `libdns/namedotcom`
  identically. It does not affect a provider that either uses pointer fields (GoDaddy, DigitalOcean, Linode) or sends the
  whole record value as one opaque string with no structured sub-fields (Core-Networks, deSEC, Gandi, Hetzner,
  RFC 2136) -- check which shape the new provider uses before assuming either way.
  - A related trap (found adding DigitalOcean, 2026-09-24): `libdns/digitalocean` does not drop
    the zero, it never fills the structured fields at all, sending the whole `0 0 443 target.` as
    the record's data. So also check that the package *uses* the provider's structured fields,
    not only how it marshals them. dnshelper talks to DigitalOcean's API itself
    (`registry/digitalocean.go`), as it does for GoDaddy.
  - Write a test asserting the actual bytes the provider would send include the zero value
    explicitly, not just that construction doesn't error. `internal/vendored/cloudflare/models_test.go`
    and `internal/vendored/namedotcom/namedotcom_test.go` are the template: build a zero-priority/
    zero-weight SRV record, marshal (or otherwise render) it the way the provider package would,
    and assert the zero survives. Confirm the test actually catches the bug by temporarily
    reverting the relevant field to its naive form and checking the test fails, the way both of
    those were verified.
  - If the provider package does have the bug, patch it the same way: a local vendored copy under
    `helper/internal/vendored/<provider>/`, copied from the pinned module version, patched only at
    the specific field(s), with a file-level comment naming the upstream version and linking back
    to whichever issue is tracking it -- not a silent in-place edit of `go.sum`'s checked-out
    source, and not skipped because "it's just the zero case."

## Credentials

- NS8 mirrors `state/environment` into Redis in plain text. Never store secrets there and never
  use `agent.set_env` for them. Use separate mode-0600 files under the module state dir
  (convention seen in other NS8 modules: `state/passwords.env`), written atomically.
- Model credentials as separate objects; zones reference a credential. One token often covers
  many zones, and rotation becomes a single edit.
- `get-configuration` never returns secrets ("set / not set" only); blank field in UI = keep.
- Encryption at rest with a co-located key adds little; the real mitigation is provider-scoped,
  least-privilege tokens. The UI should recommend zone-scoped tokens.
- Backup: state files are included only if listed in `imageroot/etc/state-include.conf`.
  Credentials must be included for restore to work; NS8 backups are restic with a destination
  data-encryption key. Decision (2026-09-19): included, documented in the README. Verified in
  ns8-core: `module-backup` runs restic with `--files-from=etc/state-include.conf` from a workdir
  holding `state/`; `10restore` runs `restic restore --target .` excluding only `state/environment`.
- Logging (journald): audit lines with caller, zone, record changes. Never log credentials or
  raw provider errors that might echo them. Map provider errors to structured NS8 errors.

## Authorization

- Roles are Redis sets of action names/globs, created in `create-module`, e.g.
  `redis-exec SADD "${AGENT_ID}/roles/dnswriter" "set-records"`. Suggested roles: read, write.
- Consumers get roles via the image label
  `org.nethserver.authorizations = dnshelper@cluster:dnswriter` (resolved at consumer
  instantiation). Verified 2026-09-19 in ns8-core: `<module>@cluster` resolves to
  `cluster/default_instance/<module>`, and `add-module` persists each module's authorizations and
  runs `refresh_permissions` after every install, so a consumer installed BEFORE dnshelper is
  granted the role when dnshelper arrives (dnshelper's roles exist by then: `create-module` has
  run). The built-in `reader` role additionally gets `get-*` and `list-*`.
- Roles are module-wide. Add an in-module policy table: which caller may touch which zone,
  record types and name patterns (e.g. mail: `_domainkey` TXT, SPF, MX; ACME: `_acme-challenge`
  only). Verified 2026-09-19 in ns8-core (`agent/htask.go`, `bind-user-domains`): `AGENT_TASK_USER` is
  `module/<id>` for module-originated tasks, the user name for humans, empty for automatic runs.

## Validation (validate-zone)

Read-only by default: `ListZones` if supported, else `GetRecords` on the zone. Optional opt-in
write test: create then delete a throwaway TXT record.

## Web UI

Vue 2 + Carbon + ns8-ui-lib (as in the NS8 template). Pages: Status, Zones (wizard: provider ->
dynamic credential form from `list-providers` -> validate -> save), Access (which modules may
change what), Audit log.

Bonus, zone import: the admin session can call any action, so the UI collects host names and
dnshelper reduces them. Action names verified 2026-09-19 against the modules' sources: cluster
`list-installed-modules` (a map of image -> modules, each with `module` = app type), mail
`list-domains` (array of `{domain}`), Traefik `list-routes` (only with `{"expand_list": true}`
does it return route objects with `host`; otherwise just route names) and webserver
`get-configuration` (`hostname`, `virtualhost[].ServerNames`). The helper's `registrable-domains`
operation reduces the names with the public suffix list (`golang.org/x/net/publicsuffix`),
dropping IPs, single labels, public suffixes and unknown top-level domains such as `.lan`; the
`suggest-zones` action marks candidates that are already managed; `list-provider-zones` lets the
wizard confirm them against the provider's own zone list. Results are candidates only: a mail
domain is not necessarily a DNS zone the administrator controls.

## Adopting ns8-powerdns zones (pull model)

ns8-powerdns is an NS8 authoritative DNS module (PowerDNS 5). dnshelper finds its primary and
takes over its zones without the administrator copying the API key. This section is the dnshelper
side of ns8-powerdns DESIGN §8 (the contract is there: §8.1 what powerdns provides, §8.2 what
dnshelper adds, §8.4 more than one primary; also §3, §9.2-9.4, §10). Verified 2026-11-05 against
ns8-powerdns master and ns8-core sources.

What powerdns provides (summary, not repeated in full):

- service key `module/<id>/srv/tcp/powerdns-api` (`host`, `port`, `role`), written only by the
  primary and not while it is a standby copy (powerdns §10); at most one primary (§3);
- role `dnsprovider` = `get-provider-config` and `list-zones`;
- `get-provider-config` returns `{"provider": "powerdns", "fields": {"api_url", "api_key",
  "server_id"}, "zones": [...]}`, zone names without the final dot;
- events `powerdns-zones-changed` (after add-zone / remove-zone) and `powerdns-provider-changed`
  (address, port or key changed; also on leaving standby), payload `{"module_id", "module_uuid"}`;
- it asks dnshelper's `has-zone` (role `dnsreader`, unchanged here) and refuses its own record
  writes with `managed_by_dnshelper` while dnshelper manages the zone.

### Authorization

`build-images.sh` declares `org.nethserver.authorizations=powerdns@any:dnsprovider`. Verified in
ns8-core: `add-module` grants a new module's authorizations *before* it runs `create-module`, and
`update-module` grants the new image's authorizations before the module's update hooks, so the
sync can call `get-provider-config` from either; `refresh_permissions` after every install means
install order does not matter (a primary installed after dnshelper is reachable too).

### The reconcile (`sync-powerdns`)

One function, `dnshelper_lib.sync_powerdns()`, run from every trigger. It is idempotent and never
trusts an event's payload: it always looks at the cluster as it is.

1. Read the `powerdns-api` service keys (`agent.list_service_providers(rdb, 'powerdns-api',
   'tcp')`) from the **leader**. If the leader is unreachable, stop with `leader_unreachable` and
   change nothing: a stale replica must not make dnshelper drop zones.
2. **More than one key (powerdns §8.4):** change nothing (no new zones, existing adopted zones
   and credentials left as they are), log an error naming the modules, and report
   `status: "multiple_primaries"` with their ids so the UI can show it.
3. **No key: the primary is gone.** Remove every managed credential and the zones adopted
   through it (see "Removing an adopted zone").
4. **One key:** call its `get-provider-config` with `agent.tasks.run()`. If the call fails or the
   output is not a PowerDNS configuration, stop with `primary_unreachable` and change nothing (the
   primary may be restarting; the next event or Sync tries again). The response is never logged:
   it holds the key.
5. Create or update the managed credential (below). Its file is rewritten only when a field
   changed, so a sync with nothing new writes nothing. If a credential made by hand already has
   that id (impossible with `add-credential`'s ids), stop with `credential_id_taken`.
6. For each zone the primary lists (normalized like `add-zone`; a name `add-zone` would refuse is
   skipped and logged):
   - not configured in dnshelper: add it with the managed credential;
   - already adopted from an earlier primary: point it at the current managed credential
     (reported as `moved`);
   - configured by hand (any provider, including a hand-made PowerDNS credential): leave it
     alone and report it as `skipped`. The administrator can remove it and press Sync to adopt
     it instead.
7. Adopted zones the primary no longer lists are removed.
8. Managed credentials of any other module (an earlier primary) are removed, after their zones
   were moved or removed in 6-7.

The whole run holds `state/sync.lock` (flock), so an event and a Sync click do not interleave;
the file updates also take the existing configuration lock. The output is
`{"status": "adopted" | "no_primary" | "multiple_primaries", "primary", "modules", "added",
"moved", "removed", "skipped"}`.

When the set of zones changed, the run writes one audit line (`action=sync-powerdns`, the
primary, added, moved and removed zones; never a field value) and publishes
`service-dnshelper-changed`, like `add-zone` / `remove-zone`.

### Triggers

| Trigger | Where | On failure |
|---|---|---|
| `powerdns-zones-changed`, `powerdns-provider-changed` | `imageroot/events/<name>/10sync` | log, exit 0 (the next event or Sync retries) |
| primary removed | `imageroot/events/module-removed/10sync`: the core publishes `cluster/event/module-removed` `{"module", "node"}` after deleting the module's keys; the handler runs only when `module` owns a managed credential | as above |
| dnshelper installed after the primary | `create-module/60sync_powerdns` | warning only: an install must not fail because powerdns is down |
| dnshelper updated (an install from before this feature) | `update-module.d/20sync_powerdns` | warning only |
| restore and clone | `restore-module/60sync_powerdns` (clone runs it through `clone-module`), after the state check | warning only |
| Sync button on the Zones page | action `sync-powerdns`, admin only (in no role) | the error is shown |

Agents subscribe to `*/event/*` (ns8-core `agent/hevent.go`), so a dnshelper handler receives
events published on `module/powerdns1/event/...`. Handlers ignore the payload, as said above.

### The managed credential and the `managed_by` marker

- The credential's id is the module id (`powerdns1`), its name the module id too. Hand-made
  credentials have random ids `c<8 hex>`, so the two cannot collide, and a fixed id keeps the
  reconcile idempotent.
- The marker lives in the credential file itself, `state/credentials/powerdns1.json`:
  `{"name": "powerdns1", "provider": "powerdns", "fields": {...}, "managed_by": "module/powerdns1"}`.
  A zone is **adopted** when its credential carries `managed_by`; zones.json is unchanged
  (`{"credential": "powerdns1"}`), so there is one source of truth and no second marker to keep in
  step.
- **Backup and restore:** `state/credentials` is already in `state-include.conf`, so the marker is
  backed up and restored with the credential. After a restore or clone the sync runs and brings it
  in line with the cluster as it is then: a primary restored under a new id gets a new credential
  and the zones move to it (step 6), the old one is removed (step 8); with no primary, adopted zones
  are removed (and come back when the primary is restored and publishes its events).
  `check_restored_state` accepts the field.
- `get-configuration` reports `managed_by` on credentials and on zones (derived), for the UI.

### The API key

The key is stored like the key of any PowerDNS credential: in `fields.api_key` of the credential
file, mode 0600, written atomically by the existing `_write_private`. It is never passed to
`agent.set_env()`, never in argv or environment (it reaches the Go helper on stdin as for every
credential), never in the audit line, and `get-configuration` shows it only as "set" (the
provider schema marks `api_key` secret). Task output of `get-provider-config` holds the key; that
is acceptable (powerdns §8.1: only the calling module and cluster administrators can read it).

### Read-only for the administrator

- Hand-written changes to managed objects are refused by the backend, not only hidden in the UI:
  `update-credential` and `remove-credential` on a managed credential (`managed_credential`),
  `update-zone` and `remove-zone` on an adopted zone (`managed_zone`), and `add-zone` or
  `update-zone` with a managed credential (`managed_credential`: a zone attached by hand would be
  taken for an adopted one and removed by the next sync). `validate-zone` and
  `list-provider-zones` still work: they only read.
- The UI shows an "Adopted from powerdns1" tag on the credential and its zones and offers no
  edit, change-credential or delete entries for them; "Validate" stays.
- Record changes through dnshelper (Records page, consumer actions) work on adopted zones as on any
  zone: that is the point of adopting them. The policy table is not touched: an adopted zone is
  default-deny for other modules until the administrator adds rules.

### Removing an adopted zone

"Remove" means: delete the zone's entry from `zones.json`, exactly what `remove-zone` does.

- **Records** written through dnshelper stay on the PowerDNS server. dnshelper never deletes
  records when it stops managing a zone, and it keeps no record ownership that would need
  cleaning. (When the primary dropped the zone, the records are gone with it anyway.)
- **Policy rules** naming the zone are kept, as the policy table is not touched. They have no
  effect while the zone is not managed (consumers get `zone_not_found`) and apply again if the
  zone is adopted again, for instance after a move or restore of the primary. The administrator
  removes them on the Access page if they are no longer wanted.
- `has-zone` then answers `managed: false`, so powerdns allows edits on its own Records page again.

### Moves, clones and restores of the primary

An NS8 move is a clone followed by removing the source; the copy starts as a standby that does not
register the key (powerdns §10). Removing the source fires `module-removed`, the sync sees no key
and removes the adopted zones; when the copy leaves standby it publishes
`powerdns-provider-changed` and `powerdns-zones-changed`, and the next sync adopts them again under
the copy's module id. Between the two, consumers get `zone_not_found` for those zones, and
powerdns's own Records page is writable. Accepted for v1: the window is the copy's reconcile
interval, nothing is lost, and the alternative (keeping zones of a primary that is gone) would
leave them pointing at a dead API.

### Records page deep link and PTR

- The Records page reads `zone` from its query (`/apps/dnshelper1?page=records&zone=example.com`,
  the link powerdns's read-only Records view opens) and selects that zone when dnshelper manages
  it; otherwise the first zone, as before.
- `PTR` is added to the PowerDNS provider's record types, so PTR records in adopted reverse zones
  can be edited here. The shared record-set code (`registry/rrset.go`, also used by deSEC, Gandi,
  Google Cloud DNS, IONOS, OVH and Vultr) treats PTR's value as a host name, like CNAME: made
  absolute before sending and compared without case and final dot.

## Additional goals

- Consumer helper library + README (presence check, call wrapper, error mapping) for other modules.
- Record ownership and cleanup (consumer registers records; removed on consumer `destroy-module`).
  libdns has no ownership marker, so track it in the module.
- Safety rails: never touch apex NS/SOA; per-zone lock; dry-run for `set-records`.
- Provider capability matrix in UI (e.g. warn when SRV unsupported).
- Optional propagation check against authoritative nameservers.
- Later: dynamic-IP updater (A/AAAA); DNS-01 for wildcard certificates via Traefik (**VERIFY**
  how NS8 configures ACME).
- Standard NS8 hygiene: Robot Framework tests, Weblate i18n, pinned images + Renovate.

## Minimum core version

`org.nethserver.min-core=3.23.0`. The earlier 3.20.1 was inherited from the ns8-kickstart template,
not derived. Checked 2026-11-06 against ns8-core history (first release containing each feature):

| Feature dnshelper relies on | Core |
|---|---|
| `AGENT_TASK_USER` (caller identity; without it every caller is unrestricted by the policy table) | 2.4.0 |
| `min-core` enforced (new installs and update candidates); `max-per-node` in the Software center install | 2.10.0 |
| `max-per-node` for clone/move | 3.4.0 |
| `max-per-node` for restore | 3.9.3 |
| `max-per-node` in the `add-module` command (`--force` skips it) | 3.23.0 |
| everything else: `agent.tasks.run` (incl. `extra=`), `list_service_providers(..., 'tcp')`, `*/event/*` subscription, `module-removed` `{module, node}` after key deletion, `update-module.d`, grants before `create-module` / update hooks, `refresh_permissions`, `@any`/`@cluster` scopes, `reader` `get-*`/`list-*`, `state-include.conf`, `module-dump-state`, `clone-module/10recvstate` | pre-1.0 (2021-2023) |

Decision (2026-11-06): 3.23.0, so the one-instance-per-node rule (two instances on a node would not
share the per-zone lock) is enforced on every path. The module would run from 2.4.0. Raise the
label when a newer core feature is used. ns8-ui-lib and the Go helper are bundled, so they add no
core requirement.

## Suggested build order

1. Scaffold from the template, rename, get an empty module installing and passing the template CI.
2. Go helper with libdns: fake in-memory provider for unit tests, then 2-3 real providers; JSON
   stdin/stdout contract; tests for TXT chunking, CNAME conflict, SetRecords merge, exact delete.
3. Actions + JSON schemas + credential store + `validate-zone`.
4. Roles, service-provider registration, policy table, audit logging.
5. Backup/restore (`state-include.conf`, restore steps).
6. UI: zones and credentials first, then access, then zone import.
7. Consumer client snippet + README; integration test with a consumer module on a real NS8 node.

## Sources consulted

- NS8 dev manual: Agents, Module agent, Service providers, Backup & Restore
  (nethserver.github.io/ns8-core)
- libdns package docs (pkg.go.dev/github.com/libdns/libdns), v1.1.1 read on 2026-09-19
- NethServer/agents module-conventions PR; ns8-odoo 1.1.0 release notes (secrets handling)

## Future improvements

- More DNS hosts
- Consider a more full-fledged DNS record/zone editor.  Currently the records page lets you add or remove records, but it's designed as a test tool, not a full DNS manager.
  - One useful feature would be a zone backup before editing, and allowing reverts to prior backups.
  - Allow direct editing of records rather than delete/add.
  - Bulk record operations (I'd expect deletions as the main one, but the ability to bulk-retarget CNAMEs could also be useful)
