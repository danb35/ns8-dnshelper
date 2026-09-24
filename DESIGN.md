# ns8-dnshelper: design brief

Helper module for NethServer 8 (NS8) that lets other modules create, edit and remove DNS
records through DNS hosts' APIs. Built on Go `libdns` (github.com/libdns/libdns, v1.x).
Status: build order steps 1-7 done (scaffold, Go helper, actions + credential store, roles/policy/audit, backup/restore, UI, node integration test); see README. Items marked **VERIFY** were not confirmed from docs.

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
| Admin | `add-zone`, `update-zone`, `remove-zone`, `validate-zone`, `list-providers` |
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
- 2026-09-23: live SRV creation through Cloudflare (a real `0 0 443 <target>` record, for
  ns8-automx) failed with a 400 from Cloudflare's own API ("weight is a required data field").
  Root cause: `libdns/cloudflare` v0.2.2 serializes SRV priority/weight/port as plain (non-pointer)
  ints with `omitempty`, so a legitimately zero value -- the common case for SRV -- is dropped from
  the request instead of sent as an explicit 0. Auditing every provider for the same mistake found
  the identical pattern in `libdns/namedotcom` v0.9.0's SRV/MX priority field (not confirmed live).
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
  identically. It does not affect a provider that either uses pointer fields (GoDaddy, DigitalOcean) or sends the
  whole record value as one opaque string with no structured sub-fields (Core-Networks, Hetzner,
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
