# ns8-dnshelper: design brief

Helper module for NethServer 8 (NS8) that lets other modules create, edit and remove DNS
records through DNS hosts' APIs. Built on Go `libdns` (github.com/libdns/libdns, v1.x).
Status: design only, nothing implemented. Items marked **VERIFY** were not confirmed from docs.

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
  module's Redis credentials). **VERIFY** the `data=` kwarg name.
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
  data-encryption key. Document the decision.
- Logging (journald): audit lines with caller, zone, record changes. Never log credentials or
  raw provider errors that might echo them. Map provider errors to structured NS8 errors.

## Authorization

- Roles are Redis sets of action names/globs, created in `create-module`, e.g.
  `redis-exec SADD "${AGENT_ID}/roles/dnswriter" "set-records"`. Suggested roles: read, write.
- Consumers get roles via the image label
  `org.nethserver.authorizations = dnshelper@cluster:dnswriter` (resolved at consumer
  instantiation). **VERIFY / open**: if dnshelper is installed AFTER a consumer, the grant does
  not exist. Fallback: cluster `grant-actions` (owner role); UI could offer "grant access to
  module X".
- Roles are module-wide. Add an in-module policy table: which caller may touch which zone,
  record types and name patterns (e.g. mail: `_domainkey` TXT, SPF, MX; ACME: `_acme-challenge`
  only). **VERIFY** how to identify a module caller (`AGENT_TASK_USER` for module-originated
  tasks).

## Validation (validate-zone)

Read-only by default: `ListZones` if supported, else `GetRecords` on the zone. Optional opt-in
write test: create then delete a throwaway TXT record.

## Web UI

Vue 2 + Carbon + ns8-ui-lib (as in the NS8 template). Pages: Status, Zones (wizard: provider ->
dynamic credential form from `list-providers` -> validate -> save), Access (which modules may
change what), Audit log.

Bonus, zone import: the admin session can call any action, so the UI can run cluster
`list-installed-modules`, then read domains from mail / web server instances and hostnames from
Traefik routes. **VERIFY** the real action names (`api-cli run --agent module/mail1
list-actions`). Reduce hostnames to registrable domains with `golang.org/x/net/publicsuffix`;
treat results as candidates only (a mail domain is not necessarily a DNS zone) and confirm
against the provider's zone list.

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
