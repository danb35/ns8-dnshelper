# NS8 dnshelper UI development

To develop dnshelper UI please refer to [this section of the Developer manual](https://nethserver.github.io/ns8-core/ui/modules/#module-ui-development).

## Screens

- **Status**: zone and access-rule counts, backup, and shortcuts to the audit log.
- **Zones**: managed zones (check credentials, change credential, remove) and the credentials
  they use (edit, delete); the *Add zone* wizard picks a DNS host, asks for its credential, lists
  the zones that credential can manage, can suggest zones used by the mail, web server and Traefik
  modules, checks access (optionally with a write test) and saves.
- **Access**: the policy table that says which module may change which record names and types,
  with presets for a mail server and for ACME DNS-01.

All calls go through `src/mixins/dnshelper.js` (`callAction`), which turns the shell's task events
into a promise. To look at the UI without an NS8 node, see [dev/README.md](dev/README.md).
