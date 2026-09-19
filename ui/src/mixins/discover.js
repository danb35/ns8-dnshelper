//
// Copyright (C) 2026 dnshelper contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
import DnsHelperService from "./dnshelper";

/**
 * Collect the host names other modules use and reduce them to candidate DNS
 * zones. The admin session may call any module's actions, so the collection
 * happens here; dnshelper only reduces the names to registrable domains and
 * says which are already managed. The results are candidates: a mail domain is
 * not necessarily a zone the administrator can manage at a DNS host.
 *
 * Sources (action names verified against the modules' sources):
 *   mail       list-domains      -> [{ domain }]
 *   traefik    list-routes       -> [{ host }]   (only with expand_list)
 *   webserver  get-configuration -> { hostname, virtualhost: [{ ServerNames }] }
 */
export default {
  name: "DiscoverService",
  mixins: [DnsHelperService],
  methods: {
    async discoverZones() {
      const installed = await this.callAction("list-installed-modules", {
        cluster: true,
      });
      const modules = [].concat(...Object.values(installed));
      const names = new Set();

      const collect = async (m) => {
        try {
          if (m.module === "mail") {
            const domains = await this.callAction("list-domains", {
              moduleId: m.id,
            });
            domains.forEach((d) => names.add(d.domain));
          } else if (m.module === "traefik") {
            const routes = await this.callAction("list-routes", {
              moduleId: m.id,
              data: { expand_list: true },
            });
            routes.forEach((r) => r.host && names.add(r.host));
          } else if (m.module === "webserver") {
            const config = await this.callAction("get-configuration", {
              moduleId: m.id,
            });
            if (config.hostname) {
              names.add(config.hostname);
            }
            (config.virtualhost || []).forEach((v) =>
              (v.ServerNames || []).forEach((n) => names.add(n))
            );
          }
        } catch (err) {
          // a module that cannot be read must not hide the others
          console.warn(`cannot read host names from ${m.id}`, err);
        }
      };
      await Promise.all(modules.map(collect));

      if (!names.size) {
        return [];
      }
      const output = await this.callAction("suggest-zones", {
        data: { names: Array.from(names) },
      });
      return output.candidates;
    },
  },
};
