// Takes the screenshots of docs/USER-GUIDE.md from the UI harness. See "Screenshots" in
// ui/dev/README.md. Runs in the Playwright image; HARNESS is the harness URL as seen from
// the container, OUT the directory the PNG files are written to.
const { chromium } = require("playwright-core");

const BASE = process.env.HARNESS || "http://host.docker.internal:8099/";
const OUT = process.env.OUT || "/out";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({
    viewport: { width: 1360, height: 900 },
    deviceScaleFactor: 1,
    locale: process.env.LOCALE || "en-US",
  });
  page.on("pageerror", (e) => console.log("PAGE ERROR", e.message));
  await page.goto(BASE);
  await sleep(2500);
  const frame = () => page.frames().find((f) => f.url().includes("/app/"));
  const shot = async (name) => {
    await sleep(700);
    await page.locator("iframe").screenshot({ path: `${OUT}/${name}.png` });
    console.log("shot", name);
  };
  // run fn(vmByName, callAction) inside the app frame
  const run = (fn, arg, ms = 45000) => Promise.race([
    new Promise((_, rej) => setTimeout(() => rej(new Error("step timed out: " + fn.toString().slice(0, 120))), ms)),
    frame().evaluate(
      async ({ src, arg }) => {
        const d = document;
        const root = d.querySelector("#ns8-app").__vue__;
        const findBy = (v, n) => {
          if (v.$options.name === n) return v;
          for (const c of v.$children) {
            const x = findBy(c, n);
            if (x) return x;
          }
        };
        const anyWith = (v, m) => {
          if (v[m]) return v;
          for (const c of v.$children) {
            const x = anyWith(c, m);
            if (x) return x;
          }
        };
        const call = (a, data) => anyWith(root, "callAction").callAction(a, data === undefined ? {} : { data });
        const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
        const nav = async (label) => {
          // by position in the side menu, so that it works in any language
          const pages = ["Status", "Zones", "Records", "Access", "Settings", "About"];
          [...d.querySelectorAll(".bx--side-nav__link")][pages.indexOf(label)].click();
          await sleep(1800);
        };
        // eslint-disable-next-line no-new-func
        return await new Function("root", "findBy", "call", "sleep", "nav", "d", "arg", `return (${src})(root, findBy, call, sleep, nav, d, arg)`)(
          root, findBy, call, sleep, nav, d, arg
        );
      },
      { src: fn.toString(), arg }
    )]);

  // ---- empty module
  await run(async (root, findBy, call, sleep, nav) => { await nav("Status"); });
  await shot("status-empty");
  await run(async (root, findBy, call, sleep, nav) => { await nav("Zones"); });
  await shot("zones-empty");

  // ---- the Add zone wizard
  await run(async (root, findBy, call, sleep) => { findBy(root, "Zones").isWizardShown = true; await sleep(1200); });
  await shot("wizard-1-provider");
  await run(async (root, findBy, call, sleep) => {
    const w = findBy(root, "ZoneWizard"); w.providerName = "cloudflare"; await sleep(600);
  });
  await shot("add-zone-1-dns-host");
  await run(async (root, findBy, call, sleep) => {
    const w = findBy(root, "ZoneWizard"); await w.nextStep(); await sleep(800);
    w.credentialName = "Cloudflare - example.com"; w.$set(w.fields, "api_token", "cf-api-token-0123456789abcdef"); await sleep(400);
  });
  await shot("add-zone-2-credential");
  await run(async (root, findBy, call, sleep) => {
    const w = findBy(root, "ZoneWizard"); await w.nextStep(); await sleep(1200);
  });
  await shot("wizard-3-zone");
  // the harness sometimes loses one of the concurrent task results: try again
  for (let i = 0; i < 4; i++) {
    try {
      await run(async (root, findBy, call, sleep) => {
        const w = findBy(root, "ZoneWizard"); await w.discover(); await sleep(1500);
      }, undefined, 15000);
      break;
    } catch (e) { console.log("discover retry", i + 1); }
  }
  await shot("add-zone-3-zone");
  await run(async (root, findBy, call, sleep) => {
    const w = findBy(root, "ZoneWizard"); w.chooseZone("example.com"); await sleep(500); await w.nextStep(); await sleep(1500);
  });
  await shot("add-zone-4-review");
  await run(async (root, findBy, call, sleep) => {
    const w = findBy(root, "ZoneWizard"); await w.save(); await sleep(2000);
  });
  await shot("zones-one-zone");

  // ---- a fuller Zones page
  await run(async (root, findBy, call, sleep, nav) => {
    const cfg = await call("get-configuration");
    const cf = cfg.credentials[0].id;
    const h = await call("add-credential", { name: "Hetzner - shop", provider: "hetzner", fields: { api_token: "hz-token-0123456789" } });
    await call("add-zone", { zone: "example.org", credential: cf });
    await call("add-zone", { zone: "my-shop.net", credential: h.id });
    // the zones of the cluster's ns8-powerdns primary (powerdns1, faked by the harness)
    await call("sync-powerdns");
    await nav("Status"); await nav("Zones");
  });
  await shot("zones");
  await run(async (root, findBy, call, sleep) => {
    const z = findBy(root, "Zones"); z.showRemoveZone(z.zoneRows.find((r) => r.zone === "my-shop.net")); await sleep(900);
  });
  await shot("zones-remove");
  await run(async (root, findBy, call, sleep) => {
    const z = findBy(root, "Zones"); z.isRemoveZoneShown = false; await sleep(400);
    z.showChangeCredential(z.zoneRows.find((r) => r.zone === "my-shop.net")); await sleep(900);
  });
  await shot("zones-change-credential");
  await run(async (root, findBy, call, sleep) => {
    const z = findBy(root, "Zones"); z.isChangeCredentialShown = false; await sleep(300);
  });

  // ---- Access
  await run(async (root, findBy, call, sleep, nav) => { await nav("Access"); });
  await shot("access-empty");
  await page.setViewportSize({ width: 1360, height: 1180 }); // the dialog is tall
  await run(async (root, findBy, call, sleep) => {
    const a = findBy(root, "Access"); a.showAddRule(); await sleep(1200);
    const m = findBy(root, "PolicyRuleModal"); m.applyPreset(m.presets.find((p) => p.key === "mail"));
    await sleep(600);
    m.caller = "module/mail1"; m.selectedZones = ["example.com"]; await sleep(800);
  });
  await shot("access-add-rule");
  await page.setViewportSize({ width: 1360, height: 900 });
  await run(async (root, findBy, call, sleep) => {
    findBy(root, "Access").isRuleShown = false; await sleep(400);
    await call("set-policy", { rules: [
      { caller: "module/mail1", zones: ["example.com", "example.org"], access: "write",
        names: ["@", "*._domainkey", "_dmarc", "autoconfig", "autodiscover", "_autodiscover._tcp"], types: ["TXT", "MX", "CNAME", "SRV"] },
      { caller: "module/traefik1", zones: ["*"], access: "write", names: ["_acme-challenge", "_acme-challenge.*"], types: ["TXT"] },
      { caller: "module/webserver1", zones: ["example.com"], access: "write", names: ["*"], types: ["CNAME"] },
      { caller: "module/monitor*", zones: ["example.org"], access: "read", names: ["*"], types: ["*"] },
    ] });
    await findBy(root, "Access").load(); await sleep(1000);
  });
  await shot("access-rules");
  await run(async (root, findBy, call, sleep) => {
    const a = findBy(root, "Access"); a.showEditRule(a.rows[0]); await sleep(1500);
  });
  await shot("access-edit-rule");
  await run(async (root, findBy, call, sleep) => { findBy(root, "Access").isRuleShown = false; await sleep(300); });

  // ---- Records
  await run(async (root, findBy, call, sleep, nav) => {
    await nav("Records"); await sleep(1200);
    const r = findBy(root, "Records"); r.zone = "example.com"; await r.loadRecords(); await sleep(1500);
  });
  await shot("records");
  // edit the MX, which mail1 wrote (harness seed): the form for MX and the warning
  await run(async (root, findBy, call, sleep) => {
    const r = findBy(root, "Records"); r.showEdit(r.rows.find((x) => x.type === "MX")); await sleep(1500);
  });
  await shot("records-edit");
  // add an A record whose reverse zone (adopted from powerdns1) is managed: the PTR is offered
  await run(async (root, findBy, call, sleep) => {
    const r = findBy(root, "Records"); r.isFormShown = false; await sleep(400);
    r.showAdd(); await sleep(900);
    const f = findBy(root, "RecordForm"); f.name = "web"; f.type = "A"; await sleep(500);
    f.fields = { address: "192.0.2.30" }; await sleep(2200);
  });
  await shot("records-add");
  await run(async (root, findBy, call, sleep) => {
    const r = findBy(root, "Records"); r.isFormShown = false; await sleep(400);
    r.showRemove(r.rows.find((x) => x.name === "mail" && x.type === "A")); await sleep(1500);
  });
  await shot("records-delete");
  // the view: TXT only, full names
  await run(async (root, findBy, call, sleep) => {
    const r = findBy(root, "Records"); r.isRemoveShown = false; await sleep(400);
    r.typeFilter = ["TXT"]; r.fullNames = true; await sleep(900);
  });
  await shot("records-filtered");
  // pending changes: a new TTL for the A records
  await run(async (root, findBy, call, sleep) => {
    const r = findBy(root, "Records"); r.typeFilter = []; r.fullNames = false; await sleep(600);
    r.selected = r.rows.filter((x) => x.type === "A").map((x) => r.keyOf(x));
    r.showTtl(); r.ttlValue = "900"; await sleep(300); r.stageTtl(); await sleep(1200);
  });
  await shot("records-pending");
  await run(async (root, findBy, call, sleep) => {
    const r = findBy(root, "Records"); r.isReviewShown = true; await sleep(3000);
  });
  await shot("records-review");
  await run(async (root, findBy, call, sleep) => {
    await findBy(root, "ReviewChanges").apply(); await sleep(2500);
    findBy(root, "Records").notice = { title: "", text: "" }; await sleep(300);
  });
  // find and replace: point the mail records at a new host
  await run(async (root, findBy, call, sleep) => {
    const r = findBy(root, "Records"); r.isFindShown = true; await sleep(800);
    const fr = findBy(root, "FindReplace"); fr.find = "mail.example.com."; fr.replace = "mx.example.com."; await sleep(900);
  });
  await shot("records-find");
  // import a zone file from another DNS host, adding what is missing (a tall dialog)
  await page.setViewportSize({ width: 1360, height: 1120 });
  await run(async (root, findBy, call, sleep) => {
    const r = findBy(root, "Records"); r.isFindShown = false; await sleep(400);
    r.isImportShown = true; await sleep(800);
    const im = findBy(root, "ImportZone");
    im.text = "$ORIGIN example.com.\n$TTL 3600\n@     IN SOA  ns1.old-host.net. hostmaster.example.com. 1 7200 3600 1209600 3600\n" +
      "@     IN NS   ns1.old-host.net.\nwww   IN CNAME example.com.\nshop  IN A    192.0.2.40\nshop  IN AAAA 2001:db8::40\n" +
      "ftp   IN CNAME www\n";
    await im.preview(); await sleep(1500);
  });
  await shot("records-import");
  await page.setViewportSize({ width: 1360, height: 900 });
  // snapshots: the history, and a comparison with the first one
  await run(async (root, findBy, call, sleep) => {
    const r = findBy(root, "Records"); r.isImportShown = false; await sleep(400);
    r.isSnapshotsShown = true; await sleep(3000);
  });
  await shot("records-snapshots");
  await run(async (root, findBy, call, sleep) => {
    const zs = findBy(root, "ZoneSnapshots"); await zs.compare(zs.snapshots[zs.snapshots.length - 1]); await sleep(2000);
  });
  await shot("records-revert");
  // propagation check of www
  await run(async (root, findBy, call, sleep) => {
    const r = findBy(root, "Records"); r.isSnapshotsShown = false; await sleep(500);
    r.showPropagation(r.rows.find((x) => x.name === "www")); await sleep(3000);
  });
  await shot("records-propagation");
  // a module that wrote records is removed (as events/module-removed does)
  await page.request.post(BASE + "dev/module-removed?module=automx1");
  await run(async (root, findBy, call, sleep) => {
    const r = findBy(root, "Records"); r.isPropagationShown = false; await sleep(400);
    await r.loadRecords(); await sleep(2000);
  });
  await shot("records-removed-module");
  // an adopted reverse zone, as the ns8-powerdns Records page opens it (?page=records&zone=...)
  await run(async (root, findBy, call, sleep) => {
    const r = findBy(root, "Records"); r.zone = "2.0.192.in-addr.arpa"; await r.loadRecords(); await sleep(1200);
  });
  await shot("records-adopted");

  // ---- Settings
  await run(async (root, findBy, call, sleep, nav) => { await nav("Settings"); await sleep(1200); });
  await shot("settings");

  // ---- Status with data
  await run(async (root, findBy, call, sleep, nav) => { await nav("Status"); await sleep(800); });
  await shot("status");

  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
