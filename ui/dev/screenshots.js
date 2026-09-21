// Takes the screenshots of docs/USER-GUIDE.md from the UI harness. See "Screenshots" in
// ui/dev/README.md. Runs in the Playwright image; HARNESS is the harness URL as seen from
// the container, OUT the directory the PNG files are written to.
const { chromium } = require("playwright-core");

const BASE = process.env.HARNESS || "http://host.docker.internal:8099/";
const OUT = process.env.OUT || "/out";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1360, height: 900 }, deviceScaleFactor: 1 });
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
          [...d.querySelectorAll("a")].find((a) => a.textContent.trim() === label).click();
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
  await shot("wizard-1-provider-chosen");
  await run(async (root, findBy, call, sleep) => {
    const w = findBy(root, "ZoneWizard"); await w.nextStep(); await sleep(800);
    w.credentialName = "Cloudflare - example.com"; w.$set(w.fields, "api_token", "cf-api-token-0123456789abcdef"); await sleep(400);
  });
  await shot("wizard-2-credentials");
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
  await shot("wizard-3-zone-suggestions");
  await run(async (root, findBy, call, sleep) => {
    const w = findBy(root, "ZoneWizard"); w.chooseZone("example.com"); await sleep(500); await w.nextStep(); await sleep(1500);
  });
  await shot("wizard-4-review");
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
    await nav("Status"); await nav("Zones");
  });
  await shot("zones-page");
  await run(async (root, findBy, call, sleep) => {
    const z = findBy(root, "Zones"); z.showRemoveZone(z.zoneRows.find((r) => r.zone === "my-shop.net")); await sleep(900);
  });
  await shot("zones-remove-zone");
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
  await run(async (root, findBy, call, sleep, nav) => { await nav("Records"); await sleep(1200); });
  await shot("records-page");
  await run(async (root, findBy, call, sleep) => {
    const r = findBy(root, "Records"); r.showAdd(); await sleep(800);
    r.form.name = "blog"; r.form.type = "CNAME"; r.form.data = "www.example.com."; await sleep(500);
  });
  await shot("records-add");
  await run(async (root, findBy, call, sleep) => {
    const r = findBy(root, "Records"); r.isAddShown = false; await sleep(300);
    r.showRemove(r.rows.find((x) => x.name === "mail" && x.type === "A")); await sleep(900);
  });
  await shot("records-delete");
  await run(async (root, findBy, call, sleep) => { findBy(root, "Records").isRemoveShown = false; await sleep(300); });

  // ---- Status with data
  await run(async (root, findBy, call, sleep, nav) => { await nav("Status"); await sleep(800); });
  await shot("status");

  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
