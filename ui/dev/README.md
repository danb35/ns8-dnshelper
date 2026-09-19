# UI harness

The dnshelper UI only runs inside the NS8 shell (it reads `window.parent.core`), which makes it
awkward to look at. This harness fakes the shell so the built UI can be exercised in a browser:

- `harness.html` is the parent page: it provides `window.core` (an event emitter, `apiUrl`,
  `$t`) and relays task results to the app, the way the shell does over its websocket.
- `server.py` is a mock NS8 API. Actions of `dnshelper1` run through the **real** Python code in
  `imageroot/pypkg/dnshelper_lib.py`; the mail, web server, Traefik and cluster actions the UI
  calls return canned data (shapes checked against those modules' sources).
- `fake_helper.py` stands in for the Go binary: it fakes the DNS host. A token containing `bad`
  is rejected, `readonly` gives a host that cannot replace records, `nolist` one that cannot list
  zones. Set `DNSHELPER_REAL_BIN` to forward `list-providers` and `registrable-domains` to the real
  binary.

```bash
cd ui && yarn build                    # needs NODE_OPTIONS=--openssl-legacy-provider on Node 17+
(cd ../helper && go build -o /tmp/dnshelper ./cmd/dnshelper)
DNSHELPER_REAL_BIN=/tmp/dnshelper CORE_CSS=/path/to/core/ui/dist/css/core.css python3 dev/server.py
```

`CORE_CSS` is the NS8 core UI's `css/core.css` (the concatenation of its `app~*.css` files);
without it the app renders without the shell's Carbon styles.
