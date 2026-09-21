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

## Screenshots

`screenshots.js` drives the harness in a headless browser and takes the pictures used in
[docs/USER-GUIDE.md](../../docs/USER-GUIDE.md), so that they can be redone when the UI changes. It
seeds its own data through the real actions, and needs the shell's stylesheet (`CORE_CSS`, see
above) or the pictures would show an unstyled page.

```bash
# in one terminal: the harness, with the shell's stylesheet
CORE_CSS=/path/to/core.css DNSHELPER_REAL_BIN=/tmp/dnshelper python3 ui/dev/server.py

# in another: the browser, in Docker (Docker Desktop reaches the host as host.docker.internal)
mkdir -p /tmp/shots
docker run --rm -v "$PWD/ui/dev:/work" -v /tmp/shots:/out -w /work \
    mcr.microsoft.com/playwright:v1.49.1-jammy \
    bash -c "npm init -y >/dev/null && npm i playwright-core@1.49.1 >/dev/null && OUT=/out node screenshots.js"
```

Start from a fresh harness (it keeps its data until it is stopped), and close any browser tab that
has the harness open: the guide's pictures are taken at 1360 pixels wide. Copy the ones the guide
uses into `docs/images/`.
