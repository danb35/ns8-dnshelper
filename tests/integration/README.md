# Integration test on a real NS8 node

`test_node.py` installs dnshelper and a tiny **consumer module** (`consumer/`, image
`dnsconsumer`) on a real NS8 node, talks to a real RFC 2136 DNS server, and checks what a real
consumer sees. It covers:

1. install order: a consumer installed *before* dnshelper is granted `dnshelper@cluster:dnswriter`
   when dnshelper arrives (roles, service key)
2. configuring a credential and a zone against the DNS server (secret never returned, file modes)
3. default deny for modules, and NS8's own `403` for actions outside the role
4. policy rules limiting names and types, with the effect checked at the DNS server
5. a DKIM key rotation (dry run, replace, exact delete, wildcard delete refused)
6. audit lines in the journal (and the TSIG key absent from it), and the `service-dnshelper-changed` event
7. a real backup to a WebDAV destination and a real restore into a new instance (secret still
   opens the DNS server, modes, roles, warning about a policy rule for a missing module)
8. removing dnshelper (the consumer's presence check turns false) and reinstalling it

Each run leaves the node as it found it: NS8 deletes a module's image when its last instance is
removed, so the test rebuilds the images when it needs to install again.

## Prerequisites

- An NS8 node you can `ssh root@` to with a key, with podman (no buildah needed: `add-module` only
  pulls an image that is not already in local storage), and a built UI (`cd ui && yarn build`).
- A DNS server the node can reach that accepts RFC 2136 updates and zone transfers with a TSIG
  key. `helper/testdata/bind/start.sh` starts a throwaway BIND: `BIND_ADDR=<your LAN ip>
  helper/testdata/bind/start.sh /tmp/bind` prints the variables below.
- Optional, for the backup and restore test: a WebDAV server the node can reach whose base path
  exists, for instance `pip install wsgidav cheroot` then
  `wsgidav --host <lan ip> --port 8081 --root /tmp/webdav --auth anonymous --no-config` after
  `mkdir /tmp/webdav/dnshelper-it`.

## Running

```bash
eval "$(BIND_ADDR=192.168.1.10 helper/testdata/bind/start.sh /tmp/bind)"
NS8_NODE=192.168.1.20 NS8_SSH_KEY=~/.ssh/id_ed25519 \
DNS_SERVER=$DNSHELPER_LIVE_RFC2136_SERVER DNS_KEY=$DNSHELPER_LIVE_RFC2136_KEY \
WEBDAV_URL=http://192.168.1.10:8081 \
    python3 -m unittest tests/integration/test_node.py -v
```

`NS8_NODE`, `DNS_SERVER` and `DNS_KEY` are required (the test is skipped without them);
`DNS_KEY_NAME` (default `dnshelper-test`), `DNS_ZONE` (default `example.test`), `WEBDAV_URL` and
`WEBDAV_BASEPATH` (default `dnshelper-it`) are optional. Stop the servers afterwards
(`helper/testdata/bind/stop.sh /tmp/bind`).

The Robot suite in `tests/` is the node's smoke test (`test-module.sh`); run it with the directory,
not the file, so that `__init__.robot` opens the SSH connection:

```bash
robot -v NODE_ADDR:<node> -v IMAGE_URL:localhost/dnshelper:test -v SSH_KEYFILE:~/.ssh/id_ed25519 tests/
```

after `tests/integration/build-on-node.sh <node>`.
