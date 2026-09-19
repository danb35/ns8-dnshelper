# Local BIND for the RFC 2136 live tests

```bash
eval "$(helper/testdata/bind/start.sh /tmp/dnshelper-bind)"
cd helper && go test ./internal/app -run Live -v
helper/testdata/bind/stop.sh /tmp/dnshelper-bind
```

`start.sh` creates a random TSIG key each time and prints it as environment variables, so no
key is stored in the repository. The zone is `example.test`; its `keep` TXT record must be
left alone by every test.

The same configuration works in a container, for instance
`internetsystemsconsortium/bind9`: mount the rendered `named.conf` and zone file and publish
port 5354/tcp.
