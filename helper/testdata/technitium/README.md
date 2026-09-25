# Local Technitium DNS Server for the RFC 2136 live tests

```bash
eval "$(helper/testdata/technitium/start.sh)"
cd helper && go test ./internal/app -run Live -v
helper/testdata/technitium/stop.sh
```

`start.sh` runs Technitium DNS Server 15.5.0 (`technitium/dns-server`) in Docker, with its web
console and API on 127.0.0.1:5380 and DNS on 127.0.0.1:5357. It creates a random admin password
and TSIG key and the zone `example.test`, sets the zone up the way the README describes for
Technitium (zone transfer and dynamic updates for the TSIG key only), and prints the environment
variables the tests read. dnshelper reaches Technitium through its RFC 2136 provider.
