# Local PowerDNS for the PowerDNS live tests

```bash
eval "$(helper/testdata/powerdns/start.sh)"
cd helper && go test ./internal/app -run Live -v
helper/testdata/powerdns/stop.sh
```

`start.sh` runs PowerDNS Authoritative 4.9.17 (`powerdns/pdns-auth-49`) in Docker with the API on
127.0.0.1:8081 and DNS on 127.0.0.1:5355, creates a random API key and the zone `example.test`,
and prints the environment variables the tests read. Give another image as its argument to test
another version, for instance `powerdns/pdns-auth-50:5.0.7`; both were tested.
