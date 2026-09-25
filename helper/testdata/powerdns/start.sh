#!/bin/bash
#
# Start a PowerDNS Authoritative server in Docker for the PowerDNS live tests and print the
# environment variables they read:
#
#   eval "$(helper/testdata/powerdns/start.sh [image])"
#
# The API key is random each time, so no key is stored in the repository. The zone is
# example.test, created through the API (so SOA-EDIT-API is set). The API listens on
# 127.0.0.1:8081, DNS on 127.0.0.1:5355.
set -euo pipefail
image=${1:-powerdns/pdns-auth-49:4.9.17}
name=dnshelper-pdns
key=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -p 127.0.0.1:8081:8081 -p 127.0.0.1:5355:53/udp -p 127.0.0.1:5355:53/tcp \
    -e PDNS_AUTH_API_KEY="$key" "$image" >/dev/null
for _ in $(seq 30); do
    curl -fsS -o /dev/null -H "X-API-Key: $key" http://127.0.0.1:8081/api/v1/servers/localhost 2>/dev/null && break
    sleep 1
done
curl -fsS -o /dev/null -H "X-API-Key: $key" -X POST \
    -d '{"name":"example.test.","kind":"Native","nameservers":["ns1.example.test."],"soa_edit_api":"DEFAULT"}' \
    http://127.0.0.1:8081/api/v1/servers/localhost/zones
echo "export DNSHELPER_LIVE_PDNS_URL=http://127.0.0.1:8081 DNSHELPER_LIVE_PDNS_KEY=$key DNSHELPER_LIVE_PDNS_ZONE=example.test"
