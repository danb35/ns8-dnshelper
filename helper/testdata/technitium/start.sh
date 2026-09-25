#!/bin/bash
#
# Start a Technitium DNS Server in Docker for the RFC 2136 live tests and print the environment
# variables they read:
#
#   eval "$(helper/testdata/technitium/start.sh [image])"
#
# It creates a random TSIG key (hmac-sha256) and the primary zone example.test, allows zone
# transfers for that key only, and dynamic updates for that key on the zone and every name under
# it (a security policy for example.test and *.example.test). The admin password is random too.
# The web console and API listen on 127.0.0.1:5380, DNS on 127.0.0.1:5357.
set -euo pipefail
image=${1:-technitium/dns-server:15.5.0}
name=dnshelper-technitium
pw=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
key=$(head -c 32 /dev/urandom | base64)
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -p 127.0.0.1:5380:5380 -p 127.0.0.1:5357:53/udp -p 127.0.0.1:5357:53/tcp \
    -e DNS_SERVER_ADMIN_PASSWORD="$pw" "$image" >/dev/null
api=http://127.0.0.1:5380/api
for _ in $(seq 60); do
    curl -fsS -o /dev/null "$api/user/login?user=admin&pass=$pw" 2>/dev/null && break
    sleep 1
done
token=$(curl -fsS "$api/user/login?user=admin&pass=$pw" | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
call() { curl -fsS -o /dev/null -H "Authorization: Bearer $token" --get "$api/$1" "${@:2}"; }
call settings/set --data-urlencode "tsigKeys=dnshelper-test|$key|hmac-sha256"
call zones/create --data-urlencode zone=example.test --data-urlencode type=Primary
call zones/options/set --data-urlencode zone=example.test \
    --data-urlencode zoneTransfer=Allow --data-urlencode zoneTransferTsigKeyNames=dnshelper-test \
    --data-urlencode update=Allow \
    --data-urlencode "updateSecurityPolicies=dnshelper-test|example.test|ANY|dnshelper-test|*.example.test|ANY"
echo "export DNSHELPER_LIVE_RFC2136_SERVER=127.0.0.1:5357 DNSHELPER_LIVE_RFC2136_ZONE=example.test DNSHELPER_LIVE_RFC2136_KEY_NAME=dnshelper-test DNSHELPER_LIVE_RFC2136_KEY=$key"
