#!/bin/bash
# Start a throwaway BIND on ${BIND_ADDR:-127.0.0.1}:5354 serving example.test, for
# the RFC 2136 live tests. Usage: [BIND_ADDR=<lan ip>] start.sh <work dir>. Needs `named` (brew install
# bind, or the bind9 package). Prints the environment variables to export.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dir=$(mkdir -p "${1:?usage: start.sh <work dir>}" && cd "$1" && pwd)
addr=${BIND_ADDR:-127.0.0.1}
key=$(openssl rand -base64 32)
sed -e "s#@DIR@#$dir#g" -e "s#@ADDR@#$addr#g" -e "s#@KEY@#$key#g" "$here/named.conf.in" > "$dir/named.conf"
cp "$here/example.test.zone" "$dir/example.test.zone"
named-checkconf "$dir/named.conf"
named -c "$dir/named.conf" -u "$(id -un)" 2>"$dir/named.stderr" || { cat "$dir/named.stderr" >&2; exit 1; }
sleep 1
cat <<VARS
export DNSHELPER_LIVE_RFC2136_SERVER=$addr:5354
export DNSHELPER_LIVE_RFC2136_ZONE=example.test
export DNSHELPER_LIVE_RFC2136_KEY_NAME=dnshelper-test
export DNSHELPER_LIVE_RFC2136_KEY='$key'
VARS
