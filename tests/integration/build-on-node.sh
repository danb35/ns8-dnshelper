#!/bin/bash
#
# Build the dnshelper and dnsconsumer module images on an NS8 node, from local
# storage only: add-module pulls an image only when it is missing locally, so
# no registry is needed. Needs Go and a built UI (ui/dist) on this machine and
# podman on the node.
#
#   tests/integration/build-on-node.sh <node address> [tag]
#
# The images are localhost/dnshelper:<tag> and localhost/dnsconsumer:<tag> (default tag: test).
# To update an installed instance in place, build a NEW tag and run update-module with it:
# NS8 cannot update to an image URL the instance already has (its cleanup step needs the
# previous URL). update-on-node.sh does the build and the update.
set -euo pipefail
node=${1:?usage: build-on-node.sh <node address> [tag]}
tag=${2:-test}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
[ -f "$root/ui/dist/index.html" ] || { echo "build the UI first: cd ui && yarn build" >&2; exit 1; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/dnshelper" "$stage/consumer"

# the node is x86_64 Linux; the binary is static
(cd "$root/helper" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
    -o "$stage/dnshelper/imageroot-bin-dnshelper" ./cmd/dnshelper)
cp -R "$root/imageroot" "$stage/dnshelper/imageroot"
mkdir -p "$stage/dnshelper/imageroot/bin"
mv "$stage/dnshelper/imageroot-bin-dnshelper" "$stage/dnshelper/imageroot/bin/dnshelper"
cp -R "$root/ui/dist" "$stage/dnshelper/ui"
cp "$here/Containerfile.dnshelper" "$stage/dnshelper/Containerfile"
cp -R "$here/consumer/imageroot" "$here/consumer/ui" "$stage/consumer/"
cp "$here/Containerfile.consumer" "$stage/consumer/Containerfile"

COPYFILE_DISABLE=1 tar --no-xattrs -C "$stage" -cf - . | ssh "root@$node" '
    set -e
    rm -rf /root/dnshelper-it && mkdir /root/dnshelper-it
    tar -C /root/dnshelper-it -xf -
    cd /root/dnshelper-it
    podman build -q -t localhost/dnshelper:'"$tag"' dnshelper
    podman build -q -t localhost/dnsconsumer:'"$tag"' consumer
    cd / && rm -rf /root/dnshelper-it
    podman images --format "{{.Repository}}:{{.Tag}} {{.Size}}" | grep "^localhost/"'
