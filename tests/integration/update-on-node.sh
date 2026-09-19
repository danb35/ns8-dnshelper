#!/bin/bash
#
# Build a new dnshelper image on a node and update an installed instance to it in place,
# keeping its zones, credentials and policy.
#
#   tests/integration/update-on-node.sh <node address> <module id> <new tag>
#
# The tag must be new for that instance (NS8 refuses to update to the image URL it already runs).
# update-module also runs a step inside the module's own rootless podman, whose image storage is
# separate from root's, so the image is loaded there first; a registry would make this
# unnecessary.
set -euo pipefail
node=${1:?usage: update-on-node.sh <node address> <module id> <new tag>}
module=${2:?usage: update-on-node.sh <node address> <module id> <new tag>}
tag=${3:?usage: update-on-node.sh <node address> <module id> <new tag>}
here=$(cd "$(dirname "$0")" && pwd)

"$here/build-on-node.sh" "$node" "$tag" >/dev/null
ssh "root@$node" "
    set -e
    podman save localhost/dnshelper:$tag | runagent -m $module podman load >/dev/null
    echo '{\"module_url\":\"localhost/dnshelper:$tag\",\"instances\":[\"$module\"]}' \
        | api-cli run update-module --data - >/dev/null
    podman rmi localhost/dnsconsumer:$tag >/dev/null 2>&1 || true
    echo \"$module now runs \$(redis-cli HGET module/$module/environment IMAGE_URL)\""
