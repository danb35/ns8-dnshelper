#!/bin/bash
# Stop the BIND started by start.sh. Usage: stop.sh <work dir>
set -euo pipefail
kill "$(cat "${1:?usage: stop.sh <work dir>}/named.pid")"
