#!/bin/sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${DIR}/pii_scrub.py"
if [ ! -f "$SCRIPT" ]; then
    SCRIPT="/app/pii_scrub.py"
fi
exec python3 -u "$SCRIPT" "$@"
