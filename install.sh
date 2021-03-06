#!/bin/sh
set -eux

rootdir="$(cd "$(dirname "$0")"/; pwd)"

app_name=Tezos
if [ "${1:-}X" != X ]; then
    app_name="$1"
fi

app_file=$rootdir/bin/app.hex
if [ "${2:-}X" != X ]; then
    app_file="$2"
fi

if [ "${3:-}X" = X ]; then
    version="$(git -C "$rootdir" describe --tags | cut -f1 -d- | cut -f2 -dv)"
else
    version="$3"
fi

set -x
python -m ledgerblue.loadApp \
    --appFlags 0x00 \
    --dataSize 0x80 \
    --tlv \
    --curve ed25519 \
    --curve secp256k1 \
    --curve prime256r1 \
    --targetId "${TARGET_ID:-0x31100004}" \
    --delete \
    --path 44"'"/1729"'" \
    --fileName "$app_file" \
    --appName "$app_name" \
    --appVersion "$version" \
    --icon "$(cat "$rootdir/dist/icon.hex")" \
    --targetVersion ""
