#!/usr/bin/env bash

root="$(git rev-parse --show-toplevel)"

if [ -z "$@" ]; then
  unset ___empty
  : "${___empty:?No command given; try running $0 make}"
fi

inotifywait="$(nix-build '<nixpkgs>' -A inotify-tools --no-out-link)/bin/inotifywait"
while true; do
  "$root/nix/env.sh" <<EOF
    $@
EOF
  "$inotifywait" -qre close_write "$root/default.nix" "$root/nix" "$root/src" "$root/Makefile";
  echo "----------------------"
  echo
done
