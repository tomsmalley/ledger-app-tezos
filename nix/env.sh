#!/usr/bin/env bash

commit=$(git describe --abbrev=8 --always 2>/dev/null)
echo >&2 "Git commit: $commit"
shell_dir="$(nix-build -A env-shell --no-out-link --argstr commit "$commit" "$@")"
shell="$shell_dir/bin/env-shell"
echo >&2 "Entering via $shell"
exec "$shell"
