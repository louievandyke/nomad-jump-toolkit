#!/usr/bin/env bash

set -eu

# Resolve this launcher through one or more symlinks so `nomad-intake` can be
# installed in ~/bin while the toolkit remains elsewhere in the operator's
# home directory.
launcher_path=$0
while [ -L "$launcher_path" ]; do
    launcher_dir=$(CDPATH= cd -- "$(dirname -- "$launcher_path")" && pwd -P)
    launcher_target=$(readlink "$launcher_path")
    case "$launcher_target" in
        /*) launcher_path=$launcher_target ;;
        *) launcher_path=$launcher_dir/$launcher_target ;;
    esac
done

toolkit_root=$(CDPATH= cd -- "$(dirname -- "$launcher_path")" && pwd -P)
intake_script=$toolkit_root/scripts/case_intake.py

if [ ! -f "$intake_script" ]; then
    printf 'ERROR: case intake script not found: %s\n' "$intake_script" >&2
    exit 2
fi

exec python3 "$intake_script" "$@"
