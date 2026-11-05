#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

shopt -s nullglob
files=("$script_dir"/*.pdf)

if (( ${#files[@]} )); then
    rm -f -- "${files[@]}"
else
    echo "No PDF files found in $script_dir" >&2
fi
