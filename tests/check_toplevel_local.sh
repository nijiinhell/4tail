#!/usr/bin/env bash
# Guard: a `local` used outside a function aborts under `set -u` the moment that code path runs
# (lib/*.sh are SOURCED at top level, so there is no enclosing function). `bash -n` cannot catch
# it - `local` is a builtin, not a syntax error. This static check does.
#
# How it works: per file, track whether we are inside a function body by brace depth, counting
# only REAL braces - first stripping ${...}, $(...), and quoted spans so jq filters, parameter
# expansions and strings don't skew the count. A function body is entered by a `name() {` (or
# `function name {`) opener. Any `local ` seen while that depth is 0 is a top-level local -> fail.
set -u
rc=0
for f in "$@"; do
  awk -v F="$f" '
    {
      s=$0
      gsub(/\$\{[^}]*\}/, "", s)      # ${...}
      while (match(s, /\$\([^()]*\)/)) sub(/\$\([^()]*\)/, "", s)   # $(...) incl. nested-ish
      gsub(/"[^"]*"/, "", s)          # "double quoted"
      gsub(/'\''[^'\'']*'\''/, "", s) # '\''single quoted'\''
      # function opener on this line?
      if (s ~ /^[[:space:]]*(function[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(\)[[:space:]]*\{/ \
          || s ~ /^[[:space:]]*function[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\{/) infn=1
      o = gsub(/\{/, "{", s); c = gsub(/\}/, "}", s)
      # a `local` on this line is only legal if we are already inside a function body
      if ($0 ~ /^[[:space:]]*local[[:space:]]/ && depth <= 0) {
        printf "%s:%d: top-level `local` (illegal when sourced): %s\n", F, NR, $0
        bad = 1
      }
      depth += o - c
      if (depth < 0) depth = 0
      if (depth == 0) infn = 0
    }
    END { exit (bad ? 1 : 0) }
  ' "$f" || rc=1
done
[ "$rc" = 0 ] && echo "no-top-level-local: OK"
exit "$rc"
