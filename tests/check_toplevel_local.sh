#!/usr/bin/env bash
# Guard: a `local` used outside a function aborts under `set -u` the moment that code path runs
# (lib/*.sh are SOURCED at top level, so there is no enclosing function). `bash -n` cannot catch
# it - `local` is a builtin, not a syntax error. This static check does.
#
# We track function context by openers/closers, NOT by brace depth: counting { } breaks on the
# multi-line single-quoted awk programs and ${...} expansions all over this codebase. In this
# codebase every function opens with `name() {` (or `function name {`) and closes with a `}` at
# column 0; a one-line function `name() { ...; }` opens and closes on the same line. A `local`
# seen while NOT inside a function body is a top-level local -> fail.
set -u
rc=0
for f in "$@"; do
  awk -v F="$f" '
    # function opener: any line with name() ... (optionally function kw). A one-line function that
    # also ends with } is self-contained (skip it, do not enter function state).
    /^[[:space:]]*(function[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(\)/ ||
    /^[[:space:]]*function[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\{/ {
      if ($0 ~ /\}[[:space:]]*$/) { next }   # one-line function - stays balanced
      infn = 1; next
    }
    /^\}/ { infn = 0 }                        # a brace at column 0 ends the function body
    /^[[:space:]]*local[[:space:]]/ {
      if (!infn) { printf "%s:%d: top-level `local` (illegal when sourced): %s\n", F, NR, $0; bad = 1 }
    }
    END { exit (bad ? 1 : 0) }
  ' "$f" || rc=1
done
[ "$rc" = 0 ] && echo "no-top-level-local: OK"
exit "$rc"
