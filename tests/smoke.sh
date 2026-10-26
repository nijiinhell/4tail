#!/usr/bin/env bash
# Offline smoke test: serve a tiny SPA fixture, stub the network tools (httpx/nuclei/ffuf),
# run the pipeline, and assert the core data-flow invariants hold. Catches regressions like
# "0 JS", broken funnel feeds, or invalid findings.json. Needs python3 + curl + jq.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
have() { command -v "$1" >/dev/null 2>&1; }
for t in python3 curl jq; do have "$t" || { echo "SKIP: smoke test needs $t"; exit 0; }; done

tmp="$(mktemp -d)"; port=$(( (RANDOM % 20000) + 20000 ))
cleanup() { [ -n "${srv_pid:-}" ] && kill "$srv_pid" 2>/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT

# --- fixture: a script-less SPA index + bundles that reference /rest + /api + a secret -------
mkdir -p "$tmp/web"
printf '<!doctype html><html><head><base href="/"></head><body><app-root></app-root></body></html>' > "$tmp/web/index.html"
printf 'fetch("/rest/user/whoami");var a="/api/Challenges";var k="AKIAIOSFODNN7EXAMPLE";\n' > "$tmp/web/main.js"
printf 'console.log("v");var p="/rest/products/search?q=";\n' > "$tmp/web/vendor.js"
( cd "$tmp/web" && python3 -m http.server "$port" >/dev/null 2>&1 ) & srv_pid=$!
sleep 1
curl -s -o /dev/null "http://localhost:$port/main.js" || { echo "FAIL: fixture server not up"; exit 1; }

# --- stub the external tools the pipeline shells out to ------------------------------------
mkdir -p "$tmp/bin"
cat > "$tmp/bin/httpx" <<EOF
#!/bin/sh
out=""; while [ \$# -gt 0 ]; do [ "\$1" = "-o" ] && { out="\$2"; shift 2; continue; }; shift; done
line='{"url":"http://localhost:$port","status_code":200,"title":"Fix","webserver":"Py","tech":["Angular"],"content_length":90,"host":"127.0.0.1","a":["127.0.0.1"]}'
[ -n "\$out" ] && printf '%s\n' "\$line" > "\$out" || printf '%s\n' "\$line"; exit 0
EOF
for t in nuclei ffuf subfinder; do printf '#!/bin/sh\nexit 0\n' > "$tmp/bin/$t"; done
chmod +x "$tmp/bin"/*

out="$tmp/out"
PATH="$tmp/bin:$PATH" NO_TUI=1 ASSUME_YES=1 SOURCEMAPS=0 OUTDIR="$out" \
  bash "$ROOT/4tail.sh" -C -j "http://localhost:$port" >"$tmp/run.log" 2>&1

# --- assertions ---------------------------------------------------------------------------
fail=0
ck() { if eval "$2"; then echo "  ok: $1"; else echo "  FAIL: $1"; fail=1; fi; }
echo "assertions:"
ck "run exited 0"                 "[ -f '$out/report.md' ]"
ck "JS bundles discovered (>=2)"  "[ \"\$(wc -l <'$out/js_urls.txt' 2>/dev/null || echo 0)\" -ge 2 ]"
ck "endpoints mined from JS"      "grep -q '/rest/\|/api/' '$out/js_endpoints.txt' 2>/dev/null"
ck "funnel has active targets"    "[ -s '$out/targets_active.txt' ]"
ck "findings.json is valid JSON"  "jq -e . '$out/findings.json' >/dev/null 2>&1"
ck "report.md non-empty"          "[ -s '$out/report.md' ]"

if [ "$fail" = 0 ]; then echo "SMOKE: PASS"; else echo "SMOKE: FAIL"; echo "--- run.log tail ---"; tail -20 "$tmp/run.log"; fi
exit "$fail"
