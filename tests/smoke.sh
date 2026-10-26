#!/usr/bin/env bash
# Offline smoke test. Phase 1: no API key -> the deterministic/degraded path. Phase 2: a mock
# curl that answers the LLM endpoint with canned OpenAI-shaped JSON -> exercises every AI parser
# (plan tags, juicy select, agent rounds, triage extraction, reasoning-strip, cost math) with
# ZERO network and zero spend. Needs python3 + curl + jq.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
have() { command -v "$1" >/dev/null 2>&1; }
for t in python3 curl jq; do have "$t" || { echo "SKIP: smoke test needs $t"; exit 0; }; done
REAL_CURL="$(command -v curl)"

tmp="$(mktemp -d)"; port=$(( (RANDOM % 20000) + 20000 )); fail=0
cleanup() { [ -n "${srv_pid:-}" ] && kill "$srv_pid" 2>/dev/null; rm -rf "$tmp"; }
trap cleanup EXIT
ck() { if eval "$2"; then echo "  ok: $1"; else echo "  FAIL: $1"; fail=1; fi; }

# --- fixture: a script-less SPA index + bundles referencing /rest + /api + a secret ---------
mkdir -p "$tmp/web"
printf '<!doctype html><html><head><base href="/"></head><body><app-root></app-root></body></html>' > "$tmp/web/index.html"
printf 'fetch("/rest/user/whoami");var a="/api/Challenges";var k="AKIAIOSFODNN7EXAMPLE";\n' > "$tmp/web/main.js"
printf 'console.log("v");var p="/rest/products/search?q=";\n' > "$tmp/web/vendor.js"
( cd "$tmp/web" && python3 -m http.server "$port" >/dev/null 2>&1 ) & srv_pid=$!
sleep 1
"$REAL_CURL" -s -o /dev/null "http://localhost:$port/main.js" || { echo "FAIL: fixture server not up"; exit 1; }

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

# ===================== Phase 1: no AI =====================
echo "phase 1 (no AI):"
out1="$tmp/out1"
PATH="$tmp/bin:$PATH" NO_TUI=1 ASSUME_YES=1 SOURCEMAPS=0 OUTDIR="$out1" \
  bash "$ROOT/4tail.sh" -C -j "http://localhost:$port" >"$tmp/run1.log" 2>&1
ck "run exited (report written)"  "[ -f '$out1/report.md' ]"
ck "JS bundles discovered (>=2)"  "[ \"\$(wc -l <'$out1/js_urls.txt' 2>/dev/null||echo 0)\" -ge 2 ]"
ck "endpoints mined from JS"      "grep -q '/rest/\|/api/' '$out1/js_endpoints.txt' 2>/dev/null"
ck "funnel has active targets"    "[ -s '$out1/targets_active.txt' ]"
ck "findings.json valid JSON"     "jq -e . '$out1/findings.json' >/dev/null 2>&1"

# ===================== Phase 2: mock AI =====================
# A mock curl: canned OpenAI JSON for /chat/completions, pass-through for everything else.
cat > "$tmp/bin/curl" <<EOF
#!/usr/bin/env bash
is_llm=0; payload=""; args=("\$@")
for ((i=0;i<\${#args[@]};i++)); do
  case "\${args[\$i]}" in */chat/completions) is_llm=1 ;; -d) payload="\${args[\$((i+1))]}" ;; esac
done
[ "\$is_llm" = 1 ] || exec "$REAL_CURL" "\$@"
c="ok"
case "\$payload" in
  *'blueprint name'*)                 c="webapp_bounty" ;;
  *'nuclei_tags'*)                    c='{"nuclei_tags":["cves","exposures","misconfiguration","iis"]}' ;;
  *'numbered endpoint patterns'*)     c="1, 2" ;;
  *'autonomous web-app pentester'*)   c=\$'NOTES:\nmock hypothesis\nACTIONS:\nDECISION: STOP' ;;
  *'## Executive summary'*)           c=\$'reasoning noise...\n## Executive summary\nMock clean report.\n## Prioritised findings\nnone' ;;
  *'runnable bash script of curl PoCs'*) c="# no body-based PoC candidates from the collected data" ;;
  *'monitor a running nuclei scan'*)  c="scan 50% nominal, no errors, ETA 1m" ;;
esac
json="\$(jq -n --arg c "\$c" '{choices:[{message:{content:\$c},finish_reason:"stop"}],usage:{prompt_tokens:10,completion_tokens:12}}')"
printf '%s\n__HTTP__200' "\$json"
EOF
chmod +x "$tmp/bin/curl"

echo "phase 2 (mock AI):"
out2="$tmp/out2"
PATH="$tmp/bin:$PATH" NO_TUI=1 ASSUME_YES=1 SOURCEMAPS=0 OUTDIR="$out2" \
  TOGETHER_API_KEY="mock-key-for-smoke" LLM_BASE_URL="http://127.0.0.1:1/v1" \
  bash "$ROOT/4tail.sh" -C -j -A "http://localhost:$port" >"$tmp/run2.log" 2>&1
ck "AI plan tags applied"           "grep -q 'iis' '$out2/ai_scan_plan.txt' 2>/dev/null"
ck "triage report written"          "[ -s '$out2/report.md' ]"
ck "triage extracted from Exec summary" "grep -q '## Executive summary' '$out2/report.md'"
ck "reasoning noise stripped"       "! grep -q 'reasoning noise' '$out2/report.md'"
ck "cost ledger accrued (>0)"       "awk 'END{exit !(\$0+0>0)}' '$out2/.llm_cost_usd' 2>/dev/null || awk '{s+=\$1} END{exit !(s>0)}' '$out2/.llm_cost_usd'"
ck "findings.json valid JSON"       "jq -e . '$out2/findings.json' >/dev/null 2>&1"

if [ "$fail" = 0 ]; then echo "SMOKE: PASS"; else echo "SMOKE: FAIL"; echo "--- run1 tail ---"; tail -8 "$tmp/run1.log"; echo "--- run2 tail ---"; tail -8 "$tmp/run2.log"; fi
exit "$fail"
