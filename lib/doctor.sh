# ===========================================================================
# DOCTOR - health checks (tools, wordlists, LLM connectivity) then exit
# ===========================================================================
DR_FAIL=0; DR_WARN=0
dr_pass(){ printf '  %s[PASS]%s %s\n' "$c_green"  "$c_reset" "$*"; }
dr_warn(){ printf '  %s[WARN]%s %s\n' "$c_yellow" "$c_reset" "$*"; DR_WARN=$((DR_WARN+1)); }
dr_fail(){ printf '  %s[FAIL]%s %s\n' "$c_red"    "$c_reset" "$*"; DR_FAIL=$((DR_FAIL+1)); }
dr_head(){ printf '\n%s== %s ==%s\n' "$c_cyan" "$*" "$c_reset"; }

# Minimal, dependency-light LLM ping: validates a model id works on this account.
llm_ping() {
  local m="$1" body resp code t json msg
  body="$(jq -n --arg model "$m" \
    '{model:$model, max_tokens:16, messages:[{role:"user",content:"reply with: ok"}]}' 2>/dev/null)"
  resp="$(curl -sS -m "$LLM_TIMEOUT" -w $'\n%{http_code} %{time_total}' \
    -H "content-type: application/json" -H "authorization: Bearer $LLM_API_KEY" \
    -d "$body" "$LLM_BASE_URL/chat/completions" 2>/dev/null)"
  code="$(printf '%s' "$resp" | tail -n1 | awk '{print $1}')"
  t="$(printf '%s'   "$resp" | tail -n1 | awk '{print $2}')"
  json="$(printf '%s' "$resp" | sed '$d')"
  msg="$(printf '%s' "$json" | jq -r '.error.message // .error // empty' 2>/dev/null)"
  if [ "$code" = 200 ] && printf '%s' "$json" | jq -e '.choices[0].message' >/dev/null 2>&1; then
    dr_pass "model '$m' reachable (${t}s)"
  elif [ -z "$code" ] || [ "$code" = 000 ]; then
    dr_fail "cannot REACH endpoint for '$m' - network/DNS/egress problem (not an auth issue)"
  elif [ "$code" = 401 ] || [ "$code" = 403 ]; then
    dr_fail "endpoint reachable, but API KEY REJECTED for '$m' (http $code)${msg:+ - $msg}"
  elif [ "$code" = 404 ]; then
    dr_fail "endpoint reachable, key OK, but MODEL id '$m' not found (http 404)${msg:+ - $msg}"
  else
    dr_fail "model '$m' NOT usable (http ${code:-?})${msg:+ - $msg}"
  fi
}

run_doctor() {
  printf '%s4tail doctor%s - environment health check\n' "$c_cyan" "$c_reset"

  dr_head "Required tools"
  local t
  for t in subfinder httpx nuclei; do
    if have "$t"; then dr_pass "$t found ($(command -v "$t"))"; else dr_fail "$t MISSING (install from projectdiscovery.io)"; fi
  done
  if have nuclei; then
    local tpl; tpl="$(locate_nuclei_templates)"
    if [ -n "$tpl" ]; then
      local nt; nt="$(grep -rhoE '^[[:space:]]*tags:' "$tpl" 2>/dev/null | wc -l | tr -d ' ')"
      dr_pass "nuclei templates: $tpl (~$nt tagged templates)"
    else
      dr_warn "nuclei templates not found - run 'nuclei -update-templates' (or UPDATE_TEMPLATES=1)"
    fi
  fi

  dr_head "Optional tools"
  for t in ffuf curl jq anew dnsx; do
    if have "$t"; then dr_pass "$t found"; else dr_warn "$t not found ($([ "$t" = ffuf ] && echo 'fuzzing skipped' || echo 'feature degraded'))"; fi
  done

  dr_head "Active funnel tools (-C) & JS/params (-j)"
  for t in katana gau waybackurls gf dalfox kxss Gxss arjun subjs sqlmap; do
    if have "$t"; then dr_pass "$t found"; else dr_warn "$t not found (that specialist is skipped)"; fi
  done
  if have interactsh-client; then dr_pass "interactsh-client found (OAST ready; enable with OAST=1)"
  else dr_warn "interactsh-client not found (OAST blind-bug confirmation disabled)"; fi

  dr_head "Agent toolbox (-A, the agent invokes these itself)"
  dr_pass "offered to agent: $(agent_tool_list)"
  # high-value optional tools + how to install them
  dr_head "Recon / surface extras (optional)"
  have tlsx      && dr_pass "tlsx found (cert-SAN subdomains)" || dr_warn "tlsx missing (go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest)"
  have cdncheck  && dr_pass "cdncheck found (CDN/WAF/cloud classify)" || dr_warn "cdncheck missing (go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest)"
  { have dnsgen || have gotator; } && dr_pass "permutation found (dnsgen/gotator)" || dr_warn "dnsgen missing (go install github.com/ProjectAnte/dnsgen@latest)"
  have qsreplace && dr_pass "qsreplace found (value-dedup)" || dr_warn "qsreplace missing (go install github.com/tomnomnom/qsreplace@latest)"
  have unfurl    && dr_pass "unfurl found (url parsing)" || dr_warn "unfurl missing (go install github.com/tomnomnom/unfurl@latest)"
  have corsy     && dr_pass "corsy found (CORS misconfig)" || dr_warn "corsy missing (pipx install corsy)"
  have waymore   && dr_pass "waymore found (multi-source URLs; preferred over gau+wayback)" || dr_warn "waymore missing (pipx install waymore) - falls back to gau+waybackurls"
  have x8        && dr_pass "x8 found (fast param discovery; preferred over arjun)" || dr_warn "x8 missing (cargo install x8) - falls back to arjun"
  have kr        && dr_pass "kiterunner (kr) found (API route discovery)" || dr_warn "kiterunner missing (github.com/assetnote/kiterunner) - API route prediction skipped"
  have feroxbuster && dr_pass "feroxbuster found (set FUZZ_ENGINE=feroxbuster to use it)" || dr_warn "feroxbuster missing - using ffuf (default)"
  { have dig || have host || have dnsx; } && dr_pass "DNS resolver found ($(have dig && echo dig || { have host && echo host || echo dnsx; })) - SPF/DMARC + zone-transfer checks on" || dr_warn "no dig/host/dnsx - DNS/email hygiene check skipped"

  dr_head "Agent optional tools"
  have crlfuzz    || dr_warn "crlfuzz missing - CRLF/header injection (go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest)"
  have x8         || dr_warn "x8 missing - fast hidden-param discovery (cargo install x8)"
  { have git-dumper || have gitdumper; } || dr_warn "git-dumper missing - dump exposed /.git source (pipx install git-dumper)"
  have trufflehog || dr_warn "trufflehog missing - verified secret scanning of dumped source (brew/apt/go install trufflehog)"

  dr_head "Wordlists (per-host lists are chosen at runtime from the detected tech)"
  if [ -n "$SECLISTS_DIR" ]; then
    dr_pass "SecLists: $SECLISTS_DIR"
    # how many content-discovery lists the dynamic matcher can actually draw from:
    local _idx; _idx="$(find "$SECLISTS_DIR/Discovery/Web-Content" -maxdepth 4 -type f \( -iname '*.txt' -o -iname '*.fuzz.txt' \) 2>/dev/null \
      | grep -viE 'raft-|big\.txt|directory-list|combined_|dirbuster|/all\.txt|/common\.txt' | wc -l | tr -d ' ')"
    dr_pass "  dynamic index: ~${_idx:-?} tech lists matchable by detected stack (CMS/*, api/*, *.fuzz.txt, jenkins/grafana/weblogic/...)"
    local rel
    for rel in Discovery/Web-Content/common.txt Discovery/Web-Content/CMS/wordpress.fuzz.txt \
               Discovery/Web-Content/api/api-endpoints.txt Discovery/Web-Content/JavaServlets-Common.fuzz.txt; do
      if [ -f "$SECLISTS_DIR/$rel" ]; then dr_pass "  sample present: $rel"; else dr_warn "  sample missing: $rel"; fi
    done
    dr_pass "  (actual per-host selection is logged to fuzz_plan.txt each run)"
  else
    dr_warn "SecLists not found (apt install seclists, or set SECLISTS_DIR)"
  fi
  if [ -n "$WORDLIST" ] && [ -f "$WORDLIST" ]; then
    case "$WORDLIST" in
      *fuzz.txt) dr_pass "Base list: $WORDLIST (Bo0oM juicy list, $(wc -l <"$WORDLIST" 2>/dev/null) lines)";;
      *)         dr_warn "Base list: $WORDLIST (not Bo0oM fuzz.txt; fine, but that list finds more)";;
    esac
    [ -n "$API_ENDPOINTS_EXTRA" ] && dr_pass "API list: $API_ENDPOINTS_EXTRA"
  else
    dr_warn "No base wordlist found (provide -w, or FETCH_FUZZTXT=1 to download Bo0oM/fuzz.txt)"
  fi

  dr_head "AI / LLM (Together AI or compatible)"
  if [ -z "$LLM_API_KEY" ]; then
    dr_warn "No API key set (TOGETHER_API_KEY) - AI steps will be skipped; scan still works with defaults"
  elif ! have curl || ! have jq; then
    dr_fail "curl and jq are required for AI steps"
  else
    dr_pass "API key present (length ${#LLM_API_KEY}, ends …${LLM_API_KEY: -4}); endpoint: $LLM_BASE_URL"
    [ "${#LLM_API_KEY}" -lt 40 ] && dr_warn "key looks SHORT (${#LLM_API_KEY} chars) - Together keys are ~64 hex chars; it may be truncated/incomplete"
    printf '  %sroutes%s plan=%s  triage=%s%s\n' "$c_dim" "$c_reset" \
      "$LLM_MODEL_PLAN" "$LLM_MODEL_TRIAGE" "${LLM_FALLBACK_MODELS:+  fallbacks=$LLM_FALLBACK_MODELS}"
    if [ "${LLM_BUDGET_USD:-0}" != 0 ]; then
      dr_pass "credit budget: \$$LLM_BUDGET_USD (prices \$$LLM_PRICE_IN in / \$$LLM_PRICE_OUT out per 1M tok - set to your model's real price)"
    else
      dr_warn "no credit budget set (LLM_BUDGET_USD=0 = unlimited); use -b 2 to cap spend"
    fi
    # Ping each unique configured model
    local seen="" m
    for m in "$LLM_MODEL_PLAN" "$LLM_MODEL_TRIAGE" ${LLM_FALLBACK_MODELS//,/ }; do
      [ -z "$m" ] && continue
      case ",$seen," in *",$m,"*) continue;; esac
      seen="$seen,$m"
      llm_ping "$m"
    done
  fi

  dr_head "Summary"
  if [ "$DR_FAIL" -gt 0 ]; then
    printf '  %s%d failed%s, %d warnings - fix the failures before running.\n' "$c_red" "$DR_FAIL" "$c_reset" "$DR_WARN"
    return 1
  elif [ "$DR_WARN" -gt 0 ]; then
    printf '  %sReady%s with %d warning(s) - 4tail will run (some features degraded).\n' "$c_green" "$c_reset" "$DR_WARN"
    return 0
  else
    printf '  %sAll good - 4tail is fully operational.%s\n' "$c_green" "$c_reset"
    return 0
  fi
}

if [ "$DOCTOR" = 1 ]; then run_doctor; exit $?; fi

# Enter the alternate screen buffer (like htop/less): a dedicated viewport the panel
# owns and redraws from home each frame, so nothing can scroll-duplicate or orphan it.
exec 3>&2   # keep a handle to the real terminal stderr so cleanup() can report even after the redirect below
if [ "$TUI" = 1 ]; then
  printf '\033[?1049h\033[?25l\033[2J\033[H'   # alt screen, hide cursor, clear, home
  render
  # In TUI mode stderr would corrupt the dashboard, so send it to a log. This also means an
  # abnormal exit (a crash hidden by the alt screen) can be surfaced by cleanup() below.
  [ -n "${OUTDIR:-}" ] && exec 2>>"$OUTDIR/run_stderr.log"
fi
STAGES_BEGAN=1

# Bring the OOB listener up now so it's live for the whole run (callbacks can land
# at any point once we start injecting payloads in the active funnel).
oast_start

