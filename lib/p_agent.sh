# Step 5.5: AGENT MODE (-A) - autonomous validation loop.
# The AI is handed the juicy situation and, each round, decides the next GET probes
# to confirm/escalate issues itself; 4tail fires them (scope-locked, GET-only, secrets
# redacted), feeds the responses back, and the AI either digs one level deeper or moves
# on. Bounded by rounds + a wall-clock cap so it never camps on a single host.
: > "$agent_file"; : > "$agent_log"
if [ "$AGENT" != 1 ]; then
  set_stage $S_AGENT skip "off (-A to enable)"
elif [ "$AI_ENABLED" != 1 ]; then
  set_stage $S_AGENT skip "needs an API key"
elif ! budget_ok; then
  set_stage $S_AGENT skip "budget reached ($(cost_fmt))"
else
  set_stage $S_AGENT running "building situation"
  agent_seen="$OUTDIR/.agent_seen"; : > "$agent_seen"
  agent_loot_dir="$OUTDIR/agent_loot"; agent_post_n=0
  # Harvest real <form> fields NOW (before the probe loop) so the agent's POST probes use the
  # actual login/register field names instead of guessing. (PoC gen later reuses forms_file.)
  [ "$CRAWL" = 1 ] && harvest_forms
  # Secret value patterns: when a response matches, the RAW body is saved locally for the
  # human (never sent to the LLM) so a cred read via LFI is actually captured, not just noted.
  AGENT_SECRET_RE='connection[-_ ]?string|<add[^>]*connectionString|Data Source=|Server=.*;.*(Password|Pwd)=|Initial Catalog=|Provider=|machineKey|validationKey=|decryptionKey=|BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|password["'"'"' ]*[:=]|SA_PASSWORD|DB_PASSWORD'
  agent_capture_secret() {  # $1=url $2=raw-response ; saves raw locally if it carries a secret
    [ "$AGENT_LOOT" = 1 ] || return 0
    printf '%s' "$2" | grep -qiE -- "$AGENT_SECRET_RE" 2>/dev/null || return 0
    mkdir -p "$agent_loot_dir"
    local f="$agent_loot_dir/$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_' | tail -c 120).txt"
    { echo "# $1"; printf '%s\n' "$2"; } > "$f"
    printf '[SECRET-LOOT] %s | raw response with credentials saved -> %s\n' "$1" "$f" >> "$agent_file"
  }
  # Scope string for the AI: in single-host / custom-port mode, hand it the exact seed URL
  # (http://localhost:3000) so it keeps the scheme+port; otherwise the wildcard host scope.
  agent_scope="*.$domain"; [ "${SINGLE:-0}" = 1 ] && agent_scope="${SEED_URL:-$agent_scope}"
  # Compact "situation" brief: the juiciest, most actionable signals only.
  situation="$( {
      echo "TARGET SCOPE: $agent_scope"
      [ -s "${stale_file:-/dev/null}" ] && { echo "LEGACY HOSTS (older=prioritize):"; head -5 "$stale_file"; }
      [ -s "$dast_file" ] && { echo "CONFIRMED DAST (nuclei):"; head -20 "$dast_file"; }
      [ -s "$nuclei_file" ] && { echo "CONFIRMED NUCLEI (cves/exposures/misconfig/tech):"; head -20 "$nuclei_file"; }
      [ -s "$js_secrets_file" ] && { echo "JS SECRET CANDIDATES (url<TAB>match):"; head -15 "$js_secrets_file"; }
      [ -s "${sourcemap_file:-/dev/null}" ] && { echo "SOURCE MAPS RECOVERED (.js.map -> original source leaked; reconstructed source mined for secrets/endpoints above):"; head -10 "$sourcemap_file"; }
      [ -s "${api_specs_file:-/dev/null}" ] && { echo "EXPOSED API SPECS (fetch + inspect):"; head -10 "$api_specs_file"; }
      [ -s "${gql_schema_file:-/dev/null}" ] && { echo "GRAPHQL INTROSPECTION OPEN (full schema readable - map authz/IDOR per field):"; head -60 "$gql_schema_file"; }
      [ -s "${bypass_file:-/dev/null}" ] && { echo "ACCESS-CONTROL BYPASSES (403->200):"; head -10 "$bypass_file"; }
      [ -s "${idor_file:-/dev/null}" ] && { echo "IDOR / AUTHZ CANDIDATES:"; head -10 "$idor_file"; }
      [ -s "$findings_dir/kxss.txt" ] && { echo "REFLECTED PARAMS (kxss):"; head -15 "$findings_dir/kxss.txt"; }
      [ -s "${js_endpoints_file:-/dev/null}" ] && { echo "MINED API ENDPOINTS (from JS bundles - the SPA's real /rest + /api surface; GET them, POST login/register bodies, id-walk numeric path segments):"; head -40 "$js_endpoints_file"; }
      [ -s "$gf_file" ] && { echo "GF CANDIDATE BUCKETS (class<TAB>url):"; head -40 "$gf_file"; }
      [ -s "$fuzz_findings_file" ] && { echo "EMPTY/SMALL 200 ENDPOINTS (param-mine candidates):";
        awk -F'\t' '$1==200 && $2+0<80 {print $3}' "$fuzz_findings_file" | head -15; }
      [ -s "$fuzz_findings_file" ] && { echo "NOTABLE PATHS:";
        awk -F'\t' '$1~/^(200|301|302|401|403)$/{print $1" "$3}' "$fuzz_findings_file" | grep -ivE 'google\.com|etc.{0,3}passwd' | head -25; }
      [ -s "${forms_file:-/dev/null}" ] && { echo "HARVESTED FORMS (page<TAB>method<TAB>action<TAB>fields - use these REAL field names for POST probes: auth SQLi, mass assignment, CSRF):"; head -20 "$forms_file"; }
      [ "$OAST" = 1 ] && [ -n "${OAST_DOMAIN:-}" ] && echo "OAST DOMAIN: you have an out-of-band collaborator. Put a unique subdomain like agent-r<round>.$OAST_DOMAIN into url/redirect/callback params or SSRF-able fields; a DNS/HTTP callback to it CONFIRMS blind SSRF/RCE."
    } | head -c 12000 )"
  astart=$SECONDS; round=0; results="(none yet - this is the first round)"
  agent_notes="(none yet - first round; form your initial hypotheses from the situation)"
  toolcalls=0
  agent_tools=""; [ "$AGENT_TOOLS" = 1 ] && agent_tools="$(agent_tool_list)"
  while [ "$round" -lt "$AGENT_ROUNDS" ]; do
    round=$((round+1))
    budget_ok || { SUP_NOTE="agent: budget reached, stopping"; break; }
    [ "$AGENT_MAX_TIME" -gt 0 ] 2>/dev/null && [ $((SECONDS-astart)) -ge "$AGENT_MAX_TIME" ] && break
    set_stage $S_AGENT running "round $round/$AGENT_ROUNDS: AI thinking"
    aout="$(mktemp)"
    # Reasoning models (GLM/DeepSeek) spend tokens on internal CoT before emitting .content;
    # too small a budget => finish_reason=length with empty content => "no probes proposed".
    ai_call "$LLM_MODEL_PLAN" "${LLM_MAX_TOKENS_PLAN:-6000}" \
"You are an autonomous web-app pentester on an AUTHORIZED target, working in rounds. You keep a running NOTES block (your hypotheses: what you suspect, why, and what is confirmed / refuted / still-unconfirmed), update it each round from the latest results, then take the next ACTIONS to chase the hottest lead, then decide whether to keep going.
Three kinds of action:
  GET <url> | why | success-regex            -> a passive fetch you confirm by regex (LFI reads, redirects, param mining, IDOR id-walking).
  POST <url> | body | why | success-regex    -> a form/JSON POST to test BODY-based bugs: login/register logic, body IDOR/SQLi, mass assignment. body is raw urlencoded (e.g. tfUName=%27&tfUPass=x) or JSON. NON-DESTRUCTIVE only: benign markers, id=1/id=2, a single quote for SQLi - never DROP/DELETE/TRUNCATE/SHUTDOWN/xp_cmdshell or mass writes (those are refused).
  TOOL <name> <url> | tags=...               -> run a real tool. ONLY these are installed: ${agent_tools:-none}. Use them to CONFIRM, e.g. sqlmap on a SQLi-looking param (it always runs capped at --level=1 --risk=1; higher levels are ignored), dalfox on a reflecting param, nuclei <url> tags=iis,cve on a fingerprinted host, git-dumper on an exposed /.git, nuclei-dast to fuzz a param URL. Prefer a TOOL to prove a lead over guessing.
Ideas: confirmed/possible LFI (Templatize.asp?item=) -> read ../web.config, ../global.asa, ../../../windows/win.ini (if it holds a connection string / machineKey, 4tail saves the raw file for the human - you just confirm the read with a regex like connectionString); empty/small 200 endpoints -> add params ?id=1&debug=1; redirect params -> //example.org/ and watch Location; exposed /.git -> git-dumper.
For the MINED API ENDPOINTS (SPA /rest + /api) go further than GET: (a) PATH-IDOR/BOLA - a numeric path segment like /api/Users/1 or /rest/basket/3 is an object id, so GET the neighbour (/2, /4) and compare; a readable neighbour you should not own is a lead; (b) AUTH/SQLi - POST a JSON body to a login/authentication endpoint with a single-quote injected into the email/username field and look for a SQL error or an unexpected auth success; (c) MASS ASSIGNMENT - POST/register with an extra JSON field such as role set to admin, or isAdmin true, and check whether it sticks. Use the POST action for (b) and (c); a body that starts with a brace is sent as application/json.
All URLs MUST be on the target scope $agent_scope (keep the scheme and port exactly as given). Respond in EXACTLY this structure, nothing else:
NOTES:
<2-6 short lines: updated hypotheses + status>
ACTIONS:
<one GET, POST or TOOL line each>
DECISION: CONTINUE
(use 'DECISION: STOP' when leads are exhausted or everything promising is already confirmed)" \
"SITUATION:
$situation

AVAILABLE TOOLS: ${agent_tools:-none}

YOUR NOTES SO FAR:
$agent_notes

LATEST RESULTS:
$results" > "$aout" 2>>"$llm_log" || true
    # --- parse the structured reply (robust to reasoning-model wrapping) ---
    # NOTES: text between a NOTES marker and the PROBES/DECISION marker.
    new_notes="$(awk 'BEGIN{p=0} /^[[:space:]]*NOTES[[:space:]]*:/{p=1;next} /^[[:space:]]*(ACTIONS|PROBES|DECISION)[[:space:]]*:/{p=0} p' "$aout" | sed '/^[[:space:]]*$/d' | head -n 8)"
    [ -n "$new_notes" ] && agent_notes="$new_notes"
    # DECISION: explicit STOP only (default is to continue while leads/probes remain).
    decision="$(grep -ioE 'DECISION[[:space:]]*:[[:space:]]*(CONTINUE|STOP)' "$aout" | head -1 | grep -ioE '(CONTINUE|STOP)' | tr 'a-z' 'A-Z')"
    # ACTIONS: lines under the ACTIONS/PROBES section (GET or TOOL); fall back to any URL line.
    probes="$(awk 'BEGIN{p=0} /^[[:space:]]*(ACTIONS|PROBES)[[:space:]]*:/{p=1;next} /^[[:space:]]*DECISION[[:space:]]*:/{p=0} p' "$aout" | grep -iE 'https?://|^[[:space:]]*TOOL ')"
    [ -n "$probes" ] || probes="$(grep -iE 'https?://|^[[:space:]]*TOOL ' "$aout")"
    probes="$(printf '%s\n' "$probes" | head -n $((AGENT_MAX_PROBES * 3)))"; rm -f "$aout"
    printf '=== round %s notes ===\n%s\n' "$round" "$agent_notes" >> "$agent_log"
    [ -n "$probes" ] || { [ "$round" -eq 1 ] && SUP_NOTE="agent: no probes proposed"; break; }
    # Default "looks sensitive" markers so a probe can confirm even when the model gives no regex.
    agent_default_rx='connectionString|<configuration|<\?xml|root:.{0,40}:0:0:|\[fonts\]|\[extensions\]|16-bit app support|BEGIN [A-Z ]*PRIVATE KEY|DB_PASSWORD|SA_PASSWORD|Microsoft OLE DB|ODBC|SQL syntax.*MySQL|ORA-[0-9]{4,}|Directory of |<web-app|runtime error'
    results=""; np=0
    while IFS= read -r pline; do
      # TOOL action: the agent runs a real tool itself (capped, scope-locked, whitelisted).
      if [ "$AGENT_TOOLS" = 1 ] && printf '%s' "$pline" | grep -qiE '(^|[^a-z])TOOL[: ]+[a-z]'; then
        [ "$toolcalls" -ge "$AGENT_MAX_TOOLCALLS" ] && continue
        tname="$(printf '%s' "$pline" | sed -E 's/.*TOOL[: ]+//I' | awk '{print tolower($1)}')"
        ttgt="$(printf '%s' "$pline" | grep -oiE 'https?://[^ "'"'"'`|<>]+' | head -1)"
        [ -n "$ttgt" ] || ttgt="$(printf '%s' "$pline" | grep -oiE '([a-z0-9-]+\.)+[a-z]{2,}' | head -1)"
        # Everything after the first '|' is the tool's extra args (tags= for nuclei, or the
        # safe sqlmap enum flags) - not just tags=, so the agent can actually pass them.
        textra="$(printf '%s' "$pline" | awk -F'|' 'NF>=2{sub(/^[^|]*\|/,""); print; exit}' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [ -n "$tname" ] && [ -n "$ttgt" ] || continue
        case " $agent_tools " in *" $tname "*) ;; *) continue ;; esac   # only offered tools
        grep -qxF "TOOL $tname $ttgt" "$agent_seen" 2>/dev/null && continue
        printf 'TOOL %s %s\n' "$tname" "$ttgt" >> "$agent_seen"; toolcalls=$((toolcalls+1))
        set_stage $S_AGENT running "round $round: TOOL $tname ($toolcalls/$AGENT_MAX_TOOLCALLS)"; render
        tr_out="$(agent_tool_run "$tname" "$ttgt" "$textra")"
        printf '[r%s] %s\n' "$round" "$tr_out" >> "$agent_log"
        results="$results"$'\n'"$tr_out"
        continue
      fi
      # POST probe: the agent tests a BODY-based bug itself (login/register logic, body
      # IDOR/SQLi, mass assignment). Scope-locked, capped, destructive bodies refused.
      if [ "$AGENT_POST" = 1 ] && printf '%s' "$pline" | grep -qiE '(^|[^a-z])POST[: ]+https?://'; then
        [ "$np" -ge "$AGENT_MAX_PROBES" ] && continue
        [ "$agent_post_n" -ge "$AGENT_MAX_POST" ] && continue
        purl="$(printf '%s' "$pline" | sed -E 's/.*POST[: ]+//I' | awk -F'|' '{print $1}' | grep -oiE 'https?://[^ "'"'"'`<>]+' | head -1)"
        pbody="$(printf '%s' "$pline" | awk -F'|' 'NF>=2{print $2}' | sed 's/^ *//;s/ *$//')"
        pwhy="$(printf '%s'  "$pline" | awk -F'|' 'NF>=3{print $3}' | sed 's/^ *//;s/ *$//')"; [ -n "$pwhy" ] || pwhy="agent POST probe"
        prx="$(printf '%s'   "$pline" | awk -F'|' 'NF>=4{print $4}' | sed 's/^ *//;s/ *$//')"; [ -n "$prx" ] || prx="$agent_default_rx"
        [ -n "$purl" ] || continue
        printf '%s' "$purl" | grep -qiE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" || continue   # scope lock
        # refuse clearly destructive bodies (quote probes / OR 1=1 / mass-assignment are allowed)
        if printf '%s' "$pbody" | grep -qiE 'drop[[:space:]]+table|truncate[[:space:]]+table|delete[[:space:]]+from|shutdown|xp_cmdshell|sp_configure|;[[:space:]]*drop|rm[[:space:]]+-rf|format[[:space:]]+c:'; then
          printf '[r%s] POST refused (destructive body): %s\n' "$round" "$purl" >> "$agent_log"; continue
        fi
        grep -qxF "POST $purl $pbody" "$agent_seen" 2>/dev/null && continue
        printf 'POST %s %s\n' "$purl" "$pbody" >> "$agent_seen"; np=$((np+1)); agent_post_n=$((agent_post_n+1))
        set_stage $S_AGENT running "round $round: POST probe ($agent_post_n/$AGENT_MAX_POST)"; render
        pct="application/x-www-form-urlencoded"; case "$pbody" in \{*|\[*) pct="application/json" ;; esac
        presp="$(_cap curl -s -i -L -X POST --max-time 15 ${CURL_NET[@]+"${CURL_NET[@]}"} -H "Content-Type: $pct" --data "$pbody" "$purl" 2>/dev/null | head -c 6000)"
        agent_capture_secret "$purl" "$presp"
        pred="$(printf '%s' "$presp" | sed -E 's/((pass(word|wd)?|connection[-_ ]?string|accountkey|secret|api[-_]?key|token)[^[:cntrl:]]{0,8}[:=])[^[:cntrl:]"'"'"']{1,}/\1<redacted>/Ig')"
        phit=""; printf '%s' "$presp" | grep -qiE -- "$prx" 2>/dev/null && phit="HIT"
        pstatus="$(printf '%s' "$presp" | head -1 | tr -d '\r')"
        psnip="$(printf '%s' "$pred" | tr '\n\r\t' '   ' | sed -E 's/  +/ /g' | head -c 240)"
        printf '[r%s] POST %-4s %s (body: %.60s)\n   why: %s\n   resp: %s | %s\n' "$round" "${phit:-...}" "$purl" "$pbody" "$pwhy" "$pstatus" "$psnip" >> "$agent_log"
        results="$results"$'\n'"POST $purl => ${phit:-no-match} [$pstatus] $psnip"
        [ "$phit" = HIT ] && printf '[CONFIRMED] POST %s (body: %s) | %s\n' "$purl" "$pbody" "$pwhy" >> "$agent_file"
        continue
      fi
      # GET probe (passive fetch, regex-confirmed).
      [ "$np" -ge "$AGENT_MAX_PROBES" ] && continue
      url="$(printf '%s' "$pline" | grep -oiE 'https?://[^ "'"'"'`|<>]+' | head -1)"
      [ -n "$url" ] || continue
      why="$(printf '%s' "$pline" | awk -F'\\|' 'NF>=2{print $2}' | sed 's/^ *//;s/ *$//')"; [ -n "$why" ] || why="agent probe"
      rx="$(printf '%s'  "$pline" | awk -F'\\|' 'NF>=3{print $3}' | sed 's/^ *//;s/ *$//')"; [ -n "$rx" ] || rx="$agent_default_rx"
      # HARD GUARDRAILS: http(s) only, must be in target scope, no dup probes.
      printf '%s' "$url" | grep -qiE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" || continue
      grep -qxF "$url" "$agent_seen" 2>/dev/null && continue
      printf '%s\n' "$url" >> "$agent_seen"; np=$((np+1))
      set_stage $S_AGENT running "round $round: probing ($(nlines "$agent_seen") sent)"; render
      resp="$(curl -s -i -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} "$url" 2>/dev/null | head -c 6000)"
      agent_capture_secret "$url" "$resp"   # save raw creds locally (not to the LLM) if present
      # redact anything that looks like a secret before it is stored or sent back to the LLM
      red="$(printf '%s' "$resp" | sed -E 's/((pass(word|wd)?|connection[-_ ]?string|accountkey|secret|api[-_]?key|token|aws[_-]?secret[_-]?access[_-]?key)[^[:cntrl:]]{0,8}[:=])[^[:cntrl:]"'"'"']{1,}/\1<redacted>/Ig')"
      hit=""; [ -n "$rx" ] && printf '%s' "$resp" | grep -qiE -- "$rx" 2>/dev/null && hit="HIT"
      local_status="$(printf '%s' "$resp" | head -1 | tr -d '\r')"
      snippet="$(printf '%s' "$red" | tr '\n\r\t' '   ' | sed -E 's/  +/ /g' | head -c 240)"
      printf '[r%s] %-4s %s\n   why: %s\n   resp: %s | %s\n' "$round" "${hit:-...}" "$url" "$why" "$local_status" "$snippet" >> "$agent_log"
      results="$results"$'\n'"$url => ${hit:-no-match} [$local_status] $snippet"
      [ "$hit" = HIT ] && printf '[CONFIRMED] %s | %s\n' "$url" "$why" >> "$agent_file"
    done <<< "$probes"
    [ -n "$results" ] || break
    # The AI chases a hot lead across rounds, but stops itself when exhausted.
    if [ "$decision" = STOP ]; then SUP_NOTE="agent: stopping (leads exhausted)"; break; fi
  done
  # Persist the agent's final reasoning for the report/transcript.
  { echo "=== final hypotheses ==="; printf '%s\n' "$agent_notes"; } >> "$agent_log"
  set_stage $S_AGENT done "$(nlines "$agent_file") confirmed · $(nlines "$agent_seen") actions (${toolcalls:-0} tool runs) · ${round}r"
fi

# OOB: correlate any interactsh callbacks to the URLs we injected, then stop the listener -
# BEFORE verify/report/triage, so confirmed blind SSRF/redirect hits reach report.md and the
# AI analyst (not just findings.json).
oast_correlate
oast_stop

# Verification: re-test confirmed findings so the report/triage lead with proven ones.
if [ "$VERIFY" = 1 ]; then set_stage $S_TRIAGE running "verifying findings"; verify_findings; fi

# Report header
{
  echo "# 4tail recon report"; echo
  echo "- **Target:** \`$domain\`"
  echo "- **Generated:** $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "- **Subdomains:** $sub_count | **Live:** $alive_count | **Nuclei findings:** $find_count | **Fuzz hits:** $(fuzz_distinct "$fuzz_findings_file") distinct (${fuzz_hits:-0} raw)"
  [ "$JSMINE" = 1 ] && echo "- **JS mined:** $(nlines "$js_urls_file") files, $(nlines "$js_secrets_file") secret hits, $(nlines "$params_file") params, $(nlines "${js_endpoints_file:-/dev/null}") endpoints, $(nlines "${sourcemap_file:-/dev/null}") source maps recovered"
  if [ "$CRAWL" = 1 ]; then
    echo "- **Active funnel (${BLUEPRINT_NAME:-defaults}):** $(nlines "$urls_file") urls → $(nlines "$url_patterns_file") patterns → **$(nlines "$targets_active_file") juicy**"
    echo "  - specialists → DAST:$(nlines "$dast_file") · dalfox:$(nlines "$findings_dir/dalfox.txt") · kxss:$(nlines "$findings_dir/kxss.txt") · sqlmap:$(nlines "$findings_dir/sqlmap.txt")"
  fi
  echo "- **Nuclei:** ${nuclei_target_count:-$alive_count} hosts scanned (deduped from $alive_count) | tags \`$nuclei_tags\` | severity \`$NUCLEI_SEVERITY\`"
  echo "- **AI models:** $([ "$AI_ENABLED" = 1 ] && echo "plan=$LLM_MODEL_PLAN, triage=$LLM_MODEL_TRIAGE" || echo "disabled")"
  [ "$AI_ENABLED" = 1 ] && echo "- **Estimated AI spend:** $(cost_fmt)$([ "${LLM_BUDGET_USD:-0}" != 0 ] && echo " (budget \$$LLM_BUDGET_USD)")"
  echo "- **SecLists:** ${SECLISTS_DIR:-not found} | **Base wordlist:** \`$WORDLIST\`"; echo
  if [ -s "${verified_file:-/dev/null}" ]; then
    echo "## ✅ Verified findings (survived an independent re-test)"; echo; echo '```'; cat "$verified_file"; echo '```'; echo
  fi
  if [ -s "${corsy_file:-/dev/null}" ]; then
    echo "## CORS misconfiguration (Corsy)"; echo; echo '```'; cat "$corsy_file"; echo '```'; echo
  fi
  if [ "$AGENT" = 1 ] && { [ -s "$agent_file" ] || [ -n "${agent_notes:-}" ]; }; then
    echo "## 🤖 Agent (autonomous probe loop)"; echo
    if [ -s "$agent_file" ]; then echo "**Confirmed / escalated:**"; echo '```'; cat "$agent_file"; echo '```'; echo; fi
    if [ -n "${agent_notes:-}" ]; then echo "**Final hypotheses:**"; echo '```'; printf '%s\n' "$agent_notes"; echo '```'; echo; fi
  fi
  if [ -s "$fuzz_findings_file" ]; then
    echo "## Content discovery hits (ffuf, top 100)"
    echo
    echo '| Status | Length | URL | Count |'
    echo '|--------|--------|-----|-------|'
    # group by response fingerprint (status,length) so WAF noise / case-variants collapse
    awk -F'\t' 'NF>=3{k=$1"\t"$2; c[k]++; if(!(k in r)) r[k]=$3}
        END{for(k in c) printf "%s\t%s\t%d\n", k, r[k], c[k]}' "$fuzz_findings_file" \
      | sort -t"$(printf '\t')" -k1,1n -k3,3nr | head -n 100 \
      | while IFS=$'\t' read -r st len u c; do
          echo "| $st | $len | \`$u\` | $([ "$c" -gt 1 ] && echo "×$c" || echo 1) |"
        done
    echo
  fi
  if [ -s "$dast_file" ]; then
    echo "## DAST findings (nuclei -dast)"; echo; echo '```'; head -n 100 "$dast_file"; echo '```'; echo
  fi
  if [ -s "${bypass_file:-/dev/null}" ]; then
    echo "## Access-control bypasses (403/401 → 2xx)"; echo; echo '```'; cat "$bypass_file"; echo '```'; echo
  fi
  if [ -s "${idor_file:-/dev/null}" ]; then
    echo "## IDOR / broken-authz candidates (verify object ownership)"; echo; echo '```'; cat "$idor_file"; echo '```'; echo
  fi
  if [ -s "${prop_file:-/dev/null}" ]; then
    echo "## Cross-host paths (found on one host, live on another)"; echo; echo '```'; head -n 60 "$prop_file"; echo '```'; echo
  fi
  if [ -s "$findings_dir/dalfox.txt" ]; then
    echo "## XSS (dalfox)"; echo; echo '```'; head -n 80 "$findings_dir/dalfox.txt"; echo '```'; echo
  fi
  if [ -s "$findings_dir/sqlmap.txt" ]; then
    echo "## SQLi confirmation (sqlmap)"; echo; echo '```'; head -n 80 "$findings_dir/sqlmap.txt"; echo '```'; echo
  fi
  if [ -s "$findings_dir/kxss.txt" ]; then
    echo "## Reflected-param candidates (kxss) — top 40"; echo; echo '```'; head -n 40 "$findings_dir/kxss.txt"; echo '```'; echo
  fi
} > "$report_file"

