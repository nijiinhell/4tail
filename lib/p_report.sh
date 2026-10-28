# Step 5.9: PoC generation for BODY-BASED bug classes (manual, never fired by 4tail).
# 4tail is GET-only when it fires requests; POST-driven bugs (auth/logic on login+register,
# body IDOR/SQLi, mass assignment, GraphQL mutations, CSRF) are detected but not exercised.
# Here we harvest the real form fields deterministically, then have the AI write ready-to-run
# curl PoCs for the HUMAN - keeping the firing invariant while closing the coverage gap.
: > "$poc_file"
if [ "$CRAWL" = 1 ] && [ "$POC_GEN" = 1 ] && [ "$AI_ENABLED" = 1 ] && budget_ok; then
  set_stage $S_TRIAGE running "harvesting forms for PoCs"
  harvest_forms   # no-op if the agent stage already harvested them
  # (b) AI writes the PoCs from the harvested forms + the injectable/authz signals we already have
  set_stage $S_TRIAGE running "AI writing manual PoCs"
  poc_sys='You are a bug-bounty exploitation assistant on an AUTHORIZED engagement. Write a runnable bash script of curl PoCs for the BODY-BASED / state-changing bug classes a GET-only scanner cannot fire: POST auth & logic flaws (login, register, password-reset), body-based IDOR and SQLi, mass assignment (extra JSON fields like "role":"admin","isAdmin":true), GraphQL mutations, and CSRF (missing anti-CSRF token). Rules: one PoC per block; above each, a "# WHAT:" line (bug class + why this endpoint) and a "# CONFIRM:" line (the exact response signal that proves it). Use the real form fields and parameters given. Same-origin only. NON-DESTRUCTIVE: no DELETE/DROP/mass writes - use benign markers (e.g. value "4tailPoC"), id=1/id=2 for IDOR, a single quote for SQLi. Reference the session as the shell var $SESSION in a -H header so the human pastes their cookie/token. Output ONLY the bash script body (no markdown fences, no prose outside comments). If the data shows no plausible body-based test, output just: # no body-based PoC candidates from the collected data'
  poc_out="$(mktemp)"
  ai_call "$LLM_MODEL_TRIAGE" "${LLM_MAX_TOKENS_TRIAGE:-8000}" "$poc_sys" "Target: $domain

=== harvested forms (page <TAB> method <TAB> action <TAB> field names) ===
$(head -c 6000 "$forms_file")

=== gf injection/authz candidate URLs (class <TAB> url) ===
$(grep -iE '^(sqli|idor|redirect|ssrf|ssti|lfi)\b' "$gf_file" 2>/dev/null | head -n 60 | head -c 6000)

=== discovered parameters (url <TAB> param) ===
$(head -c 3000 "$params_file" 2>/dev/null)

=== GraphQL schema (if introspection was open - write mutation PoCs) ===
$(head -c 6000 "${gql_schema_file:-/dev/null}" 2>/dev/null)

=== mined API endpoints (SPA /rest + /api surface - no HTML forms exist, so write PoCs for these: login/register, body IDOR on numeric path ids, mass assignment) ===
$(grep -iE '/api/|/rest/|/graphql' "${js_endpoints_file:-/dev/null}" 2>/dev/null | head -n 60 | head -c 5000)

=== mined request field names (the app's real body/param vocabulary - use these in PoC bodies, not guesses) ===
$(paste -sd, "${js_fields_file:-/dev/null}" 2>/dev/null | head -c 1200)

=== exposed API specs (Swagger/OpenAPI/GraphQL - derive request shapes) ===
$(head -c 3000 "${api_specs_file:-/dev/null}" 2>/dev/null)

=== agent-confirmed / verified issues (anchor PoCs to these first) ===
$(head -c 3000 "$agent_file" 2>/dev/null)
$(head -c 2000 "${verified_file:-/dev/null}" 2>/dev/null)" >"$poc_out" 2>>"$llm_log" || true
  if [ -s "$poc_out" ] && ! grep -q 'no body-based PoC candidates' "$poc_out"; then
    {
      echo "#!/usr/bin/env bash"
      echo "# 4tail MANUAL PoCs for $domain - generated $(date -u +%FT%TZ)"
      echo "# 4tail did NOT run these (it only fires GET). REVIEW every command, then set your"
      echo "# session and run the ones you want:   export SESSION='Cookie: session=...'"
      echo "# Authorized testing only."
      echo "set -u"
      # Default SESSION so the no-auth PoCs (login SQLi, unauth register) run without a crash;
      # the user overrides it with their real cookie/token when testing authed endpoints.
      echo ': "${SESSION:=Cookie: 4tail=none}"'
      echo
      # strip code fences, any shebang the model emitted, AND any SESSION=/TARGET= reassignment
      # (the model likes to emit SESSION="PASTE_...HERE", which would clobber the user's real value)
      sed -E '/^```/d; /^#!\/.*(bash|sh)[[:space:]]*$/d; /^[[:space:]]*(export[[:space:]]+)?(SESSION|TARGET|BASE)=/d' "$poc_out"
    } > "$poc_file"
    chmod +x "$poc_file" 2>/dev/null || true
  fi
  rm -f "$poc_out"
  [ -s "$poc_file" ] && set_stage $S_TRIAGE running "PoCs written ($(nlines "$forms_file") forms)" || set_stage $S_TRIAGE running "no body-based PoCs"
fi

# Step 6: AI triage  (analyses nuclei + content-discovery + JS + crawl/DAST)
have_extra=0; { [ -s "$js_secrets_file" ] || [ -s "$params_file" ] || [ -s "$fuzz_findings_file" ] || [ -s "$dast_file" ] || [ -s "$gf_file" ] || [ -s "$findings_dir/dalfox.txt" ] || [ -s "$findings_dir/sqlmap.txt" ] || [ -s "$agent_file" ] || [ -s "${bypass_file:-/dev/null}" ] || [ -s "${idor_file:-/dev/null}" ] || [ -s "${corsy_file:-/dev/null}" ] || [ -s "${verified_file:-/dev/null}" ] || [ -s "${open_dir_file:-/dev/null}" ] || [ -s "${unauth_api_file:-/dev/null}" ] || [ -s "${openredir_file:-/dev/null}" ] || [ -s "${jwt_file:-/dev/null}" ] || [ -s "${stacktrace_file:-/dev/null}" ]; } && have_extra=1
if [ "$AI_ENABLED" = "1" ] && { [ "$find_count" -gt 0 ] || [ "$have_extra" = 1 ]; } && ! budget_ok; then
  { echo "## Findings (budget reached, no AI triage)"; echo '```'; cat "$nuclei_file" 2>/dev/null
    [ -s "$js_secrets_file" ] && { echo; echo "# JS secret candidates:"; cat "$js_secrets_file"; }; echo '```'; } >> "$report_file"
  set_stage $S_TRIAGE skip "budget reached ($(cost_fmt))"
elif [ "$AI_ENABLED" = "1" ] && { [ "$find_count" -gt 0 ] || [ "$have_extra" = 1 ]; }; then
  sorted_findings="$(
    for sev in critical high medium low info; do grep -iE "\[$sev\]" "$nuclei_file" 2>/dev/null; done
    grep -viE '\[(critical|high|medium|low|info)\]' "$nuclei_file" 2>/dev/null
  )"
  [ -z "$sorted_findings" ] && sorted_findings="$(cat "$nuclei_file" 2>/dev/null)"
  sys_triage='You are a senior security analyst on an AUTHORIZED bug-bounty engagement.
Given a technology brief, nuclei output, CONTENT-DISCOVERY hits (discovered URLs/paths),
JS secret candidates and discovered request parameters, produce a thorough report in
GitHub-flavored Markdown with:
"## Executive summary" (3-5 sentences),
"## Prioritised findings" (table: Severity | Host | Issue | Why it matters | Next step),
"## Notable discovered paths" (from the content-discovery hits, call out the juicy ones:
backups/.git/.env/config/admin/api/upload/debug endpoints; ignore generic assets; note
which 401/403 are worth auth testing),
"## Injection candidates (DAST & params)" (from nuclei -dast findings and gf-bucketed
parametered URLs: name the parameter, the suspected class (SQLi/XSS/SSRF/LFI/redirect),
and a concrete safe test),
"## Secrets & sensitive exposure" (assess each JS secret candidate: likely real vs false
positive, impact, safe verification - flag private keys / cloud creds as critical),
"## Interesting parameters to test" (map discovered params to bug classes: IDOR, SSRF,
LFI, SQLi, open-redirect - concrete test idea each),
"## Known-CVE exposure" (for each VERSIONED COMPONENT provided, name the specific public
CVEs you are confident affect that exact product+version - CVE id, one-line impact, and
whether it is likely exploitable here; say "no high-confidence CVE" rather than guessing),
"## Infra & hardening" (assess the DNS/EMAIL HYGIENE and SECURITY-HEADER findings: SPF/DMARC
spoofing, zone transfer, clickjacking, missing HSTS/CSP, weak cookie flags - impact + fix),
"## Attack surface notes" and "## Recommended manual follow-ups".
Use ONLY the provided data - do not invent findings. Keep tables concise and do NOT repeat the
same endpoint across multiple tables; prefer one row per issue. Finish every section - do not
run long. Keep your internal thinking brief; do NOT draft tables in reasoning before the output.
Limit each table to the top 8 highest-signal rows.
Output ONLY the final report starting exactly with the line "## Executive summary".
Do NOT include any reasoning, planning, or preamble before it.'
  triage_out="$(mktemp)"
  run_ai_stage $S_TRIAGE "$LLM_MODEL_TRIAGE" "$LLM_MAX_TOKENS_TRIAGE" "$sys_triage" "Target: $domain

=== technology brief ===
$(head -c 8000 "$tech_brief")

=== nuclei findings (severity-sorted) ===
$(printf '%s\n' "$sorted_findings" | head -n 400 | head -c 30000)

=== content-discovery hits (status  length  urls; grouped by fingerprint - ALL urls listed for small buckets so nothing is hidden) ===
$(awk -F'\t' 'NF>=3{ st=$1; len=$2; u=$3; if(st==500||st==403){cap=3}else{cap=10}
    k=st"\t"len; c[k]++; if(ns[k]<cap){smp[k]=(smp[k]==""?u:smp[k]" "u); ns[k]++} }
  END{ for(k in c){ extra=(c[k]>ns[k]?" (+"(c[k]-ns[k])" more)":""); printf "%s\t%s%s\n", k, smp[k], extra } }' \
    "$fuzz_findings_file" 2>/dev/null | sort -t"$(printf '\t')" -k1,1n | head -n 200 | head -c 14000)

=== nuclei DAST findings ===
$(head -c 8000 "$dast_file" 2>/dev/null)

=== mined REST/API surface (from JS bundles + source maps - the SPA's real endpoints; probed statuses are in the content-discovery table above) ===
$(grep -iE '/api/|/rest/|/graphql' "${js_endpoints_file:-/dev/null}" 2>/dev/null | sort -u | head -n 150 | head -c 8000)

=== OWASP/API detector hits (open dirs, verbose errors, unauth API exposure, open redirects, JWT) ===
$({ cat "${open_dir_file:-/dev/null}" "${stacktrace_file:-/dev/null}" "${unauth_api_file:-/dev/null}" "${openredir_file:-/dev/null}" "${jwt_file:-/dev/null}"; } 2>/dev/null | head -c 6000)

=== dalfox XSS findings ===
$(head -c 4000 "$findings_dir/dalfox.txt" 2>/dev/null)

=== sqlmap SQLi confirmation ===
$(head -c 3000 "$findings_dir/sqlmap.txt" 2>/dev/null)

=== gf injection-candidate URLs (pattern <TAB> url) ===
$(head -n 120 "$gf_file" 2>/dev/null | head -c 8000)

=== JS secret candidates (url <TAB> match) ===
$(head -c 8000 "$js_secrets_file" 2>/dev/null)

=== discovered parameters (url <TAB> param) ===
$(head -c 4000 "$params_file" 2>/dev/null)

=== agent-confirmed issues (autonomous probe loop; treat as CONFIRMED, rank high) ===
$(head -c 4000 "$agent_file" 2>/dev/null)

=== access-control bypasses (403/401 -> 2xx; CONFIRMED, rank high) ===
$(head -c 2000 "${bypass_file:-/dev/null}" 2>/dev/null)

=== IDOR / broken-authz candidates (A/B/anon diff; verify object ownership) ===
$(head -c 2000 "${idor_file:-/dev/null}" 2>/dev/null)

=== VERIFIED findings (survived independent re-test; rank these highest) ===
$(head -c 2000 "${verified_file:-/dev/null}" 2>/dev/null)

=== CORS misconfiguration (Corsy) ===
$(head -c 1500 "${corsy_file:-/dev/null}" 2>/dev/null)

=== reflected parameters (kxss; XSS/injection candidates) ===
$(head -c 2000 "$findings_dir/kxss.txt" 2>/dev/null)

=== confirmed blind SSRF / open-redirect (OAST callbacks; CONFIRMED, rank high) ===
$(head -c 1500 "${oast_hits_file:-/dev/null}" 2>/dev/null)

=== GraphQL introspection (open = full schema readable; map per-field authz/IDOR) ===
$(head -c 2000 "${gql_schema_file:-/dev/null}" 2>/dev/null)

=== exposed source maps (.js.map -> original source leaked) ===
$(head -c 1000 "${sourcemap_file:-/dev/null}" 2>/dev/null)

=== exposed API specs (Swagger/OpenAPI/GraphQL) ===
$(head -c 1500 "${api_specs_file:-/dev/null}" 2>/dev/null)

=== cross-host propagated endpoints (same path live on sibling hosts) ===
$(head -c 1500 "${prop_file:-/dev/null}" 2>/dev/null)

=== versioned components (map each to specific known CVEs) ===
$(head -c 2000 "${versions_file:-/dev/null}" 2>/dev/null)

=== subdomain takeover candidates (dangling CNAME to unclaimed backend; CONFIRMED-ish, rank high) ===
$(head -c 1500 "${takeover_file:-/dev/null}" 2>/dev/null)

=== DNS / email hygiene (SPF/DMARC spoofing, zone transfer) ===
$(head -c 1500 "${dns_hygiene_file:-/dev/null}" 2>/dev/null)

=== security headers / clickjacking / cookie flags ===
$(head -c 3000 "${sec_headers_file:-/dev/null}" 2>/dev/null)" "$triage_out"
  if [ -s "$triage_out" ]; then
    # Drop any leading reasoning: keep from the LAST "## Executive summary" to the end
    # (reasoning models may restate the section names earlier while thinking).
    ln="$(grep -n '## Executive summary' "$triage_out" | tail -1 | cut -d: -f1)"
    if [ -n "$ln" ]; then sed -n "${ln},\$p" "$triage_out" >> "$report_file"
    else cat "$triage_out" >> "$report_file"; fi
    set_stage $S_TRIAGE done "report.md written"
  else
    { echo "## Raw findings"; echo '```'; cat "$nuclei_file" 2>/dev/null; echo '```'; } >> "$report_file"
    set_stage $S_TRIAGE warn "AI failed, raw findings saved"
  fi
  rm -f "$triage_out"
else
  {
    echo "## Findings"
    if [ "$find_count" -gt 0 ]; then echo '```'; cat "$nuclei_file"; echo '```'; else echo "_No nuclei findings._"; fi
    if [ -s "$js_secrets_file" ]; then echo; echo "## JS secret candidates"; echo '```'; cat "$js_secrets_file"; echo '```'; fi
    if [ -s "$params_file" ]; then echo; echo "## Discovered parameters"; echo '```'; cat "$params_file"; echo '```'; fi
  } >> "$report_file"
  set_stage $S_TRIAGE skip "$([ "$AI_ENABLED" = 1 ] && echo "nothing to triage" || echo "AI off")"
fi

# The report header's AI-spend line was written in p_agent BEFORE the two biggest calls (PoC gen +
# triage) ran here. Rewrite it now with the final total so it matches the terminal summary.
[ "$AI_ENABLED" = 1 ] && [ -f "$report_file" ] && \
  sed -i -E "s|^(- \*\*Estimated AI spend:\*\* )\\\$?[0-9.]+|\\1$(cost_fmt)|" "$report_file" 2>/dev/null || true

# Manual-PoC section: point the human at the runnable body-based PoCs 4tail generated but
# did not fire. Kept as its own report section + standalone script artifact.
if [ -s "${poc_file:-/dev/null}" ]; then
  {
    echo
    echo "## Manual PoC commands (body-based — 4tail did NOT run these)"
    echo
    echo "POST auth/logic, body IDOR/SQLi, mass assignment, GraphQL mutations and CSRF are"
    echo "outside 4tail's GET-only firing. The script below was written from the harvested"
    echo "form fields and injectable signals — **review each command, set \`\$SESSION\`, then"
    echo "run only what you intend**. Saved as \`$(basename "$poc_file")\`."
    echo
    echo '```bash'
    cat "$poc_file"
    echo '```'
  } >> "$report_file"
fi

# Structured output: findings.json (and optional SARIF) for automation / ticketing.
findings_json="$OUTDIR/findings.json"
if have jq; then
  emit_f() { jq -nc --arg type "$1" --arg sev "$2" --arg src "$3" --arg url "$4" --arg detail "$5" \
      '{type:$type,severity:$sev,source:$src,url:$url,detail:$detail}'; }
  nsev() { printf '%s' "$1" | grep -oiE '\[(critical|high|medium|low|info|unknown)\]' | head -1 | tr -d '[]' | tr 'A-Z' 'a-z'; }
  nurl() { printf '%s' "$1" | grep -oE 'https?://[^ ]+' | head -1; }
  {
    [ -f "$nuclei_file" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f nuclei "$(nsev "$l")" nuclei "$(nurl "$l")" "$l"; done < "$nuclei_file"
    [ -f "$dast_file" ]   && while IFS= read -r l; do [ -n "$l" ] && emit_f dast "$(nsev "$l")" nuclei-dast "$(nurl "$l")" "$l"; done < "$dast_file"
    # Group ffuf hits by response fingerprint (status,length) - never by URL string -
    # so case-variants (db.asp/DB.asp on IIS) and WAF noise (32 identical 403/312
    # traversal blocks) collapse to one representative with a count.
    [ -f "$fuzz_findings_file" ] && awk -F'\t' '
        NF>=3 { st=$1; len=$2+0; u=$3
          # 500/403 error pages echo the path -> lengths differ by a few bytes; bucket by 64 so
          # they collapse to one finding instead of dozens. Other statuses keep exact length.
          if (st==500||st==403) { b=int(len/64)*64; k=st SUBSEP "b" b; disp="~"b } else { k=st SUBSEP len; disp=len }
          c[k]++; if(!(k in r)) r[k]=u; d[k]=disp; sv[k]=st }
        END{for(k in c) printf "%s\t%s\t%s\t%d\n", sv[k], d[k], r[k], c[k]}' "$fuzz_findings_file" \
      | while IFS=$'\t' read -r st len u c; do
          [ -n "$u" ] || continue
          note="status=$st length=$len"; [ "${c:-1}" -gt 1 ] && note="$note (×$c similar responses)"
          emit_f content-discovery info ffuf "$u" "$note"
        done
    [ -f "$findings_dir/dalfox.txt" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f xss high dalfox "$(nurl "$l")" "$l"; done < "$findings_dir/dalfox.txt"
    [ -f "$findings_dir/sqlmap.txt" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f sqli high sqlmap "" "$l"; done < "$findings_dir/sqlmap.txt"
    [ -f "$js_secrets_file" ] && while IFS=$'\t' read -r u m; do [ -n "$m" ] && emit_f secret medium js-mining "$u" "$m"; done < "$js_secrets_file"
    [ -f "${sourcemap_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f source-map medium js-mining "$l" "source map exposed - original source reconstructed from $l"; done < "$sourcemap_file"
    [ -f "${takeover_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] || continue
        emit_f subdomain-takeover high dns "$(printf '%s' "$l" | awk '{print $2}')" "$l"; done < "$takeover_file"
    [ -f "${dns_hygiene_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] || continue
        case "$l" in *zone-transfer*) _s=high ;; *) _s=low ;; esac
        emit_f "$(printf '%s' "$l" | grep -oE '^\[[a-z-]+\]' | tr -d '[]')" "$_s" dns-hygiene "$domain" "$l"; done < "$dns_hygiene_file"
    [ -f "${sec_headers_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] || continue
        _u="$(printf '%s' "$l" | grep -oE 'https?://[^ ]+' | head -1)"
        emit_f "$(printf '%s' "$l" | grep -oE '^\[[a-z-]+\]' | tr -d '[]')" low security-headers "${_u:-$domain}" "$l"; done < "$sec_headers_file"
    [ -f "$findings_dir/kxss.txt" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f reflected-param low kxss "$(nurl "$l")" "$l"; done < "$findings_dir/kxss.txt"
    # OWASP/API Top-10 detector outputs
    [ -f "${open_dir_file:-}" ]   && grep '^\[open-directory\]' "$open_dir_file" 2>/dev/null | while IFS= read -r l; do emit_f open-directory medium discovery "$(nurl "$l")" "$l"; done
    [ -f "${stacktrace_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f verbose-error medium error-harvest "$(nurl "$l")" "$l"; done < "$stacktrace_file"
    [ -f "${unauth_api_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f unauth-api-exposure high api-probe "$(nurl "$l")" "$l"; done < "$unauth_api_file"
    [ -f "${openredir_file:-}" ]  && while IFS= read -r l; do [ -n "$l" ] && emit_f open-redirect medium redirect-probe "$(nurl "$l")" "$l"; done < "$openredir_file"
    [ -f "${jwt_file:-}" ]        && while IFS= read -r l; do [ -n "$l" ] && emit_f jwt-weakness medium jwt-analysis "" "$l"; done < "$jwt_file"
    [ -f "${dom_xss_file:-}" ]    && while IFS=$'\t' read -r u m; do [ -n "$m" ] && emit_f dom-xss-sink medium js-mining "$u" "$m"; done < "$dom_xss_file"
    [ -f "${spa_routes_file:-}" ] && grep -iE '/(admin|account|internal|debug|config|audit|score|board|wallet|payment|deluxe|b2b|support|logs|sandbox|web3)' "$spa_routes_file" 2>/dev/null | while IFS= read -r l; do emit_f spa-route info js-mining "$l" "client-side SPA route (often privileged/hidden): $l"; done
    [ -f "${api_specs_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f api-spec info api-discovery "$l" "exposed API spec: $l"; done < "$api_specs_file"
    [ -f "${gql_schema_file:-}" ] && grep '^== GraphQL introspection OPEN: ' "$gql_schema_file" 2>/dev/null \
      | sed 's/^== GraphQL introspection OPEN: //; s/ ==$//' \
      | while IFS= read -r l; do [ -n "$l" ] && emit_f graphql-introspection medium graphql "$l" "GraphQL introspection enabled - full schema readable at $l"; done
    [ -f "${oast_hits_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f blind-ssrf-redirect high oast "$(nurl "$l")" "$l"; done < "$oast_hits_file"
    [ -f "${agent_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f agent-confirmed "$(agent_sev "$l")" agent "$(nurl "$l")" "$l"; done < "$agent_file"
    [ -f "${bypass_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f access-control-bypass high bypass "$(nurl "$l")" "$l"; done < "$bypass_file"
    [ -f "${idor_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f idor-authz high idor "$(nurl "$l")" "$l"; done < "$idor_file"
    [ -f "${prop_file:-}" ] && while IFS=$'\t' read -r c u; do [ -n "$u" ] && emit_f content-discovery info cross-host "$u" "status=$c (found on a sibling host)"; done < "$prop_file"
    [ -f "${corsy_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f cors-misconfig medium corsy "$(nurl "$l")" "$l"; done < "$corsy_file"
    true   # force group exit 0: a trailing false [ -f ] test must not (via pipefail) trip the || fallback and clobber jq's output
  } | jq -s "{target:\"$domain\", generated:\"$(date -u +%FT%TZ)\", blueprint:\"${BLUEPRINT_NAME:-}\", count:length, findings:.}" > "$findings_json" 2>/dev/null
  [ -s "$findings_json" ] || echo '{}' > "$findings_json"

  if [ "$EMIT_SARIF" = 1 ]; then
    jq '{version:"2.1.0", "$schema":"https://json.schemastore.org/sarif-2.1.0.json",
         runs:[{tool:{driver:{name:"4tail", rules:[]}},
                results:[.findings[] | {ruleId:.type, level:(if .severity=="critical" or .severity=="high" then "error" elif .severity=="medium" then "warning" else "note" end),
                                        message:{text:.detail}, properties:{source:.source,severity:.severity},
                                        locations:[{physicalLocation:{artifactLocation:{uri:.url}}}]}]}]}' \
       "$findings_json" > "$OUTDIR/findings.sarif" 2>/dev/null || true
  fi
fi

# Change-detection vs the last run of this target (must come after findings.json exists).
diff_state
diff_new="$(grep -c . "$diff_file" 2>/dev/null || echo 0)"

# Final summary
spend_note=""; [ "$AI_ENABLED" = 1 ] && spend_note="  ·  AI spend ~$(cost_fmt)"
# Capability-aware tally: every zero says whether the tool ran, is off, or isn't installed.
_pt="$({ [ "$PREFER_X8" = 1 ] && have x8; } && echo x8 || echo arjun)"
tally="$(cov nuclei nuclei 1 "$find_count")  fuzz:$(fuzz_distinct "$fuzz_findings_file")u/$(cov hits ffuf "$([ "$SKIP_FUZZ" != 1 ] && echo 1 || echo 0)" "${fuzz_hits:-0}" | sed 's/^hits://')"
tally="$tally  $(cov js-secrets "" "$([ "$JSMINE" = 1 ] && echo 1 || echo 0)" "$(nlines "$js_secrets_file")")  $(cov params "$_pt" "$([ "$JSMINE" = 1 ] && echo 1 || echo 0)" "$(nlines "$params_file")")"
if [ "$CRAWL" = 1 ]; then
  tally="$tally  active:$(nlines "$targets_active_file")  api-specs:$(nlines "${api_specs_file:-/dev/null}")"
  tally="$tally  $(cov dast nuclei "$(has_spec nuclei-dast && echo 1 || echo 0)" "$(nlines "$dast_file")")"
  tally="$tally  $(cov dalfox dalfox "$(has_spec dalfox && echo 1 || echo 0)" "$(nlines "$findings_dir/dalfox.txt")")"
  tally="$tally  $(cov kxss kxss "$(has_spec kxss && echo 1 || echo 0)" "$(nlines "$findings_dir/kxss.txt")")"
  tally="$tally  $(cov sqlmap sqlmap "$({ has_spec sqlmap && [ "$SQLMAP_CONFIRM" = 1 ] && [ "${ACT_MAX_SQLMAP:-0}" -gt 0 ] 2>/dev/null; } && echo 1 || echo 0)" "$(nlines "$findings_dir/sqlmap.txt")")"
  tally="$tally  bypass:$(nlines "${bypass_file:-/dev/null}")  $(cov idor "" "$([ -n "$AUTH_A" ] && echo 1 || echo 0)" "$(nlines "${idor_file:-/dev/null}")")  $(cov cors corsy "$([ "$CORS_SCAN" = 1 ] && echo 1 || echo 0)" "$(nlines "${corsy_file:-/dev/null}")")"
  [ -s "${unauth_api_file:-/dev/null}" ] && tally="$tally  api-leak:$(nlines "$unauth_api_file")"
fi
[ "$OAST" = 1 ] && tally="$tally  $(cov oast interactsh-client 1 "$(nlines "${oast_hits_file:-/dev/null}")")"
[ "$AGENT" = 1 ] && tally="$tally  agent:$(nlines "${agent_file:-/dev/null}")"
[ -s "${takeover_file:-/dev/null}" ] && tally="$tally  takeover:$(nlines "$takeover_file")"
[ "$DNS_HYGIENE" = 1 ] && tally="$tally  dns-hygiene:$(nlines "${dns_hygiene_file:-/dev/null}")"
[ "$SEC_HEADERS" = 1 ] && tally="$tally  sec-headers:$(nlines "${sec_headers_file:-/dev/null}")"
[ -s "${sourcemap_file:-/dev/null}" ] && tally="$tally  sourcemaps:$(nlines "$sourcemap_file")"
[ -s "${poc_file:-/dev/null}" ] && tally="$tally  pocs:yes"
tally="$tally  verified:$(nlines "${verified_file:-/dev/null}")"
if [ "$TUI" = 1 ]; then
  tui_end    # leave alt screen, reprint final panel into normal scrollback
  printf '\n %s✔ done in %ss%s%s\n   %s%s%s\n   report → %s%s%s\n' \
    "$c_green" "$((SECONDS-started))" "$c_reset" "$spend_note" \
    "$c_dim" "$tally" "$c_reset" "$c_cyan" "$report_file" "$c_reset"
  [ -f "$findings_json" ] && printf '   %sJSON   → %s%s%s\n' "$c_dim" "$c_cyan" "$findings_json" "$c_reset"
  [ -s "${poc_file:-/dev/null}" ] && printf '   %sPoCs   → %s%s%s %s(manual, review before running)%s\n' "$c_dim" "$c_cyan" "$poc_file" "$c_reset" "$c_dim" "$c_reset"
  [ -n "$(ls -A "${agent_loot_dir:-/nonexistent}" 2>/dev/null)" ] && printf '   %sLOOT   → %s%s/%s %s(raw creds the agent read — kept local, never sent to the LLM)%s\n' "$c_dim" "$c_cyan" "$agent_loot_dir" "$c_reset" "$c_dim" "$c_reset"
  [ "$DIFF_STATE" = 1 ] && printf '   %schanges since last run: %s new items%s%s\n' "$c_dim" "${diff_new:-0}" "$([ "${diff_new:-0}" -gt 0 ] 2>/dev/null && echo "  → $diff_file")" "$c_reset"
else
  ok "Done in $((SECONDS-started))s.$spend_note"
  ok "$tally"
  ok "Report: $report_file"
  [ -f "$findings_json" ] && ok "JSON:   $findings_json$([ "$EMIT_SARIF" = 1 ] && echo "  (+ findings.sarif)")"
  [ -s "${poc_file:-/dev/null}" ] && ok "PoCs:   $poc_file  (manual, review before running)"
  [ -n "$(ls -A "${agent_loot_dir:-/nonexistent}" 2>/dev/null)" ] && ok "Loot:   $agent_loot_dir/  (raw creds the agent read - kept local, never sent to the LLM)"
  [ "$DIFF_STATE" = 1 ] && ok "Changes since last run: ${diff_new:-0} new items$([ "${diff_new:-0}" -gt 0 ] 2>/dev/null && echo " ($diff_file)")"
fi
_FINISHED=1   # reached the end normally - the EXIT trap won't report a failure
