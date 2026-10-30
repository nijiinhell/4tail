# Step 5.9: PoC generation for BODY-BASED bug classes (manual, never fired by 4tail).
# 4tail is GET-only when it fires requests; POST-driven bugs (auth/logic on login+register,
# body IDOR/SQLi, mass assignment, GraphQL mutations, CSRF) are detected but not exercised.
# Here we harvest the real form fields deterministically, then have the AI write ready-to-run
# curl PoCs for the HUMAN - keeping the firing invariant while closing the coverage gap.
: > "$forms_file"; : > "$poc_file"
if [ "$CRAWL" = 1 ] && [ "$POC_GEN" = 1 ] && [ "$AI_ENABLED" = 1 ] && budget_ok; then
  set_stage $S_TRIAGE running "harvesting forms for PoCs"
  # (a) deterministic form harvest from auth / state-changing pages
  form_cand="$( { sort -u "$alive_file" 2>/dev/null; cat "$targets_active_file" 2>/dev/null; } \
                 | grep -iE 'login|signin|sign-in|register|signup|sign-up|reset|password|forgot|account|profile|checkout|cart|upload|contact|comment|graphql' \
                 | sort -u | head -n "$POC_FORM_HOSTS" )"
  [ -n "$form_cand" ] || form_cand="$(sort -u "$alive_file" 2>/dev/null | head -n 3)"   # fall back to roots
  while IFS= read -r pg; do
    [ -n "$pg" ] || continue
    html="$(curl -s -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} "$pg" 2>/dev/null | tr '\n' ' ' | head -c 200000)"
    [ -n "$html" ] || continue
    # Split into per-<form> chunks (awk RS on the opening tag) so multiple forms stay distinct;
    # for each, pull method, action and the field names. grep ERE has no lazy match, hence awk.
    printf '%s' "$html" | awk 'BEGIN{IGNORECASE=1; RS="<form"} NR>1{ e=index(tolower($0),"</form>"); print (e>0?substr($0,1,e):$0) }' 2>/dev/null \
      | while IFS= read -r frm; do
          [ -n "$frm" ] || continue
          m="$(printf '%s' "$frm" | grep -oiE 'method=["'"'"']?[a-z]+' | head -1 | grep -oiE '[a-z]+$' | tr 'a-z' 'A-Z')"; [ -n "$m" ] || m=GET
          a="$(printf '%s' "$frm" | grep -oiE 'action=["'"'"'][^"'"'"']*' | head -1 | sed -E 's/^action=["'"'"']//')"; [ -n "$a" ] || a="$pg"
          names="$(printf '%s' "$frm" | grep -oiE 'name=["'"'"'][^"'"'"']+' | sed -E 's/^name=["'"'"']//' | sort -u | paste -sd, -)"
          [ -n "$names" ] && printf '%s\t%s\t%s\t%s\n' "$pg" "$m" "$a" "$names" >> "$forms_file"
        done
  done <<< "$form_cand"
  # (b) AI writes the PoCs from the harvested forms + the injectable/authz signals we already have
  set_stage $S_TRIAGE running "AI writing manual PoCs"
  poc_sys='You are a bug-bounty exploitation assistant on an AUTHORIZED engagement. Write a runnable bash script of curl PoCs for the BODY-BASED / state-changing bug classes a GET-only scanner cannot fire: POST auth & logic flaws (login, register, password-reset), body-based IDOR and SQLi, mass assignment (extra JSON fields like "role":"admin","isAdmin":true), GraphQL mutations, and CSRF (missing anti-CSRF token). Group the PoCs into clear titled sections (e.g. "# ====================\n# [HIGH] Authentication & Logic Flaws\n# ===================="). Rules: one PoC per block; above each, a "# WHAT:" line (bug class + why this endpoint) and a "# CONFIRM:" line (the exact response signal that proves it). Use the real form fields and parameters given. Same-origin only. NON-DESTRUCTIVE: no DELETE/DROP/mass writes - use benign markers (e.g. value "4tailPoC"), id=1/id=2 for IDOR, a single quote for SQLi. Reference the session as the shell var $SESSION in a -H header so the human pastes their cookie/token. Output ONLY the bash script body (no markdown fences, no prose outside comments). If the data shows no plausible body-based test, output just: # no body-based PoC candidates from the collected data'
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
      echo
      sed -E '/^```/d' "$poc_out"
    } > "$poc_file"
    chmod +x "$poc_file" 2>/dev/null || true
  fi
  rm -f "$poc_out"
  [ -s "$poc_file" ] && set_stage $S_TRIAGE running "PoCs written ($(nlines "$forms_file") forms)" || set_stage $S_TRIAGE running "no body-based PoCs"
fi

# Step 6: AI triage  (analyses nuclei + content-discovery + JS + crawl/DAST)
have_extra=0; { [ -s "$js_secrets_file" ] || [ -s "$params_file" ] || [ -s "$fuzz_findings_file" ] || [ -s "$dast_file" ] || [ -s "$gf_file" ] || [ -s "$findings_dir/dalfox.txt" ] || [ -s "$findings_dir/sqlmap.txt" ] || [ -s "$agent_file" ] || [ -s "${bypass_file:-/dev/null}" ] || [ -s "${idor_file:-/dev/null}" ] || [ -s "${corsy_file:-/dev/null}" ] || [ -s "${verified_file:-/dev/null}" ]; } && have_extra=1
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
Use ONLY the provided data - do not invent findings.
Output ONLY the final report starting exactly with the line "## Executive summary".
Do NOT include any reasoning, planning, or preamble before it.'
  triage_out="$(mktemp)"
  run_ai_stage $S_TRIAGE "$LLM_MODEL_TRIAGE" "$LLM_MAX_TOKENS_TRIAGE" "$sys_triage" "Target: $domain

=== technology brief ===
$(head -c 8000 "$tech_brief")

=== nuclei findings (severity-sorted) ===
$(printf '%s\n' "$sorted_findings" | head -n 400 | head -c 30000)

=== content-discovery hits (status  length  url  count; grouped by response fingerprint) ===
$(awk -F'\t' 'NF>=3{
    st=$1; len=$2; u=$3
    if (st ~ /^(301|302|307|308)$/ && len < 400) {
      match(u, /^https?:\/\/[^\/]+/);
      h = substr(u, RSTART, RLENGTH);
      k = st "\tredirect\t" h;
    } else {
      k = st "\t" len;
    }
    c[k]++; if (!(k in r)) r[k]=u;
  }
  END{
    for (k in c) {
      if (k ~ /\tredirect\t/) {
        split(k, p, "\t");
        printf "%s\t~%s\t%s\tx%d\n", p[1], p[2], p[3], c[k];
      } else {
        printf "%s\t%s\tx%d\n", k, r[k], c[k];
      }
    }
  }' "$fuzz_findings_file" 2>/dev/null | sort -t"$(printf '\t')" -k1,1n -k3,3r | head -n 150 | head -c 12000)

=== nuclei DAST findings ===
$(head -c 8000 "$dast_file" 2>/dev/null)

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

=== versioned components (map each to specific known CVEs) ===
$(head -c 2000 "${versions_file:-/dev/null}" 2>/dev/null)

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

# OOB: correlate any interactsh callbacks to the URLs we injected, then stop the listener.
oast_correlate
oast_stop

# Structured output: findings.json (and optional SARIF) for automation / ticketing.
findings_json="$OUTDIR/findings.json"
if have jq; then
  emit_f() { jq -nc --arg type "$1" --arg sev "$2" --arg src "$3" --arg url "$4" --arg detail "$5" --arg poc "${6:-}" \
      '{type:$type,severity:$sev,source:$src,url:$url,detail:$detail,poc:$poc}'; }
  nsev() { printf '%s' "$1" | grep -oiE '\[(critical|high|medium|low|info|unknown)\]' | head -1 | tr -d '[]' | tr 'A-Z' 'a-z'; }
  nurl() { printf '%s' "$1" | grep -oE 'https?://[^ ]+' | head -1; }
  {
    if [ -s "${findings_jsonl:-}" ]; then
      jq -c '. | {type:.type, severity:(.severity // "info"), source:(.stage // "hit"), url:(.target // ""), detail:.evidence, poc:(.poc // "")}' "$findings_jsonl" 2>/dev/null
    fi
    [ -f "$nuclei_file" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f nuclei "$(nsev "$l")" nuclei "$(nurl "$l")" "$l"; done < "$nuclei_file"
    [ -f "$dast_file" ]   && while IFS= read -r l; do [ -n "$l" ] && emit_f dast "$(nsev "$l")" nuclei-dast "$(nurl "$l")" "$l"; done < "$dast_file"
    # Group ffuf hits by response fingerprint (status,length) - never by URL string -
    # so case-variants (db.asp/DB.asp on IIS) and WAF noise (32 identical 403/312
    # traversal blocks) collapse to one representative with a count.
    [ -f "$fuzz_findings_file" ] && awk -F'\t' 'NF>=3{
        st=$1; len=$2; u=$3
        if (st ~ /^(301|302|307|308)$/ && len < 400) {
          match(u, /^https?:\/\/[^\/]+/);
          h = substr(u, RSTART, RLENGTH);
          k = st "\tredirect\t" h;
        } else {
          k = st "\t" len;
        }
        c[k]++; if (!(k in r)) r[k]=u;
      }
      END{
        for (k in c) {
          if (k ~ /\tredirect\t/) {
            split(k, p, "\t");
            printf "%s\tredirect\t%s\t%d\n", p[1], r[k], c[k];
          } else {
            split(k, p, "\t");
            printf "%s\t%s\t%s\t%d\n", p[1], p[2], r[k], c[k];
          }
        }
      }' "$fuzz_findings_file" \
      | while IFS=$'\t' read -r st len u c; do
          [ -n "$u" ] || continue
          note="status=$st length=$len"; [ "${c:-1}" -gt 1 ] && note="$note (×$c identical responses)"
          emit_f content-discovery info ffuf "$u" "$note"
        done
    [ -f "$findings_dir/dalfox.txt" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f xss high dalfox "$(nurl "$l")" "$l"; done < "$findings_dir/dalfox.txt"
    [ -f "$findings_dir/sqlmap.txt" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f sqli high sqlmap "" "$l"; done < "$findings_dir/sqlmap.txt"
    [ -f "$js_secrets_file" ] && while IFS=$'\t' read -r u m; do [ -n "$m" ] && emit_f secret medium js-mining "$u" "$m"; done < "$js_secrets_file"
    [ -f "${sourcemap_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f source-map medium js-mining "$l" "source map exposed - original source reconstructed from $l"; done < "$sourcemap_file"
    [ -f "${dns_hygiene_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] || continue
        case "$l" in *zone-transfer*) _s=high ;; *) _s=low ;; esac
        emit_f "$(printf '%s' "$l" | grep -oE '^\[[a-z-]+\]' | tr -d '[]')" "$_s" dns-hygiene "$domain" "$l"; done < "$dns_hygiene_file"
    [ -f "${sec_headers_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] || continue
        _u="$(printf '%s' "$l" | grep -oE 'https?://[^ ]+' | head -1)"
        emit_f "$(printf '%s' "$l" | grep -oE '^\[[a-z-]+\]' | tr -d '[]')" low security-headers "${_u:-$domain}" "$l"; done < "$sec_headers_file"
    [ -f "$findings_dir/kxss.txt" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f reflected-param low kxss "$(nurl "$l")" "$l"; done < "$findings_dir/kxss.txt"
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
    [ -f "${takeover_file:-}" ] && while IFS=$'\t' read -r u cn st; do [ -n "$u" ] && emit_f subdomain-takeover high dns "$u" "dangling CNAME $cn ($st)"; done < "$takeover_file"
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

  # Standalone interactive HTML report (offline, zero-dependency, filterable)
  report_html="$OUTDIR/report.html"
  if [ -s "$findings_json" ] && have jq; then
    rows="$(jq -r '.findings[]? | 
      "<tr data-sev=\"" + (.severity // "info") + "\" data-src=\"" + (.source // "-") + "\">" +
      "<td class=\"sev sev-" + (.severity // "info") + "\">" + (.severity // "info") + "</td>" +
      "<td>" + (.type // "-") + "</td>" +
      "<td class=\"src-col\">" + (.source // "-") + "</td>" +
      "<td><a href=\"" + (.url // "#") + "\" target=\"_blank\">" + (.url // "-") + "</a></td>" +
      "<td><code>" + (.detail // "" | @html) + "</code></td>" +
      "<td>" + (if (.poc // "") != "" then "<button class=\"btn-sm\" data-poc=\"" + (.poc | @html) + "\" onclick=\"copyPoc(this)\">Copy cURL</button>" elif ((.url // "") | test("^https?://")) then "<button class=\"btn-sm\" data-poc=\"curl -i &#39;" + (.url | @html) + "&#39;\" onclick=\"copyPoc(this)\">Copy cURL</button>" else "<span class=\"dash\">-</span>" end) + "</td>" +
      "</tr>"' "$findings_json" 2>/dev/null || true)"
    total_f="$(jq -r '.count // 0' "$findings_json" 2>/dev/null || echo 0)"
    crit_f="$(jq -r '[.findings[]? | select(.severity=="critical")] | length' "$findings_json" 2>/dev/null || echo 0)"
    high_f="$(jq -r '[.findings[]? | select(.severity=="high")] | length' "$findings_json" 2>/dev/null || echo 0)"
    med_f="$(jq -r '[.findings[]? | select(.severity=="medium")] | length' "$findings_json" 2>/dev/null || echo 0)"
    low_f="$(jq -r '[.findings[]? | select(.severity=="low")] | length' "$findings_json" 2>/dev/null || echo 0)"
    cat <<'HTMLEOF' > "$report_html"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>4tail Recon Report - __DOMAIN__</title>
<style>
:root { --bg:#0b0f19; --card:#151c2e; --text:#f1f5f9; --muted:#94a3b8; --border:#243049; --crit:#ef4444; --high:#f97316; --med:#eab308; --low:#3b82f6; --info:#64748b; }
body { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background:var(--bg); color:var(--text); margin:0; padding:24px; line-height:1.5; }
.header { margin-bottom:20px; border-bottom:1px solid var(--border); padding-bottom:16px; }
h1 { margin:0 0 6px 0; font-size:24px; font-weight:700; color:#fff; }
.meta { color:var(--muted); font-size:13px; }
.cards { display:flex; gap:14px; margin-bottom:20px; flex-wrap:wrap; }
.card { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:14px 20px; min-width:130px; }
.card .val { font-size:28px; font-weight:700; }
.card .lbl { font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:0.5px; }
.controls { display:flex; gap:12px; margin-bottom:16px; align-items:center; flex-wrap:wrap; background:var(--card); border:1px solid var(--border); padding:12px 16px; border-radius:8px; }
input[type="text"] { background:#0b0f19; border:1px solid var(--border); color:var(--text); padding:7px 12px; border-radius:6px; width:240px; font-size:13px; outline:none; }
input[type="text"]:focus { border-color:#3b82f6; }
.group-label { font-size:11px; color:var(--muted); font-weight:700; text-transform:uppercase; margin-right:2px; }
.btn-group { display:inline-flex; gap:4px; align-items:center; }
.btn { background:#1e293b; border:1px solid var(--border); color:var(--muted); padding:5px 10px; border-radius:6px; cursor:pointer; font-size:12px; font-weight:600; transition:all 0.15s; }
.btn:hover { background:#283548; color:#fff; }
.btn.active { background:#3b82f6; color:#fff; border-color:#3b82f6; }
.export-btn { margin-left:auto; background:#059669; color:#fff; border-color:#059669; }
.export-btn:hover { background:#047857; }
.btn-sm { background:#2563eb; color:#fff; border:none; border-radius:4px; padding:3px 8px; font-size:11px; cursor:pointer; font-weight:600; white-space:nowrap; transition:all 0.15s; }
.btn-sm:hover { background:#1d4ed8; }
.btn-sm.copied { background:#16a34a !important; color:#fff; }
table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--border); border-radius:8px; overflow:hidden; font-size:13px; }
th, td { padding:10px 14px; text-align:left; border-bottom:1px solid var(--border); vertical-align:middle; }
th { background:#151c2e; color:var(--muted); font-weight:600; text-transform:uppercase; font-size:11px; letter-spacing:0.5px; border-bottom:2px solid var(--border); }
tr:hover { background:rgba(255,255,255,0.02); }
a { color:#38bdf8; text-decoration:none; word-break:break-all; }
a:hover { text-decoration:underline; }
code { background:#0b0f19; padding:2px 6px; border-radius:4px; font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace; font-size:12px; word-break:break-all; color:#cbd5e1; border:1px solid rgba(255,255,255,0.05); }
.sev { font-weight:700; text-transform:uppercase; font-size:10px; border-radius:4px; padding:3px 7px; display:inline-block; }
.sev-critical { background:rgba(239,68,68,0.2); color:#fca5a5; border:1px solid rgba(239,68,68,0.4); }
.sev-high { background:rgba(249,115,22,0.2); color:#fdba74; border:1px solid rgba(249,115,22,0.4); }
.sev-medium { background:rgba(234,179,8,0.2); color:#fde047; border:1px solid rgba(234,179,8,0.4); }
.sev-low { background:rgba(59,130,246,0.2); color:#93c5fd; border:1px solid rgba(59,130,246,0.4); }
.sev-info { background:rgba(100,116,139,0.2); color:#cbd5e1; border:1px solid rgba(100,116,139,0.4); }
.dash { color:var(--border); }
</style>
</head>
<body>
<div class="header">
  <h1>4tail Recon Report: __DOMAIN__</h1>
  <div class="meta">Target: <b>__DOMAIN__</b> | Blueprint: <b>__BLUEPRINT__</b> | Generated: __DATE__</div>
</div>
<div class="cards">
  <div class="card"><div class="val">__TOTAL__</div><div class="lbl">Total Findings</div></div>
  <div class="card"><div class="val" style="color:var(--crit)">__CRIT__</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="val" style="color:var(--high)">__HIGH__</div><div class="lbl">High</div></div>
  <div class="card"><div class="val" style="color:var(--med)">__MED__</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="val" style="color:var(--low)">__LOW__</div><div class="lbl">Low</div></div>
</div>
<div class="controls">
  <input type="text" id="search" placeholder="Search findings, URLs, tools..." onkeyup="filterTable()">
  <div class="btn-group">
    <span class="group-label">Severity:</span>
    <button class="btn sev-btn active" onclick="setSev('all', this)">All</button>
    <button class="btn sev-btn" onclick="setSev('critical', this)">Critical</button>
    <button class="btn sev-btn" onclick="setSev('high', this)">High</button>
    <button class="btn sev-btn" onclick="setSev('medium', this)">Med</button>
    <button class="btn sev-btn" onclick="setSev('low', this)">Low</button>
    <button class="btn sev-btn" onclick="setSev('info', this)">Info</button>
  </div>
  <div class="btn-group">
    <span class="group-label">Source:</span>
    <button class="btn src-btn active" onclick="setSrc('all', this)">All</button>
    <button class="btn src-btn" onclick="setSrc('nuclei', this)">Nuclei</button>
    <button class="btn src-btn" onclick="setSrc('ffuf', this)">Ffuf</button>
    <button class="btn src-btn" onclick="setSrc('js', this)">Secrets</button>
    <button class="btn src-btn" onclick="setSrc('dns', this)">Takeover</button>
    <button class="btn src-btn" onclick="setSrc('agent', this)">Agent</button>
  </div>
  <button class="btn export-btn" onclick="exportCSV()">Export CSV</button>
</div>
<table id="ftable">
<thead>
  <tr><th style="width:90px">Severity</th><th style="width:130px">Type</th><th style="width:110px">Source</th><th>URL / Target</th><th>Details / Evidence</th><th style="width:100px">Action</th></tr>
</thead>
<tbody>
__ROWS__
</tbody>
</table>
<script>
let curSev = 'all';
let curSrc = 'all';
function setSev(s, el) {
  curSev = s;
  document.querySelectorAll('.sev-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  filterTable();
}
function setSrc(s, el) {
  curSrc = s;
  document.querySelectorAll('.src-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  filterTable();
}
function filterTable() {
  const q = document.getElementById('search').value.toLowerCase();
  const rows = document.querySelectorAll('#ftable tbody tr');
  rows.forEach(r => {
    const txt = r.innerText.toLowerCase();
    const sev = (r.getAttribute('data-sev') || '').toLowerCase();
    const src = (r.getAttribute('data-src') || '').toLowerCase();
    const matchQ = !q || txt.includes(q);
    const matchSev = (curSev === 'all') || (sev === curSev);
    const matchSrc = (curSrc === 'all') || src.includes(curSrc);
    r.style.display = (matchQ && matchSev && matchSrc) ? '' : 'none';
  });
}
function copyPoc(btn) {
  const poc = btn.getAttribute('data-poc');
  if (!poc) return;
  navigator.clipboard.writeText(poc).then(() => {
    const orig = btn.innerText;
    btn.innerText = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.innerText = orig;
      btn.classList.remove('copied');
    }, 1500);
  });
}
function exportCSV() {
  const rows = document.querySelectorAll('#ftable tr');
  let csv = [];
  rows.forEach(r => {
    if (r.style.display === 'none') return;
    const cols = r.querySelectorAll('th, td');
    const row = [];
    cols.forEach(col => {
      let val = '';
      const pocBtn = col.querySelector('[data-poc]');
      if (pocBtn) {
        val = pocBtn.getAttribute('data-poc');
      } else {
        val = col.innerText.trim();
      }
      row.push('"' + val.replace(/"/g, '""') + '"');
    });
    csv.push(row.join(','));
  });
  const blob = new Blob([csv.join('\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'findings_' + (document.title.replace(/[^a-zA-Z0-9_-]/g, '_')) + '.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
</script>
</body>
</html>
HTMLEOF
    sed -i "s/__DOMAIN__/$domain/g; s/__DATE__/$(date -u +%FT%TZ)/g; s/__BLUEPRINT__/${BLUEPRINT_NAME:-default}/g; s/__TOTAL__/$total_f/g; s/__CRIT__/$crit_f/g; s/__HIGH__/$high_f/g; s/__MED__/$med_f/g; s/__LOW__/$low_f/g" "$report_html"
    awk -v r="$rows" '{if ($0 ~ /__ROWS__/) print r; else print $0}' "$report_html" > "$report_html.tmp" && mv "$report_html.tmp" "$report_html"
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
fi
[ "$OAST" = 1 ] && tally="$tally  $(cov oast interactsh-client 1 "$(nlines "${oast_hits_file:-/dev/null}")")"
[ "$AGENT" = 1 ] && tally="$tally  agent:$(nlines "${agent_file:-/dev/null}")"
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
  [ -f "${report_html:-/dev/null}" ] && printf '   %sHTML   → %s%s%s\n' "$c_dim" "$c_cyan" "$report_html" "$c_reset"
  [ -s "${poc_file:-/dev/null}" ] && printf '   %sPoCs   → %s%s%s %s(manual, review before running)%s\n' "$c_dim" "$c_cyan" "$poc_file" "$c_reset" "$c_dim" "$c_reset"
  [ -n "$(ls -A "${agent_loot_dir:-/nonexistent}" 2>/dev/null)" ] && printf '   %sLOOT   → %s%s/%s %s(raw creds the agent read — kept local, never sent to the LLM)%s\n' "$c_dim" "$c_cyan" "$agent_loot_dir" "$c_reset" "$c_dim" "$c_reset"
  [ "$DIFF_STATE" = 1 ] && printf '   %schanges since last run: %s new items%s%s\n' "$c_dim" "${diff_new:-0}" "$([ "${diff_new:-0}" -gt 0 ] 2>/dev/null && echo "  → $diff_file")" "$c_reset"
else
  ok "Done in $((SECONDS-started))s.$spend_note"
  ok "$tally"
  ok "Report: $report_file"
  [ -f "$findings_json" ] && ok "JSON:   $findings_json$([ "$EMIT_SARIF" = 1 ] && echo "  (+ findings.sarif)")"
  [ -f "${report_html:-/dev/null}" ] && ok "HTML:   $report_html"
  [ -s "${poc_file:-/dev/null}" ] && ok "PoCs:   $poc_file  (manual, review before running)"
  [ -n "$(ls -A "${agent_loot_dir:-/nonexistent}" 2>/dev/null)" ] && ok "Loot:   $agent_loot_dir/  (raw creds the agent read - kept local, never sent to the LLM)"
  [ "$DIFF_STATE" = 1 ] && ok "Changes since last run: ${diff_new:-0} new items$([ "${diff_new:-0}" -gt 0 ] 2>/dev/null && echo " ($diff_file)")"
fi
_FINISHED=1   # reached the end normally - the EXIT trap won't report a failure
