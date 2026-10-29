# Step 5: Nuclei
# Close the plan feedback loop: Step 3 chose tags from only the bare "/" of each host, but
# Steps 4-4.7 then discovered paths (/wp-json, /graphql, /actuator, /swagger, /.git, ...). Fold
# those surface-PROVEN tags in so the scan actually covers what recon just found. Prepended
# (ahead of the AI's speculative tags) and deduped BEFORE the MAX_TAGS cap, so a proven tag is
# never the one truncated away.
enrich_plan_from_surface() {
  local blob extra=""
  # Only enrich from PROVEN surface: fuzz_findings rows that actually returned 200/401/403, the
  # probed API specs, and a non-empty GraphQL schema. Using raw $urls_file (unverified string
  # literals) or 500 pages caused false enrichment (e.g. a bogus leading 'graphql' tag on a
  # target with no GraphQL at all).
  blob="$({ [ -s "$fuzz_findings_file" ] && awk -F'\t' '$1==200||$1==401||$1==403{print $3}' "$fuzz_findings_file"
            [ -s "$api_specs_file" ] && cat "$api_specs_file"
            [ -s "$gql_schema_file" ] && echo /graphql
          } 2>/dev/null | tr 'A-Z' 'a-z')"
  [ -n "$blob" ] || return 0
  case "$blob" in *wp-content*|*wp-json*|*wp-includes*|*wp-login*) extra="$extra,wordpress,wp-plugin" ;; esac
  case "$blob" in *actuator*|*jolokia*|*'/env'*) extra="$extra,springboot,java" ;; esac
  case "$blob" in *graphql*|*graphiql*) extra="$extra,graphql" ;; esac
  case "$blob" in *swagger*|*openapi*|*'/api-docs'*) extra="$extra,swagger,api" ;; esac
  case "$blob" in *'/.git'*|*'/.svn'*) extra="$extra,git,svn" ;; esac
  case "$blob" in *'/.env'*|*'/config'*|*'/.aws'*) extra="$extra,config,exposures" ;; esac
  case "$blob" in */jenkins/*|*/gitlab/*|*/grafana/*|*/kibana/*) extra="$extra,default-login,panel" ;; esac
  case "$blob" in *'/v2/_catalog'*|*'/dockerfile'*) extra="$extra,docker,exposures" ;; esac
  printf '%s' "${extra#,}"
}
surface_tags="$(enrich_plan_from_surface)"
# nuclei matches template tags EXACTLY, and real templates use both singular and plural forms
# (prometheus-metrics is tagged `exposure`, not `exposures`), so a plan that said only `exposures`
# missed it. Add both forms so either spelling matches.
_ntags="$(printf '%s,%s,exposure,exposures,misconfig,misconfiguration' "${surface_tags}" "$nuclei_tags" | tr ',' '\n' | awk 'NF')"
# Pure DAST parameter classes (sqli/xss/lfi/ssrf/...) at the HOST level pull hundreds of slow
# product/fuzz templates against the root and are already covered by `nuclei -dast` on the
# parameterized URLs in the funnel - drop them here when DAST runs (jumped nuclei 70s -> 241s).
if [ "${DAST:-1}" = 1 ]; then
  _ntags="$(printf '%s\n' "$_ntags" | grep -vixE 'sqli|xss|lfi|rfi|ssrf|ssti|redirect|injection|xxe|crlf')"
fi
# Prepend proven tags, then sanitize (allowlist + first-occurrence dedupe) BEFORE the MAX_TAGS
# cap, so a surface-proven tag is never the one head() truncates away.
nuclei_tags="$(printf '%s\n' "$_ntags" \
  | sanitize_tags | tr ',' '\n' | awk 'NF' | head -n "$MAX_TAGS" | paste -sd, -)"

# Build the nuclei target list: dedupe by (origin, response signature), then VALUE-RANK
# so the interesting hosts (admin/login/api/dev, auth-gated, notable tech) are scanned
# first - with the time cap, the important stuff gets covered even if it doesn't finish.
nuclei_targets_file="$OUTDIR/nuclei_targets.txt"
if [ "$NUCLEI_DEDUPE" = 1 ] && [ -s "$httpx_json" ]; then
  jq -r '
      ((.cname // (.a[0]? // .host)) | tostring) as $o
      | (.url | sub("^https?://";"") | sub("[:/].*";"")) as $host
      # Dedup key: collapse only CONTENT-RICH pages that are truly identical across vhosts
      # (shared origin + status + length + title). A generic/empty root (401/404, no title, or
      # tiny body) is keyed per HOSTNAME instead, so distinct microservices behind one gateway
      # IP (users-api / payments-api, all "404 Not Found" at /) are NOT collapsed away.
      | (if ((.title // "") == "") or ((.content_length // 0) < 256)
         then $host
         else ($o + "|" + (.status_code|tostring) + "|" + ((.content_length//0)|tostring) + "|" + (.title//"")) end) as $sig
      | [ .url,
          ((.tech // []) | map(ascii_downcase) | join(",")),
          (.status_code|tostring),
          (.title // ""),
          $sig ]
      | @tsv' "$httpx_json" 2>/dev/null \
    | awk -F'\t' '!seen[$5]++' \
    | { [ "$NUCLEI_SKIP_CDN" = 1 ] && grep -viE "$CDN_RE" || cat; } \
    | awk -F'\t' -v stale="${stale_file:-}" '
        BEGIN{ if (stale != "") { while ((getline ln < stale) > 0) { n=split(ln,a,"\t"); if (n>=2) sc[a[2]]=a[1] } } }
        { url=$1; tech=$2; st=$3; l=tolower($1" "$4" "$2); s=0;
          if (l ~ /admin|login|portal|dashboard|dev|staging|test|internal|api|graphql|swagger|git|jenkins|grafana|kibana|vpn|auth|sso|jira|confluence|gitlab|panel|backend|secure|account|billing|payment|upload|debug|config/) s+=3;
          if (st=="401"||st=="403") s+=2;
          if (st=="500"||st=="503") s+=1;
          if (tech ~ /wordpress|drupal|joomla|magento|jira|confluence|gitlab|jenkins|grafana|tomcat|spring|php/) s+=2;
          if (tech ~ /cloudfront|cloudflare|akamai|fastly|imperva|incapsula|sucuri|edgecast/) s-=5;
          if (url in sc) s += sc[url];   # legacy/outdated hosts (stale score) rank higher here too
          printf "%d\t%s\n", s, url }' \
    | sort -t"$(printf '\t')" -k1,1nr -s \
    | cut -f2 > "$nuclei_targets_file"
  [ -s "$nuclei_targets_file" ] || cp "$alive_file" "$nuclei_targets_file"
else
  cp "$alive_file" "$nuclei_targets_file"
fi
# optional hard cap on host count (targets are already value-ranked)
if [ "$NUCLEI_MAX_HOSTS" -gt 0 ] 2>/dev/null; then
  head -n "$NUCLEI_MAX_HOSTS" "$nuclei_targets_file" > "$nuclei_targets_file.tmp" && mv "$nuclei_targets_file.tmp" "$nuclei_targets_file"
fi
nuclei_target_count="$(wc -l <"$nuclei_targets_file" 2>/dev/null || echo 0)"
if done_marker nuclei && [ -f "$nuclei_file" ]; then
  set_stage $S_NUCLEI done "$(wc -l <"$nuclei_file") findings (resumed)"
else
  # Bounded run with live stats (-stats-json): per-request timeout, 1 retry, skip
  # error-prone hosts, hard overall time cap. Stats JSON -> nuclei_stats_file (stderr).
  : > "$nuclei_stats_file"
  nuclei_cmd=(nuclei -silent -stats -stats-json -stats-interval "${NUCLEI_STATS_INTERVAL:-5}"
              -tags "$nuclei_tags" -severity "$NUCLEI_SEVERITY"
              -rate-limit "$NUCLEI_RATELIMIT" -timeout "$NUCLEI_TIMEOUT"
              -retries "$NUCLEI_RETRIES" -mhe "$NUCLEI_MHE"
              -c "$NUCLEI_CONC" -bulk-size "$NUCLEI_BULK"
              -l "$nuclei_targets_file" -o "$nuclei_file")
  [ "${#NUCLEI_NET[@]}" -gt 0 ] && nuclei_cmd+=("${NUCLEI_NET[@]}")
  if [ "$NUCLEI_MAX_TIME" -gt 0 ] 2>/dev/null && have timeout; then
    nuclei_cmd=(timeout "${NUCLEI_MAX_TIME}s" "${nuclei_cmd[@]}")
  fi
  set_stage $S_NUCLEI running "starting… ($nuclei_target_count hosts)"
  # no wrapping subshell, so $npid is timeout/nuclei directly and a kill reaches it
  "${nuclei_cmd[@]}" >/dev/null 2>>"$nuclei_stats_file" & npid=$!
  ns=$SECONDS; last_sup=0; sup_pid=""; sup_out=""; last_err=0; last_hits=0
  while kill -0 "$npid" 2>/dev/null; do
    st="$(grep '^{' "$nuclei_stats_file" 2>/dev/null | tail -1)"
    if [ -n "$st" ]; then
      pct="$(printf '%s' "$st"  | jq -r '.percent // empty' 2>/dev/null)"
      req="$(printf '%s' "$st"  | jq -r '.requests // 0' 2>/dev/null)"
      errs="$(printf '%s' "$st" | jq -r '.errors // 0' 2>/dev/null)"
      rps="$(printf '%s' "$st"  | jq -r '.rps // 0' 2>/dev/null)"
      el=$((SECONDS - ns))
      eta=""; [ -n "$pct" ] && awk "BEGIN{exit !($pct>0)}" 2>/dev/null && \
        eta="$(awk -v e="$el" -v p="$pct" 'BEGIN{r=e*(100-p)/p; printf "%dm%02ds", r/60, r%60}')"
      hits="$(wc -l <"$nuclei_file" 2>/dev/null || echo 0)"
      ST_DETAIL[$S_NUCLEI]="${pct:-0}% req:$req err:$errs rps:$rps hits:$hits${eta:+ ETA:$eta}"
    else
      ST_DETAIL[$S_NUCLEI]="starting… $((SECONDS-ns))s"
    fi
    # AI supervisor: periodic plain-language status (background, non-blocking)
    if [ "$SUPERVISOR" = 1 ] && [ "$AI_ENABLED" = 1 ] && budget_ok; then
      if [ -n "$sup_pid" ] && ! kill -0 "$sup_pid" 2>/dev/null; then
        wait "$sup_pid" 2>/dev/null || true
        [ -s "$sup_out" ] && { SUP_NOTE="$(grep -v '^[[:space:]]*$' "$sup_out" | tail -1 | head -c 400)"; printf '[%s] %s\n' "$(date +%H:%M:%S)" "$SUP_NOTE" >>"$supervisor_log"; }
        rm -f "$sup_out"; sup_pid=""
      fi
      if [ -z "$sup_pid" ] && [ $((SECONDS - last_sup)) -ge "$SUPERVISOR_INTERVAL" ] && [ -n "$st" ]; then
        last_sup=$SECONDS
        # Only spend an LLM call when something noteworthy changed (errors climbed or a new
        # finding landed). Otherwise write a free, deterministic status line - the model note
        # on a quiet, error-free scan adds nothing and just burns tokens.
        if [ "${errs:-0}" -le "$last_err" ] && [ "${hits:-0}" -le "$last_hits" ]; then
          SUP_NOTE="scan ${pct:-0}% · ${req:-0} req · ${errs:-0} err · ${rps:-0} rps · ${hits:-0} hits${eta:+ · ETA $eta}"
          last_err="${errs:-0}"; last_hits="${hits:-0}"
        else
        last_err="${errs:-0}"; last_hits="${hits:-0}"; sup_out="$(mktemp)"
        sup_sys='You monitor a running nuclei scan (AUTHORIZED test). Output ONLY the final status as one short sentence (<=30 words): progress %, whether the error rate is concerning and the likely cause (WAF 429s, dead hosts, timeouts), and ETA. No reasoning, no preamble, no "Let me" - just the sentence.'
        sup_usr="tags: $nuclei_tags
hosts: $alive_count  elapsed: $((SECONDS-ns))s
recent stats: $(grep '^{' "$nuclei_stats_file" | tail -3)
error sample: $(grep -iv '^{' "$nuclei_stats_file" | grep -iE 'error|timeout|refused|denied|429' | tail -5 | head -c 1500)"
        ( ai_call "$LLM_MODEL_PLAN" 1200 "$sup_sys" "$sup_usr" >"$sup_out" 2>>"$llm_log" ) & sup_pid=$!
        fi
      fi
    fi
    render; sleep 3
  done
  wait "$npid" 2>/dev/null; nrc=$?
  if [ -n "$sup_pid" ]; then
    wait "$sup_pid" 2>/dev/null || true
    [ -s "$sup_out" ] && { SUP_NOTE="$(grep -v '^[[:space:]]*$' "$sup_out" | tail -1 | head -c 400)"; printf '[%s] %s\n' "$(date +%H:%M:%S)" "$SUP_NOTE" >>"$supervisor_log"; }
    rm -f "$sup_out"
  fi
  # Replace the mid-scan supervisor note so the finished dashboard never shows a
  # stale "X% … ETA …" line (it was captured early and would otherwise linger).
  if [ "$nrc" = 124 ]; then
    SUP_NOTE="nuclei hit the ${NUCLEI_MAX_TIME}s time cap - partial results kept"
  else
    SUP_NOTE="nuclei finished: $(wc -l <"$nuclei_file" 2>/dev/null || echo 0) findings in $((SECONDS-ns))s"
  fi
  render
  touch "$OUTDIR/.done_nuclei"
fi
find_count=$(wc -l < "$nuclei_file" 2>/dev/null || echo 0)
set_stage $S_NUCLEI done "$find_count findings$(done_marker nuclei && echo ' (resumed)')"

