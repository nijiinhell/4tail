# Step 4.7: ACTIVE FUNNEL (-C): crawl (broad/passive) -> cluster -> AI picks juicy URLs
# -> dispatch paired specialists (parallel, capped) -> merge. The "bug-hunter brain".
has_spec() { case ",$ACT_SPECIALISTS," in *",$1,"*) return 0;; *) return 1;; esac; }
# Deterministic URL clustering: collapse ids/uuids/hashes/values so 5000 URLs -> ~N patterns.
cluster_urls() {  # stdin: urls -> stdout: pattern<TAB>example-url
  sed -E \
    -e 'h' \
    -e 's#/[0-9a-fA-F]{8}-[0-9a-fA-F-]{20,}#/{uuid}#g' \
    -e 's#=[^&]*#={v}#g' \
    -e 's#/[0-9]+(/|\?|$)#/{id}\1#g' \
    -e 's#/[0-9a-fA-F]{12,}(/|\?|$)#/{hash}\1#g' \
    -e 'G' \
    -e 's/\n/\t/'
}

if [ "$CRAWL" != 1 ]; then
  set_stage $S_CRAWL skip "off (-C to enable)"
elif done_marker crawl && [ -f "$targets_active_file" ]; then
  set_stage $S_CRAWL done "$(nlines "$urls_file") urls, $(nlines "$targets_active_file") active, $(nlines "$dast_file") dast (resumed)"
else
  set_stage $S_CRAWL running "collecting URLs"
  esc_domain="$(printf '%s' "$domain" | sed 's/\./\\./g')"
  : > "$urls_file"
  # (A) Broad / passive URL collection - WAF-safe. Run ALL available sources and UNION them
  # (waymore adds commoncrawl+alienvault+urlscan, but gau/waybackurls often surface URLs it
  # misses) - more coverage, deduped later anyway.
  [ "$NO_ARCHIVE" != 1 ] && have gau         && { printf '%s\n' "$domain" | tmo "$GAU_MAX_TIME" gau --subs 2>>"$llm_log" | grep -ivE '\.(png|jpe?g|gif|svg|woff2?|ttf|eot|ico|css)([?#]|$)' | head -n 50000 >> "$urls_file" || true; }
  [ "$NO_ARCHIVE" != 1 ] && have waybackurls && { printf '%s\n' "$domain" | tmo "$GAU_MAX_TIME" waybackurls 2>>"$llm_log" | grep -ivE '\.(png|jpe?g|gif|svg|woff2?|ttf|eot|ico|css)([?#]|$)' | head -n 50000 >> "$urls_file" || true; }
  if [ "$NO_ARCHIVE" != 1 ] && [ "$USE_WAYMORE" = 1 ] && have waymore; then
    set_stage $S_CRAWL running "waymore: aggregating more sources"
    tmo "$((GAU_MAX_TIME*2))" waymore -i "$domain" -mode U -oU "$OUTDIR/.waymore.txt" >/dev/null 2>>"$llm_log" || true
    [ -f "$OUTDIR/.waymore.txt" ] && cat "$OUTDIR/.waymore.txt" >> "$urls_file"; rm -f "$OUTDIR/.waymore.txt"
  fi
  if have katana; then
    set_stage $S_CRAWL running "katana crawling…"
    kcmd=(katana -silent -list "$alive_file" -d 2 -jc -kf all -c 15 -o "$OUTDIR/.katana.txt")
    [ "${#KATANA_NET[@]}" -gt 0 ] && kcmd+=("${KATANA_NET[@]}")
    [ "$CRAWL_MAX_TIME" -gt 0 ] 2>/dev/null && have timeout && kcmd=(timeout "${CRAWL_MAX_TIME}s" "${kcmd[@]}")
    "${kcmd[@]}" >/dev/null 2>>"$llm_log" & kpid=$!
    kstart=$SECONDS
    while kill -0 "$kpid" 2>/dev/null; do
      ST_DETAIL[$S_CRAWL]="katana crawling… $(nlines "$OUTDIR/.katana.txt") urls · $((SECONDS-kstart))s"; render; sleep 1
    done
    wait "$kpid" 2>/dev/null || true
    [ -f "$OUTDIR/.katana.txt" ] && cat "$OUTDIR/.katana.txt" >> "$urls_file" && rm -f "$OUTDIR/.katana.txt"
  fi
  # fold in endpoints mined from source maps + JS bundles (SPA API surface); scoped+deduped below
  [ -s "${smap_endpoints_file:-/dev/null}" ] && cat "$smap_endpoints_file" >> "$urls_file"
  [ -s "${js_endpoints_file:-/dev/null}" ] && cat "$js_endpoints_file" >> "$urls_file"
  grep -iE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" "$urls_file" 2>/dev/null \
    | grep -vE '/:[a-zA-Z0-9_]+' \
    | sort -u | head -n "$CRAWL_MAX_URLS" > "$urls_file.tmp" && mv "$urls_file.tmp" "$urls_file"
  # Only URLs with a real ?k=v, and NOT static assets - so clustering, AI selection and
  # every downstream specialist work on genuine injectable endpoints.
  grep -E '\?[^=]+=' "$urls_file" 2>/dev/null | drop_static | sort -u > "$urls_params_file" || : > "$urls_params_file"
  url_total="$(nlines "$urls_file")"; param_total="$(nlines "$urls_params_file")"

  # (B) Cluster parametered URLs into endpoint patterns (one exemplar per pattern).
  set_stage $S_CRAWL running "clustering $param_total param-urls"
  cluster_urls < "$urls_params_file" | awk -F'\t' '!seen[$1]++' > "$OUTDIR/.patterns.tsv"
  cut -f1 "$OUTDIR/.patterns.tsv" > "$url_patterns_file"
  pattern_total="$(nlines "$url_patterns_file")"

  # (C) AI "juicy" funnel: cheap model picks the most promising patterns; expand to real
  # URLs (capped ACT_MAX_JUICY). Falls back to all param exemplars when AI is off.
  : > "$targets_active_file"
  if [ "$AI_ENABLED" = 1 ] && budget_ok && [ "$pattern_total" -gt 0 ]; then
    set_stage $S_CRAWL running "AI selecting juicy endpoints ($pattern_total patterns)"
    nl -ba -w1 -s') ' "$url_patterns_file" | head -n 600 > "$OUTDIR/.patterns_numbered.txt"
    # Surface the legacy ranking so the model prefers URLs on older/outdated hosts.
    stale_hint=""
    [ "$STALE_RANK" = 1 ] && [ -s "${stale_file:-/dev/null}" ] && \
      stale_hint=" These hosts look the most legacy/outdated (older stack = higher bug likelihood, prioritize their URLs): $(awk -F'\t' '{printf "%s(%s) ",$2,$3}' "$stale_file" | head -c 500)."
    jout="$(mktemp)"
    ai_call "$LLM_MODEL_PLAN" 1500 \
      "You are an expert bug-bounty hunter. From the numbered endpoint patterns, select the ones MOST likely to hold IDOR, SQLi, XSS, SSRF, LFI, open-redirect or logic flaws, given the focus areas: $ACT_FOCUS.${stale_hint} Ignore static assets (js/css/img/fonts), analytics, and generic CMS noise. Reply with ONLY a comma-separated list of the numbers you pick (max $ACT_MAX_JUICY), nothing else." \
      "$(cat "$OUTDIR/.patterns_numbered.txt")" >"$jout" 2>>"$llm_log" || true
    # parse chosen line numbers -> exemplar URLs
    sel="$(grep -oE '[0-9]+' "$jout" | sort -un | head -n "$ACT_MAX_JUICY")"; rm -f "$jout"
    if [ -n "$sel" ]; then
      while read -r n; do sed -n "${n}p" "$OUTDIR/.patterns.tsv" | cut -f2; done <<< "$sel" >> "$targets_active_file"
    fi
  fi
  # fallback / augment: if AI gave nothing, use all param exemplars (capped)
  [ -s "$targets_active_file" ] || cut -f2 "$OUTDIR/.patterns.tsv" | head -n "$ACT_MAX_JUICY" > "$targets_active_file"
  sort -u -o "$targets_active_file" "$targets_active_file"
  rm -f "$OUTDIR/.patterns_numbered.txt"
  active_total="$(nlines "$targets_active_file")"

  # (C2) API specs: find Swagger/OpenAPI/GraphQL, let the AI turn each spec into concrete
  # test requests, and fold them into the active set. APIs are where IDOR/authz/logic bugs
  # live and plain crawling misses them (undocumented params, methods, versioned paths).
  : > "$api_specs_file"; : > "$api_tests_file"
  if [ "$API_SPECS" = 1 ]; then
    set_stage $S_CRAWL running "probing for API specs (swagger/openapi/graphql)"
    # (a) specs already seen in collected URLs (strictly in-scope only)
    grep -iE '(swagger|openapi|api-docs|v[0-9]+/api-docs|/graphql|/graphiql|apispec|/\.well-known/)' \
      "$urls_file" 2>/dev/null \
      | grep -iE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" \
      | sort -u >> "$api_specs_file" || true
    # (b) probe common spec paths on each live host (validate genuine spec signatures)
    api_probe_paths=(/swagger.json /swagger/v1/swagger.json /openapi.json /v2/api-docs /v3/api-docs \
                     /api-docs /api/swagger.json /api/openapi.json /swagger-ui/index.html /graphql /api/graphql)
    while IFS= read -r h; do
      [ -n "$h" ] || continue
      base="${h%/}"
      for p in "${api_probe_paths[@]}"; do
        u="$base$p"
        resp="$(curl -s -L --max-time 8 ${CURL_NET[@]+"${CURL_NET[@]}"} "$u" 2>/dev/null | head -c 1200)"
        [ -n "$resp" ] || continue
        # Must contain legitimate API spec/schema indicators (never plain 401/403 or SPA catch-all HTML)
        if printf '%s' "$resp" | grep -qiE '("openapi"|"swagger"|"paths"[[:space:]]*:|swagger-ui|SwaggerUIBundle|GraphiQL|"__schema")'; then
          printf '%s\n' "$u" >> "$api_specs_file"
        fi
      done
    done < <(sort -u "$alive_file" 2>/dev/null | head -n 25)
    sort -u -o "$api_specs_file" "$api_specs_file"

    # (c) fetch each spec and let the AI generate targeted test URLs
    spec_n=0
    while IFS= read -r spec; do
      [ -n "$spec" ] || continue
      [ "$spec_n" -ge "$API_MAX_SPECS" ] && break
      body="$(curl -s -L --max-time 15 ${CURL_NET[@]+"${CURL_NET[@]}"} "$spec" 2>/dev/null \
               | head -c 60000)"
      [ -n "$body" ] || continue
      spec_n=$((spec_n+1))
      set_stage $S_CRAWL running "AI building API tests from spec $spec_n/$API_MAX_SPECS"
      if [ "$AI_ENABLED" = 1 ] && budget_ok; then
        aout="$(mktemp)"
        ai_call "$LLM_MODEL_PLAN" 2000 \
          "You are an API security tester. Below is an API spec (OpenAPI/Swagger JSON/YAML, or a GraphQL/GraphiQL page) fetched from $spec. Build concrete HTTP GET test URLs (absolute, same origin) that exercise the riskiest endpoints for IDOR, broken authz, SQLi, SSRF and mass-assignment: substitute realistic probe values for path/query params (ids=1, user=1, q=test', url=http://169.254.169.254/, file=/etc/passwd as appropriate). Only GET-able URLs, one per line, no commentary, no markdown, max $API_MAX_TESTS lines." \
          "$body" >"$aout" 2>>"$llm_log" || true
        grep -oE 'https?://[^ "'"'"'`<>]+' "$aout" 2>/dev/null \
          | grep -iE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" \
          >> "$api_tests_file" || true
        rm -f "$aout"
      fi
    done < "$api_specs_file"

    if [ -s "$api_tests_file" ]; then
      sort -u "$api_tests_file" | head -n "$API_MAX_TESTS" > "$api_tests_file.tmp" && mv "$api_tests_file.tmp" "$api_tests_file"
      cat "$api_tests_file" >> "$targets_active_file"
      sort -u -o "$targets_active_file" "$targets_active_file"
      active_total="$(nlines "$targets_active_file")"
    fi
    set_stage $S_CRAWL running "api specs: $(nlines "$api_specs_file") found, $(nlines "$api_tests_file") tests built"

    # (C2.5) GraphQL introspection: if a /graphql endpoint answers an introspection query,
    # the whole schema (types, fields, args) is readable - the single highest-signal GraphQL
    # find, since it hands you the full attack surface for IDOR/authz/injection. Done with a
    # GET introspection query (read-only, no mutation) to stay within the GET-only invariant;
    # servers that only accept POST simply won't introspect, which is the safe tradeoff.
    : > "$gql_schema_file"
    gql_q='{__schema{queryType{name}mutationType{name}types{name kind fields{name args{name}}}}}'
    gql_n=0
    gql_endpoints="$(grep -iE 'https?://[^ ]*/(graphql|graphiql|api/graphql|v[0-9]+/graphql)([?/]|$)' \
                      "$api_specs_file" 2>/dev/null | sort -u)"
    while IFS= read -r gql; do
      [ -n "$gql" ] || continue
      [ "$gql_n" -ge "${GRAPHQL_MAX:-5}" ] && break
      gql_n=$((gql_n+1))
      set_stage $S_CRAWL running "graphql introspection $gql_n ($gql)"
      gresp="$(curl -s -G --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} \
                 -H 'Content-Type: application/json' \
                 --data-urlencode "query=$gql_q" "$gql" 2>/dev/null | head -c 400000)"
      # introspection is OPEN only if the server actually returned a __schema with its types
      printf '%s' "$gresp" | jq -e '.data.__schema.types | length > 0' >/dev/null 2>&1 || continue
      {
        echo "== GraphQL introspection OPEN: $gql =="
        printf '%s' "$gresp" | jq -r '
          .data.__schema as $s
          | "queryType: \($s.queryType.name // "-")   mutationType: \($s.mutationType.name // "-")",
            ( $s.types[]
              | select(.name | test("^__") | not)
              | select(.fields != null and (.fields | length > 0))
              | "type \(.name) {" ,
                ( .fields[] | "  \(.name)(\((.args // []) | map(.name) | join(", ")))" ),
                "}" )' 2>/dev/null
        # Extract sensitive mutations (auth, admin, role, delete, create)
        muts="$(printf '%s' "$gresp" | jq -r '
          .data.__schema as $s
          | ($s.mutationType.name // "Mutation") as $mname
          | (.data.__schema.types[]? | select(.name == $mname) | .fields[]?.name) // empty' 2>/dev/null \
          | grep -iE 'create|update|delete|modify|admin|add|remove|set|change|grant|invite|reset|auth|password|role' | sort -u | head -20)"
        if [ -n "$muts" ]; then
          echo "== Sensitive Mutations to Test ($gql) =="
          printf '%s\n' "$muts" | sed 's/^/  mutation /'
          echo
        fi
        echo
      } >> "$gql_schema_file"
      # Let the AI turn the live schema into concrete GET query-probes folded into the active set.
      if [ "$AI_ENABLED" = 1 ] && budget_ok; then
        gout="$(mktemp)"
        ai_call "$LLM_MODEL_PLAN" 1500 \
          "GraphQL introspection is OPEN at $gql. Below is the dumped schema. Build concrete HTTP GET probe URLs of the form ${gql}?query=<url-unencoded graphql query> that exercise the riskiest query fields for IDOR/broken-authz (fetch objects by id=1), injection (string args = test'), and SSRF (url/uri args = http://169.254.169.254/). Keep queries minimal and same-origin. One URL per line, no commentary, no markdown, max 20 lines." \
          "$(head -c 20000 "$gql_schema_file")" >"$gout" 2>>"$llm_log" || true
        grep -oE 'https?://[^ "'"'"'`<>]+' "$gout" 2>/dev/null \
          | grep -iE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" \
          >> "$api_tests_file" || true
        rm -f "$gout"
      fi
    done <<< "$gql_endpoints"
    if [ -s "$api_tests_file" ]; then   # re-fold (AI may have added GraphQL query probes)
      sort -u "$api_tests_file" | head -n "$API_MAX_TESTS" > "$api_tests_file.tmp" && mv "$api_tests_file.tmp" "$api_tests_file"
      cat "$api_tests_file" >> "$targets_active_file"; sort -u -o "$targets_active_file" "$targets_active_file"
      active_total="$(nlines "$targets_active_file")"
    fi
    [ -s "$gql_schema_file" ] && set_stage $S_CRAWL running "graphql: introspection OPEN on $(grep -c 'introspection OPEN' "$gql_schema_file") endpoint(s)"
  fi

  # (C3) kiterunner: API-route discovery with API-specific wordlists + route prediction -
  # finds /api/v1/users/{id}/roles style endpoints ffuf can't guess. Routes feed the active set.
  if [ "$USE_KITERUNNER" = 1 ] && have kr; then
    set_stage $S_CRAWL running "kiterunner: API route discovery"
    kapi="${SECLISTS_DIR:+$SECLISTS_DIR/Discovery/Web-Content/api/api-endpoints.txt}"
    if [ -n "$kapi" ] && [ -f "$kapi" ]; then
      sort -u "$alive_file" 2>/dev/null | head -n 20 \
        | tmo 300 kr scan - -w "$kapi" -q 2>/dev/null \
        | grep -oE 'https?://[^ ]+' | grep -iE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" \
        | sort -u | head -n 200 >> "$targets_active_file" || true
      sort -u -o "$targets_active_file" "$targets_active_file"
    fi
  fi

  # (D) Hidden parameters -> real test URLs in the active set.
  # (D1) Reuse params already discovered by the -j stage (params.txt: url<TAB>param)
  #      instead of re-running arjun, and emit a testable URL (?param=1), not a bare ?param.
  if [ -s "${params_file:-/dev/null}" ]; then
    set_stage $S_CRAWL running "folding $(nlines "$params_file") discovered params into tests"
    awk -F'\t' 'NF>=2{sep=($1 ~ /\?/)?"&":"?"; print $1 sep $2 "=1"}' "$params_file" >> "$targets_active_file"
    sort -u -o "$targets_active_file" "$targets_active_file"
  # (D2) else run arjun here on the juicy hosts (also emitting ?param=1, not bare ?param)
  elif has_spec arjun && have arjun && [ "${ACT_MAX_ARJUN:-0}" -gt 0 ] 2>/dev/null && [ "$active_total" -gt 0 ]; then
    set_stage $S_CRAWL running "arjun param discovery"
    awk -F/ '{print $1"//"$3}' "$targets_active_file" | sort -u | head -n "$ACT_MAX_ARJUN" \
      | while read -r h; do [ -n "$h" ] && tmo "$ARJUN_MAX_TIME" arjun -u "$h" -q -oT /dev/stdout 2>/dev/null \
          | sed "s#^#${h}/?#; s#\$#=1#" ; done >> "$targets_active_file" 2>/dev/null || true
  fi
  # Final clean of the set that feeds every slow specialist: drop static assets, then dedupe.
  drop_static < "$targets_active_file" 2>/dev/null | sort -u > "$targets_active_file.tmp" \
    && mv "$targets_active_file.tmp" "$targets_active_file"
  active_total="$(nlines "$targets_active_file")"

  # (E) gf bucketing on the active set (candidate classes for routing)
  : > "$gf_file"
  if have gf && [ -s "$targets_active_file" ]; then
    for pat in sqli xss ssrf lfi redirect rce ssti idor; do
      case ",$ACT_FOCUS," in *",$pat,"*|*",rce,"*) ;; *) [ "$pat" != idor ] && continue ;; esac
      gf "$pat" < "$targets_active_file" 2>/dev/null | sed "s/^/${pat}\t/" >> "$gf_file" || true
    done
  fi

  # (F) Dispatch paired specialists in parallel, each strictly capped.
  : > "$dast_file"; : > "$findings_dir/dalfox.txt"; : > "$findings_dir/kxss.txt"; : > "$findings_dir/sqlmap.txt"
  set_stage $S_CRAWL running "dispatching specialists ($active_total urls)"
  declare -a SPIDS=()
  # XSS reflection FIRST (fast): kxss/Gxss flags params that reflect unfiltered chars.
  # Run it synchronously so its output can actually feed dalfox (the real pairing).
  if { has_spec kxss && { have kxss || have Gxss; }; } && [ -s "$targets_active_file" ]; then
    set_stage $S_CRAWL running "kxss: probing reflection"; render
    xtool="kxss"; have kxss || xtool="Gxss"
    head -n "$ACT_MAX_KXSS" "$targets_active_file" | "$xtool" 2>/dev/null > "$findings_dir/kxss.txt" || true
  fi
  # XSS confirm: dalfox on the URLs kxss just flagged as reflecting (chained!) plus the
  # gf xss-bucket; only if neither yields anything do we fall back to the full active set.
  if has_spec dalfox && have dalfox && [ -s "$targets_active_file" ]; then
    xq="$findings_dir/.xssq.txt"; : > "$xq"
    grep -oiE 'https?://[^ ]+' "$findings_dir/kxss.txt" 2>/dev/null >> "$xq"   # kxss reflecting URLs (highest signal)
    grep -iE '^xss\t' "$gf_file" 2>/dev/null | cut -f2 >> "$xq"                 # gf xss-bucket
    # collapse value-variants (/s?q=1 /s?q=2 -> one) so dalfox tests each endpoint once
    if have qsreplace; then qsreplace FUZZ < "$xq" 2>/dev/null | sort -u | qsreplace 1 2>/dev/null | sort -u -o "$xq"; else sort -u -o "$xq" "$xq"; fi
    [ -s "$xq" ] || cp "$targets_active_file" "$xq"                             # fallback: whole active set
    dfx=(dalfox pipe --silence --skip-bav -o "$findings_dir/dalfox.txt"); [ "${#DALFOX_NET[@]}" -gt 0 ] && dfx+=("${DALFOX_NET[@]}")
    ( head -n "$ACT_MAX_DALFOX" "$xq" | tmo "$DALFOX_MAX_TIME" "${dfx[@]}" >/dev/null 2>>"$llm_log" ) & SPIDS+=($!)
  fi
  # Broad DAST: nuclei -dast across all classes (or ACT_DAST_TAGS)
  if has_spec nuclei-dast && have nuclei && [ -s "$targets_active_file" ]; then
    head -n "$DAST_MAX_URLS" "$targets_active_file" > "$OUTDIR/.dast_targets.txt"
    dcmd=(nuclei -silent -dast -l "$OUTDIR/.dast_targets.txt" -rate-limit "$NUCLEI_RATELIMIT"
          -timeout "$NUCLEI_TIMEOUT" -retries "$NUCLEI_RETRIES" -mhe "$NUCLEI_MHE" -o "$dast_file")
    [ -n "$ACT_DAST_TAGS" ] && dcmd+=(-tags "$ACT_DAST_TAGS")
    [ "${#NUCLEI_NET[@]}" -gt 0 ] && dcmd+=("${NUCLEI_NET[@]}")
    [ "$NUCLEI_MAX_TIME" -gt 0 ] 2>/dev/null && have timeout && dcmd=(timeout "${NUCLEI_MAX_TIME}s" "${dcmd[@]}")
    ( "${dcmd[@]}" >/dev/null 2>>"$llm_log" ) & SPIDS+=($!)
  fi
  # Blind SSRF / open-redirect confirmation via OAST: inject unique payloads into
  # redirect/SSRF-style params (prefers the gf redirect/ssrf buckets, else the active set).
  if [ "$OAST" = 1 ] && [ -n "$OAST_DOMAIN" ]; then
    { grep -iE '^(redirect|ssrf)\t' "$gf_file" 2>/dev/null | cut -f2; cat "$targets_active_file"; } \
      | sort -u | oast_inject & SPIDS+=($!)
  fi
  # SQLi confirmation: sqlmap on the gf-sqli URLs ONLY, tightly capped (not discovery)
  if has_spec sqlmap && [ "$SQLMAP_CONFIRM" = 1 ] && have sqlmap && [ "${ACT_MAX_SQLMAP:-0}" -gt 0 ] 2>/dev/null; then
    sq="$findings_dir/.sqliq.txt"; grep -iE '^sqli\t' "$gf_file" 2>/dev/null | cut -f2 | head -n "$ACT_MAX_SQLMAP" > "$sq"
    if [ -s "$sq" ]; then
      ( tmo "$SQLMAP_MAX_TIME" sqlmap -m "$sq" --batch --smart --level=1 --risk=1 --technique=BEU \
          --output-dir="$findings_dir/sqlmap" >/dev/null 2>>"$llm_log"
        grep -rhiE 'parameter .* is vulnerable|is injectable|Type: ' "$findings_dir/sqlmap" 2>/dev/null \
          | sort -u > "$findings_dir/sqlmap.txt" ) & SPIDS+=($!)
    fi
  fi
  # live progress while specialists run
  while :; do
    alive=0; for sp in "${SPIDS[@]:-}"; do [ -n "$sp" ] && kill -0 "$sp" 2>/dev/null && alive=$((alive+1)); done
    [ "$alive" -eq 0 ] && break
    ST_DETAIL[$S_CRAWL]="specialists running:$alive  dast:$(nlines "$dast_file") dalfox:$(nlines "$findings_dir/dalfox.txt") kxss:$(nlines "$findings_dir/kxss.txt")"
    render; sleep 2
  done
  for sp in "${SPIDS[@]:-}"; do [ -n "$sp" ] && wait "$sp" 2>/dev/null || true; done
  rm -f "$OUTDIR/.dast_targets.txt" "$findings_dir/.xssq.txt" "$findings_dir/.sqliq.txt"

  # (G) Correlation / exploitation passes that connect findings into verdicts.
  : > "$bypass_file"; : > "$prop_file"; : > "$idor_file"; : > "$corsy_file"
  set_stage $S_CRAWL running "403 bypass · path propagation · authz diff · CORS"
  awk -F'\t' '$1==401||$1==403' "$fuzz_findings_file" 2>/dev/null \
    | grep -viE 'google\.com|%2e%2e|\\\.\\\.|etc.{0,3}passwd' \
    | awk -F'\t' '!seen[$1"\t"$2]++' | try_403_bypass; render
  propagate_paths; render
  idor_check; render
  # CORS misconfiguration (Corsy) on the live hosts + juicy URLs (bug class we don't cover elsewhere).
  if [ "$CORS_SCAN" = 1 ] && have corsy; then
    { sort -u "$alive_file" 2>/dev/null; head -n 30 "$targets_active_file" 2>/dev/null; } | sort -u | head -n "$CORS_MAX" > "$OUTDIR/.cors_in.txt"
    # Strip Corsy's ANSI colors, drop its "No misconfigurations found" banner, and keep only
    # lines that are an actual finding (carry a URL or a named misconfig class).
    [ -s "$OUTDIR/.cors_in.txt" ] && tmo 180 corsy -i "$OUTDIR/.cors_in.txt" 2>/dev/null \
      | sed -E 's/\x1b\[[0-9;]*m//g' \
      | grep -viE 'no misconfig|not vulnerable|unreachable|could not|timed out|invalid|connection (refused|error)|^[[:space:]]*-?[[:space:]]*$' \
      | grep -iE 'reflect|wildcard|null origin|arbitrary origin|post-domain|pre-domain|trusted|credentials|origin reflected' > "$corsy_file" || true
    rm -f "$OUTDIR/.cors_in.txt"
  fi; render

  touch "$OUTDIR/.done_crawl"
  set_stage $S_CRAWL done "$url_total urls -> $active_total active | dast:$(nlines "$dast_file") dalfox:$(nlines "$findings_dir/dalfox.txt") kxss:$(nlines "$findings_dir/kxss.txt") sqlmap:$(nlines "$findings_dir/sqlmap.txt") bypass:$(nlines "$bypass_file") prop:$(nlines "$prop_file") idor:$(nlines "$idor_file")"
fi

