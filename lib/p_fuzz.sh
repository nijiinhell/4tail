# Step 4: Fuzzing (tech-aware, per host)
# For each live host: base "juicy" wordlist  +  SecLists lists matched to its
# detected tech  ->  deduped combined list  ->  ffuf. Every AI/static path is
# existence-checked, so nothing bogus reaches ffuf.

# Index every real SecLists Web-Content list once (basename<TAB>abs-path), excluding
# the big generic lists. Lets us match detected tech to files that ACTUALLY exist -
# auto-covering tech we never hardcoded (jenkins, grafana, weblogic, ...) and never
# referencing a path that isn't installed.
build_seclists_index() {
  [ "$SECLISTS_DYNAMIC" = 1 ] && [ -n "$SECLISTS_DIR" ] || return 0
  [ -s "$seclists_index" ] && return 0   # already built (e.g. resume)
  local root="$SECLISTS_DIR/Discovery/Web-Content"; [ -d "$root" ] || root="$SECLISTS_DIR"
  find "$root" -maxdepth 4 -type f \( -iname '*.txt' -o -iname '*.fuzz.txt' \) 2>/dev/null \
    | grep -viE 'raft-|big\.txt|directory-list|combined_|dirbuster|/all\.txt|/common\.txt' \
    | while IFS= read -r f; do printf '%s\t%s\n' "$(basename "$f" | tr 'A-Z' 'a-z')" "$f"; done \
    > "$seclists_index" 2>/dev/null || true
}
# Real SecLists files whose basename contains a tech token (specific lists only).
seclists_match() {  # tech-token -> abs paths
  # Strip a version suffix (httpx emits "php:8.1.2", "apache 2.4") - the bare
  # token is what appears in SecLists filenames; the versioned one matches nothing.
  local t; t="$(printf '%s' "$1" | tr 'A-Z' 'a-z' | sed -E 's/[:[:space:]/][0-9].*$//')"
  [ "${#t}" -ge 3 ] && [ -s "$seclists_index" ] || return 0
  awk -F'\t' -v t="$t" 'index($1,t){print $2}' "$seclists_index" | head -n "$SECLISTS_MATCH_MAX"
}

# Collect the wordlist paths for a given comma-separated, lowercased tech string.
# Prints one absolute wordlist path per line (base list first, then tech lists).
host_wordlists() {
  local techs="$1" t key rel
  [ -f "$WORDLIST" ] && printf '%s\n' "$WORDLIST"
  # Bo0oM api-endpoints.txt (if present next to base list) for API-ish hosts
  if [ -n "$API_ENDPOINTS_EXTRA" ]; then
    case ",$techs," in *api*|*graphql*|*swagger*|*rest*|*json*) printf '%s\n' "$API_ENDPOINTS_EXTRA" ;; esac
  fi
  [ -n "$SECLISTS_DIR" ] || return 0
  IFS=',' read -ra _arr <<< "$techs"
  # (a) static + AI tech->list map
  if [ -s "$tech_map_file" ]; then
    for t in "${_arr[@]}"; do
      [ -z "$t" ] && continue
      t="${t%%:*}"                       # drop version suffix (php:8.1 -> php)
      while IFS=$'\t' read -r key rel; do
        [ -z "$key" ] && continue
        case "$rel" in *raft-*|*big.txt|*directory-list*|*combined_*|*dirbuster*|*/all.txt) continue ;; esac
        # 'java' key must not swallow 'javascript' (substring match would mis-map it to J2EE lists)
        [ "$key" = java ] && case "$t" in *javascript*) continue ;; esac
        case "$t" in *"$key"*)
          if [ -f "$SECLISTS_DIR/$rel" ]; then
            printf '%s\n' "$SECLISTS_DIR/$rel"
          else
            # AI-suggested path not on disk (hallucinated path/casing): fall back to the
            # real indexed SecLists file whose name carries this list's token.
            seclists_match "$(basename "$rel" | sed 's/\.[^.]*$//')"
          fi ;;
        esac
      done < "$tech_map_file"
    done
  fi
  # (b) dynamic: match detected tech against REAL SecLists filenames
  if [ "$SECLISTS_DYNAMIC" = 1 ]; then
    for t in "${_arr[@]}"; do [ -n "$t" ] && seclists_match "$t"; done
  fi
}

# Generic "juicy" extensions distilled from Bo0oM/fuzz.txt's extensions.txt
# (backups, configs, source, archives, editor swap files). Highest-value first so
# they survive the MAX_EXTS cap. Applied to every host.
GENERIC_EXTS="bak,old,zip,sql,conf,config,txt,log,backup,save,orig,swp,~,tar.gz,tgz,gz,ini,inc,tmp"

# Per-host extension set = tech-specific exts (FIRST - highest signal, e.g. .php lets
# us find config.php.bak) + generic juicy exts. ffuf requests word AND word.ext.
host_extensions() {
  local techs="$1" tech="" t
  IFS=',' read -ra _e <<< "$techs"
  for t in "${_e[@]}"; do
    case "$t" in
      # javascript MUST precede *java* - otherwise *java* swallows it and JS hosts
      # get .jsp/.war exts (filling the MAX_EXTS cap) instead of .js/.map/.env.
      *node*|*express*|*javascript*)           tech="$tech,js,map,env" ;;
      *php*)                                    tech="$tech,php,phtml,phps" ;;
      *asp*|*iis*|*aspnet*|*asp.net*|*dotnet*) tech="$tech,aspx,asp,ashx,config,cs" ;;
      *java*|*jsp*|*tomcat*|*spring*|*struts*) tech="$tech,jsp,jspx,war,properties,class" ;;
      *coldfusion*|*cfm*)                      tech="$tech,cfm,cfc" ;;
      *python*|*django*|*flask*)               tech="$tech,py,pyc" ;;
      *ruby*|*rails*)                          tech="$tech,rb,erb" ;;
      *perl*)                                  tech="$tech,pl,cgi" ;;
    esac
  done
  printf '%s,%s' "${tech#,}" "$GENERIC_EXTS"
}

# Turn a tech string into an ffuf -e value (deduped, capped, leading dot on each).
build_ext_flag() {
  local techs="$1" raw
  if [ -n "$EXTENSIONS" ]; then raw="$EXTENSIONS"; else raw="$(host_extensions "$techs")"; fi
  printf '%s' "$raw" | tr ',[:space:]' '\n\n' | grep -oE '[A-Za-z0-9.~_-]+' \
    | awk '!seen[$0]++' | head -n "$MAX_EXTS" \
    | sed -E 's/^([A-Za-z0-9])/.\1/' | paste -sd, -
}

# Do we have anything at all to fuzz with?
fuzz_possible=0
{ [ -f "$WORDLIST" ] || { [ -n "$SECLISTS_DIR" ] && [ -s "$tech_map_file" ]; }; } && fuzz_possible=1

CDN_RE='cloudfront|cloudflare|akamai|fastly|imperva|incapsula|sucuri|edgecast|stackpath|azure front door'
if [ "$SKIP_FUZZ" = 1 ]; then
  set_stage $S_FUZZ skip "disabled (-q / SKIP_FUZZ)"
elif [ "$FUZZING_STRATEGY" = off ]; then
  # SPA/CDN-fronted targets: classic path fuzzing is mostly noise against a JS
  # front-end served from one origin - the value is in JS mining + the API, not /FUZZ.
  set_stage $S_FUZZ skip "off (blueprint fuzzing_strategy=off)"
elif ! have ffuf; then
  set_stage $S_FUZZ skip "ffuf not installed"
elif [ "$fuzz_possible" != 1 ]; then
  set_stage $S_FUZZ skip "no wordlist / SecLists"
elif [ "$RESUME" = 1 ] && [ -f "$OUTDIR/.done_fuzz" ]; then
  set_stage $S_FUZZ done "$(grep -c . "$fuzz_plan_file" 2>/dev/null || echo 0) hosts (resumed)"
else
  if [ "$FUZZING_STRATEGY" = light ]; then
    # Lighten path fuzzing (SPA/CDN blueprints): smaller wordlist, fewer exts, tighter
    # per-host cap. Still runs - just cheap - so a stray classic path is still found.
    # An explicit user value (CLI/env) always wins over the lightening.
    [ -n "${_user_set_MAX_FUZZ_WORDS:-}" ] || MAX_FUZZ_WORDS=4000
    [ -n "${_user_set_MAX_EXTS:-}" ]       || MAX_EXTS=2
    [ -n "${_user_set_FUZZ_MAX_TIME:-}" ]  || FUZZ_MAX_TIME=120
  fi
  set_stage $S_FUZZ running "indexing SecLists$([ "$FUZZING_STRATEGY" = light ] && echo ' (light)')"
  build_seclists_index   # index real SecLists files once so tech matching is grounded in what's installed
  set_stage $S_FUZZ running "0 hosts ($(nlines "${seclists_index:-/dev/null}") lists indexed)"
  [ "$RESUME" = 1 ] || : > "$fuzz_plan_file"   # keep prior progress when resuming
  if [ "$DEDUPE_ORIGINS" = 1 ] && [ -s "$httpx_json" ]; then
    # One representative per (origin, response signature): origin = cname or first IP;
    # signature = status|content_length|title. Kills near-identical pages and shared
    # origins so we don't fuzz the same thing hundreds of times.
    hosts_tsv="$(jq -r '
        ((.cname // (.a[0]? // .host)) | tostring) as $origin
        | (.url | sub("^https?://";"") | sub("[:/].*";"")) as $host
        # generic/empty roots -> keyed per hostname (keep distinct microservices behind one IP);
        # content-rich identical pages -> collapsed by shared signature.
        | (if ((.title // "") == "") or ((.content_length // 0) < 256)
           then $host
           else ($origin + "|" + (.status_code|tostring) + "|" + ((.content_length//0)|tostring) + "|" + (.title//"")) end) as $sig
        | [ (.url),
            ((.tech // []) | map(ascii_downcase) | join(",")),
            $sig ]
        | @tsv' "$httpx_json" 2>/dev/null \
      | awk -F'\t' '!seen[$3]++ {print $1"\t"$2}' | rank_filter)"
  else
    hosts_tsv="$(jq -r '[.url, ((.tech // []) | map(ascii_downcase) | join(","))] | @tsv' \
                   "$httpx_json" 2>/dev/null | rank_filter)"
  fi
  # rank_filter orders hosts by value (not alphabetically) so MAX_FUZZ_HOSTS keeps the top N.
  [ -n "$hosts_tsv" ] || hosts_tsv="$(sed 's/$/\t/' "$alive_file" | rank_filter)"
  total=$(printf '%s\n' "$hosts_tsv" | grep -c .)
  cap="$total"
  [ "$MAX_FUZZ_HOSTS" -gt 0 ] 2>/dev/null && cap="$MAX_FUZZ_HOSTS"

  # concurrency (sanitize) + auto-backoff state
  P="$FUZZ_PARALLEL"; case "$P" in ''|*[!0-9]*) P=1;; esac; [ "$P" -lt 1 ] && P=1
  p_eff="$P"; block_hits=0; backoff=0
  BACKOFF_TRIGGER="${FUZZ_BACKOFF_TRIGGER:-3}"; BACKOFF_SLEEP="${FUZZ_BACKOFF_SLEEP:-15}"
  declare -A JOB=()
  fuzzed=0; skipped_cdn=0; resumed=0; done_count=0

  fuzz_running() { local p n=0; for p in "${!JOB[@]}"; do kill -0 "$p" 2>/dev/null && n=$((n+1)); done; echo "$n"; }
  fuzz_reap() {
    local p sf jf r429
    for p in "${!JOB[@]}"; do
      kill -0 "$p" 2>/dev/null && continue
      wait "$p" 2>/dev/null || true
      sf="${JOB[$p]}"; jf="$fuzz_dir/${sf}.json"
      r429="$(jq '[.results[]?|select(.status==429)]|length' "$jf" 2>/dev/null || echo 0)"
      [ "${r429:-0}" -gt 0 ] 2>/dev/null && block_hits=$((block_hits + 1))
      # stream this host's hits so the live loot feed shows ffuf discoveries DURING the stage,
      # not only after it (the final block below still rebuilds the canonical sorted/deduped list).
      jq -r '.results[]? | [(.status|tostring),(.length|tostring),.url] | @tsv' "$jf" 2>/dev/null >> "$fuzz_findings_file"
      rm -f "$fuzz_dir/.wl_${sf}.txt"; unset 'JOB[$p]'; done_count=$((done_count + 1))
    done
  }
  fuzz_status() {
    ST_DETAIL[$S_FUZZ]="run:$(fuzz_running)/$p_eff done:$done_count/$cap${skipped_cdn:+ cdn:$skipped_cdn}${resumed:+ res:$resumed}$([ "$backoff" = 1 ] && echo ' ⚠backoff')"
  }
  : > "$fuzz_findings_file"   # fresh file for live streaming from fuzz_reap (rebuilt canonically after the loop)

  while IFS=$'\t' read -r url techs; do
    [ -z "$url" ] && continue
    safe="$(printf '%s' "$url" | tr -c 'A-Za-z0-9._-' '_')"
    if [ "$RESUME" = 1 ] && [ -f "$fuzz_dir/${safe}.json" ]; then resumed=$((resumed + 1)); continue; fi
    if [ "$SKIP_CDN_FUZZ" = 1 ]; then
      _h="$(printf '%s' "$url" | sed -E 's#^[a-z]+://##; s#[:/].*$##')"
      if printf '%s' "$techs" | grep -qiE "$CDN_RE" || { [ -s "$cdn_file" ] && grep -qxiF "$_h" "$cdn_file"; }; then
        skipped_cdn=$((skipped_cdn + 1)); continue
      fi
    fi
    if [ "$MAX_FUZZ_HOSTS" -gt 0 ] 2>/dev/null && [ "$fuzzed" -ge "$MAX_FUZZ_HOSTS" ]; then break; fi
    mapfile -t wls < <(host_wordlists "$techs" | awk 'NF' | awk '!seen[$0]++')
    [ "${#wls[@]}" -eq 0 ] && continue
    fuzz_reap   # process any finished jobs so block_hits is current
    # auto-backoff: too many 429s -> drop to serial + space out requests
    if [ "$backoff" = 0 ] && [ "$block_hits" -ge "$BACKOFF_TRIGGER" ]; then
      backoff=1; p_eff=1
      [ "$TUI" = 1 ] || warn "WAF rate-limiting detected ($block_hits hosts hit 429) - backing off (serial + ${BACKOFF_SLEEP}s spacing)"
    fi
    # wait for a free slot
    while [ "$(fuzz_running)" -ge "$p_eff" ]; do fuzz_reap; fuzz_status; render; sleep 0.25; done
    fuzzed=$((fuzzed + 1))
    combined="$fuzz_dir/.wl_${safe}.txt"
    # authenticated fuzzing: drop logout/session-kill words so ffuf doesn't nuke the session
    if [ "$AVOID_LOGOUT" = 1 ] && [ "${#AUTH_H[@]}" -gt 0 ]; then
      cat "${wls[@]}" 2>/dev/null | grep -viE "$LOGOUT_RE" | sort -u | head -n "$MAX_FUZZ_WORDS" > "$combined"
    else
      cat "${wls[@]}" 2>/dev/null | sort -u | head -n "$MAX_FUZZ_WORDS" > "$combined"
    fi
    # Prepend AI-generated, org-specific words (payments-v2, partner-portal, internal, ...) that
    # no static SecLists list carries. Added AFTER the cap so they always get fuzzed (they're few).
    if [ -s "${custom_words_file:-}" ]; then
      { cat "$custom_words_file"; cat "$combined"; } | awk 'NF && !seen[$0]++' > "$combined.tmp" && mv "$combined.tmp" "$combined"
    fi
    names="$(printf '%s\n' "${wls[@]}" | sed 's#.*/##' | paste -sd+ -)"
    ext_flag="$(build_ext_flag "$techs")"
    printf '%s\t%s\t(%s words) exts:[%s]\n' "$url" "$names" "$(wc -l < "$combined")" "$ext_flag" >> "$fuzz_plan_file"
    # -ac auto-calibration filters soft-404 / catch-all responses (huge quality boost:
    # without it a host that answers 200 to everything floods the results with junk).
    [ "$TUI" = 1 ] || log "Fuzzing $fuzzed/$cap: $url"
    if [ "$FUZZ_ENGINE" = feroxbuster ] && have feroxbuster; then
      # feroxbuster (Rust, recursive) - bounded depth + time so recursion can't balloon.
      # Convert its JSONL to the ffuf-shaped {results:[{status,length,url}]} the aggregator reads.
      fx_ext="$(printf '%s' "$ext_flag" | tr -d '.')"   # feroxbuster wants exts without dots
      fcmd=(feroxbuster -u "$url" -w "$combined" -q --json --no-state -d "$FEROX_DEPTH"
            -s 200,204,301,302,307,401,403,405,500 -o "$fuzz_dir/.fx_${safe}.jsonl")
      [ -n "$fx_ext" ] && fcmd+=(-x "$fx_ext")
      [ -n "$AUTH_HEADER" ] && while IFS= read -r _hl; do [ -n "$_hl" ] && fcmd+=(-H "$_hl"); done <<< "$AUTH_HEADER"
      [ -n "$AUTH_COOKIE" ] && fcmd+=(-b "$AUTH_COOKIE")
      [ -n "$PROXY" ] && fcmd+=(-p "$PROXY")
      [ "$FUZZ_MAX_TIME" -gt 0 ] 2>/dev/null && fcmd+=(--time-limit "${FUZZ_MAX_TIME}s")
      ( "${fcmd[@]}" >/dev/null 2>>"$llm_log"
        jq -s '{results:[.[]?|select(.type=="response")|{status:.status,length:.content_length,url:.url}]}' \
           "$fuzz_dir/.fx_${safe}.jsonl" 2>/dev/null > "$fuzz_dir/${safe}.json" || echo '{"results":[]}' > "$fuzz_dir/${safe}.json"
        rm -f "$fuzz_dir/.fx_${safe}.jsonl" ) & JOB[$!]="$safe"
    else
      ffuf_args=(-u "$url/FUZZ" -w "$combined" -ac -mc 200,204,301,302,307,401,403,405,500
                 -of json -o "$fuzz_dir/${safe}.json" -s)
      [ "${#FFUF_NET[@]}" -gt 0 ] && ffuf_args+=("${FFUF_NET[@]}")
      [ -n "$ext_flag" ] && ffuf_args+=(-e "$ext_flag")
      [ "$FFUF_RATE" -gt 0 ] 2>/dev/null && ffuf_args+=(-rate "$FFUF_RATE")
      [ "$FUZZ_MAX_TIME" -gt 0 ] 2>/dev/null && ffuf_args+=(-maxtime "$FUZZ_MAX_TIME")  # stop a slow host after N s
      ffuf "${ffuf_args[@]}" >/dev/null 2>>"$llm_log" & JOB[$!]="$safe"
    fi
    fuzz_status; render
    [ "$backoff" = 1 ] && sleep "$BACKOFF_SLEEP"
  done <<< "$hosts_tsv"
  # drain remaining jobs
  while [ "$(fuzz_running)" -gt 0 ]; do fuzz_reap; fuzz_status; render; sleep 0.25; done
  fuzz_reap
  [ "$MAX_FUZZ_HOSTS" -gt 0 ] 2>/dev/null || touch "$OUTDIR/.done_fuzz"
  set_stage $S_FUZZ done "$fuzzed fuzzed$([ "$resumed" -gt 0 ] && echo ", $resumed resumed")$([ "$skipped_cdn" -gt 0 ] && echo ", $skipped_cdn CDN skipped")$([ "$backoff" = 1 ] && echo ", backoff")"
fi

# Aggregate ffuf per-host JSON into one findings list (status<TAB>length<TAB>url),
# prioritised by interestingness. Runs for fresh and resumed runs alike. Without this
# the content-discovery results were written to disk and never surfaced.
: > "$fuzz_findings_file"
if ls "$fuzz_dir"/*.json >/dev/null 2>&1; then
  for jf in "$fuzz_dir"/*.json; do
    jq -r '.results[]? | [(.status|tostring), (.length|tostring), .url] | @tsv' "$jf" 2>/dev/null
  done | awk -F'\t' '!seen[$3]++' > "$OUTDIR/.fuzz_raw"
  { for s in 200 302 301 307 401 403 405 500 204; do awk -F'\t' -v s="$s" '$1==s' "$OUTDIR/.fuzz_raw"; done
    awk -F'\t' '$1!~/^(200|301|302|307|401|403|405|500|204)$/' "$OUTDIR/.fuzz_raw"; } > "$fuzz_findings_file"
  rm -f "$OUTDIR/.fuzz_raw"
fi
fuzz_hits="$(nlines "$fuzz_findings_file")"

