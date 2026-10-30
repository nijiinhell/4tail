# Step 4.5: JS & secret mining + param discovery (opt-in with -j)
js_urls_file="$OUTDIR/js_urls.txt"
js_secrets_file="$OUTDIR/js_secrets.txt"
params_file="$OUTDIR/params.txt"
# Regex for common leaked secrets (no single-quote chars, so it stays shell-safe).
SECRET_RE='AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|ghp_[0-9A-Za-z]{36}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|[a-z0-9.-]+\.s3\.amazonaws\.com|(api[_-]?key|secret|access[_-]?token|client[_-]?secret|aws_secret|password)["[:space:]:=]{1,4}[0-9A-Za-z._+/-]{12,}'

if [ "$JSMINE" != 1 ]; then
  set_stage $S_JS skip "off (-j to enable)"
elif ! have curl; then
  set_stage $S_JS skip "curl required"
elif done_marker js && [ -f "$js_secrets_file" ]; then
  set_stage $S_JS done "$(wc -l <"$js_secrets_file" 2>/dev/null||echo 0) secret hits (resumed)"
else
  set_stage $S_JS running "collecting JS"
  JS_HOSTS="${JS_HOSTS:-60}"; JS_MAX="${JS_MAX:-200}"
  # 1) gather JS URLs. UNION every available method (subjs/getJS can whiff on SPAs, and a
  #    direct scrape of <script src> catches the Angular/Vue/React bundles they miss).
  : > "$js_urls_file"
  scan_targets="$(sort -u "$alive_file" | head -n "$JS_HOSTS")"
  have subjs && printf '%s\n' "$scan_targets" | subjs 2>/dev/null >> "$js_urls_file"
  have getJS && printf '%s\n' "$scan_targets" | while read -r u; do getJS --url "$u" 2>/dev/null; done >> "$js_urls_file"
  # Always also scrape <script src=...> directly (handles ", ', and module scripts), so a SPA's
  # runtime/polyfills/vendor/main bundles are found even when the dedicated tools return nothing.
  printf '%s\n' "$scan_targets" | while read -r u; do
    curl -s -L --max-time 15 ${CURL_NET[@]+"${CURL_NET[@]}"} "$u" 2>/dev/null \
      | grep -aoiE 'src=["'"'"']?[^"'"'"' >]+\.js([?][^"'"'"' >]*)?' | sed -E 's/^src=["'"'"']?//' \
      | while read -r jrel; do case "$jrel" in
          http*) echo "$jrel" ;;
          //*)   echo "${u%%/*}$jrel" ;;
          /*)    echo "$(printf '%s' "$u" | sed -E 's#(https?://[^/]+).*#\1#')$jrel" ;;
          *)     echo "${u%/}/$jrel" ;;
        esac; done
  done >> "$js_urls_file"
  # Fold in historical JS bundles discovered by passive archives (gau/wayback/waymore)
  if [ -s "${urls_archive_file:-}" ]; then
    grep -iE '\.js([?#]|$)' "$urls_archive_file" 2>/dev/null \
      | grep -ivE '\.(json|jsp|map|css)([?#]|$)' >> "$js_urls_file" || true
  fi
  sort -u -o "$js_urls_file" "$js_urls_file"
  # SPA fallback: if scraping + subjs/getJS came up nearly empty (some SPAs inject their
  # scripts dynamically, so there's nothing to scrape), probe common entry-bundle names on
  # each host root directly and keep the ones that are actually served as JS. This is what
  # finds an Angular/Vue/React app's main/vendor/runtime/polyfills bundles reliably.
  if [ "$(nlines "$js_urls_file")" -lt 3 ]; then
    JS_COMMON="${JS_COMMON:-main.js vendor.js runtime.js polyfills.js app.js bundle.js index.js scripts.js common.js chunk-vendors.js app.bundle.js runtime-main.js}"
    printf '%s\n' "$scan_targets" | head -n 10 | while read -r u; do
      base="$(printf '%s' "$u" | sed -E 's#(https?://[^/]+).*#\1#')"
      for b in $JS_COMMON; do
        hdr="$(curl -s -D - -o /dev/null -L --max-time 8 ${CURL_NET[@]+"${CURL_NET[@]}"} "$base/$b" 2>/dev/null)"
        printf '%s' "$hdr" | head -1 | grep -q ' 200' || continue
        printf '%s' "$hdr" | grep -qiE 'content-type:[[:space:]]*(application|text)/(javascript|ecmascript|x-javascript)' && echo "$base/$b" >> "$js_urls_file"
      done
    done
    sort -u -o "$js_urls_file" "$js_urls_file"
  fi
  # Keep only FIRST-PARTY JS (hosted on the target's own domain). Third-party scripts
  # (google-analytics, gtag, cloudflare, jquery cdn...) carry public keys and produce
  # false positives that aren't the target's to fix. Override with JS_FIRST_PARTY=0.
  if [ "${JS_FIRST_PARTY:-1}" = 1 ] && [ -s "$js_urls_file" ]; then
    esc_domain="$(printf '%s' "$domain" | sed 's/\./\\./g')"
    grep -iE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" "$js_urls_file" > "$js_urls_file.fp" 2>/dev/null || true
    mv "$js_urls_file.fp" "$js_urls_file"
  fi
  js_total="$(nlines "$js_urls_file")"
  # 2) fetch each JS and scan for secrets. If trufflehog is present, save the JS and let it
  #    do entropy + verification (far fewer false positives than regex); else regex fallback.
  : > "$js_secrets_file"; : > "$js_endpoints_file"; ji=0
  js_dir=""; [ "$TRUFFLEHOG_JS" = 1 ] && have trufflehog && { js_dir="$OUTDIR/jsfiles"; mkdir -p "$js_dir"; }
  while read -r j; do
    [ -z "$j" ] && continue
    ji=$((ji + 1)); [ "$ji" -gt "$JS_MAX" ] && break
    ST_DETAIL[$S_JS]="scanning JS $ji/$js_total  hits:$(nlines "$js_secrets_file") eps:$(nlines "$js_endpoints_file")"; render
    jtmp="$(mktemp)"
    curl -s -L --max-time 15 ${CURL_NET[@]+"${CURL_NET[@]}"} "$j" 2>/dev/null > "$jtmp"
    [ -s "$jtmp" ] || { rm -f "$jtmp"; continue; }
    # secrets: trufflehog on the saved file (verified) else inline regex
    if [ -n "$js_dir" ]; then cp "$jtmp" "$js_dir/$(printf '%s' "$j" | tr -c 'A-Za-z0-9._-' '_' | tail -c 120).js"
    else grep -aoE "$SECRET_RE" "$jtmp" 2>/dev/null | sort -u | sed "s#^#${j}\t#" >> "$js_secrets_file"; fi
    # endpoints: a SPA's API surface (/rest, /api, absolute URLs) lives in its JS bundles; mine
    # them so they feed the funnel even with no archive data and no source map. Origin = this JS's.
    jorigin="$(printf '%s' "$j" | sed -E 's#(https?://[^/]+).*#\1#')"
    {
      grep -aoiE "https?://([a-z0-9._-]+\.)?${esc_domain}[a-z0-9._/?=&%:-]*" "$jtmp" 2>/dev/null
      grep -aoE "[\"'\`]/[a-zA-Z0-9_./?=&%-]{2,}[\"'\`]" "$jtmp" 2>/dev/null | tr -d "\"'\`" | sed "s#^#${jorigin}#"
      grep -aoE "[\"'\`](rest|api|graphql|v[0-9]+)/[a-zA-Z0-9_./?=&%-]{2,}[\"'\`]" "$jtmp" 2>/dev/null | tr -d "\"'\`" | sed "s#^#${jorigin}/#"
    } 2>/dev/null >> "$js_endpoints_file"
    rm -f "$jtmp"
  done < "$js_urls_file"
  if [ -s "$js_endpoints_file" ]; then
    grep -iE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" "$js_endpoints_file" 2>/dev/null \
      | grep -ivE '\.(png|jpe?g|gif|svg|woff2?|ttf|eot|css|ico|map)([?#]|$)' \
      | grep -vE '/:[a-zA-Z0-9_]+' \
      | sort -u | head -n 4000 > "$js_endpoints_file.tmp" && mv "$js_endpoints_file.tmp" "$js_endpoints_file"
  fi
  if [ -n "$js_dir" ] && [ -n "$(ls -A "$js_dir" 2>/dev/null)" ]; then
    ST_DETAIL[$S_JS]="trufflehog scanning JS secrets"; render
    tmo 180 trufflehog --no-update filesystem "$js_dir" --json 2>/dev/null \
      | jq -r '[(.SourceMetadata.Data.Filesystem.file // "js"), (.DetectorName // "secret"), (if .Verified == true then "VERIFIED" else "UNVERIFIED" end), (.Raw // "")] | @tsv' 2>/dev/null \
      | sed -E 's#'"$js_dir"'/##' >> "$js_secrets_file" || true
  fi
  # 2.5) Source maps: a .js.map reconstructs the ORIGINAL (pre-minify) source - full
  #      endpoints, internal API shapes, and the secrets minification hides. Highest-signal
  #      JS find on SPAs/webpack builds, and purely a GET fetch of a file the build shipped.
  : > "$sourcemap_file"; : > "$smap_endpoints_file"
  if [ "$SOURCEMAPS" = 1 ] && have jq && [ -s "$js_urls_file" ]; then
    smap_dir="$OUTDIR/sourcemaps_src"; rm -rf "$smap_dir"; mkdir -p "$smap_dir"
    smi=0; smaps=0
    while read -r j; do
      [ -z "$j" ] && continue
      smi=$((smi+1)); [ "$smi" -gt "$SOURCEMAP_MAX" ] && break
      ST_DETAIL[$S_JS]="source maps $smi: $(nlines "$sourcemap_file") recovered"; render
      # candidate map URL: the convention <file>.map, else the //# sourceMappingURL directive.
      mapurl="$j.map"
      mbody="$(curl -s -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} "$mapurl" 2>/dev/null | head -c 8000000)"
      if ! printf '%s' "$mbody" | jq -e '.sourcesContent | length > 0' >/dev/null 2>&1; then
        ref="$(curl -s -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} "$j" 2>/dev/null \
                | grep -aoiE 'sourceMappingURL=[^ "'"'"'*]+' | tail -1 | sed 's/^sourceMappingURL=//')"
        case "$ref" in
          "" ) continue ;;
          data:* ) continue ;;                              # inline map, not a separate leak
          http* ) mapurl="$ref" ;;
          /* ) mapurl="$(printf '%s' "$j" | sed -E 's#(https?://[^/]+).*#\1#')$ref" ;;
          * ) mapurl="${j%/*}/$ref" ;;
        esac
        mbody="$(curl -s -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} "$mapurl" 2>/dev/null | head -c 8000000)"
        printf '%s' "$mbody" | jq -e '.sourcesContent | length > 0' >/dev/null 2>&1 || continue
      fi
      printf '%s\n' "$mapurl" >> "$sourcemap_file"; smaps=$((smaps+1))
      origin="$(printf '%s' "$j" | sed -E 's#(https?://[^/]+).*#\1#')"
      mtmp="$(mktemp)"; printf '%s' "$mbody" > "$mtmp"
      mapglob="$smap_dir/${smaps}_"                   # this map's reconstructed files share this prefix
      scount="$(jq '.sources | length' "$mtmp" 2>/dev/null || echo 0)"
      [ "$scount" -gt "$SOURCEMAP_SRC_MAX" ] 2>/dev/null && scount="$SOURCEMAP_SRC_MAX"
      si=0
      while [ "$si" -lt "$scount" ]; do
        name="$(jq -r ".sources[$si] // empty" "$mtmp" 2>/dev/null)"
        jq -e ".sourcesContent[$si] != null" "$mtmp" >/dev/null 2>&1 || { si=$((si+1)); continue; }
        case "$name" in *node_modules*|*webpack/bootstrap*|*/vendor*) si=$((si+1)); continue ;; esac   # skip library code we can't fix
        safe="$(printf '%s_%s' "$smaps" "$name" | tr -c 'A-Za-z0-9._-' '_' | tail -c 140)"
        jq -r ".sourcesContent[$si]" "$mtmp" > "$smap_dir/$safe" 2>/dev/null
        si=$((si+1))
      done
      rm -f "$mtmp"
      # endpoints out of THIS map's source (origin is correct per map) -> crawl URL pool
      {
        grep -rhaoiE "https?://([a-z0-9._-]+\.)?${esc_domain}[a-z0-9._/?=&%-]*" "$mapglob"* 2>/dev/null
        grep -rhaoE '["'"'"'`](/[a-zA-Z0-9_./?=&%-]{2,})["'"'"'`]' "$mapglob"* 2>/dev/null \
          | sed -E 's#^.(/[^"'"'"'`]*).$#\1#' | sed "s#^#${origin}#"
      } 2>/dev/null >> "$smap_endpoints_file" || true
    done < "$js_urls_file"
    if [ "$smaps" -gt 0 ] && [ -n "$(ls -A "$smap_dir" 2>/dev/null)" ]; then
      # secrets out of the reconstructed source (trufflehog verified, else regex fallback)
      if [ "$TRUFFLEHOG_JS" = 1 ] && have trufflehog; then
        tmo 180 trufflehog --no-update filesystem "$smap_dir" --json 2>/dev/null \
          | jq -r '[("sourcemap:"+(.SourceMetadata.Data.Filesystem.file // "src")), (.DetectorName // "secret"), (if .Verified == true then "VERIFIED" else "UNVERIFIED" end), (.Raw // "")] | @tsv' 2>/dev/null \
          | sed -E 's#'"$smap_dir"'/##' >> "$js_secrets_file" || true
      else
        grep -rhaoE "$SECRET_RE" "$smap_dir" 2>/dev/null | sort -u | sed 's#^#sourcemap-src\t#' >> "$js_secrets_file" || true
      fi
      sort -u -o "$smap_endpoints_file" "$smap_endpoints_file"
    fi
    sort -u -o "$js_secrets_file" "$js_secrets_file"
    [ "$smaps" -gt 0 ] && set_stage $S_JS running "source maps: $smaps recovered, $(nlines "$smap_endpoints_file") endpoints"
  fi
  if [ -s "$js_secrets_file" ]; then
    # High-precision noise suppression:
    # 1. Drop syntax highlighter keyword lists, long space-separated words, and common code constants
    # 2. Drop asset paths, media/font extensions, placeholder/dummy values, and JS framework keywords
    grep -vE '([a-zA-Z]+[[:space:]]+){3,}' "$js_secrets_file" 2>/dev/null \
      | grep -ivE '(true|false|null|undefined|application/json|text/html|void 0|this\.|window\.|process\.env|document\.|console\.log|export (default|const)|import \{|class [a-zA-Z])' \
      | grep -ivE '/(api|v[0-9]+|assets|static|images|chunks|packs)/|\.(png|jpe?g|gif|svg|css|woff2?|ttf|eot|ico|map)' \
      | grep -ivE '(placeholder|dummy|example|sample|changeme|default_value|your[-_]?key|xxxx+|123456)' \
      | awk -F'\t' '{ k=($NF); if(!seen[k]++) print }' > "$js_secrets_file.tmp" && mv "$js_secrets_file.tmp" "$js_secrets_file"

    # Emit canonical findings into findings.jsonl
    while IFS=$'\t' read -r j_src j_det j_ver j_val; do
      [ -n "$j_src" ] || continue
      if [ -n "$j_val" ]; then
        s_sev="medium"
        [ "$j_ver" = "VERIFIED" ] && s_sev="critical"
        emit_finding js "secret-$j_det" "$s_sev" "$j_src" "TruffleHog ($j_ver): $j_det found"
      elif [ -n "$j_det" ]; then
        emit_finding js "secret-candidate" "medium" "$j_src" "Pattern matched: $(printf '%.60s' "$j_det")"
      fi
    done < "$js_secrets_file"
  fi
  # 3) param discovery (arjun if available) - arjun is slow, so background each host
  #    and keep the dashboard ticking instead of freezing.
  : > "$params_file"
  # Param discovery: prefer x8 (Rust, faster/accurate) when installed, else arjun. Both
  # emit one "host<TAB>param" line per finding so downstream (params folding) is unchanged.
  pwl="${SECLISTS_DIR:+$SECLISTS_DIR/Discovery/Web-Content/burp-parameter-names.txt}"
  if { { [ "$PREFER_X8" = 1 ] && have x8; } || have arjun; }; then
    PARAM_HOSTS="${PARAM_HOSTS:-20}"
    ptotal="$(printf '%s\n' "$scan_targets" | head -n "$PARAM_HOSTS" | grep -c .)"
    pi=0
    while read -r u; do
      [ -z "$u" ] && continue
      pi=$((pi + 1)); [ "$pi" -gt "$PARAM_HOSTS" ] && break
      ptmp="$(mktemp)"
      if [ "$PREFER_X8" = 1 ] && have x8; then
        ( tmo "$ARJUN_MAX_TIME" x8 -u "$u" ${pwl:+-w "$pwl"} -O "$ptmp" 2>/dev/null ) & apid=$!
        param_primary=x8
      else
        ( tmo "$ARJUN_MAX_TIME" arjun -u "$u" -q -oT "$ptmp" 2>/dev/null ) & apid=$!
        param_primary=arjun
      fi
      ps=$SECONDS
      while kill -0 "$apid" 2>/dev/null; do
        ST_DETAIL[$S_JS]="param discovery $pi/$ptotal ($param_primary)  $((SECONDS-ps))s"
        [ "$TUI" = 1 ] && render; sleep 0.3
      done
      wait "$apid" 2>/dev/null || true
      # Fallback: arjun gets rate-limited a lot and x8 can whiff - if the primary found nothing,
      # try the other tool on this host before moving on.
      if [ ! -s "$ptmp" ]; then
        if [ "$param_primary" = x8 ] && have arjun; then
          ST_DETAIL[$S_JS]="param discovery $pi/$ptotal (arjun fallback)"; [ "$TUI" = 1 ] && render
          tmo "$ARJUN_MAX_TIME" arjun -u "$u" -q -oT "$ptmp" 2>/dev/null || true
        elif [ "$param_primary" = arjun ] && have x8; then
          ST_DETAIL[$S_JS]="param discovery $pi/$ptotal (x8 fallback)"; [ "$TUI" = 1 ] && render
          tmo "$ARJUN_MAX_TIME" x8 -u "$u" ${pwl:+-w "$pwl"} -O "$ptmp" 2>/dev/null || true
        fi
      fi
      # normalise either tool's output to bare param names, prefix the host.
      if [ -s "$ptmp" ]; then
        grep -oiE '[a-z0-9_.\[\]-]{1,40}' "$ptmp" 2>/dev/null | awk 'length>=2 && !seen[$0]++' \
          | sed "s#^#${u}\t#" >> "$params_file"
      fi
      rm -f "$ptmp"
    done <<< "$(printf '%s\n' "$scan_targets" | head -n "$PARAM_HOSTS")"
  fi
  touch "$OUTDIR/.done_js"
  sec_hits="$(nlines "$js_secrets_file")"
  set_stage $S_JS done "$js_total JS, $sec_hits secret hits$([ -s "$params_file" ] && echo ', params')"
fi

