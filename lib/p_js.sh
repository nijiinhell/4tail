# Step 4.5: JS & secret mining + param discovery (opt-in with -j)
js_urls_file="$OUTDIR/js_urls.txt"
js_secrets_file="$OUTDIR/js_secrets.txt"
params_file="$OUTDIR/params.txt"
# Regex for common leaked secrets (no single-quote chars, so it stays shell-safe).
# The generic keyword branch REQUIRES a quote immediately before the value, so a minified
# variable reference (password:t.applicationSecretKey, password:t.projectSecret) is NOT flagged
# as a hardcoded secret - only a literal "secret":"<value>" / secret='<value>' / secret=`<value>` is.
SECRET_RE='AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|ghp_[0-9A-Za-z]{36}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|[a-z0-9.-]+\.s3\.amazonaws\.com|0x[a-fA-F0-9]{64}|["`]([a-z]{3,8} ){11,23}[a-z]{3,8}["`]|(api[_-]?key|secret|access[_-]?token|client[_-]?secret|aws_secret|password|passwd|pwd|mnemonic|seed[_-]?phrase|private[_-]?key)["]?[[:space:]]*[:=][[:space:]]*["`][0-9A-Za-z._+/=-]{8,}'

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
  scan_targets="$(ranked_hosts "$JS_HOSTS")"
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
    grep -iE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" "$js_urls_file" > "$js_urls_file.fp" 2>/dev/null || true
    mv "$js_urls_file.fp" "$js_urls_file"
  fi
  js_total="$(nlines "$js_urls_file")"
  # 2) fetch each JS and scan for secrets. If trufflehog is present, save the JS and let it
  #    do entropy + verification (far fewer false positives than regex); else regex fallback.
  : > "$js_secrets_file"; : > "$js_endpoints_file"; : > "${spa_routes_file:-/dev/null}"; : > "${dom_xss_file:-/dev/null}"; ji=0
  js_dir=""; [ "$TRUFFLEHOG_JS" = 1 ] && have trufflehog && { js_dir="$OUTDIR/jsfiles"; mkdir -p "$js_dir"; }
  while read -r j; do
    [ -z "$j" ] && continue
    ji=$((ji + 1)); [ "$ji" -gt "$JS_MAX" ] && break
    ST_DETAIL[$S_JS]="scanning JS $ji/$js_total  hits:$(nlines "$js_secrets_file") eps:$(nlines "$js_endpoints_file")"; render
    jtmp="$(mktemp)"
    curl -s -L --max-time 15 ${CURL_NET[@]+"${CURL_NET[@]}"} "$j" 2>/dev/null > "$jtmp"
    [ -s "$jtmp" ] || { rm -f "$jtmp"; continue; }
    # secrets: ALWAYS run the regex scan (catches hardcoded passwords/keys/mnemonics that
    # trufflehog --only-verified discards), and ADDITIONALLY save the file for trufflehog's
    # verified cloud-key check. (The old `if js_dir; then cp; else regex` skipped the regex
    # whenever trufflehog was installed -> js-secrets:0 even with creds in the bundle.)
    grep -aoE "$SECRET_RE" "$jtmp" 2>/dev/null | sort -u | sed "s#^#${j}\t#" >> "$js_secrets_file"
    [ -n "$js_dir" ] && cp "$jtmp" "$js_dir/$(printf '%s' "$j" | tr -c 'A-Za-z0-9._-' '_' | tail -c 120).js"
    # endpoints: a SPA's API surface (/rest, /api, absolute URLs) lives in its JS bundles; mine
    # them so they feed the funnel even with no archive data and no source map. Origin = this JS's.
    jorigin="$(printf '%s' "$j" | sed -E 's#(https?://[^/]+).*#\1#')"
    {
      grep -aoiE "https?://([a-z0-9._-]+\.)?${esc_domain}[a-z0-9._/?=&%:-]*" "$jtmp" 2>/dev/null
      grep -aoE "[\"'\`]/[a-zA-Z0-9_./?=&%-]{2,}[\"'\`]" "$jtmp" 2>/dev/null | tr -d "\"'\`" | sed "s#^#${jorigin}#"
      grep -aoE "[\"'\`](rest|api|graphql|v[0-9]+)/[a-zA-Z0-9_./?=&%-]{2,}[\"'\`]" "$jtmp" 2>/dev/null | tr -d "\"'\`" | sed "s#^#${jorigin}/#"
      # Template-literal API paths: `${this.hostServer}/rest/products/search?q=${q}` - the boundary
      # chars are } and ${, not quotes, so the quote-anchored patterns above miss them. Match the
      # API path directly (any boundary); $ stops the class, leaving a trailing =/ we normalise below.
      grep -aoiE "/(rest|api|graphql|ftp|admin|auth|metrics|v[0-9]+)/[a-zA-Z0-9_./?=&%-]*" "$jtmp" 2>/dev/null | sed "s#^#${jorigin}#"
    } 2>/dev/null >> "$js_endpoints_file"
    # Field-name vocabulary (so the agent/PoC use the target's REAL body fields, not guesses):
    # form bindings (high precision) + object-literal keys (noisy -> filtered/capped below).
    {
      grep -aoE '(formControlName|ng-model|v-model|data-field|name|id)="[a-zA-Z_][a-zA-Z0-9_.-]{1,39}"' "$jtmp" 2>/dev/null | sed -E 's/.*="([^"]+)".*/\1/'
      grep -aoE '[{,][[:space:]]*"[a-zA-Z_][a-zA-Z0-9_]{2,30}"[[:space:]]*:' "$jtmp" 2>/dev/null | grep -aoE '"[a-zA-Z_][a-zA-Z0-9_]{2,30}"' | tr -d '"'
    } 2>/dev/null >> "$js_fields_file"
    # version banners for CVE mapping (httpx only sees response headers): "/*! lib vX.Y.Z */"
    grep -aoE '[A-Za-z][A-Za-z.@/_-]{2,40} v?[0-9]+\.[0-9]+\.[0-9]+' "$jtmp" 2>/dev/null \
      | grep -viE 'chunk|webpack|sourcemap|node_modules' | head -8 >> "${versions_file:-/dev/null}" 2>/dev/null || true
    # SPA router paths: Angular/React/Vue declare routes as path:"administration" (NO leading slash),
    # so the /-anchored endpoint patterns miss them. Mine them -> they are often privileged/hidden.
    grep -aoE '\bpath[[:space:]]*:[[:space:]]*["'"'"'][a-zA-Z0-9_/:.-]{3,60}["'"'"']' "$jtmp" 2>/dev/null \
      | sed -E 's/^path[[:space:]]*:[[:space:]]*["'"'"']\/?//; s/["'"'"']$//' | grep -E '[a-zA-Z]{3,}' \
      | sed "s#^#${jorigin}/#" >> "${spa_routes_file:-/dev/null}" 2>/dev/null || true
    # client-side DOM-XSS sinks (kxss/dalfox only see server responses; SPA DOM XSS lives in JS)
    grep -aoE '.{0,30}(bypassSecurityTrust(Html|Script|ResourceUrl|Url)|dangerouslySetInnerHTML|v-html=|\.(inner|outer)HTML[[:space:]]*=|document\.write\(|insertAdjacentHTML\().{0,50}' "$jtmp" 2>/dev/null \
      | head -4 | sed "s#^#${j}\t#" >> "${dom_xss_file:-/dev/null}" 2>/dev/null || true
    rm -f "$jtmp"
  done < "$js_urls_file"
  # fold SPA routes into the endpoint pool (probed + fed to the funnel) and dedupe both artifacts
  if [ -s "${spa_routes_file:-/dev/null}" ]; then
    sort -u -o "$spa_routes_file" "$spa_routes_file"
    cat "$spa_routes_file" >> "$js_endpoints_file"
  fi
  [ -s "${dom_xss_file:-/dev/null}" ] && sort -u -o "$dom_xss_file" "$dom_xss_file"
  # ng-version from the root HTML + a runtime version from /metrics (both exact, both missed by httpx)
  {
    ranked_hosts 3 | while IFS= read -r _h; do [ -n "$_h" ] && curl -s -L --max-time 10 ${CURL_NET[@]+"${CURL_NET[@]}"} "$_h" 2>/dev/null \
      | grep -aoiE 'ng-version="[0-9][0-9.]+"' | head -1 | sed -E 's/ng-version="/Angular:/; s/"$//'; done
    if grep -qaiE '/metrics([^a-z]|$)' "${fuzz_findings_file:-/dev/null}" "${nuclei_file:-/dev/null}" 2>/dev/null; then
      curl -s -L --max-time 10 ${CURL_NET[@]+"${CURL_NET[@]}"} "$(ranked_hosts 1)/metrics" 2>/dev/null \
        | grep -aoiE '(nodejs|process|runtime|go|python)[a-z_]*version[^0-9]{0,20}v?[0-9]+\.[0-9]+\.[0-9]+' | head -3
    fi
  } 2>/dev/null >> "${versions_file:-/dev/null}" || true
  [ -s "${versions_file:-/dev/null}" ] && sort -u -o "$versions_file" "$versions_file" 2>/dev/null || true
  # Rank mined field names by frequency (real fields recur across the app), drop JS-internal noise,
  # cap, and record a compact vocab line in forms_file for the agent + PoC generator.
  if [ -s "$js_fields_file" ]; then
    grep -avwiE 'function|return|length|prototype|constructor|default|window|document|undefined|null|true|false|this|var|let|const|typeof|string|number|object|array|value|target|event|type|name|class|style|children|props|state|render|module|exports|require|import|export' "$js_fields_file" \
      | sort | uniq -c | sort -rn | awk '$1>=1{print $2}' | head -n 120 > "$js_fields_file.t" && mv "$js_fields_file.t" "$js_fields_file"
  fi
  if [ -s "$js_endpoints_file" ]; then
    grep -iE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" "$js_endpoints_file" 2>/dev/null \
      | grep -ivE '\.(png|jpe?g|gif|svg|woff2?|ttf|eot|css|ico|map)([?#]|$)' \
      | grep -vE '^https?://[^/]+(/[0-9]+)+/?(\?|$)' \
      | sed -E '/\?/ s/=(&|$)/=1\1/g' \
      | sed -E 's#(/(rest|api)/[a-zA-Z0-9_-]+)/$#\1/1#' \
      | sort -u | head -n 4000 > "$js_endpoints_file.tmp" && mv "$js_endpoints_file.tmp" "$js_endpoints_file"
  fi
  if [ -n "$js_dir" ] && [ -n "$(ls -A "$js_dir" 2>/dev/null)" ]; then
    ST_DETAIL[$S_JS]="trufflehog verifying JS secrets"; render
    tmo 180 trufflehog --no-update filesystem "$js_dir" --only-verified --json 2>/dev/null \
      | jq -r '[(.SourceMetadata.Data.Filesystem.file // "js"), (.DetectorName // "secret"), (.Raw // "")] | @tsv' 2>/dev/null \
      | sed -E 's#'"$js_dir"'/##' >> "$js_secrets_file" || true
  fi
  # 2.4) nuclei token/key extractors over the JS bundles themselves. Step 5 only scans host
  # ROOTS, so it never looks inside the .js files; nuclei's curated token templates (150+) catch
  # provider keys our regex misses, and it clusters/fetches each file once.
  if [ "${NUCLEI_JS:-1}" = 1 ] && have nuclei && [ -s "$js_urls_file" ]; then
    ST_DETAIL[$S_JS]="nuclei token scan over JS"; render
    tmo "${NUCLEI_JS_MAX_TIME:-180}" nuclei -silent -l "$js_urls_file" \
        -tags token,tokens,keys,exposure -severity critical,high,medium,low \
        ${NUCLEI_NET[@]+"${NUCLEI_NET[@]}"} 2>/dev/null \
      | sed 's#^#nuclei-js\t#' >> "$js_secrets_file" || true
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
      # Fetch the whole .map to a temp file (vendor/main maps routinely exceed 8MB; `head -c 8M`
      # cut the JSON mid-stream -> "unexpected EOF" -> 0 maps recovered). --max-filesize skips
      # genuinely huge maps cleanly instead of leaving truncated JSON.
      mraw="$(mktemp)"
      mapurl="$j.map"
      curl -s -L --max-time 25 --max-filesize "${SOURCEMAP_MAX_BYTES:-25000000}" ${CURL_NET[@]+"${CURL_NET[@]}"} -o "$mraw" "$mapurl" 2>/dev/null
      if ! jq -e '.sourcesContent | length > 0' "$mraw" >/dev/null 2>&1; then
        ref="$(curl -s -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} "$j" 2>/dev/null \
                | grep -aoiE 'sourceMappingURL=[^ "'"'"'*]+' | tail -1 | sed 's/^sourceMappingURL=//')"
        case "$ref" in
          "" ) rm -f "$mraw"; continue ;;
          data:* ) rm -f "$mraw"; continue ;;                # inline map, not a separate leak
          http* ) mapurl="$ref" ;;
          /* ) mapurl="$(printf '%s' "$j" | sed -E 's#(https?://[^/]+).*#\1#')$ref" ;;
          * ) mapurl="${j%/*}/$ref" ;;
        esac
        curl -s -L --max-time 25 --max-filesize "${SOURCEMAP_MAX_BYTES:-25000000}" ${CURL_NET[@]+"${CURL_NET[@]}"} -o "$mraw" "$mapurl" 2>/dev/null
        jq -e '.sourcesContent | length > 0' "$mraw" >/dev/null 2>&1 || { rm -f "$mraw"; continue; }
      fi
      printf '%s\n' "$mapurl" >> "$sourcemap_file"; smaps=$((smaps+1))
      origin="$(printf '%s' "$j" | sed -E 's#(https?://[^/]+).*#\1#')"
      mtmp="$mraw"                                     # already the full map on disk (no truncation)
      mapglob="$smap_dir/${smaps}_"                   # this map's reconstructed files share this prefix
      scount="$(jq '.sources | length' "$mtmp" 2>/dev/null || echo 0)"
      [ "$scount" -gt "$SOURCEMAP_SRC_MAX" ] 2>/dev/null && scount="$SOURCEMAP_SRC_MAX"
      si=0
      while [ "$si" -lt "$scount" ]; do
        name="$(jq -r ".sources[$si] // empty" "$mtmp" 2>/dev/null)"
        jq -e ".sourcesContent[$si] != null" "$mtmp" >/dev/null 2>&1 || { si=$((si+1)); continue; }
        case "$name" in *node_modules*|*webpack/bootstrap*|*/vendor*) si=$((si+1)); continue ;; esac   # skip library code we can't fix
        safe="${smaps}_$(printf '%s' "$name" | tr -c 'A-Za-z0-9._-' '_' | tail -c 140)"   # keep the ${smaps}_ glob prefix after truncation
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
        tmo 180 trufflehog --no-update filesystem "$smap_dir" --only-verified --json 2>/dev/null \
          | jq -r '[("sourcemap:"+(.SourceMetadata.Data.Filesystem.file // "src")), (.DetectorName // "secret"), (.Raw // "")] | @tsv' 2>/dev/null \
          | sed -E 's#'"$smap_dir"'/##' >> "$js_secrets_file" || true
      else
        grep -rhaoE "$SECRET_RE" "$smap_dir" 2>/dev/null | sort -u | sed 's#^#sourcemap-src\t#' >> "$js_secrets_file" || true
      fi
      sort -u -o "$smap_endpoints_file" "$smap_endpoints_file"
    fi
    sort -u -o "$js_secrets_file" "$js_secrets_file"
    [ "$smaps" -gt 0 ] && set_stage $S_JS running "source maps: $smaps recovered, $(nlines "$smap_endpoints_file") endpoints"
  fi
  sort -u -o "$js_secrets_file" "$js_secrets_file"
  # 3) param discovery (arjun if available) - arjun is slow, so background each host
  #    and keep the dashboard ticking instead of freezing.
  : > "$params_file"
  # Param discovery: prefer x8 (Rust, faster/accurate) when installed, else arjun. Both
  # emit one "host<TAB>param" line per finding so downstream (params folding) is unchanged.
  pwl="${SECLISTS_DIR:+$SECLISTS_DIR/Discovery/Web-Content/burp-parameter-names.txt}"
  if { { [ "$PREFER_X8" = 1 ] && have x8; } || have arjun; }; then
    PARAM_HOSTS="${PARAM_HOSTS:-20}"
    # Probe the real API/script surface, not just the SPA's static "/" (which serves index.html
    # and yields params:0). Prefer mined /api//rest/ endpoints + non-static 200s, then host roots.
    param_targets="$( {
        [ -s "${js_endpoints_file:-/dev/null}" ] && grep -iE '/api/|/rest/|/graphql|\?' "$js_endpoints_file" 2>/dev/null
        [ -s "${fuzz_findings_file:-/dev/null}" ] && awk -F'\t' '$1==200 && $2+0>0 {print $3}' "$fuzz_findings_file" 2>/dev/null
        printf '%s\n' "$scan_targets"
      } | awk 'NF && !seen[$0]++' )"
    ptotal="$(printf '%s\n' "$param_targets" | head -n "$PARAM_HOSTS" | grep -c .)"
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
    done <<< "$(printf '%s\n' "$param_targets" | head -n "$PARAM_HOSTS")"
  fi
  # Post-JS SPA fallback: httpx fingerprinted no server tech, but JS mining found a real SPA/API
  # surface. Record it in the brief and, if the auto-blueprint only fell back to the generic
  # default, apply spa traits now (sqlmap/nuclei-dast on the /rest+/api backend, light fuzzing) -
  # these drive the funnel stage that runs next.
  js_count="$(nlines "$js_urls_file")"; ep_count="$(nlines "${js_endpoints_file:-/dev/null}")"
  if { [ "${js_count:-0}" -ge 10 ] || [ "${ep_count:-0}" -ge 10 ]; } \
     && ! grep -qiE 'wordpress|drupal|joomla|magento|php|iis|asp|tomcat|spring|django|express|angular|react|vue|svelte' "${tech_brief:-/dev/null}" 2>/dev/null; then
    echo "== detected: SPA / REST API (JS-heavy; httpx saw no server tech; JS mining found $js_count bundles / $ep_count endpoints) ==" >> "$tech_brief"
    if [ "${BLUEPRINT:-auto}" = auto ] && [ "${BLUEPRINT_NAME:-}" = webapp_bounty ] && command -v load_blueprint >/dev/null 2>&1 && [ -n "${BLUEPRINTS_DIR:-}" ]; then
      load_blueprint spa && { [ "$ASSUME_YES" = 1 ] || log "Blueprint: spa (post-JS detection - httpx saw no tech, JS surface is a SPA)"; }
    fi
  fi
  touch "$OUTDIR/.done_js"
  sec_hits="$(nlines "$js_secrets_file")"
  set_stage $S_JS done "$js_total JS, $sec_hits secret hits$([ -s "$params_file" ] && echo ', params')"
fi

