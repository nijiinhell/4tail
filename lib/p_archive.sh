# ===========================================================================
# Step 2.5: PASSIVE ARCHIVE URL HARVESTING
# Queries third-party web archives (gau, waybackurls, waymore) for historical URLs,
# unlinked endpoints, and past JS bundles across the root domain.
# Runs passive-only (0 packets sent to target), feeding downstream JS mining & funnel.
# ===========================================================================

if [ "$NO_ARCHIVE" = 1 ]; then
  set_stage $S_ARCH skip "skipped (localhost/single-host IP)"
elif done_marker archive && [ -s "$urls_archive_file" ]; then
  set_stage $S_ARCH done "$(nlines "$urls_archive_file") archive URLs (resumed)"
else
  set_stage $S_ARCH running "querying passive archives"
  : > "$urls_archive_file"
  esc_domain="$(printf '%s' "$domain" | sed 's/\./\\./g')"
  [ -n "${GAU_MAX_TIME:-}" ] || GAU_MAX_TIME=120

  if have gau; then
    set_stage $S_ARCH running "gau: AlienVault / URLScan / Wayback"
    printf '%s\n' "$domain" | tmo "$GAU_MAX_TIME" gau --subs --blacklist png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,css 2>>"$llm_log" \
      | grep -iE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" \
      | head -n 50000 >> "$urls_archive_file" || true
  fi

  if have waybackurls; then
    set_stage $S_ARCH running "waybackurls: Wayback Machine"
    printf '%s\n' "$domain" | tmo "$GAU_MAX_TIME" waybackurls 2>>"$llm_log" \
      | grep -iE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" \
      | grep -ivE '\.(png|jpe?g|gif|svg|woff2?|ttf|eot|ico|css)([?#]|$)' \
      | head -n 50000 >> "$urls_archive_file" || true
  fi

  if [ "$USE_WAYMORE" = 1 ] && have waymore; then
    set_stage $S_ARCH running "waymore: CommonCrawl / Wayback"
    tmo "$((GAU_MAX_TIME*2))" waymore -i "$domain" -mode U -oU "$OUTDIR/.waymore.txt" >/dev/null 2>>"$llm_log" || true
    if [ -f "$OUTDIR/.waymore.txt" ]; then
      grep -iE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" "$OUTDIR/.waymore.txt" 2>/dev/null \
        | grep -ivE '\.(png|jpe?g|gif|svg|woff2?|ttf|eot|ico|css)([?#]|$)' >> "$urls_archive_file" || true
      rm -f "$OUTDIR/.waymore.txt"
    fi
  fi

  if [ -s "$urls_archive_file" ]; then
    sort -u -o "$urls_archive_file" "$urls_archive_file"
  fi
  arch_count="$(nlines "$urls_archive_file")"
  touch "$OUTDIR/.done_archive"
  set_stage $S_ARCH done "$arch_count archive URLs"
fi
