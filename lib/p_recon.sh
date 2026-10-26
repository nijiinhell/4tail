# ===========================================================================
# PIPELINE
# ===========================================================================

# resume helper: was this stage already completed?
done_marker() { [ "$RESUME" = 1 ] && [ -f "$OUTDIR/.done_$1" ]; }

# Step 1: Subdomains
if [ "$SINGLE" = 1 ]; then
  # Single-host mode: no enumeration - the one host is the whole scope.
  printf '%s\n' "$domain" > "$subdomains_file"
  touch "$OUTDIR/.done_subs"
  set_stage $S_SUBS done "single host (subdomain enum skipped)"
elif done_marker subs && [ -s "$subdomains_file" ]; then
  set_stage $S_SUBS done "$(wc -l <"$subdomains_file") subs (resumed)"
else
  # -all uses every passive source (higher recall); SUBFINDER_ALL=0 to keep it lean/fast.
  _sf_all=(); [ "${SUBFINDER_ALL:-1}" = 1 ] && _sf_all=(-all)
  run_stage $S_SUBS "$subdomains_file" " subs" subfinder -silent "${_sf_all[@]}" -d "$domain" -o "$subdomains_file"
  # subfinder enumerates subdomains OF the target but not the target host itself; always
  # include it (and www.) so a specific host like testasp.vulnweb.com is actually probed.
  { printf '%s\n' "$domain" "www.$domain"; cat "$subdomains_file" 2>/dev/null; } | sort -u > "$subdomains_file.tmp" \
    && mv "$subdomains_file.tmp" "$subdomains_file"
  # TLS cert SANs: pull in-scope hostnames from the certificates (passive, fast).
  if [ "$USE_TLSX" = 1 ] && have tlsx; then
    set_stage $S_SUBS running "tlsx: harvesting cert SANs"
    tmo 120 tlsx -silent -san -resp-only -l "$subdomains_file" 2>/dev/null \
      | grep -iE "(^|\.)${esc_domain}\$" | tr 'A-Z' 'a-z' >> "$subdomains_file" || true
    sort -u -o "$subdomains_file" "$subdomains_file"
  fi
  # DNS permutation is a WILDCARD-SCOPE technique: on a handful of hosts it just generates
  # thousands of dead names and bloats resolve/probe. Only run it when the seed set is big
  # enough to be worth it, and cap generation hard.
  _seed_subs="$(nlines "$subdomains_file")"
  if [ "$USE_PERMUTE" = 1 ] && [ "${_seed_subs:-0}" -ge "$PERMUTE_MIN_SUBS" ] 2>/dev/null \
     && have dnsx && { have dnsgen || have gotator; }; then
    set_stage $S_SUBS running "permutation ($_seed_subs seeds -> dnsx, cap $PERMUTE_MAX)"
    perm="$OUTDIR/.perm.txt"
    if have dnsgen; then tmo 60 dnsgen "$subdomains_file" 2>/dev/null | head -n "$PERMUTE_MAX" > "$perm"
    else tmo 60 gotator -sub "$subdomains_file" -perm "$subdomains_file" -silent 2>/dev/null | head -n "$PERMUTE_MAX" > "$perm"; fi
    [ -s "$perm" ] && tmo 120 dnsx -silent -l "$perm" 2>/dev/null | grep -iE "(^|\.)${esc_domain}\$" >> "$subdomains_file"
    rm -f "$perm"; sort -u -o "$subdomains_file" "$subdomains_file"
  fi
  touch "$OUTDIR/.done_subs"
fi
sub_count=$(wc -l < "$subdomains_file" 2>/dev/null || echo 0)
if [ "$sub_count" -eq 0 ]; then
  set_stage $S_SUBS warn "none found"; [ "$TUI" = 1 ] || warn "No subdomains; stopping."; exit 0
fi
[ "$SINGLE" = 1 ] || set_stage $S_SUBS done "$sub_count subs$(done_marker subs && echo ' (resumed)')"

# Step 2: Live hosts + tech detection
if done_marker httpx && [ -s "$httpx_json" ]; then
  set_stage $S_LIVE done "resumed"
else
  # Optional: resolve + drop wildcard DNS with dnsx (removes bogus subdomains that
  # all resolve to a catch-all record - a huge source of wasted work on big targets).
  probe_input="$subdomains_file"
  if [ "$SINGLE" = 1 ]; then
    # Probe EXACTLY the given scheme://host:port (httpx takes full URLs in its -l list), so a
    # custom port like :3000 and the chosen scheme are honored; no DNS resolution needed.
    printf '%s\n' "$SEED_URL" > "$OUTDIR/.seed_url.txt"; probe_input="$OUTDIR/.seed_url.txt"
  elif [ "$USE_DNSX" = 1 ] && have dnsx; then
    resolved_file="$OUTDIR/resolved.txt"
    set_stage $S_LIVE running "resolving (dnsx, wildcard filter)"
    dnsx -silent -l "$subdomains_file" -wd "$domain" -o "$resolved_file" 2>>"$llm_log" || true
    [ -s "$resolved_file" ] && probe_input="$resolved_file"
  fi
  # -fhr follows a host's redirect (http->https, /->/login) so tech/title/length come from the
  # real destination, not the bare redirect - better tech_brief and dedup signatures.
  run_stage $S_LIVE "$httpx_json" " live" \
    httpx -silent -json -tech-detect -status-code -title -web-server -ip -cname -fhr \
          ${HTTPX_NET[@]+"${HTTPX_NET[@]}"} \
          -threads "$HTTPX_THREADS" -l "$probe_input" -o "$httpx_json"
  touch "$OUTDIR/.done_httpx"
fi
if [ -s "$httpx_json" ]; then jq -r '.url' "$httpx_json" 2>/dev/null | sort -u > "$alive_file"; else : > "$alive_file"; fi
alive_count=$(wc -l < "$alive_file" 2>/dev/null || echo 0)
if [ "$alive_count" -eq 0 ]; then
  set_stage $S_LIVE warn "none live"; [ "$TUI" = 1 ] || warn "No live hosts; stopping."; exit 0
fi
# cdncheck: accurately classify CDN/WAF/cloud so we skip fuzzing edges and flag cloud
# hosts (SSRF-to-metadata context) - more reliable than a static banner regex.
# Runs BEFORE the stage is marked done, so the Live-hosts spinner can't get stuck.
: > "$cdn_file"; cloud_hosts=""
if [ "$USE_CDNCHECK" = 1 ] && have cdncheck && [ "${alive_count:-0}" -ge "$CDNCHECK_MIN_HOSTS" ] 2>/dev/null; then
  set_stage $S_LIVE running "$alive_count live · cdncheck classifying…"
  # classify the live hosts by IP range; hard 20s cap (first run refreshes CDN ranges).
  sed -E 's#^[a-z]+://##; s#[:/].*$##' "$alive_file" | sort -u | head -n 200 \
    | tmo 20 cdncheck -silent -resp -cdn -waf -cloud 2>/dev/null > "$OUTDIR/.cdncheck.txt" || true
  grep -iE '\[(cdn|waf)\]' "$OUTDIR/.cdncheck.txt" 2>/dev/null | awk '{print $1}' | sort -u > "$cdn_file" || true
  cloud_hosts="$(grep -iE '\[cloud\]' "$OUTDIR/.cdncheck.txt" 2>/dev/null | awk '{print $1}' | sort -u | head -20)"
  rm -f "$OUTDIR/.cdncheck.txt"
fi

# DNS / email hygiene (cheap, high-signal recon): missing/weak SPF+DMARC = email spoofing;
# an open zone transfer (AXFR) dumps the whole internal DNS map. Uses whatever resolver CLI
# is installed (dig > dnsx > host); skipped silently if none can answer.
: > "$dns_hygiene_file"
if [ "$DNS_HYGIENE" = 1 ] && [ "$NO_ARCHIVE" != 1 ] && { have dig || have dnsx || have host; }; then
  set_stage $S_LIVE running "$alive_count live · DNS/email hygiene"
  _txt() { if have dig; then dig +short TXT "$1" 2>/dev/null | tr -d '"'
           elif have dnsx; then printf '%s\n' "$1" | dnsx -silent -txt -resp-only 2>/dev/null | tr -d '"'
           elif have host; then host -t TXT "$1" 2>/dev/null | sed -E 's/.*descriptive text //; s/"//g'; fi; }
  _ns()  { if have dig; then dig +short NS "$1" 2>/dev/null
           elif have dnsx; then printf '%s\n' "$1" | dnsx -silent -ns -resp-only 2>/dev/null
           elif have host; then host -t NS "$1" 2>/dev/null | awk '/name server/{print $NF}'; fi; }
  spf="$(_txt "$domain" | grep -i 'v=spf1' | head -1)"
  if [ -z "$spf" ]; then echo "[email-spoofing] no SPF record on $domain - sender spoofing possible" >> "$dns_hygiene_file"
  else case "$spf" in *'+all'*|*'?all'*) echo "[email-spoofing] weak SPF ('$(printf '%s' "$spf" | grep -oiE '[+?]all')') on $domain" >> "$dns_hygiene_file" ;; esac; fi
  dmarc="$(_txt "_dmarc.$domain" | grep -i 'v=DMARC1' | head -1)"
  if [ -z "$dmarc" ]; then echo "[email-spoofing] no DMARC record on $domain - spoofed mail not rejected" >> "$dns_hygiene_file"
  else case "$dmarc" in *'p=none'*) echo "[email-spoofing] DMARC p=none on $domain (monitor-only, does not block spoofing)" >> "$dns_hygiene_file" ;; esac; fi
  if have dig || have host; then
    _ns "$domain" | sed 's/\.$//' | sort -u | head -4 | while IFS= read -r ns; do
      [ -n "$ns" ] || continue
      if have dig; then axfr="$(tmo 12 dig +short axfr "$domain" "@$ns" 2>/dev/null | head -c 2000)"
      else axfr="$(tmo 12 host -l "$domain" "$ns" 2>/dev/null | grep -iv 'Transfer failed\|not found\|no servers' | head -c 2000)"; fi
      [ -n "$axfr" ] && printf '%s\n' "$axfr" | grep -qiE '(IN[[:space:]]+(A|CNAME|MX|NS)|has address|name server)' \
        && echo "[zone-transfer] AXFR allowed from $ns for $domain - full DNS zone disclosed (HIGH)" >> "$dns_hygiene_file"
    done
  fi
fi

# Security headers / clickjacking / cookie flags (deterministic, submittable lows). One GET
# per host (capped); read the response headers and flag what's missing or weak.
: > "$sec_headers_file"
if [ "$SEC_HEADERS" = 1 ]; then
  set_stage $S_LIVE running "$alive_count live · security headers"
  sort -u "$alive_file" 2>/dev/null | head -n "$SEC_HEADERS_MAX" | while IFS= read -r u; do
    [ -n "$u" ] || continue
    resp="$(curl -s -D - -o /dev/null -L --max-time 8 ${CURL_NET[@]+"${CURL_NET[@]}"} -w $'\n4TCT %{content_type}' "$u" 2>/dev/null | tr -d '\r')"
    ctype="$(printf '%s' "$resp" | sed -n 's/^4TCT //p' | tail -1)"
    # Keep ONLY the FINAL response's header block (-L dumps every redirect hop's headers;
    # merging them produced false 'present/missing' results). awk paragraph-mode -> last HTTP block.
    hdrs="$(printf '%s' "$resp" | sed '/^4TCT /d' | awk -v RS='' '/^HTTP\//{h=$0} END{print h}')"
    [ -n "$hdrs" ] || continue
    lc="$(printf '%s' "$hdrs" | tr 'A-Z' 'a-z')"
    miss=""
    # Clickjacking / CSP only apply to HTML documents - skip them on JSON/API responses
    # (bug-bounty programs reject "missing XFO on an API" as not-applicable noise).
    case "$ctype" in *json*|*xml*|*javascript*|*octet-stream*) _is_doc=0 ;; *) _is_doc=1 ;; esac
    if [ "$_is_doc" = 1 ]; then
      printf '%s' "$lc" | grep -q 'x-frame-options' || printf '%s' "$lc" | grep -q 'frame-ancestors' || miss="$miss clickjacking(no-XFO/frame-ancestors)"
      printf '%s' "$lc" | grep -q 'content-security-policy' || miss="$miss no-CSP"
    fi
    case "$u" in https://*) printf '%s' "$lc" | grep -q 'strict-transport-security' || miss="$miss no-HSTS" ;; esac
    # cookie flags: inspect each Set-Cookie
    printf '%s' "$hdrs" | grep -iE '^set-cookie:' | while IFS= read -r ck; do
      cl="$(printf '%s' "$ck" | tr 'A-Z' 'a-z')"; cn="$(printf '%s' "$ck" | sed -E 's/^[Ss]et-[Cc]ookie:[[:space:]]*([^=]+)=.*/\1/')"
      cf=""
      case "$u" in https://*) printf '%s' "$cl" | grep -q 'secure' || cf="$cf Secure" ;; esac
      printf '%s' "$cl" | grep -q 'httponly' || cf="$cf HttpOnly"
      printf '%s' "$cl" | grep -q 'samesite' || cf="$cf SameSite"
      [ -n "$cf" ] && echo "[cookie] $u cookie '$cn' missing:$cf" >> "$sec_headers_file"
    done
    [ -n "$miss" ] && echo "[headers] $u missing:$miss" >> "$sec_headers_file"
  done
fi

set_stage $S_LIVE done "$alive_count live$(done_marker httpx && echo ' (resumed)')"

# Aggregated, cost-frugal brief for the AI
{
  echo "== technologies (count) =="
  jq -r '(.tech // [])[]' "$httpx_json" 2>/dev/null | sort | uniq -c | sort -rn | head -40
  echo "== web servers (count) =="
  jq -r '.webserver // empty' "$httpx_json" 2>/dev/null | sort | uniq -c | sort -rn | head -15
  # Versioned components -> match to known CVEs. A product string carrying a version number
  # (IIS 8.5, Apache 2.4.49, PHP 7.2, jQuery 1.7...) is the strongest CVE signal we have.
  jq -r '((.tech // [])[], (.webserver // empty))' "$httpx_json" 2>/dev/null \
    | grep -oiE '[a-z][a-z0-9 ._/+-]*[ :/-][0-9]+(\.[0-9]+){0,3}' \
    | sed -E 's/^[ :/-]+//; s/[ :/-]+$//; s#[ :/]+# #g' \
    | sort -u | head -40 > "$versions_file" 2>/dev/null || true
  [ -s "$versions_file" ] && { echo "== versioned components (match to known CVEs) =="; cat "$versions_file"; }
  echo "== status codes (count) =="
  jq -r '.status_code // empty' "$httpx_json" 2>/dev/null | sort | uniq -c | sort -rn
  echo "== notable hosts =="
  jq -r '.url' "$httpx_json" 2>/dev/null \
    | grep -iE 'admin|login|portal|api|dev|staging|test|git|jenkins|grafana|kibana|vpn' \
    | sort -u | head -25
  [ -n "$cloud_hosts" ] && { echo "== cloud-hosted (SSRF-to-metadata candidates) =="; printf '%s\n' "$cloud_hosts"; }
} > "$tech_brief" 2>/dev/null
[ -s "$tech_brief" ] || cp "$alive_file" "$tech_brief"

# Staleness ranking: score each host by how legacy/outdated its stack looks (EOL
# servers, old runtimes, dated libraries). Older stacks are disproportionately
# more likely to hold bugs, so the AI uses this to funnel budget to them first.
if [ "$STALE_RANK" = 1 ] && have jq && [ -s "$httpx_json" ]; then
  : > "$stale_file"
  while IFS= read -r row; do
    [ -n "$row" ] || continue
    local_url="$(printf '%s' "$row" | jq -r '.url // empty' 2>/dev/null)"
    [ -n "$local_url" ] || continue
    blob="$(printf '%s' "$row" | jq -r '[(.webserver // ""), ((.tech // [])|join(" "))] | join(" ")' 2>/dev/null)"
    lc="$(printf '%s' "$blob" | tr 'A-Z' 'a-z')"
    score=0; ev=""
    case "$lc" in *iis/5*|*iis/6*|*iis/7*|*iis/8*) score=$((score+3)); ev="$ev,EOL-IIS";; esac
    case "$lc" in *apache/2.0*|*apache/2.2*)       score=$((score+3)); ev="$ev,EOL-Apache";; esac
    case "$lc" in *nginx/0.*|*nginx/1.0*|*nginx/1.1*|*nginx/1.2*|*nginx/1.4*) score=$((score+2)); ev="$ev,old-nginx";; esac
    case "$lc" in *php/4*|*php/5*|*php/7.0*|*php/7.1*) score=$((score+3)); ev="$ev,EOL-PHP";; esac
    case "$lc" in *frontpage*)                     score=$((score+2)); ev="$ev,FrontPage";; esac
    case "$lc" in *coldfusion*|*struts*)           score=$((score+3)); ev="$ev,legacy-framework";; esac
    case "$lc" in *wordpress*|*drupal*|*joomla*|*magento*) score=$((score+1)); ev="$ev,CMS";; esac
    # Modern-but-outdated stacks (the real EOL risk now) - match OLD major versions only, so a
    # current .NET 8 / Bootstrap 5 / Next 14 host is NOT scored as "legacy".
    case "$lc" in *angularjs*|*"angular "1.*|*angular/1.*) score=$((score+3)); ev="$ev,AngularJS-1.x";; esac
    case "$lc" in *"vue"*2.*|*vue/2.*)             score=$((score+2)); ev="$ev,Vue2";; esac
    case "$lc" in *"spring"*boot*1.*|*springboot/1*) score=$((score+2)); ev="$ev,SpringBoot-1.x";; esac
    case "$lc" in *jenkins*|*gitlab*|*grafana*|*confluence*|*jira*|*weblogic*|*websphere*|*jboss*) score=$((score+2)); ev="$ev,ops-app(check-version)";; esac
    case "$lc" in *express*3.*|*express/3*|*express*2.*) score=$((score+2)); ev="$ev,old-Express";; esac
    [ "$score" -gt 0 ] && printf '%d\t%s\t%s\n' "$score" "$local_url" "${ev#,}" >> "$stale_file"
  done < "$httpx_json"
  if [ -s "$stale_file" ]; then
    sort -rn -o "$stale_file" "$stale_file"
    { echo "== legacy ranking (higher score = older stack, prioritize) =="
      awk -F'\t' '{printf "%s  %s  [%s]\n",$1,$2,$3}' "$stale_file" | head -20; } >> "$tech_brief"
  fi
fi

# Resolve the strategy blueprint (AI-chosen from the tech surface when BLUEPRINT=auto).
# Only needed for the active funnel (-C), where it sets focus/specialists/caps.
if [ "$CRAWL" = 1 ]; then
  resolve_blueprint
  log "Blueprint: ${BLUEPRINT_NAME:-defaults}  (focus: $ACT_FOCUS | specialists: $ACT_SPECIALISTS)"
fi

