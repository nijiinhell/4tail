# --- Blueprints -------------------------------------------------------------
BLUEPRINT_NAME=""
if [ -z "$BLUEPRINTS_DIR" ]; then
  _sd="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
  # next to the script (repo run), or one level up (single-file build in dist/).
  for _bd in "$_sd/blueprints" "$_sd/../blueprints"; do
    [ -d "$_bd" ] && { BLUEPRINTS_DIR="$(cd "$_bd" && pwd)"; break; }
  done
fi
list_blueprints()    { ls "$BLUEPRINTS_DIR"/*.json 2>/dev/null | sed 's#.*/##; s#\.json$##'; }
blueprint_catalog()  { local f; for f in "$BLUEPRINTS_DIR"/*.json; do [ -f "$f" ] && jq -r '"- "+.name+": "+(.description // "")' "$f" 2>/dev/null; done; }
bp_set() { # set $1=var to blueprint value $2, only if user didn't set it and value is real
  local var="$1" val="$2" flag="_user_set_$1"
  [ -n "${!flag:-}" ] && return 0
  { [ -z "$val" ] || [ "$val" = "null" ]; } && return 0
  eval "$var=\$val"
}
load_blueprint() { # $1 = name or path; applies focus/specialists/caps
  local bp="$1" f=""
  case "$bp" in
    */*|*.json) [ -f "$bp" ] && f="$bp" ;;
    *) [ -n "$BLUEPRINTS_DIR" ] && [ -f "$BLUEPRINTS_DIR/$bp.json" ] && f="$BLUEPRINTS_DIR/$bp.json" ;;
  esac
  [ -z "$f" ] && { warn "blueprint '$bp' not found - using built-in active defaults"; return 1; }
  have jq || { warn "jq required for blueprints - using defaults"; return 1; }
  BLUEPRINT_NAME="$(jq -r '.name // "custom"' "$f" 2>/dev/null)"
  bp_set ACT_FOCUS       "$(jq -r '(.focus_areas // []) | join(",")' "$f" 2>/dev/null)"
  bp_set ACT_SPECIALISTS "$(jq -r '(.specialists // []) | join(",")' "$f" 2>/dev/null)"
  bp_set ACT_DAST_TAGS   "$(jq -r '.nuclei_dast_tags // ""' "$f" 2>/dev/null)"
  bp_set FUZZING_STRATEGY "$(jq -r '.fuzzing_strategy // ""' "$f" 2>/dev/null)"
  # stage toggles: a blueprint can turn on JS mining (e.g. spa) so `-C` alone still
  # mines JS when the surface demands it, without the user remembering `-j`.
  bp_set JSMINE          "$(jq -r '.stages.jsmine // .jsmine // empty' "$f" 2>/dev/null)"
  # rate shaping: let a blueprint (e.g. stealth) throttle the active tools it drives
  # AFTER recon. httpx threads are deliberately NOT here - httpx runs before this.
  bp_set FFUF_RATE       "$(jq -r '.rates.ffuf_rate // empty' "$f" 2>/dev/null)"
  bp_set FUZZ_PARALLEL   "$(jq -r '.rates.fuzz_parallel // empty' "$f" 2>/dev/null)"
  bp_set NUCLEI_RATELIMIT "$(jq -r '.rates.nuclei_ratelimit // empty' "$f" 2>/dev/null)"
  bp_set NUCLEI_CONC     "$(jq -r '.rates.nuclei_conc // empty' "$f" 2>/dev/null)"
  bp_set ACT_MAX_JUICY   "$(jq -r '.caps.max_juicy_urls // empty' "$f" 2>/dev/null)"
  bp_set ACT_MAX_DALFOX  "$(jq -r '.caps.max_dalfox // empty' "$f" 2>/dev/null)"
  bp_set ACT_MAX_KXSS    "$(jq -r '.caps.max_kxss // empty' "$f" 2>/dev/null)"
  bp_set ACT_MAX_SQLMAP  "$(jq -r '.caps.max_sqlmap // empty' "$f" 2>/dev/null)"
  bp_set ACT_MAX_ARJUN   "$(jq -r '.caps.max_arjun_hosts // empty' "$f" 2>/dev/null)"
  bp_set CRAWL_MAX_URLS  "$(jq -r '.caps.crawl_max_urls // empty' "$f" 2>/dev/null)"
  bp_set CRAWL_MAX_TIME  "$(jq -r '.caps.crawl_max_time // empty' "$f" 2>/dev/null)"
  bp_set DAST_MAX_URLS   "$(jq -r '.caps.dast_max_urls // empty' "$f" 2>/dev/null)"
  return 0
}
# Resolve the blueprint: explicit name, or AI-chosen from the catalog using the tech brief.
resolve_blueprint() {
  if [ "$BLUEPRINT" != "auto" ]; then load_blueprint "$BLUEPRINT"; return; fi
  local chosen="webapp_bounty" n pick out
  # Deterministic (no AI, works with AI_ENABLED=0): match a distinctive stack in the tech
  # surface to its blueprint. Order matters - most specific first. WordPress and GraphQL
  # before the generic SPA/AI fallback so an unkeyed run still loads the right profile.
  if [ -s "$tech_brief" ] && [ -n "$BLUEPRINTS_DIR" ] && [ -f "$BLUEPRINTS_DIR/wordpress.json" ] \
     && grep -qiE 'wordpress|wp-content|wp-includes|wp-json' "$tech_brief" 2>/dev/null; then
    load_blueprint wordpress
    [ "$ASSUME_YES" = 1 ] || log "Blueprint: wordpress (WordPress detected in tech surface)"
    return
  fi
  if [ -s "$tech_brief" ] && [ -n "$BLUEPRINTS_DIR" ] && [ -f "$BLUEPRINTS_DIR/graphql.json" ] \
     && grep -qiE 'graphql|graphiql|apollo|/graphql' "$tech_brief" 2>/dev/null; then
    load_blueprint graphql
    [ "$ASSUME_YES" = 1 ] || log "Blueprint: graphql (GraphQL detected in tech surface)"
    return
  fi
  # Deterministic: a JS SPA framework in the tech surface -> the spa blueprint (JS-mining +
  # DOM-XSS + the API behind the front-end). The generic AI pick tends to default to
  # webapp_bounty and miss that the real surface is the mined /rest + /api, not path fuzzing.
  if [ -s "$tech_brief" ] && [ -n "$BLUEPRINTS_DIR" ] && [ -f "$BLUEPRINTS_DIR/spa.json" ] \
     && grep -qiE 'angular|react|vue\.?js|next\.?js|nuxt|svelte|ember|backbone|single[ -]?page' "$tech_brief" 2>/dev/null; then
    load_blueprint spa
    [ "$ASSUME_YES" = 1 ] || log "Blueprint: spa (SPA framework detected in tech surface)"
    return
  fi
  if [ "$AI_ENABLED" = 1 ] && [ -n "$BLUEPRINTS_DIR" ] && budget_ok && [ -s "$tech_brief" ]; then
    out="$(mktemp)"
    ai_call "$LLM_MODEL_PLAN" 400 \
      'You are a bug-bounty strategist. Pick the single best scan blueprint for this target from the catalog, based on its technology surface. Reply with ONLY the blueprint name (one token), nothing else.' \
      "Catalog:
$(blueprint_catalog)

Target: $domain
Tech brief:
$(head -c 4000 "$tech_brief")" >"$out" 2>>"$llm_log" || true
    pick="$(grep -oiE '[a-z_]+' "$out" | tail -1 | tr 'A-Z' 'a-z')"; rm -f "$out"
    for n in $(list_blueprints); do [ "$pick" = "$n" ] && chosen="$pick"; done
  fi
  load_blueprint "$chosen"
}

# kill background children (nuclei/ffuf/arjun/supervisor) so nothing lingers after
# a Ctrl-C and pollutes a later resumed run's stats.
# Signal the CHILDREN (the real tools) BEFORE the backgrounded subshell parent - killing the
# parent first reparents its children to init and pkill -P then finds nothing (orphans).
kill_children() { local p; for p in $(jobs -p 2>/dev/null); do pkill -P "$p" 2>/dev/null; kill "$p" 2>/dev/null; done; }
cleanup() {   # restore terminal, and if we died mid-run with the dashboard up, show WHY
  local rc=$?
  [ "$TUI" = 1 ] && printf '\033[?25h\033[?1049l'
  if [ "${STAGES_BEGAN:-0}" = 1 ] && [ "${_FINISHED:-0}" != 1 ] && [ "$rc" -ne 0 ] && [ "$rc" -ne 130 ]; then
    # Write to fd 3 (the real terminal) since fd 2 may be redirected to the log in TUI mode.
    printf '\n\033[1;31m[!]\033[0m 4tail stopped early (exit %s) before finishing.\n' "$rc" >&3 2>/dev/null
    if [ -s "${OUTDIR:-}/run_stderr.log" ]; then
      printf '    last error output:\n' >&3 2>/dev/null
      grep -viE 'nuclei\.txt: No such file' "${OUTDIR}/run_stderr.log" 2>/dev/null | tail -8 | sed 's/^/      /' >&3 2>/dev/null
      printf '    (full log: %s/run_stderr.log)\n' "$OUTDIR" >&3 2>/dev/null
    else
      printf '    Re-run with -P (plain output, no dashboard) to see the error inline.\n' >&3 2>/dev/null
    fi
  fi
}
trap cleanup EXIT
trap 'kill_children; oast_stop; cleanup; err "interrupted"; exit 130' INT TERM

# --- OAST (out-of-band) via interactsh: confirm BLIND SSRF / redirects -------
# Started in the background as 4tail launches so the listener is live for the whole
# run; we inject unique per-URL payload subdomains and, at the end, any DNS/HTTP
# callback is correlated back to the exact URL -> a Confirmed blind finding.
OAST_PID=""; OAST_DOMAIN=""
oast_start() {
  [ "$OAST" = 1 ] || return 0
  if ! have interactsh-client; then warn "OAST on but interactsh-client not found; skipping"; OAST=0; return 0; fi
  local cmd=(interactsh-client -json -o "$oast_log")
  [ -n "$OAST_SERVER" ] && cmd+=(-s "$OAST_SERVER")
  : > "$oast_log"; : > "$oast_map"
  "${cmd[@]}" > "$oast_dir/client.out" 2>&1 &
  OAST_PID=$!
  local tries=0
  while [ "$tries" -lt 20 ]; do
    OAST_DOMAIN="$(grep -i 'payload' "$oast_dir/client.out" 2>/dev/null | head -1 | grep -oE '[A-Za-z0-9.-]+\.[A-Za-z]{2,}' | tail -1)"
    [ -n "$OAST_DOMAIN" ] && break
    kill -0 "$OAST_PID" 2>/dev/null || break
    sleep 0.5; tries=$((tries+1))
  done
  [ -n "$OAST_DOMAIN" ] || warn "OAST: could not obtain a payload domain; OOB injection disabled"
}
oast_stop() { [ -n "${OAST_PID:-}" ] && kill "$OAST_PID" 2>/dev/null; OAST_PID=""; }
# Inject a unique OOB payload into redirect/SSRF-style params of the given URLs.
oast_inject() {  # reads URLs on stdin
  [ "$OAST" = 1 ] && [ -n "$OAST_DOMAIN" ] || { cat >/dev/null; return 0; }
  local u n=0 idx
  idx="$(wc -l < "$oast_map" 2>/dev/null | tr -d ' ')"; [ -n "$idx" ] 2>/dev/null || idx=0
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    printf '%s' "$u" | grep -qiE '([?&])(url|uri|redirect|redir|next|dest|destination|return|returnurl|return_url|returnto|returl|callback|continue|out|link|target|to|forward|image|img|file|load|fetch|feed|host|site|domain|data|reference|ref)=' || continue
    [ "$n" -ge "$OAST_MAX_INJECT" ] && break
    idx=$((idx+1)); n=$((n+1))
    local marker="m${idx}"
    local payload="http://${marker}.${OAST_DOMAIN}/"
    # swap every matching param's value for the payload
    local inj; inj="$(printf '%s' "$u" | sed -E "s#([?&])(url|uri|redirect|redir|next|dest|destination|return|returnurl|return_url|returnto|returl|callback|continue|out|link|target|to|forward|image|img|file|load|fetch|feed|host|site|domain|data|reference|ref)=[^&]*#\1\2=${payload//#/\\#}#Ig")"
    printf '%s\t%s\n' "$marker" "$u" >> "$oast_map"
    curl -s -o /dev/null --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} "$inj" 2>/dev/null || true
  done
}
# Correlate callbacks -> confirmed findings.
oast_correlate() {
  [ "$OAST" = 1 ] && [ -n "$OAST_DOMAIN" ] && [ -s "$oast_map" ] || return 0
  : > "$oast_hits_file"
  sleep 3   # let late callbacks land
  local marker u proto
  while IFS=$'\t' read -r marker u; do
    [ -n "$marker" ] || continue
    if grep -qi "${marker}\." "$oast_log" 2>/dev/null; then
      proto="$(grep -i "${marker}\." "$oast_log" 2>/dev/null | head -1 | jq -r '.protocol // "oob"' 2>/dev/null)"
      printf '[CONFIRMED] blind OOB interaction (%s) via %s\n' "${proto:-oob}" "$u" >> "$oast_hits_file"
    fi
  done < "$oast_map"
}

# Run a command in the background, live-updating a stage from a growing file.
#   run_stage <idx> <count_file|""> <suffix> <cmd...>
run_stage() {
  local idx="$1" cfile="$2" suffix="$3"; shift 3
  set_stage "$idx" running "0${suffix} · 0s"
  if [ "$TUI" = 1 ]; then
    ( "$@" ) >/dev/null 2>>"$llm_log" & local pid=$!
    local s=$SECONDS n
    while kill -0 "$pid" 2>/dev/null; do
      n=0; [ -n "$cfile" ] && [ -f "$cfile" ] && n=$(wc -l < "$cfile" 2>/dev/null || echo 0)
      ST_DETAIL[$idx]="${n}${suffix} · $((SECONDS-s))s"; render; sleep 0.25
    done
    wait "$pid"; return $?
  else
    log "${ST_LABEL[$idx]} ..."; ( "$@" ) >/dev/null 2>>"$llm_log"; return $?
  fi
}

