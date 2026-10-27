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
  # stage toggles: a blueprint can turn stages on/off (e.g. spa turns on JS mining so `-C`
  # alone mines JS without the user remembering `-j`; a config-focused profile can skip the
  # client-side XSS passes). Each still yields to an explicit user/env value.
  bp_set JSMINE          "$(jq -r '.stages.jsmine // .jsmine // empty' "$f" 2>/dev/null)"
  bp_set SOURCEMAPS      "$(jq -r '.stages.sourcemaps // empty' "$f" 2>/dev/null)"
  bp_set PROPAGATE       "$(jq -r '.stages.propagate // empty' "$f" 2>/dev/null)"
  bp_set CORS_SCAN       "$(jq -r '.stages.cors // empty' "$f" 2>/dev/null)"
  # rate shaping: let a blueprint (e.g. stealth) throttle the active tools it drives
  # AFTER recon. httpx threads are deliberately NOT here - httpx runs before this.
  bp_set FFUF_RATE       "$(jq -r '.rates.ffuf_rate // empty' "$f" 2>/dev/null)"
  bp_set FUZZ_PARALLEL   "$(jq -r '.rates.fuzz_parallel // empty' "$f" 2>/dev/null)"
  bp_set NUCLEI_RATELIMIT "$(jq -r '.rates.nuclei_ratelimit // empty' "$f" 2>/dev/null)"
  bp_set NUCLEI_CONC     "$(jq -r '.rates.nuclei_conc // empty' "$f" 2>/dev/null)"
  bp_set NUCLEI_SEVERITY "$(jq -r '.nuclei.severity // empty' "$f" 2>/dev/null)"
  # nuclei.extra_tags are ADDED to the fallback tag set, so a blueprint pre-seeds stack-specific
  # tags (wordpress -> wp-plugin,wpscan) even with AI_ENABLED=0. Skipped if the user set -t.
  local _ntags; _ntags="$(jq -r '.nuclei.extra_tags // empty' "$f" 2>/dev/null)"
  if [ -n "$_ntags" ] && [ "$_ntags" != null ] && [ -z "${_user_set_DEFAULT_NUCLEI_TAGS:-}" ]; then
    DEFAULT_NUCLEI_TAGS="$DEFAULT_NUCLEI_TAGS,$_ntags"
  fi
  bp_set ACT_MAX_JUICY   "$(jq -r '.caps.max_juicy_urls // empty' "$f" 2>/dev/null)"
  bp_set ACT_MAX_DALFOX  "$(jq -r '.caps.max_dalfox // empty' "$f" 2>/dev/null)"
  bp_set ACT_MAX_KXSS    "$(jq -r '.caps.max_kxss // empty' "$f" 2>/dev/null)"
  bp_set ACT_MAX_SQLMAP  "$(jq -r '.caps.max_sqlmap // empty' "$f" 2>/dev/null)"
  bp_set ACT_MAX_ARJUN   "$(jq -r '.caps.max_arjun_hosts // empty' "$f" 2>/dev/null)"
  bp_set CRAWL_MAX_URLS  "$(jq -r '.caps.crawl_max_urls // empty' "$f" 2>/dev/null)"
  bp_set CRAWL_MAX_TIME  "$(jq -r '.caps.crawl_max_time // empty' "$f" 2>/dev/null)"
  bp_set DAST_MAX_URLS   "$(jq -r '.caps.dast_max_urls // empty' "$f" 2>/dev/null)"
  bp_set MAX_EXTS        "$(jq -r '.caps.max_exts // empty' "$f" 2>/dev/null)"
  bp_set MAX_FUZZ_HOSTS  "$(jq -r '.caps.max_fuzz_hosts // empty' "$f" 2>/dev/null)"
  bp_set MAX_FUZZ_WORDS  "$(jq -r '.caps.max_fuzz_words // empty' "$f" 2>/dev/null)"
  bp_set FUZZ_MAX_TIME   "$(jq -r '.caps.fuzz_max_time // empty' "$f" 2>/dev/null)"
  return 0
}
# --- Mixed-scope helpers ----------------------------------------------------
_bp_av() { [ -n "$BLUEPRINTS_DIR" ] && [ -f "$BLUEPRINTS_DIR/$1.json" ]; }
# How many live hosts show a tech/webserver/url signature (one line per host in httpx_json).
_stack_hosts() {
  { [ -s "${httpx_json:-}" ] && have jq; } || { echo 0; return; }
  jq -r '[.url, (.webserver//""), ((.tech//[])|join(" "))] | @tsv' "$httpx_json" 2>/dev/null \
    | grep -ciE "$1"
}
# Should a stack set the PRIMARY profile for the whole scope? Only when it's on a meaningful
# SHARE of live hosts (>=STACK_DOMINANCE_PCT%, default 30) - so one WordPress/Grafana outlier
# among 50 hosts can't hijack the scan - or when the scope is tiny (<=3 hosts).
_stack_dominant() {
  local c; c="$(_stack_hosts "$1")"
  [ "${c:-0}" -gt 0 ] 2>/dev/null || return 1
  [ "${alive_count:-0}" -le 3 ] && return 0
  [ "$(( c * 100 ))" -ge "$(( ${alive_count:-1} * ${STACK_DOMINANCE_PCT:-30} ))" ]
}
_add_def_tags() {  # append nuclei tags unless the user pinned -t
  [ -z "${_user_set_DEFAULT_NUCLEI_TAGS:-}" ] && [ -n "$1" ] && DEFAULT_NUCLEI_TAGS="$DEFAULT_NUCLEI_TAGS,$1"
}
# Layer ADDITIVE traits from SECONDARY stacks present on a mixed scope, so hosts outside the
# primary profile still get the right JS mining / nuclei tags (sets $_layered for logging).
layer_secondary_traits() {
  _layered=""
  if [ "$(_stack_hosts 'react|angular|vue\.?js|next\.?js|nuxt|svelte|ember|backbone')" -gt 0 ] 2>/dev/null; then
    if [ "${JSMINE:-0}" != 1 ] && [ -z "${_user_set_JSMINE:-}" ]; then JSMINE=1; _layered="$_layered,jsmine"; fi
  fi
  if [ "$(_stack_hosts 'wordpress|wp-content|wp-json')" -gt 0 ] 2>/dev/null; then
    _add_def_tags 'wordpress,wp-plugin'; _layered="$_layered,wp-tags"
  fi
  if [ "$(_stack_hosts 'jenkins|grafana|kibana|gitlab|kubernetes|consul|vault|prometheus')" -gt 0 ] 2>/dev/null; then
    _add_def_tags 'default-login,takeover,exposures'; _layered="$_layered,devops-tags"
  fi
  _layered="${_layered#,}"
}
# --- Blueprint composition (-B spa+api_bounty / spa,api_bounty) --------------
_csv_union() {  # var  new-csv : append items not already present (respects a user-set flag)
  local var="$1" add="$2" flag="_user_set_$1" oldifs tok out
  [ -n "${!flag:-}" ] && return 0
  { [ -z "$add" ] || [ "$add" = null ]; } && return 0
  out="${!var:-}"; oldifs="$IFS"; IFS=','
  for tok in $add; do [ -z "$tok" ] && continue; case ",$out," in *",$tok,"*) ;; *) out="${out:+$out,}$tok" ;; esac; done
  IFS="$oldifs"; eval "$var=\$out"
}
_cap_max() {  # var  new : keep the LARGER (composing must never shrink the scope)
  local var="$1" nv="$2" flag="_user_set_$1" cur
  [ -n "${!flag:-}" ] && return 0
  { [ -z "$nv" ] || [ "$nv" = null ]; } && return 0
  cur="${!var:-}"; case "$cur" in ''|*[!0-9]*) eval "$var=\$nv"; return ;; esac
  [ "$nv" -gt "$cur" ] 2>/dev/null && eval "$var=\$nv"
}
# Union ONE more blueprint's additive traits + max caps onto the already-loaded base.
_union_blueprint() {
  local bp="$1" f=""; _bp_av "$bp" && f="$BLUEPRINTS_DIR/$bp.json"; [ -n "$f" ] && have jq || return 0
  _csv_union ACT_FOCUS       "$(jq -r '(.focus_areas // []) | join(",")' "$f" 2>/dev/null)"
  _csv_union ACT_SPECIALISTS "$(jq -r '(.specialists // []) | join(",")' "$f" 2>/dev/null)"
  _csv_union ACT_DAST_TAGS   "$(jq -r '.nuclei_dast_tags // ""' "$f" 2>/dev/null)"
  local et; et="$(jq -r '.nuclei.extra_tags // empty' "$f" 2>/dev/null)"; _add_def_tags "$et"
  [ "$(jq -r '.stages.jsmine // .jsmine // empty' "$f" 2>/dev/null)" = 1 ] && bp_set JSMINE 1
  [ "$(jq -r '.fuzzing_strategy // empty' "$f" 2>/dev/null)" = light ] && [ -z "${FUZZING_STRATEGY:-}" ] && bp_set FUZZING_STRATEGY light
  _cap_max ACT_MAX_JUICY  "$(jq -r '.caps.max_juicy_urls // empty' "$f" 2>/dev/null)"
  _cap_max ACT_MAX_DALFOX "$(jq -r '.caps.max_dalfox // empty' "$f" 2>/dev/null)"
  _cap_max ACT_MAX_KXSS   "$(jq -r '.caps.max_kxss // empty' "$f" 2>/dev/null)"
  _cap_max ACT_MAX_SQLMAP "$(jq -r '.caps.max_sqlmap // empty' "$f" 2>/dev/null)"
  _cap_max ACT_MAX_ARJUN  "$(jq -r '.caps.max_arjun_hosts // empty' "$f" 2>/dev/null)"
  _cap_max CRAWL_MAX_URLS "$(jq -r '.caps.crawl_max_urls // empty' "$f" 2>/dev/null)"
  _cap_max CRAWL_MAX_TIME "$(jq -r '.caps.crawl_max_time // empty' "$f" 2>/dev/null)"
  _cap_max DAST_MAX_URLS  "$(jq -r '.caps.dast_max_urls // empty' "$f" 2>/dev/null)"
}
compose_blueprints() {  # $1 = "a+b" or "a,b,c" : first sets the base, the rest union on top
  local label spec first n
  label="$(printf '%s' "$1" | tr ',' '+')"
  spec="$(printf '%s' "$1" | tr '+,' '  ')"; set -- $spec
  first="${1:-webapp_bounty}"; shift || true
  load_blueprint "$first" || return 1
  for n in "$@"; do [ -n "$n" ] && _union_blueprint "$n"; done
  BLUEPRINT_NAME="$label"
}

# Resolve the blueprint: explicit name/composition, or auto-picked from the DOMINANT stack
# (falling back to the AI / webapp_bounty on a mixed scope), then layer secondary traits.
resolve_blueprint() {
  if [ "$BLUEPRINT" != "auto" ]; then
    case "$BLUEPRINT" in
      */*|*.json)  load_blueprint "$BLUEPRINT" ;;        # explicit path - no composition
      *[+,]*)      compose_blueprints "$BLUEPRINT" ;;    # a+b / a,b
      *)           load_blueprint "$BLUEPRINT" ;;
    esac
    [ "$ASSUME_YES" = 1 ] || log "Blueprint: ${BLUEPRINT_NAME:-$BLUEPRINT}"
    return
  fi
  local chosen="" n pick out
  # PRIMARY = the dominant stack only (a lone outlier host must not force its profile on the
  # whole scope). Priority order applies when more than one stack clears the threshold.
  if   _bp_av wordpress         && _stack_dominant 'wordpress|wp-content|wp-includes|wp-json'; then chosen=wordpress
  elif _bp_av graphql           && _stack_dominant 'graphql|graphiql|apollo'; then chosen=graphql
  elif _bp_av spa               && _stack_dominant 'angular|react|vue\.?js|next\.?js|nuxt|svelte|ember|backbone|single[ -]?page'; then chosen=spa
  elif _bp_av cloud_devops      && _stack_dominant 'kubernetes|kubelet|docker|jenkins|gitlab|grafana|kibana|prometheus|consul|vault|argocd|rancher|harbor|spring ?boot'; then chosen=cloud_devops
  elif _bp_av legacy_enterprise && _stack_dominant 'weblogic|websphere|jboss|coldfusion|struts|/sap/|netweaver|iis/[5-8][^0-9]'; then chosen=legacy_enterprise
  fi
  # No single dominant stack (mixed scope) -> AI pick if available, else webapp_bounty.
  if [ -z "$chosen" ]; then
    chosen="webapp_bounty"
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
  fi
  load_blueprint "$chosen"
  # Mixed scope: layer additive traits (JS mining, wp/devops tags) from any SECONDARY stack
  # present, so hosts outside the primary profile aren't neglected.
  layer_secondary_traits
  [ "$ASSUME_YES" = 1 ] || log "Blueprint: $BLUEPRINT_NAME${_layered:+ (+traits: $_layered)}"
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

