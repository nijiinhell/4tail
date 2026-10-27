# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
# `doctor` subcommand (before getopts, which doesn't parse bare words)
if [ "${1:-}" = "doctor" ]; then DOCTOR=1; shift; fi

while getopts ":w:o:t:S:m:M:p:b:B:H:x:OARqjsCyPDh" opt; do
  case "$opt" in
    w) WORDLIST="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    t) DEFAULT_NUCLEI_TAGS="$OPTARG"; _user_set_DEFAULT_NUCLEI_TAGS=1 ;;  # wins over a blueprint's extra_tags
    S) NUCLEI_SEVERITY="$OPTARG"; _user_set_NUCLEI_SEVERITY=1 ;;          # wins over a blueprint's severity
    m) LLM_MODEL="$OPTARG" ;;
    M) MAX_FUZZ_HOSTS="$OPTARG"; _user_set_MAX_FUZZ_HOSTS=1 ;;  # wins over a blueprint cap
    p) FUZZ_PARALLEL="$OPTARG"; _user_set_FUZZ_PARALLEL=1 ;;  # authoritative over a blueprint
    j) JSMINE=1; _user_set_JSMINE=1 ;;                        # explicit -j wins over a blueprint toggle

    C) CRAWL=1 ;;
    B) BLUEPRINT="$OPTARG" ;;
    H) AUTH_HEADER="${AUTH_HEADER:+$AUTH_HEADER$'\n'}$OPTARG" ;;
    x) PROXY="$OPTARG" ;;
    O) OAST=1 ;;
    A) AGENT=1 ;;
    b) LLM_BUDGET_USD="$OPTARG" ;;
    R) RESUME=1 ;;
    q) SKIP_FUZZ=1 ;;
    s) SINGLE=1 ;;
    y) ASSUME_YES=1 ;;
    P) NO_TUI=1 ;;
    D) DOCTOR=1 ;;
    h) usage; exit 0 ;;
    \?) err "Unknown option: -$OPTARG"; usage; exit 1 ;;
    :)  err "Option -$OPTARG requires an argument"; exit 1 ;;
  esac
done
shift $((OPTIND - 1))

# Resolve per-role models/token budgets now that -m / env are applied.
LLM_MODEL_PLAN="${LLM_MODEL_PLAN:-$LLM_MODEL}"
LLM_MODEL_TRIAGE="${LLM_MODEL_TRIAGE:-$LLM_MODEL}"
LLM_MAX_TOKENS_TRIAGE="${LLM_MAX_TOKENS_TRIAGE:-16000}"  # headroom: reasoning models + a rich finding set overran 8000 mid-report

raw_target="${1:-}"
# Normalize but KEEP scheme + port so we can test a specific host:port (e.g. http://localhost:3000).
# TARGET_SCHEME / TARGET_PORT are carried separately; $domain stays the bare host (used for scope
# matching, subfinder and the output dir name). SEED_URL is the exact URL httpx will probe.
TARGET_SCHEME="$(printf '%s' "$raw_target" | sed -nE 's#^([a-zA-Z]+)://.*#\1#p' | tr 'A-Z' 'a-z')"
_hostport="$(printf '%s' "$raw_target" | tr -d '[:space:]' | sed -E 's#^[a-zA-Z]+://##; s#/.*$##' | tr 'A-Z' 'a-z')"
# Split host[:port], IPv6-aware: a bracketed [::1] / [::1]:8080 keeps the brackets as the host.
case "$_hostport" in
  \[*\]:[0-9]*) domain="${_hostport%]:*}]"; TARGET_PORT="${_hostport##*]:}" ;;   # [::1]:8080
  \[*\])        domain="$_hostport"; TARGET_PORT="" ;;                            # [::1]
  *:[0-9]*)     TARGET_PORT="${_hostport##*:}"; domain="${_hostport%:*}"
                case "$TARGET_PORT" in ''|*[!0-9]*) TARGET_PORT=""; domain="$_hostport" ;; esac ;;  # host:port (reject non-numeric)
  *)            domain="$_hostport"; TARGET_PORT="" ;;
esac
# regex-safe host for scope filters: escape every regex metachar (handles . and IPv6 [ ] : ).
esc_domain="$(printf '%s' "$domain" | sed -E 's/[][(){}.^$*+?|\\]/\\&/g')"
# Auto-enable single-host mode when subdomain enumeration is meaningless/impossible:
# an explicit port, localhost, a bare IP, or a single-label host (no dot).
if [ -n "$TARGET_PORT" ] || [ "$domain" = localhost ] \
   || printf '%s' "$domain" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
   || ! printf '%s' "$domain" | grep -q '\.'; then
  SINGLE=1
fi
# If the user gave a scheme, honor it exactly; if not, hand httpx a bare host[:port] so it
# probes BOTH http and https (dev servers vary). SEED_URL is what httpx probes in single mode.
if [ -n "$TARGET_SCHEME" ]; then
  SEED_URL="${TARGET_SCHEME}://${domain}${TARGET_PORT:+:$TARGET_PORT}"
else
  SEED_URL="${domain}${TARGET_PORT:+:$TARGET_PORT}"
fi
# Public archives (gau/waybackurls/waymore) are keyed by internet domain - useless (and a time
# sink) against localhost / a bare IP / a non-standard port, so skip them there.
NO_ARCHIVE=0
{ [ "$domain" = localhost ] || printf '%s' "$domain" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || [ -n "$TARGET_PORT" ]; } && NO_ARCHIVE=1
if [ "$DOCTOR" != 1 ]; then
  if [ -z "$domain" ]; then err "No target domain provided."; usage; exit 1; fi
  if [ "$SINGLE" = 1 ]; then
    if ! printf '%s' "$domain" | grep -qE '^[a-z0-9._-]+$'; then
      err "Invalid host (got: '$1' -> '$domain'). Single-host mode accepts e.g. localhost, 127.0.0.1, host:3000"; exit 1
    fi
    [ "$ASSUME_YES" = 1 ] || log "Parsed target: $SEED_URL  (single-host mode: no subdomain enumeration)"
  else
    if ! printf '%s' "$domain" | grep -qE '^[a-z0-9.-]+\.[a-z]{2,}$'; then
      err "That doesn't look like a bare domain (got: '$1' -> '$domain'). Use e.g. example.com, or -s for a single host/localhost/IP:port"; exit 1
    fi
    [ "$ASSUME_YES" = 1 ] || log "Parsed target: $domain"
  fi
fi

# Build auth header list + per-tool network (auth+proxy) argument arrays, cascaded to
# every active tool so scans can reach the logged-in surface and route through a proxy.
# If the dual-identity IDOR already handed us a session (AUTH_A) but no general scan-auth
# header was given, reuse identity A as the scan auth - so "hand it one session" means the
# whole crawl/fuzz/nuclei/agent pass runs authenticated, not just the A/B/anon IDOR diff.
if [ -z "$AUTH_HEADER" ] && [ -z "$AUTH_COOKIE" ] && [ -n "$AUTH_A" ]; then
  AUTH_HEADER="$AUTH_A"
  [ "$ASSUME_YES" != 1 ] && log "Auth: reusing IDOR identity A as the authenticated scan session"
fi
AUTH_H=()
[ -n "$AUTH_COOKIE" ] && AUTH_H+=("Cookie: $AUTH_COOKIE")
if [ -n "$AUTH_HEADER" ]; then
  while IFS= read -r _l; do [ -n "$_l" ] && AUTH_H+=("$_l"); done <<< "$AUTH_HEADER"
fi
_hdr=(); for _h in ${AUTH_H[@]+"${AUTH_H[@]}"}; do _hdr+=(-H "$_h"); done
HTTPX_NET=("${_hdr[@]}");  [ -n "$PROXY" ] && HTTPX_NET+=(-proxy "$PROXY")
NUCLEI_NET=("${_hdr[@]}"); [ -n "$PROXY" ] && NUCLEI_NET+=(-proxy "$PROXY")
FFUF_NET=("${_hdr[@]}");   [ -n "$PROXY" ] && FFUF_NET+=(-x "$PROXY")
KATANA_NET=("${_hdr[@]}"); [ -n "$PROXY" ] && KATANA_NET+=(-proxy "$PROXY")
DALFOX_NET=("${_hdr[@]}"); [ -n "$PROXY" ] && DALFOX_NET+=(--proxy "$PROXY")
CURL_NET=("${_hdr[@]}");   [ -n "$PROXY" ] && CURL_NET+=(-x "$PROXY")
# Proxy-only net (NO auth headers): for requests that must NOT carry identity A's session -
# the IDOR "anonymous" and "user B" legs. Using CURL_NET there would send A's cookie and
# falsely flag every readable URL as anon-accessible.
CURL_PROXY=(); [ -n "$PROXY" ] && CURL_PROXY+=(-x "$PROXY")
[ "${#AUTH_H[@]}" -gt 0 ] && [ "$ASSUME_YES" != 1 ] && log "Auth: ${#AUTH_H[@]} header(s) will be sent to active tools"
[ -n "$PROXY" ] && log "Proxy: routing active tools through $PROXY"
# JWT pre-flight: if the session token is a JWT, warn when it is already expired or will
# expire during the scan - a dead token silently turns an authenticated scan anonymous.
if have jq; then
  _jwt="$(printf '%s\n%s\n%s' "$AUTH_HEADER" "$AUTH_COOKIE" "$AUTH_A" | grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+' | head -1)"
  if [ -n "$_jwt" ]; then
    _pl="${_jwt#*.}"; _pad=$(( (4 - ${#_pl} % 4) % 4 )); _pl="$_pl$(printf '%*s' "$_pad" '' | tr ' ' '=')"
    _exp="$(printf '%s' "$_pl" | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r '.exp // empty' 2>/dev/null)"
    if [ -n "$_exp" ] && printf '%s' "$_exp" | grep -qE '^[0-9]+$'; then
      _now="$(date +%s)"
      if [ "$_exp" -le "$_now" ]; then warn "Auth JWT is ALREADY EXPIRED ($(date -u -d "@$_exp" 2>/dev/null || echo "$_exp")) - the scan will run UNAUTHENTICATED. Refresh the token."
      elif [ "$((_exp - _now))" -lt 1800 ]; then warn "Auth JWT expires in <30min ($(( (_exp-_now)/60 ))m) - it may die mid-scan; refresh it for a long run."
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
# have() is defined in 00-prelude.sh (needed earlier, e.g. the JWT pre-flight above).
missing=()
for tool in httpx nuclei; do have "$tool" || missing+=("$tool"); done
# subfinder is only needed to enumerate subdomains; single-host mode doesn't use it.
[ "$SINGLE" = 1 ] || have subfinder || missing+=("subfinder")
if [ "${#missing[@]}" -gt 0 ] && [ "$DOCTOR" != 1 ]; then
  err "Missing required tools: ${missing[*]} (see projectdiscovery.io)"; exit 1
fi
[ "$DOCTOR" = 1 ] || have ffuf || warn "ffuf not found - content-discovery step will be skipped."

# Self-heal preflight: refresh nuclei templates on request (UPDATE_TEMPLATES=1 / -U behaviour).
if [ "$DOCTOR" != 1 ] && [ "$UPDATE_TEMPLATES" = 1 ] && have nuclei; then
  log "Self-heal: updating nuclei templates (this can take a bit)…"
  nuclei -update-templates -silent >/dev/null 2>&1 || warn "nuclei template update failed (continuing)"
fi

AI_ENABLED=1
if [ -z "$LLM_API_KEY" ]; then
  [ "$DOCTOR" = 1 ] || warn "No API key (TOGETHER_API_KEY) - AI steps disabled, using static defaults."; AI_ENABLED=0
elif ! have curl || ! have jq; then
  [ "$DOCTOR" = 1 ] || warn "curl and jq are required for AI steps - disabling AI, using defaults."; AI_ENABLED=0
fi
if [ "$AI_ENABLED" = 1 ] && [ "$DOCTOR" != 1 ]; then
  log "AI routing -> plan: $LLM_MODEL_PLAN | triage: $LLM_MODEL_TRIAGE${LLM_FALLBACK_MODELS:+ | fallbacks: $LLM_FALLBACK_MODELS}"
fi

# ---------------------------------------------------------------------------
# Authorization gate
# ---------------------------------------------------------------------------
if [ "$DOCTOR" != 1 ] && [ "$ASSUME_YES" != "1" ]; then
  printf '%s' "${c_yellow}Confirm you are AUTHORIZED to test '${domain}' [y/N]: ${c_reset}"
  read -r reply
  case "$reply" in y|Y|yes|YES) ;; *) err "Aborted - authorization not confirmed."; exit 1 ;; esac
fi

# ---------------------------------------------------------------------------
# Output layout
# ---------------------------------------------------------------------------
llm_log="/dev/null"   # overridden below for a real run
if [ "$DOCTOR" != 1 ]; then
  if [ "$RESUME" = 1 ] && [ -z "$OUTDIR" ]; then
    # resume the newest matching run dir for this domain
    OUTDIR="$(ls -1dt "4tail_${domain}_"* 2>/dev/null | head -1)"
    [ -n "$OUTDIR" ] && log "Resuming previous run: $OUTDIR"
  fi
  if [ -z "$OUTDIR" ]; then
    ts="$(date +%Y%m%d_%H%M%S)"; OUTDIR="4tail_${domain}_${ts}"
    [ "$RESUME" = 1 ] && warn "No previous run found for $domain - starting fresh."
  fi
  mkdir -p "$OUTDIR"
  subdomains_file="$OUTDIR/subdomains.txt"
  httpx_json="$OUTDIR/httpx.jsonl"
  alive_file="$OUTDIR/alive.txt"
  alive_ranked_file="$OUTDIR/alive_ranked.txt"   # value-ranked alive hosts (shared by all capped stages)
  tech_brief="$OUTDIR/tech_brief.txt"
  fuzz_dir="$OUTDIR/fuzz"; mkdir -p "$fuzz_dir"
  nuclei_file="$OUTDIR/nuclei.txt"
  report_file="$OUTDIR/report.md"
  llm_log="$OUTDIR/llm.log"
  tech_map_file="$OUTDIR/tech_wordlists.tsv"   # tech <TAB> seclists-relative-path
  seclists_index="$OUTDIR/.seclists_index.tsv" # basename <TAB> abs-path of real SecLists Web-Content lists
  nuclei_tag_index="$OUTDIR/.nuclei_tags.txt"  # real category tags present in the installed nuclei templates
  fuzz_plan_file="$OUTDIR/fuzz_plan.txt"        # host <TAB> wordlists used
  nuclei_stats_file="$OUTDIR/nuclei_stats.jsonl"
  supervisor_log="$OUTDIR/supervisor.log"
  fuzz_findings_file="$OUTDIR/fuzz_findings.txt"   # aggregated ffuf hits: status<TAB>length<TAB>url
  urls_file="$OUTDIR/urls.txt"                     # crawled + historical URLs (in-scope)
  custom_words_file="$OUTDIR/custom_words.txt"     # AI-generated org/product-specific fuzz words
  urls_params_file="$OUTDIR/urls_params.txt"       # URLs with query params (for gf/DAST)
  gf_file="$OUTDIR/gf_hits.txt"                    # gf pattern -> url
  dast_file="$OUTDIR/dast_findings.txt"            # nuclei -dast findings
  url_patterns_file="$OUTDIR/url_patterns.txt"     # clustered endpoint patterns
  targets_active_file="$OUTDIR/targets_active.txt" # AI-selected juicy URLs for specialists
  api_specs_file="$OUTDIR/api_specs.txt"           # discovered Swagger/OpenAPI/GraphQL spec URLs
  api_tests_file="$OUTDIR/api_tests.txt"           # AI-generated API test URLs (folded into active set)
  gql_schema_file="$OUTDIR/graphql_schema.txt"     # dumped GraphQL schema when introspection is open
  sourcemap_file="$OUTDIR/sourcemaps.txt"          # recovered .js.map URLs (source leak)
  smap_endpoints_file="$OUTDIR/sourcemap_endpoints.txt"  # endpoints reconstructed from source maps (folded into urls)
  js_endpoints_file="$OUTDIR/js_endpoints.txt"     # API endpoints/paths mined from JS bundles (SPA surface -> folded into urls)
  js_fields_file="$OUTDIR/js_fields.txt"           # request field/param names mined from JS (so the agent doesn't guess bodies)
  open_dir_file="$OUTDIR/open_dirs.txt"            # open directory listings + extracted confidential files
  stacktrace_file="$OUTDIR/stack_traces.txt"       # 500 pages leaking stack traces / DB errors
  unauth_api_file="$OUTDIR/unauth_api.txt"         # unauthenticated REST/API data exposure (BOLA candidates)
  openredir_file="$OUTDIR/open_redirect.txt"       # deterministically-confirmed open redirects
  jwt_file="$OUTDIR/jwt_issues.txt"                # passive JWT weakness findings
  stale_file="$OUTDIR/stale.tsv"                   # per-host legacy score: score<TAB>url<TAB>evidence
  oast_dir="$OUTDIR/oast"; mkdir -p "$oast_dir"    # interactsh output + injection map
  oast_log="$oast_dir/interactions.jsonl"          # raw interactsh interactions
  oast_map="$oast_dir/injected.tsv"                # marker<TAB>url we injected an OOB payload into
  oast_hits_file="$oast_dir/confirmed.txt"         # correlated: confirmed blind SSRF/redirect
  agent_file="$OUTDIR/agent_confirmed.txt"         # agent loop: confirmed/escalated issues
  agent_log="$OUTDIR/agent_log.txt"                # agent loop: full probe transcript
  bypass_file="$OUTDIR/findings/bypass.txt"        # 403/401 access-control bypasses
  prop_file="$OUTDIR/findings/propagated.txt"      # paths found on one host, live on another
  idor_file="$OUTDIR/findings/idor.txt"            # dual-identity IDOR / broken-authz candidates
  corsy_file="$OUTDIR/findings/cors.txt"           # Corsy CORS-misconfig findings
  cdn_file="$OUTDIR/.cdn_hosts.txt"                # hosts classified CDN/WAF by cdncheck (skip-fuzz)
  verified_file="$OUTDIR/verified.txt"             # findings that survived the verification re-test
  diff_file="$OUTDIR/changes.txt"                  # what changed since the last run of this target
  findings_dir="$OUTDIR/findings"; mkdir -p "$findings_dir"  # per-specialist output
  forms_file="$OUTDIR/forms.txt"                   # harvested POST/GET form fields (for PoC accuracy)
  poc_file="$OUTDIR/poc_requests.sh"               # AI-written MANUAL curl PoCs (4tail never runs these)
  takeover_file="$OUTDIR/takeover.txt"             # dangling-CNAME subdomain-takeover candidates
  dns_hygiene_file="$OUTDIR/dns_hygiene.txt"       # SPF/DMARC/zone-transfer findings
  sec_headers_file="$OUTDIR/security_headers.txt"  # clickjacking / HSTS / CSP / cookie-flag findings
  versions_file="$OUTDIR/versioned_components.txt" # product:version pairs for CVE matching
  cost_ledger="${LLM_COST_LEDGER:-$OUTDIR/.llm_cost_usd}"
  [ -f "$cost_ledger" ] || printf '0\n' > "$cost_ledger"
fi

# Auto-detect a SecLists installation so fuzzing can pick tech-specific lists.
# `apt install seclists` (Debian/Ubuntu/Kali) puts it in /usr/share/seclists.
if [ -z "$SECLISTS_DIR" ]; then
  for d in /usr/share/seclists /usr/share/wordlists/seclists /usr/share/SecLists \
           /usr/share/wordlists/SecLists "$HOME/SecLists" "$HOME/seclists" /opt/SecLists; do
    [ -d "$d" ] && { SECLISTS_DIR="$d"; break; }
  done
fi
# Resolve the base "juicy" wordlist. Prefer Bo0oM/fuzz.txt (dotfiles, backups, VCS
# metadata, cloud creds, path-traversal/WAF-bypass payloads); else SecLists common.txt.
resolve_base_wordlist() {
  [ -n "$WORDLIST" ] && [ -f "$WORDLIST" ] && return 0
  local c
  for c in \
    "/root/Desktop/bugs/tools/fuzz.txt/fuzz.txt" \
    "$HOME/fuzz.txt/fuzz.txt" "$HOME/tools/fuzz.txt/fuzz.txt" \
    "$HOME/.4tail/fuzz.txt" "/usr/share/wordlists/fuzz.txt" \
    "/opt/fuzz.txt/fuzz.txt" "./fuzz.txt/fuzz.txt" "./fuzz.txt"; do
    [ -f "$c" ] && { WORDLIST="$c"; return 0; }
  done
  if [ "$FETCH_FUZZTXT" = 1 ] && have curl; then
    mkdir -p "$HOME/.4tail"
    if curl -fsSL --max-time 60 \
         "https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt" \
         -o "$HOME/.4tail/fuzz.txt" 2>/dev/null && [ -s "$HOME/.4tail/fuzz.txt" ]; then
      WORDLIST="$HOME/.4tail/fuzz.txt"; return 0
    fi
  fi
  [ -n "$SECLISTS_DIR" ] && [ -f "$SECLISTS_DIR/Discovery/Web-Content/common.txt" ] \
    && WORDLIST="$SECLISTS_DIR/Discovery/Web-Content/common.txt"
}
resolve_base_wordlist

# If a Bo0oM api-endpoints.txt sits next to the base list, use it for API hosts.
base_dir="$(dirname "${WORDLIST:-/nonexistent}")"
API_ENDPOINTS_EXTRA=""
[ -f "$base_dir/api-endpoints.txt" ] && API_ENDPOINTS_EXTRA="$base_dir/api-endpoints.txt"

if [ "$DOCTOR" != 1 ]; then
  if [ -n "$SECLISTS_DIR" ]; then
    log "SecLists: $SECLISTS_DIR (tech-aware fuzzing enabled)"
  else
    warn "SecLists not found - fuzzing will use only the base wordlist + tech extensions."
    warn "Install it (apt install seclists) or set SECLISTS_DIR=/path/to/SecLists."
  fi
  if [ -n "$WORDLIST" ] && [ -f "$WORDLIST" ]; then
    case "$WORDLIST" in *fuzz.txt) log "Base wordlist: $WORDLIST (Bo0oM juicy list)";; *) log "Base wordlist: $WORDLIST";; esac
  else
    warn "No base wordlist found. Provide -w, or set FETCH_FUZZTXT=1 to download Bo0oM/fuzz.txt."
  fi
fi

