# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
# `doctor` subcommand (before getopts, which doesn't parse bare words)
if [ "${1:-}" = "doctor" ]; then DOCTOR=1; shift; fi

while getopts ":w:o:t:S:m:M:p:b:B:H:x:OARqjsCyPDh" opt; do
  case "$opt" in
    w) WORDLIST="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    t) DEFAULT_NUCLEI_TAGS="$OPTARG" ;;
    S) NUCLEI_SEVERITY="$OPTARG" ;;
    m) LLM_MODEL="$OPTARG" ;;
    M) MAX_FUZZ_HOSTS="$OPTARG" ;;
    p) FUZZ_PARALLEL="$OPTARG" ;;
    j) JSMINE=1 ;;
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
LLM_MAX_TOKENS_TRIAGE="${LLM_MAX_TOKENS_TRIAGE:-8000}"

raw_target="${1:-}"
# Normalize but KEEP scheme + port so we can test a specific host:port (e.g. http://localhost:3000).
# TARGET_SCHEME / TARGET_PORT are carried separately; $domain stays the bare host (used for scope
# matching, subfinder and the output dir name). SEED_URL is the exact URL httpx will probe.
TARGET_SCHEME="$(printf '%s' "$raw_target" | sed -nE 's#^([a-zA-Z]+)://.*#\1#p' | tr 'A-Z' 'a-z')"
_hostport="$(printf '%s' "$raw_target" | tr -d '[:space:]' | sed -E 's#^[a-zA-Z]+://##; s#/.*$##' | tr 'A-Z' 'a-z')"
TARGET_PORT="$(printf '%s' "$_hostport" | sed -nE 's#^[^:]+:([0-9]+)$#\1#p')"
domain="$(printf '%s' "$_hostport" | sed -E 's#:[0-9]+$##')"
esc_domain="$(printf '%s' "$domain" | sed 's/\./\\./g')"   # regex-safe host, defined once for all scope filters
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
DEFAULT_UA="${CUSTOM_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36}"
has_ua=0
for _h in ${AUTH_H[@]+"${AUTH_H[@]}"}; do
  case "$_h" in [Uu][Ss][Ee][Rr]-[Aa][Gg][Ee][Nn][Tt]:*) has_ua=1 ;; esac
done
[ "$has_ua" = 0 ] && AUTH_H+=("User-Agent: $DEFAULT_UA")

_hdr=(); for _h in ${AUTH_H[@]+"${AUTH_H[@]}"}; do _hdr+=(-H "$_h"); done
HTTPX_NET=("${_hdr[@]}");  [ -n "$PROXY" ] && HTTPX_NET+=(-proxy "$PROXY")
NUCLEI_NET=("${_hdr[@]}"); [ -n "$PROXY" ] && NUCLEI_NET+=(-proxy "$PROXY")
FFUF_NET=("${_hdr[@]}");   [ -n "$PROXY" ] && FFUF_NET+=(-x "$PROXY")
KATANA_NET=("${_hdr[@]}"); [ -n "$PROXY" ] && KATANA_NET+=(-proxy "$PROXY")
DALFOX_NET=("${_hdr[@]}"); [ -n "$PROXY" ] && DALFOX_NET+=(--proxy "$PROXY"); DALFOX_NET+=(--user-agent "$DEFAULT_UA")
CURL_NET=(--compressed "${_hdr[@]}");   [ -n "$PROXY" ] && CURL_NET+=(-x "$PROXY")
[ "${#AUTH_H[@]}" -gt 0 ] && [ "$ASSUME_YES" != 1 ] && log "Auth: ${#AUTH_H[@]} header(s) will be sent to active tools"
[ -n "$PROXY" ] && log "Proxy: routing active tools through $PROXY"

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
missing=()
for tool in httpx nuclei; do have "$tool" || missing+=("$tool"); done
# subfinder is only needed to enumerate subdomains; single-host mode doesn't use it.
[ "$SINGLE" = 1 ] || have subfinder || missing+=("subfinder")
if [ "${#missing[@]}" -gt 0 ] && [ "$DOCTOR" != 1 ]; then
  err "Missing required tools: ${missing[*]} (see projectdiscovery.io)"; exit 1
fi
[ "$DOCTOR" = 1 ] || have ffuf || warn "ffuf not found - content-discovery step will be skipped."

# Self-heal preflight: refresh nuclei templates on request (UPDATE_TEMPLATES=1 / -U)
# or auto-bootstrap if nuclei is installed but templates are completely absent.
if [ "$DOCTOR" != 1 ] && have nuclei; then
  if [ "$UPDATE_TEMPLATES" = 1 ]; then
    log "Self-heal: updating nuclei templates (this can take a bit)…"
    nuclei -update-templates -silent >/dev/null 2>&1 || warn "nuclei template update failed (continuing)"
  elif [ -z "$(locate_nuclei_templates)" ]; then
    log "Self-heal: nuclei templates not found - auto-downloading (nuclei -update-templates)…"
    nuclei -update-templates -silent >/dev/null 2>&1 || warn "nuclei template download failed (continuing)"
  fi
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
  # Tiered directory layout
  mkdir -p "$OUTDIR"
  recon_dir="$OUTDIR/recon"; mkdir -p "$recon_dir"
  surface_dir="$OUTDIR/surface"; mkdir -p "$surface_dir"
  findings_dir="$OUTDIR/findings"; mkdir -p "$findings_dir"
  loot_dir="$OUTDIR/loot"; mkdir -p "$loot_dir"
  logs_dir="$OUTDIR/logs"; mkdir -p "$logs_dir"

  # Tier 1: Primary Deliverables (clean root OUTDIR)
  report_file="$OUTDIR/report.md"
  report_html="$OUTDIR/report.html"
  findings_json="$OUTDIR/findings.json"
  poc_file="$OUTDIR/poc_requests.sh"

  # Tier 2: Reconnaissance & Infrastructure Intelligence
  subdomains_file="$recon_dir/subdomains.txt"
  httpx_json="$recon_dir/httpx.jsonl"
  alive_file="$recon_dir/alive.txt"
  tech_brief="$recon_dir/tech_brief.txt"
  stale_file="$recon_dir/stale.tsv"
  cdn_file="$recon_dir/cdn_hosts.txt"
  dns_hygiene_file="$recon_dir/dns_hygiene.txt"
  sec_headers_file="$recon_dir/security_headers.txt"
  versions_file="$recon_dir/versioned_components.txt"
  resolved_file="$recon_dir/resolved.txt"

  # Tier 3: Attack Surface & Crawl Data
  urls_archive_file="$surface_dir/urls_archive.txt"
  urls_file="$surface_dir/urls.txt"
  urls_params_file="$surface_dir/urls_params.txt"
  params_file="$surface_dir/params.txt"
  url_patterns_file="$surface_dir/url_patterns.txt"
  targets_active_file="$surface_dir/targets_active.txt"
  api_specs_file="$surface_dir/api_specs.txt"
  api_tests_file="$surface_dir/api_tests.txt"
  gql_schema_file="$surface_dir/graphql_schema.txt"
  sourcemap_file="$surface_dir/sourcemaps.txt"
  smap_endpoints_file="$surface_dir/sourcemap_endpoints.txt"
  js_endpoints_file="$surface_dir/js_endpoints.txt"
  js_urls_file="$surface_dir/js_urls.txt"
  forms_file="$surface_dir/forms.txt"
  nuclei_targets_file="$surface_dir/nuclei_targets.txt"

  # Tier 4: Security Findings & Vulnerability Evidence
  findings_jsonl="$findings_dir/findings.jsonl"
  nuclei_file="$findings_dir/nuclei.txt"
  dast_file="$findings_dir/dast_findings.txt"
  fuzz_findings_file="$findings_dir/fuzz_findings.txt"
  gf_file="$findings_dir/gf_hits.txt"
  bypass_file="$findings_dir/bypass.txt"
  prop_file="$findings_dir/propagated.txt"
  idor_file="$findings_dir/idor.txt"
  corsy_file="$findings_dir/cors.txt"
  takeover_file="$findings_dir/takeover.txt"
  agent_file="$findings_dir/agent_confirmed.txt"
  verified_file="$findings_dir/verified.txt"
  diff_file="$findings_dir/changes.txt"

  # Tier 5: Extracted Loot & Source Reconstructions
  js_secrets_file="$loot_dir/js_secrets.txt"
  agent_loot_dir="$loot_dir/agent_loot"
  js_dir="$loot_dir/jsfiles"
  smap_dir="$loot_dir/sourcemaps_src"

  # Tier 6: Diagnostics, Metrics & Tool Logs
  supervisor_log="$logs_dir/supervisor.log"
  llm_log="$logs_dir/llm.log"
  agent_log="$logs_dir/agent_log.txt"
  nuclei_stats_file="$logs_dir/nuclei_stats.jsonl"
  fuzz_plan_file="$logs_dir/fuzz_plan.txt"
  tech_map_file="$logs_dir/tech_wordlists.tsv"
  seclists_index="$logs_dir/.seclists_index.tsv"
  nuclei_tag_index="$logs_dir/.nuclei_tags.txt"
  fuzz_dir="$logs_dir/fuzz"; mkdir -p "$fuzz_dir"
  oast_dir="$logs_dir/oast"; mkdir -p "$oast_dir"
  oast_log="$oast_dir/interactions.jsonl"
  oast_map="$oast_dir/injected.tsv"
  oast_hits_file="$oast_dir/confirmed.txt"
  cost_ledger="${LLM_COST_LEDGER:-$logs_dir/llm_cost_usd}"
  [ -f "$cost_ledger" ] || printf '0\n' > "$cost_ledger"

  # Backwards compatibility symlinks in OUTDIR root
  ln -sf "recon/alive.txt" "$OUTDIR/alive.txt" 2>/dev/null || true
  ln -sf "recon/subdomains.txt" "$OUTDIR/subdomains.txt" 2>/dev/null || true
  ln -sf "surface/urls.txt" "$OUTDIR/urls.txt" 2>/dev/null || true
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

