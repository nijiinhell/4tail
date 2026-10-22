#!/usr/bin/env bash
#
# 4tail - AI-assisted recon pipeline for AUTHORIZED bug-bounty / pentest work.
#
# Pipeline: subfinder -> httpx (tech detect) -> [AI plans the scan]
#           -> ffuf (content discovery) -> nuclei -> [AI triages findings].
#
# Features a LIVE terminal dashboard that tracks each stage in real time.
# The AI steps use any OpenAI-compatible endpoint (defaults: Together AI + GLM),
# tuned to keep token spend small.
#
# USE ONLY against targets you are explicitly authorised to test.

set -u
set -o pipefail

# Snapshot which tuning vars the user set explicitly, BEFORE we apply any defaults,
# so a loaded blueprint never overrides a value the user chose on the CLI/env.
for _v in CRAWL_MAX_URLS CRAWL_MAX_TIME DAST_MAX_URLS NUCLEI_MAX_HOSTS NUCLEI_SEVERITY \
          MAX_TAGS ACT_MAX_JUICY ACT_MAX_DALFOX ACT_MAX_KXSS ACT_MAX_SQLMAP ACT_MAX_ARJUN \
          ACT_DAST_TAGS ACT_SPECIALISTS ACT_FOCUS; do
  eval "_user_set_$_v=\${$_v+1}"
done

# ---------------------------------------------------------------------------
# LLM configuration (OpenAI-compatible; defaults = Together AI + cheap GLM)
# ---------------------------------------------------------------------------
LLM_API_KEY="${TOGETHER_API_KEY:-${LLM_API_KEY:-}}"
# Strip stray whitespace/newlines (a trailing newline corrupts the auth header -> 401).
LLM_API_KEY="$(printf '%s' "$LLM_API_KEY" | tr -d '[:space:]')"
LLM_BASE_URL="${LLM_BASE_URL:-https://api.together.xyz/v1}"
LLM_MODEL="${LLM_MODEL:-zai-org/GLM-5.3-Flash}"   # base default for every role (Flash = ~9x cheaper output than non-Flash GLM-5.3, same quality for these tasks)
LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-4000}"    # reasoning models spend tokens thinking; leave room for real output
LLM_TEMPERATURE="${LLM_TEMPERATURE:-0.2}"
LLM_TIMEOUT="${LLM_TIMEOUT:-300}"
LLM_RETRIES="${LLM_RETRIES:-2}"

# --- Smart model routing (per-task "swarm"-style switching) -----------------
LLM_MODEL_PLAN="${LLM_MODEL_PLAN:-}"        # scan planner; default = LLM_MODEL
LLM_MODEL_TRIAGE="${LLM_MODEL_TRIAGE:-}"    # findings analyst; default = LLM_MODEL
LLM_MAX_TOKENS_PLAN="${LLM_MAX_TOKENS_PLAN:-6000}"   # headroom for reasoning models (GLM/DeepSeek think first)
LLM_MAX_TOKENS_TRIAGE="${LLM_MAX_TOKENS_TRIAGE:-}"  # default = LLM_MAX_TOKENS
LLM_FALLBACK_MODELS="${LLM_FALLBACK_MODELS:-deepseek-ai/DeepSeek-V4.1-Flash}"  # tried in order if the primary errors (resilience; only billed when used)
# AI supervisor: periodic plain-language status during the long nuclei stage.
SUPERVISOR="${SUPERVISOR:-1}"                        # 1 = on (needs API key); report-only
SUPERVISOR_INTERVAL="${SUPERVISOR_INTERVAL:-120}"   # seconds between supervisor notes

# --- Cost / credit budget ---------------------------------------------------
# Stop calling the AI once estimated spend reaches LLM_BUDGET_USD (0 = unlimited).
# Cost is estimated from each response's token usage x the prices below (USD per
# 1M tokens). Prices are approximate - set them to your model's real Together price
# for an accurate cap. The running total persists across resumed runs.
LLM_BUDGET_USD="${LLM_BUDGET_USD:-0}"
LLM_PRICE_IN="${LLM_PRICE_IN:-0.30}"
LLM_PRICE_OUT="${LLM_PRICE_OUT:-0.30}"
LLM_COST_LEDGER="${LLM_COST_LEDGER:-}"      # cost tally file; default = per-run in OUTDIR
cost_ledger=""                               # resolved after OUTDIR is known

# ---------------------------------------------------------------------------
# Scan configuration
# ---------------------------------------------------------------------------
WORDLIST="${WORDLIST:-}"                   # base "juicy" list; auto-resolved below (Bo0oM/fuzz.txt preferred)
SECLISTS_DIR="${SECLISTS_DIR:-}"          # auto-detected below if empty
SECLISTS_DYNAMIC="${SECLISTS_DYNAMIC:-1}" # 1 = also match detected tech against REAL SecLists filenames (not just the static map)
SECLISTS_MATCH_MAX="${SECLISTS_MATCH_MAX:-3}" # cap dynamically-matched lists per tech token
MAX_FUZZ_WORDS="${MAX_FUZZ_WORDS:-18000}" # cap per-host combined wordlist size (bounty-sized; raise for deep runs)
MAX_FUZZ_HOSTS="${MAX_FUZZ_HOSTS:-0}"     # cap number of hosts to fuzz (0 = all)
FUZZ_MAX_TIME="${FUZZ_MAX_TIME:-300}"     # hard per-host ffuf time cap (s) so a slow host can't stall the stage; 0 = unlimited
SKIP_FUZZ="${SKIP_FUZZ:-0}"               # 1 = skip content discovery entirely (nuclei-only)
SKIP_CDN_FUZZ="${SKIP_CDN_FUZZ:-1}"       # 1 = don't fuzz CDN/WAF edges (cloudfront, cloudflare, …)
EXTENSIONS="${EXTENSIONS:-}"              # explicit ffuf -e list (overrides tech-aware exts)
MAX_EXTS="${MAX_EXTS:-4}"                 # cap on per-host extensions (each one multiplies total requests)
FFUF_RATE="${FFUF_RATE:-0}"              # ffuf requests/sec per host (0 = unlimited)
FUZZ_PARALLEL="${FUZZ_PARALLEL:-1}"      # fuzz N hosts at once (-p); auto-backoff on WAF blocks
FETCH_FUZZTXT="${FETCH_FUZZTXT:-0}"      # 1 = download Bo0oM/fuzz.txt if no base list found
DEDUPE_ORIGINS="${DEDUPE_ORIGINS:-1}"    # 1 = one fuzz target per IP/CNAME + response cluster
USE_DNSX="${USE_DNSX:-1}"                # 1 = use dnsx (if installed) to resolve + drop wildcards
JSMINE="${JSMINE:-0}"                    # 1 = JS/secret mining + param discovery (-j)
CRAWL="${CRAWL:-0}"                       # 1 = active funnel: crawl -> cluster -> AI juicy -> specialists (-C)
# Static assets never hold injection bugs - strip them before the slow tools (dalfox/
# nuclei-dast/kxss/sqlmap) so caps and time are spent on real endpoints, not app.js?v=1.
# Matched against the PATH only (query stripped first by drop_static), so a file-ish
# VALUE like ?file=app.js is KEPT - that's an LFI lead, not a static asset.
STATIC_URL_RE="${STATIC_URL_RE:-\.(js|css|png|jpe?g|gif|svg|ico|webp|avif|bmp|tiff?|woff2?|ttf|eot|otf|map|mp4|webm|mp3|ogg|wav|pdf|zip|t?gz|rar|7z|bz2|swf)$}"
CRAWL_MAX_URLS="${CRAWL_MAX_URLS:-8000}" # cap collected URLs
CRAWL_MAX_TIME="${CRAWL_MAX_TIME:-1200}" # hard cap on crawling (s); 0 = unlimited
DAST="${DAST:-1}"                        # run nuclei -dast on selected URLs
DAST_MAX_URLS="${DAST_MAX_URLS:-1500}"   # cap URLs sent to DAST

# --- Blueprint (strategy profile) + active-phase caps -----------------------
# BLUEPRINT: "auto" = AI picks from blueprints/ after recon; or a name / path.
BLUEPRINT="${BLUEPRINT:-auto}"
BLUEPRINTS_DIR="${BLUEPRINTS_DIR:-}"      # auto-detected next to the script if empty
# Active-phase caps/specialists (filled from the blueprint; env here overrides it).
ACT_MAX_JUICY="${ACT_MAX_JUICY:-100}"     # cap URLs that reach the active specialists
ACT_MAX_DALFOX="${ACT_MAX_DALFOX:-50}"
ACT_MAX_KXSS="${ACT_MAX_KXSS:-400}"
ACT_MAX_SQLMAP="${ACT_MAX_SQLMAP:-3}"     # sqlmap = confirmation only, tightly capped
ACT_MAX_ARJUN="${ACT_MAX_ARJUN:-25}"
ACT_SPECIALISTS="${ACT_SPECIALISTS:-nuclei-dast,dalfox,kxss,arjun,sqlmap}"
ACT_FOCUS="${ACT_FOCUS:-idor,sqli,xss,ssrf,lfi,redirect,ssti}"
ACT_DAST_TAGS="${ACT_DAST_TAGS:-}"        # empty = all nuclei fuzzing (DAST) templates
SQLMAP_CONFIRM="${SQLMAP_CONFIRM:-1}"     # allow sqlmap when the blueprint lists it (0 to hard-disable)
API_SPECS="${API_SPECS:-1}"               # 1 = detect Swagger/OpenAPI/GraphQL specs -> AI builds targeted tests (part of -C)
API_MAX_SPECS="${API_MAX_SPECS:-5}"       # cap spec documents fetched + fed to the AI
API_MAX_TESTS="${API_MAX_TESTS:-60}"      # cap AI-generated API test URLs folded into the active set

# --- Authentication + proxy (cascade to all active tools) -------------------
AUTH_HEADER="${AUTH_HEADER:-}"            # one or more "Header: value" (newline-separated); also -H
AUTH_COOKIE="${AUTH_COOKIE:-}"           # "name=val; name2=val2"  -> sent as Cookie header
PROXY="${PROXY:-}"                       # http(s)://host:port routed through httpx/nuclei/ffuf/katana/dalfox/curl
UPDATE_TEMPLATES="${UPDATE_TEMPLATES:-0}" # 1 = nuclei -update-templates before scanning (self-heal)
EMIT_SARIF="${EMIT_SARIF:-0}"            # 1 = also write findings.sarif
NUCLEI_TAG_INDEX="${NUCLEI_TAG_INDEX:-1}" # 1 = index REAL category tags from the installed templates so the AI plan isn't limited to the hardcoded allowlist
NUCLEI_TEMPLATES_DIR="${NUCLEI_TEMPLATES_DIR:-}" # override template store path; auto-located if empty

# --- Staleness ranking + OAST (blind-bug confirmation) ----------------------
STALE_RANK="${STALE_RANK:-1}"            # 1 = compute a per-host "legacy" score; AI funnels budget to older stacks first
OAST="${OAST:-0}"                        # 1 = start interactsh in the background + inject OOB payloads into redirect/SSRF params
OAST_SERVER="${OAST_SERVER:-}"           # optional self-hosted interactsh server (-s); empty = public (oast.fun)
OAST_MAX_INJECT="${OAST_MAX_INJECT:-40}" # cap URLs we inject an OOB payload into

# --- Agent mode (autonomous AI validation loop) -----------------------------
# The AI looks at the juicy findings and fires its own GET probes to confirm/escalate
# them (read web.config via LFI, param-mine empty 200s, test redirects, walk IDOR ids),
# sees the responses, and decides the next move - bounded so it never camps on one host.
AGENT="${AGENT:-0}"                       # 1 = run the autonomous probe loop (-A)
AGENT_ROUNDS="${AGENT_ROUNDS:-6}"         # max observe->decide->act rounds (AI stops itself when leads run out)
AGENT_MAX_PROBES="${AGENT_MAX_PROBES:-8}" # max GET probes the AI may fire per round
AGENT_MAX_TIME="${AGENT_MAX_TIME:-240}"   # hard wall-clock cap (s) for the whole loop; 0 = unlimited
DEFAULT_NUCLEI_TAGS="${DEFAULT_NUCLEI_TAGS:-cves,exposures,misconfiguration,tech,default-login,takeover}"
MAX_TAGS="${MAX_TAGS:-15}"                # cap nuclei tags (more tags = far more templates = much slower)
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-critical,high,medium,low}"
NUCLEI_RATELIMIT="${NUCLEI_RATELIMIT:-150}"
NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-8}"    # per-request timeout (s) - stops hanging on dead/slow hosts
NUCLEI_RETRIES="${NUCLEI_RETRIES:-1}"
NUCLEI_MHE="${NUCLEI_MHE:-15}"           # skip a host after this many errors (kills dead-host error spam)
NUCLEI_MAX_TIME="${NUCLEI_MAX_TIME:-3600}"  # hard cap on the whole nuclei stage (s); 0 = unlimited
NUCLEI_CONC="${NUCLEI_CONC:-40}"         # template concurrency (-c); higher = faster, more load/errors
NUCLEI_BULK="${NUCLEI_BULK:-25}"         # hosts scanned in parallel per template (-bulk-size)
NUCLEI_DEDUPE="${NUCLEI_DEDUPE:-1}"      # 1 = scan one representative per origin+response signature
NUCLEI_SKIP_CDN="${NUCLEI_SKIP_CDN:-0}"  # 1 = also drop CDN/WAF edges from nuclei (keeps takeover if 0)
NUCLEI_MAX_HOSTS="${NUCLEI_MAX_HOSTS:-100}" # cap hosts scanned (0 = all). Hosts are value-ranked, so this keeps the top-N most interesting.
HTTPX_THREADS="${HTTPX_THREADS:-50}"
OUTDIR="${OUTDIR:-}"
RESUME="${RESUME:-0}"      # 1 = continue a previous run (reuse finished stages)
ASSUME_YES="${ASSUME_YES:-0}"
NO_TUI="${NO_TUI:-0}"
LOOT_FEED="${LOOT_FEED:-1}"  # 1 = live "loot" feed panel (findings stream into the dashboard)
LOOT_ROWS="${LOOT_ROWS:-6}"  # rows reserved for the loot feed (fixed height keeps the redraw stable)
DOCTOR="${DOCTOR:-0}"      # 1 = run health checks and exit (see -D / `doctor`)

# ---------------------------------------------------------------------------
# Colors / plain-log helpers (used in non-TUI mode)
# ---------------------------------------------------------------------------
c_reset=$'\033[0m'; c_blue=$'\033[1;34m'; c_green=$'\033[1;32m'
c_yellow=$'\033[1;33m'; c_red=$'\033[1;31m'; c_dim=$'\033[2m'; c_cyan=$'\033[1;36m'
log()  { printf '%s[*]%s %s\n' "$c_blue"   "$c_reset" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$c_green"  "$c_reset" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_yellow" "$c_reset" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$c_red"    "$c_reset" "$*" >&2; }

usage() {
  cat <<EOF
4tail - AI-assisted recon for authorized security testing

Usage: $0 [options] <target_domain>
       $0 doctor            # run health checks (tools, wordlists, LLM) and exit

Options:
  -w <file>   Wordlist for ffuf              (env WORDLIST)
  -o <dir>    Output directory               (env OUTDIR)
  -t <tags>   Fallback nuclei tags           (env DEFAULT_NUCLEI_TAGS)
  -S <sev>    Nuclei severities              (env NUCLEI_SEVERITY, default $NUCLEI_SEVERITY)
  -m <model>  LLM model id                   (env LLM_MODEL, default $LLM_MODEL)
  -q          Quick: skip fuzzing (nuclei-only) (env SKIP_FUZZ=1)
  -M <n>      Fuzz at most N hosts            (env MAX_FUZZ_HOSTS, 0=all)
  -p <n>      Fuzz N hosts in parallel        (env FUZZ_PARALLEL, default 1; auto-backoff)
  -j          JS/secret mining + param discovery (env JSMINE=1)
  -C          Active funnel: crawl -> cluster -> AI juicy -> API specs -> specialists (env CRAWL=1)
  -B <name>   Blueprint/strategy (env BLUEPRINT; "auto"=AI picks; or webapp_bounty/api_bounty/wordpress/stealth/deep)
  -H <hdr>    Auth header, repeatable (e.g. -H "Authorization: Bearer X"); env AUTH_HEADER/AUTH_COOKIE
  -x <proxy>  Route tools through http(s) proxy (env PROXY)
  -O          OAST: start interactsh, inject OOB payloads, confirm blind SSRF/redirect (env OAST=1)
  -A          Agent: autonomous AI probe loop - confirms/escalates juicy findings itself (env AGENT=1)
  -R          Resume: continue a previous run (env RESUME=1; use with -o <dir>)
  -b <usd>    LLM credit budget, e.g. 2      (env LLM_BUDGET_USD, 0=unlimited)
  -y          Skip the authorization prompt  (env ASSUME_YES=1)
  -P          Plain output, no live dashboard(env NO_TUI=1)
  -D          Run health checks and exit     (same as: $0 doctor)
  -h          Show this help

LLM (OpenAI-compatible, defaults to Together AI + GLM):
  TOGETHER_API_KEY   API key. If unset, AI steps are skipped (static defaults).
  LLM_BASE_URL       API base   (default $LLM_BASE_URL)
  LLM_MODEL          Model id   (default $LLM_MODEL)
  LLM_MAX_TOKENS     Output cap (default $LLM_MAX_TOKENS, kept low for cost)

Example:
  TOGETHER_API_KEY=... $0 -w wordlist.txt example.com
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
# `doctor` subcommand (before getopts, which doesn't parse bare words)
if [ "${1:-}" = "doctor" ]; then DOCTOR=1; shift; fi

while getopts ":w:o:t:S:m:M:p:b:B:H:x:OARqjCyPDh" opt; do
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

domain="${1:-}"
# Normalize: strip scheme, any path/port, whitespace, and lowercase - so a pasted URL
# or stray character can't turn into a different/invalid target.
domain="$(printf '%s' "$domain" | tr -d '[:space:]' | sed -E 's#^[a-zA-Z]+://##; s#[/:].*$##' | tr 'A-Z' 'a-z')"
if [ "$DOCTOR" != 1 ]; then
  if [ -z "$domain" ]; then err "No target domain provided."; usage; exit 1; fi
  if ! printf '%s' "$domain" | grep -qE '^[a-z0-9.-]+\.[a-z]{2,}$'; then
    err "That doesn't look like a bare domain (got: '$1' -> '$domain'). Use e.g. example.com"; exit 1
  fi
  [ "$ASSUME_YES" = 1 ] || log "Parsed target: $domain"
fi

# Build auth header list + per-tool network (auth+proxy) argument arrays, cascaded to
# every active tool so scans can reach the logged-in surface and route through a proxy.
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
[ "${#AUTH_H[@]}" -gt 0 ] && [ "$ASSUME_YES" != 1 ] && log "Auth: ${#AUTH_H[@]} header(s) will be sent to active tools"
[ -n "$PROXY" ] && log "Proxy: routing active tools through $PROXY"

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
missing=()
for tool in subfinder httpx nuclei; do have "$tool" || missing+=("$tool"); done
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
  urls_params_file="$OUTDIR/urls_params.txt"       # URLs with query params (for gf/DAST)
  gf_file="$OUTDIR/gf_hits.txt"                    # gf pattern -> url
  dast_file="$OUTDIR/dast_findings.txt"            # nuclei -dast findings
  url_patterns_file="$OUTDIR/url_patterns.txt"     # clustered endpoint patterns
  targets_active_file="$OUTDIR/targets_active.txt" # AI-selected juicy URLs for specialists
  api_specs_file="$OUTDIR/api_specs.txt"           # discovered Swagger/OpenAPI/GraphQL spec URLs
  api_tests_file="$OUTDIR/api_tests.txt"           # AI-generated API test URLs (folded into active set)
  stale_file="$OUTDIR/stale.tsv"                   # per-host legacy score: score<TAB>url<TAB>evidence
  oast_dir="$OUTDIR/oast"; mkdir -p "$oast_dir"    # interactsh output + injection map
  oast_log="$oast_dir/interactions.jsonl"          # raw interactsh interactions
  oast_map="$oast_dir/injected.tsv"                # marker<TAB>url we injected an OOB payload into
  oast_hits_file="$oast_dir/confirmed.txt"         # correlated: confirmed blind SSRF/redirect
  agent_file="$OUTDIR/agent_confirmed.txt"         # agent loop: confirmed/escalated issues
  agent_log="$OUTDIR/agent_log.txt"                # agent loop: full probe transcript
  findings_dir="$OUTDIR/findings"; mkdir -p "$findings_dir"  # per-specialist output
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

# ===========================================================================
# LIVE TERMINAL DASHBOARD
# ===========================================================================
if [ -t 1 ] && [ "$NO_TUI" != "1" ]; then TUI=1; else TUI=0; fi

# Stages (named indices so the order is easy to change).
S_SUBS=0 S_LIVE=1 S_PLAN=2 S_FUZZ=3 S_JS=4 S_CRAWL=5 S_NUCLEI=6 S_AGENT=7 S_TRIAGE=8
ST_LABEL=("Subdomains" "Live hosts" "AI scan plan" "Fuzzing" "JS & params" "Active funnel" "Nuclei scan" "AI agent" "AI triage")
ST_STATE=(pending pending pending pending pending pending pending pending pending)
ST_DETAIL=("" "" "" "" "" "" "" "" "")
SUP_NOTE=""                              # latest AI-supervisor status line
# Loot feed state: a bounded in-memory history of findings ("sev\tsrc\ttext"),
# plus a per-file cursor so each source file is only read for its new lines.
LOOT_LINES=()
declare -A LOOT_SEEN=()
declare -A LOOT_FP=()
LOOT_MAX=200
LOOT_LAST=0
[ "$LOOT_ROWS" -ge 1 ] 2>/dev/null || LOOT_ROWS=6
PANEL_LINES=$(( ${#ST_LABEL[@]} + 4 ))  # top border + info + stages + supervisor + bottom border
[ "$LOOT_FEED" = 1 ] && PANEL_LINES=$(( PANEL_LINES + 1 + LOOT_ROWS ))  # loot header + fixed rows
panel_drawn=0
SPIN='|/-\'; spin_i=0
started=$SECONDS

icon() {
  case "$1" in
    pending) printf '%s○%s' "$c_dim" "$c_reset" ;;
    running) printf '%s%s%s' "$c_yellow" "${SPIN:spin_i:1}" "$c_reset" ;;
    done)    printf '%s✔%s' "$c_green" "$c_reset" ;;
    warn)    printf '%s▲%s' "$c_yellow" "$c_reset" ;;
    skip)    printf '%s–%s' "$c_dim" "$c_reset" ;;
    *)       printf ' ' ;;
  esac
}

# Build a horizontal border fitted to the terminal width (box chars are 1 column
# each, so code-point length tracks display width). Keeps the panel from wrapping
# on narrow terminals, which would desync the in-place redraw.
hbar() {  # corner  label  width
  local corner="$1" label="$2" w="$3" base n dashes
  if [ -n "$label" ]; then base="${corner}─ ${label} "; else base="${corner}─"; fi
  n=$(( w - ${#base} - 2 )); [ "$n" -lt 2 ] && n=2
  dashes="$(printf '─%.0s' $(seq 1 "$n"))"
  printf '%s%s' "$base" "$dashes"
}

# --- Loot feed --------------------------------------------------------------
loot_sev_color() {
  case "$1" in
    critical|high) printf '%s' "$c_red" ;;
    medium)        printf '%s' "$c_yellow" ;;
    low)           printf '%s' "$c_cyan" ;;
    *)             printf '%s' "$c_dim" ;;
  esac
}
loot_add() {  # sev  src  text   -> push one finding, bounded history
  LOOT_LINES+=("$1"$'\t'"$2"$'\t'"$3")
  local n=${#LOOT_LINES[@]}
  [ "$n" -gt "$LOOT_MAX" ] && LOOT_LINES=("${LOOT_LINES[@]: -$LOOT_MAX}")
}
# Read only the new lines of a source file and fold them into the feed.
loot_scan() {  # file  src  mode
  local file="$1" src="$2" mode="$3"
  [ -n "$file" ] && [ -f "$file" ] || return 0
  local total cur l sev txt fp
  total="$(wc -l < "$file" 2>/dev/null | tr -d ' ')"; [ -n "$total" ] 2>/dev/null || total=0
  cur="${LOOT_SEEN[$file]:-0}"
  if [ "$total" -le "$cur" ]; then LOOT_SEEN[$file]="$total"; return 0; fi
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    case "$mode" in
      nuclei)  sev="$(printf '%s' "$l" | grep -oiE '\[(critical|high|medium|low|info|unknown)\]' | head -1 | tr -d '[]' | tr 'A-Z' 'a-z')"
               txt="$(printf '%s' "$l" | grep -oE 'https?://[^ ]+' | head -1)"
               [ -n "$txt" ] || txt="$l" ;;
      ffuf)    sev=info
               # suppress by response fingerprint: only the first hit of each
               # (status,length) reaches the feed, so WAF noise doesn't flood it.
               fp="$(printf '%s' "$l" | awk -F'\t' '{print $1"-"$2}')"
               if [ -n "${LOOT_FP[$fp]:-}" ]; then continue; fi
               LOOT_FP[$fp]=1
               txt="$(printf '%s' "$l" | awk -F'\t' '{print $1" "$3}')" ;;
      kxss)    sev=low;    txt="$(printf '%s' "$l" | sed -E 's/ Unfiltered.*//')" ;;
      dalfox)  sev=high;   txt="$(printf '%s' "$l" | grep -oE 'https?://[^ ]+' | head -1)"; [ -n "$txt" ] || txt="$l" ;;
      sqlmap)  sev=high;   txt="$l" ;;
      secret)  sev=medium; txt="$(printf '%s' "$l" | tr '\t' ' ')" ;;
      apispec) sev=info;   txt="spec: $l" ;;
      *)       sev=info;   txt="$l" ;;
    esac
    [ -n "$sev" ] || sev=info
    loot_add "$sev" "$src" "$txt"
  done < <(sed -n "$((cur+1)),${total}p" "$file")
  LOOT_SEEN[$file]="$total"
}
# Pull fresh findings from every known source (throttled to ~1/s).
loot_refresh() {
  [ "$LOOT_FEED" = 1 ] || return 0
  [ $((SECONDS - LOOT_LAST)) -lt 1 ] && return 0
  LOOT_LAST=$SECONDS
  loot_scan "${fuzz_findings_file:-}"      ffuf    ffuf
  loot_scan "${dast_file:-}"               dast    nuclei
  loot_scan "${nuclei_file:-}"             nuclei  nuclei
  loot_scan "${findings_dir:-}/dalfox.txt" dalfox  dalfox
  loot_scan "${findings_dir:-}/kxss.txt"   kxss    kxss
  loot_scan "${findings_dir:-}/sqlmap.txt" sqlmap  sqlmap
  loot_scan "${js_secrets_file:-}"         js      secret
  loot_scan "${api_specs_file:-}"          api     apispec
  loot_scan "${oast_hits_file:-}"          oast    sqlmap
  loot_scan "${agent_file:-}"              agent   sqlmap
}

# _draw_panel: emit the panel body at the current cursor position (no positioning).
# render() handles positioning; this just paints the rows.
_draw_panel() {
  local model_line="off"
  if [ "$AI_ENABLED" = 1 ]; then
    if [ "$LLM_MODEL_PLAN" = "$LLM_MODEL_TRIAGE" ]; then model_line="${LLM_MODEL_PLAN##*/}"
    else model_line="plan:${LLM_MODEL_PLAN##*/} triage:${LLM_MODEL_TRIAGE##*/}"; fi
  fi
  local cost_seg=""
  if [ "$AI_ENABLED" = 1 ] && [ -n "$cost_ledger" ]; then
    cost_seg="  spent=$(cost_fmt)"; [ "${LLM_BUDGET_USD:-0}" != 0 ] && cost_seg="$cost_seg/\$$LLM_BUDGET_USD"
  fi
  # Keep every line within one terminal row - a wrapped line desyncs the redraw.
  local width; width="${COLUMNS:-0}"; [ "$width" -gt 0 ] 2>/dev/null || width="$(tput cols 2>/dev/null || echo 100)"
  local info="target=$domain  ai=$model_line  elapsed=$((SECONDS-started))s$cost_seg"
  local iw=$((width - 4)); [ "${#info}" -gt "$iw" ] && info="${info:0:iw}"
  printf ' %s%s%s\033[K\n' "$c_cyan" "$(hbar '╭' '4tail' "$width")" "$c_reset"
  printf ' %s│%s %s\033[K\n' "$c_cyan" "$c_reset" "$info"
  local i d dw=$((width - 24))
  for i in "${!ST_LABEL[@]}"; do
    d="${ST_DETAIL[$i]:-}"
    [ "$dw" -gt 4 ] && [ "${#d}" -gt "$dw" ] && d="${d:0:dw}…"
    printf ' %s│%s  %s  %-13s %s%s%s\033[K\n' \
      "$c_cyan" "$c_reset" "$(icon "${ST_STATE[$i]}")" "${ST_LABEL[$i]}" \
      "$c_dim" "$d" "$c_reset"
  done
  local sup="${SUP_NOTE:-}"; [ -z "$sup" ] && [ "${SUPERVISOR:-0}" = 1 ] && [ "$AI_ENABLED" = 1 ] && sup="(supervisor idle)"
  local sw=$((width - 8)); [ "$sw" -gt 4 ] && [ "${#sup}" -gt "$sw" ] && sup="${sup:0:sw}…"
  printf ' %s│%s  %s🤖 %s%s\033[K\n' "$c_cyan" "$c_reset" "$c_dim" "$sup" "$c_reset"
  # Loot feed: always exactly (1 header + LOOT_ROWS) lines so PANEL_LINES stays exact.
  if [ "$LOOT_FEED" = 1 ]; then
    printf ' %s%s%s\033[K\n' "$c_cyan" "$(hbar '├' 'loot' "$width")" "$c_reset"
    local total=${#LOOT_LINES[@]} start r idx line sev rest src txt col tag body lw=$((width - 6))
    start=$(( total - LOOT_ROWS )); [ "$start" -lt 0 ] && start=0
    for (( r=0; r<LOOT_ROWS; r++ )); do
      idx=$(( start + r ))
      if [ "$idx" -lt "$total" ]; then
        line="${LOOT_LINES[$idx]}"
        sev="${line%%$'\t'*}"; rest="${line#*$'\t'}"; src="${rest%%$'\t'*}"; txt="${rest#*$'\t'}"
        col="$(loot_sev_color "$sev")"
        tag="$(printf '%s' "$sev" | tr 'a-z' 'A-Z' | cut -c1-4)"
        body="[$tag] $txt ($src)"
        [ "$lw" -gt 4 ] && [ "${#body}" -gt "$lw" ] && body="${body:0:lw}…"
        printf ' %s│%s  %s%s%s\033[K\n' "$c_cyan" "$c_reset" "$col" "$body" "$c_reset"
      else
        printf ' %s│%s\033[K\n' "$c_cyan" "$c_reset"
      fi
    done
  fi
  printf ' %s%s%s\033[K\n' "$c_cyan" "$(hbar '╰' '' "$width")" "$c_reset"
}

# render: redraw the live panel in the alternate screen, anchored at home (row 1).
# Home-anchored redraw (not relative cursor-up) means stray output or terminal
# scrolling can never desync or orphan the panel.
render() {
  [ "$TUI" = 1 ] || return 0
  loot_refresh
  spin_i=$(( (spin_i + 1) & 3 ))
  printf '\033[H'          # cursor home (top-left of the alt screen)
  _draw_panel
  printf '\033[J'          # clear anything below the panel
  panel_drawn=1
}

# tui_end: leave the alternate screen and reprint the final panel state into the
# normal scrollback, so the finished dashboard stays visible after the run.
tui_end() {
  [ "$TUI" = 1 ] || return 0
  loot_refresh
  printf '\033[?25h\033[?1049l'   # restore cursor + leave alt screen
  TUI=0
  _draw_panel                     # static dump to normal screen
}

set_stage() {
  ST_STATE[$1]="$2"; [ -n "${3+x}" ] && ST_DETAIL[$1]="$3"
  if [ "$TUI" = 1 ]; then render
  else case "$2" in done|warn|skip) log "${ST_LABEL[$1]}: ${ST_DETAIL[$1]:-$2}";; esac; fi
}

# --- Cost ledger (estimated USD spent on the LLM) ---------------------------
cost_now() { [ -n "$cost_ledger" ] && cat "$cost_ledger" 2>/dev/null || echo 0; }
add_cost() { # $1 = usd to add
  [ -n "$cost_ledger" ] || return 0
  awk -v c="$(cost_now)" -v a="$1" 'BEGIN{printf "%.6f\n", c+a}' > "$cost_ledger"
}
budget_ok() { # 0 (true) if under budget or unlimited
  [ "${LLM_BUDGET_USD:-0}" = 0 ] && return 0
  awk -v c="$(cost_now)" -v b="$LLM_BUDGET_USD" 'BEGIN{exit !(c<b)}'
}
cost_fmt() { awk -v c="$(cost_now)" 'BEGIN{printf "$%.4f", c}'; }
nlines() { [ -f "$1" ] && wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }
# Drop static-asset URLs (stdin->stdout), testing the extension on the PATH only so a
# file-ish query value (?file=app.js) is kept. Used to clean input to the slow scanners.
drop_static() { awk -v re="$STATIC_URL_RE" '{ p=tolower($0); sub(/[?#].*/,"",p); if (p !~ re) print }'; }

# Find the installed nuclei template store (config -> common paths). Defined early
# so `doctor` (which runs before the pipeline helpers) can call it too.
locate_nuclei_templates() {
  [ -n "$NUCLEI_TEMPLATES_DIR" ] && { [ -d "$NUCLEI_TEMPLATES_DIR" ] && printf '%s\n' "$NUCLEI_TEMPLATES_DIR"; return; }
  local d; d="$(jq -r '."nuclei-templates-directory" // empty' "$HOME/.config/nuclei/.templates-config.json" 2>/dev/null)"
  [ -n "$d" ] && [ -d "$d" ] && { printf '%s\n' "$d"; return; }
  for d in "$HOME/nuclei-templates" "$HOME/.local/nuclei-templates" /root/nuclei-templates /root/.local/nuclei-templates; do
    [ -d "$d" ] && { printf '%s\n' "$d"; return; }
  done
}

# --- Blueprints -------------------------------------------------------------
BLUEPRINT_NAME=""
if [ -z "$BLUEPRINTS_DIR" ]; then
  _sd="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
  [ -d "$_sd/blueprints" ] && BLUEPRINTS_DIR="$_sd/blueprints"
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
kill_children() { local p; for p in $(jobs -p 2>/dev/null); do kill "$p" 2>/dev/null; pkill -P "$p" 2>/dev/null; done; }
cleanup() { [ "$TUI" = 1 ] && printf '\033[?25h\033[?1049l'; }   # restore cursor + leave alt screen (abnormal exit)
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

# ---------------------------------------------------------------------------
# LLM helper: ai_call <model> <max_tokens> <system> <user> -> prints text.
# Retry+backoff per model; if the primary model keeps failing, fall through to
# LLM_FALLBACK_MODELS in order (smart model switching for reliability).
# ---------------------------------------------------------------------------
ai_call() {
  local model="$1" maxtok="$2" system="$3" user="$4"
  local candidates m payload response text attempt delay
  candidates="$model"; [ -n "$LLM_FALLBACK_MODELS" ] && candidates="$model,$LLM_FALLBACK_MODELS"
  IFS=',' read -ra _models <<< "$candidates"
  for m in "${_models[@]}"; do
    m="$(printf '%s' "$m" | tr -d '[:space:]')"; [ -z "$m" ] && continue
    payload="$(jq -n --arg model "$m" --arg sys "$system" --arg usr "$user" \
      --argjson max "$maxtok" --argjson temp "$LLM_TEMPERATURE" \
      '{model:$model, max_tokens:$max, temperature:$temp,
        messages:[{role:"system",content:$sys},{role:"user",content:$usr}]}')" || continue
    attempt=0; delay=2
    while :; do
      attempt=$((attempt + 1))
      local http_code curl_rc
      response="$(curl -sS --max-time "$LLM_TIMEOUT" -w $'\n__HTTP__%{http_code}' \
        "$LLM_BASE_URL/chat/completions" \
        -H "content-type: application/json" -H "authorization: Bearer $LLM_API_KEY" \
        -d "$payload" 2>>"$llm_log")"; curl_rc=$?
      http_code="$(printf '%s' "$response" | sed -n 's/.*__HTTP__//p' | tail -1)"
      response="$(printf '%s' "$response" | sed 's/__HTTP__[0-9]*$//')"
      if [ "$curl_rc" != 0 ] || [ -z "$response" ]; then
        echo "[fail] model=$m curl_rc=$curl_rc http=${http_code:-none} (timeout/connection/empty)" >>"$llm_log"
      elif echo "$response" | jq -e '.error' >/dev/null 2>&1; then
        echo "[fail] model=$m http=${http_code:-?}: $(echo "$response" | jq -r '.error.message // .error' 2>/dev/null)" >>"$llm_log"
      fi
      if [ "$curl_rc" = 0 ] && [ -n "$response" ] && ! echo "$response" | jq -e '.error' >/dev/null 2>&1; then
        # Reasoning models (GLM/DeepSeek) may leave .content empty and put text in
        # .reasoning_content, especially if truncated (finish_reason=length).
        text="$(echo "$response" | jq -r '.choices[0].message.content // empty' 2>/dev/null)"
        [ -z "$text" ] && text="$(echo "$response" | jq -r '.choices[0].message.reasoning_content // empty' 2>/dev/null)"
        if [ -z "$text" ] && [ "$(echo "$response" | jq -r '.choices[0].finish_reason // empty' 2>/dev/null)" = "length" ]; then
          echo "[warn] model=$m hit token limit with empty content - raise LLM_MAX_TOKENS_PLAN/TRIAGE" >>"$llm_log"
        fi
        if [ -n "$text" ]; then
          # accrue estimated cost from token usage
          local uin uout ucost
          uin="$(echo "$response"  | jq -r '.usage.prompt_tokens // 0' 2>/dev/null)"
          uout="$(echo "$response" | jq -r '.usage.completion_tokens // 0' 2>/dev/null)"
          ucost="$(awk -v i="$uin" -v o="$uout" -v pi="$LLM_PRICE_IN" -v po="$LLM_PRICE_OUT" \
                   'BEGIN{printf "%.6f",(i*pi+o*po)/1000000}')"
          add_cost "$ucost"
          echo "[ok] model=$m tokens_in=$uin tokens_out=$uout cost=\$$ucost total=$(cost_now)" >>"$llm_log"
          printf '%s' "$text"; return 0
        fi
      fi
      if [ "$attempt" -gt "$LLM_RETRIES" ]; then
        echo "[fail] model=$m: $(echo "$response" | jq -r '.error.message // .error // "empty response"' 2>/dev/null)" >>"$llm_log"
        break   # give up on this model, try the next candidate
      fi
      sleep "$delay"; delay=$((delay * 2))
    done
  done
  return 1
}

# Background an AI call while spinning the given stage; result -> outfile.
#   run_ai_stage <idx> <model> <max_tokens> <system> <user> <outfile>
run_ai_stage() {
  local idx="$1" model="$2" maxtok="$3" sys="$4" usr="$5" outfile="$6"
  set_stage "$idx" running "querying ${model##*/} · 0s"
  ( ai_call "$model" "$maxtok" "$sys" "$usr" >"$outfile" 2>>"$llm_log" ) & local pid=$!
  local s=$SECONDS
  while kill -0 "$pid" 2>/dev/null; do
    ST_DETAIL[$idx]="querying ${model##*/} · $((SECONDS-s))s"
    [ "$TUI" = 1 ] && render; sleep 0.25
  done
  wait "$pid"; return $?
}

# ===========================================================================
# DOCTOR - health checks (tools, wordlists, LLM connectivity) then exit
# ===========================================================================
DR_FAIL=0; DR_WARN=0
dr_pass(){ printf '  %s[PASS]%s %s\n' "$c_green"  "$c_reset" "$*"; }
dr_warn(){ printf '  %s[WARN]%s %s\n' "$c_yellow" "$c_reset" "$*"; DR_WARN=$((DR_WARN+1)); }
dr_fail(){ printf '  %s[FAIL]%s %s\n' "$c_red"    "$c_reset" "$*"; DR_FAIL=$((DR_FAIL+1)); }
dr_head(){ printf '\n%s== %s ==%s\n' "$c_cyan" "$*" "$c_reset"; }

# Minimal, dependency-light LLM ping: validates a model id works on this account.
llm_ping() {
  local m="$1" body resp code t json msg
  body="$(jq -n --arg model "$m" \
    '{model:$model, max_tokens:16, messages:[{role:"user",content:"reply with: ok"}]}' 2>/dev/null)"
  resp="$(curl -sS -m "$LLM_TIMEOUT" -w $'\n%{http_code} %{time_total}' \
    -H "content-type: application/json" -H "authorization: Bearer $LLM_API_KEY" \
    -d "$body" "$LLM_BASE_URL/chat/completions" 2>/dev/null)"
  code="$(printf '%s' "$resp" | tail -n1 | awk '{print $1}')"
  t="$(printf '%s'   "$resp" | tail -n1 | awk '{print $2}')"
  json="$(printf '%s' "$resp" | sed '$d')"
  msg="$(printf '%s' "$json" | jq -r '.error.message // .error // empty' 2>/dev/null)"
  if [ "$code" = 200 ] && printf '%s' "$json" | jq -e '.choices[0].message' >/dev/null 2>&1; then
    dr_pass "model '$m' reachable (${t}s)"
  elif [ -z "$code" ] || [ "$code" = 000 ]; then
    dr_fail "cannot REACH endpoint for '$m' - network/DNS/egress problem (not an auth issue)"
  elif [ "$code" = 401 ] || [ "$code" = 403 ]; then
    dr_fail "endpoint reachable, but API KEY REJECTED for '$m' (http $code)${msg:+ - $msg}"
  elif [ "$code" = 404 ]; then
    dr_fail "endpoint reachable, key OK, but MODEL id '$m' not found (http 404)${msg:+ - $msg}"
  else
    dr_fail "model '$m' NOT usable (http ${code:-?})${msg:+ - $msg}"
  fi
}

run_doctor() {
  printf '%s4tail doctor%s - environment health check\n' "$c_cyan" "$c_reset"

  dr_head "Required tools"
  local t
  for t in subfinder httpx nuclei; do
    if have "$t"; then dr_pass "$t found ($(command -v "$t"))"; else dr_fail "$t MISSING (install from projectdiscovery.io)"; fi
  done
  if have nuclei; then
    local tpl; tpl="$(locate_nuclei_templates)"
    if [ -n "$tpl" ]; then
      local nt; nt="$(grep -rhoE '^[[:space:]]*tags:' "$tpl" 2>/dev/null | wc -l | tr -d ' ')"
      dr_pass "nuclei templates: $tpl (~$nt tagged templates)"
    else
      dr_warn "nuclei templates not found - run 'nuclei -update-templates' (or UPDATE_TEMPLATES=1)"
    fi
  fi

  dr_head "Optional tools"
  for t in ffuf curl jq anew dnsx; do
    if have "$t"; then dr_pass "$t found"; else dr_warn "$t not found ($([ "$t" = ffuf ] && echo 'fuzzing skipped' || echo 'feature degraded'))"; fi
  done

  dr_head "Active funnel tools (-C) & JS/params (-j)"
  for t in katana gau waybackurls gf dalfox kxss Gxss arjun subjs sqlmap; do
    if have "$t"; then dr_pass "$t found"; else dr_warn "$t not found (that specialist is skipped)"; fi
  done
  if have interactsh-client; then dr_pass "interactsh-client found (OAST ready; enable with OAST=1)"
  else dr_warn "interactsh-client not found (OAST blind-bug confirmation disabled)"; fi

  dr_head "Wordlists"
  if [ -n "$SECLISTS_DIR" ]; then
    dr_pass "SecLists: $SECLISTS_DIR"
    local rel
    for rel in Discovery/Web-Content/common.txt Discovery/Web-Content/CMS/wordpress.fuzz.txt \
               Discovery/Web-Content/api/api-endpoints.txt Discovery/Web-Content/JavaServlets-Common.fuzz.txt; do
      if [ -f "$SECLISTS_DIR/$rel" ]; then dr_pass "  $rel"; else dr_warn "  missing: $rel"; fi
    done
  else
    dr_warn "SecLists not found (apt install seclists, or set SECLISTS_DIR)"
  fi
  if [ -n "$WORDLIST" ] && [ -f "$WORDLIST" ]; then
    case "$WORDLIST" in
      *fuzz.txt) dr_pass "Base list: $WORDLIST (Bo0oM juicy list, $(wc -l <"$WORDLIST" 2>/dev/null) lines)";;
      *)         dr_warn "Base list: $WORDLIST (not Bo0oM fuzz.txt; fine, but that list finds more)";;
    esac
    [ -n "$API_ENDPOINTS_EXTRA" ] && dr_pass "API list: $API_ENDPOINTS_EXTRA"
  else
    dr_warn "No base wordlist found (provide -w, or FETCH_FUZZTXT=1 to download Bo0oM/fuzz.txt)"
  fi

  dr_head "AI / LLM (Together AI or compatible)"
  if [ -z "$LLM_API_KEY" ]; then
    dr_warn "No API key set (TOGETHER_API_KEY) - AI steps will be skipped; scan still works with defaults"
  elif ! have curl || ! have jq; then
    dr_fail "curl and jq are required for AI steps"
  else
    dr_pass "API key present (length ${#LLM_API_KEY}, ends …${LLM_API_KEY: -4}); endpoint: $LLM_BASE_URL"
    [ "${#LLM_API_KEY}" -lt 40 ] && dr_warn "key looks SHORT (${#LLM_API_KEY} chars) - Together keys are ~64 hex chars; it may be truncated/incomplete"
    printf '  %sroutes%s plan=%s  triage=%s%s\n' "$c_dim" "$c_reset" \
      "$LLM_MODEL_PLAN" "$LLM_MODEL_TRIAGE" "${LLM_FALLBACK_MODELS:+  fallbacks=$LLM_FALLBACK_MODELS}"
    if [ "${LLM_BUDGET_USD:-0}" != 0 ]; then
      dr_pass "credit budget: \$$LLM_BUDGET_USD (prices \$$LLM_PRICE_IN in / \$$LLM_PRICE_OUT out per 1M tok - set to your model's real price)"
    else
      dr_warn "no credit budget set (LLM_BUDGET_USD=0 = unlimited); use -b 2 to cap spend"
    fi
    # Ping each unique configured model
    local seen="" m
    for m in "$LLM_MODEL_PLAN" "$LLM_MODEL_TRIAGE" ${LLM_FALLBACK_MODELS//,/ }; do
      [ -z "$m" ] && continue
      case ",$seen," in *",$m,"*) continue;; esac
      seen="$seen,$m"
      llm_ping "$m"
    done
  fi

  dr_head "Summary"
  if [ "$DR_FAIL" -gt 0 ]; then
    printf '  %s%d failed%s, %d warnings - fix the failures before running.\n' "$c_red" "$DR_FAIL" "$c_reset" "$DR_WARN"
    return 1
  elif [ "$DR_WARN" -gt 0 ]; then
    printf '  %sReady%s with %d warning(s) - 4tail will run (some features degraded).\n' "$c_green" "$c_reset" "$DR_WARN"
    return 0
  else
    printf '  %sAll good - 4tail is fully operational.%s\n' "$c_green" "$c_reset"
    return 0
  fi
}

if [ "$DOCTOR" = 1 ]; then run_doctor; exit $?; fi

# Enter the alternate screen buffer (like htop/less): a dedicated viewport the panel
# owns and redraws from home each frame, so nothing can scroll-duplicate or orphan it.
if [ "$TUI" = 1 ]; then
  printf '\033[?1049h\033[?25l\033[2J\033[H'   # alt screen, hide cursor, clear, home
  render
fi

# Bring the OOB listener up now so it's live for the whole run (callbacks can land
# at any point once we start injecting payloads in the active funnel).
oast_start

# ===========================================================================
# PIPELINE
# ===========================================================================

# resume helper: was this stage already completed?
done_marker() { [ "$RESUME" = 1 ] && [ -f "$OUTDIR/.done_$1" ]; }

# Step 1: Subdomains
if done_marker subs && [ -s "$subdomains_file" ]; then
  set_stage $S_SUBS done "$(wc -l <"$subdomains_file") subs (resumed)"
else
  run_stage $S_SUBS "$subdomains_file" " subs" subfinder -silent -d "$domain" -o "$subdomains_file"
  # subfinder enumerates subdomains OF the target but not the target host itself; always
  # include it (and www.) so a specific host like testasp.vulnweb.com is actually probed.
  { printf '%s\n' "$domain" "www.$domain"; cat "$subdomains_file" 2>/dev/null; } | sort -u > "$subdomains_file.tmp" \
    && mv "$subdomains_file.tmp" "$subdomains_file"
  touch "$OUTDIR/.done_subs"
fi
sub_count=$(wc -l < "$subdomains_file" 2>/dev/null || echo 0)
if [ "$sub_count" -eq 0 ]; then
  set_stage $S_SUBS warn "none found"; [ "$TUI" = 1 ] || warn "No subdomains; stopping."; exit 0
fi
set_stage $S_SUBS done "$sub_count subs$(done_marker subs && echo ' (resumed)')"

# Step 2: Live hosts + tech detection
if done_marker httpx && [ -s "$httpx_json" ]; then
  set_stage $S_LIVE done "resumed"
else
  # Optional: resolve + drop wildcard DNS with dnsx (removes bogus subdomains that
  # all resolve to a catch-all record - a huge source of wasted work on big targets).
  probe_input="$subdomains_file"
  if [ "$USE_DNSX" = 1 ] && have dnsx; then
    resolved_file="$OUTDIR/resolved.txt"
    set_stage $S_LIVE running "resolving (dnsx, wildcard filter)"
    dnsx -silent -l "$subdomains_file" -wd "$domain" -o "$resolved_file" 2>>"$llm_log" || true
    [ -s "$resolved_file" ] && probe_input="$resolved_file"
  fi
  run_stage $S_LIVE "$httpx_json" " live" \
    httpx -silent -json -tech-detect -status-code -title -web-server -ip -cname \
          ${HTTPX_NET[@]+"${HTTPX_NET[@]}"} \
          -threads "$HTTPX_THREADS" -l "$probe_input" -o "$httpx_json"
  touch "$OUTDIR/.done_httpx"
fi
if [ -s "$httpx_json" ]; then jq -r '.url' "$httpx_json" 2>/dev/null | sort -u > "$alive_file"; else : > "$alive_file"; fi
alive_count=$(wc -l < "$alive_file" 2>/dev/null || echo 0)
if [ "$alive_count" -eq 0 ]; then
  set_stage $S_LIVE warn "none live"; [ "$TUI" = 1 ] || warn "No live hosts; stopping."; exit 0
fi
set_stage $S_LIVE done "$alive_count live$(done_marker httpx && echo ' (resumed)')"

# Aggregated, cost-frugal brief for the AI
{
  echo "== technologies (count) =="
  jq -r '(.tech // [])[]' "$httpx_json" 2>/dev/null | sort | uniq -c | sort -rn | head -40
  echo "== web servers (count) =="
  jq -r '.webserver // empty' "$httpx_json" 2>/dev/null | sort | uniq -c | sort -rn | head -15
  echo "== status codes (count) =="
  jq -r '.status_code // empty' "$httpx_json" 2>/dev/null | sort | uniq -c | sort -rn
  echo "== notable hosts =="
  jq -r '.url' "$httpx_json" 2>/dev/null \
    | grep -iE 'admin|login|portal|api|dev|staging|test|git|jenkins|grafana|kibana|vpn' \
    | sort -u | head -25
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
    case "$lc" in *php/4*|*php/5*)                 score=$((score+3)); ev="$ev,EOL-PHP";; esac
    case "$lc" in *frontpage*)                     score=$((score+2)); ev="$ev,FrontPage";; esac
    case "$lc" in *tinymce*)                       score=$((score+2)); ev="$ev,TinyMCE";; esac
    case "$lc" in *coldfusion*)                    score=$((score+3)); ev="$ev,ColdFusion";; esac
    case "$lc" in *jquery*)                        score=$((score+1)); ev="$ev,jQuery";; esac
    case "$lc" in *bootstrap*)                     score=$((score+1)); ev="$ev,Bootstrap";; esac
    case "$lc" in *wordpress*|*drupal*|*joomla*)   score=$((score+1)); ev="$ev,legacy-CMS";; esac
    case "$lc" in *asp.net*|*microsoft*)           score=$((score+1)); ev="$ev,ASP.NET";; esac
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

# Step 3: AI scan plan (with allowlist guardrail)
NUCLEI_TAG_ALLOWLIST="cves,cve,exposures,exposure,misconfiguration,misconfig,tech,\
default-login,takeover,subdomain-takeover,panel,login,exposed-panels,config,\
backup,files,logs,debug,git,svn,env,sqli,xss,ssrf,lfi,rce,injection,auth-bypass,\
wordpress,wp-plugin,joomla,drupal,magento,laravel,django,spring,struts,\
apache,nginx,tomcat,iis,php,jira,confluence,jenkins,gitlab,grafana,kibana,\
elasticsearch,kubernetes,docker,aws,azure,gcp,ssl,tls,cors,headers,\
oauth,jwt,api,graphql,swagger,firebase,s3,redis,mongodb,mysql,postgres"
# Curated base kept separate from the runtime-widened list: explicit JSON tag choices
# are checked against the (wide) NUCLEI_TAG_ALLOWLIST, but loose prose salvage is checked
# against this strict base only, so reasoning words (target/dreamweaver/eol/...) can't leak.
NUCLEI_TAG_ALLOWLIST_BASE="$NUCLEI_TAG_ALLOWLIST"
sanitize_tags() {  # [allowlist]  (reads tags on stdin; defaults to the widened allowlist)
  local allow="${1:-$NUCLEI_TAG_ALLOWLIST}"
  tr ',[:space:]' '\n\n' | tr 'A-Z' 'a-z' | grep -oE '[a-z0-9._-]+' \
    | while read -r t; do
        case ",${allow//[[:space:]]/}," in *",$t,"*) echo "$t";; esac
      done | awk '!seen[$0]++' | paste -sd, -
}
# Index the REAL category tags present in the installed templates, dropping the
# thousands of per-CVE id tags (cve-YYYY-N) so we keep the useful ~few-hundred
# (iis, weblogic, rce, lfi, fortinet, ...). Then widen the tag allowlist with them,
# so the AI plan can select any tag the user's template store actually supports -
# grounded in what's installed, never hallucinated.
build_nuclei_tag_index() {
  [ "$NUCLEI_TAG_INDEX" = 1 ] && have nuclei && have grep || return 0
  [ -s "$nuclei_tag_index" ] && return 0   # cached (e.g. resume)
  local tpl; tpl="$(locate_nuclei_templates)"
  [ -n "$tpl" ] || return 0
  grep -rhoE '^[[:space:]]*tags:[[:space:]]*.*' "$tpl" 2>/dev/null \
    | sed -E 's/^[[:space:]]*tags:[[:space:]]*//; s/["'"'"']//g' \
    | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | tr 'A-Z' 'a-z' \
    | grep -E '^[a-z0-9._-]{2,40}$' \
    | grep -vE '^cve-[0-9]{4}-[0-9]+$|^[0-9]{4}$' \
    | sort -u > "$nuclei_tag_index" 2>/dev/null || true
  if [ -s "$nuclei_tag_index" ]; then
    NUCLEI_TAG_ALLOWLIST="$NUCLEI_TAG_ALLOWLIST,$(paste -sd, "$nuclei_tag_index")"
  fi
}
# Seed a built-in tech -> SecLists wordlist map. Every path below was verified to
# exist in SecLists (github.com/danielmiessler/SecLists). Paths are still
# existence-checked at fuzz time, so any that are absent in a given SecLists
# version are simply skipped. This makes fuzzing tech-aware even with no API key.
#
# What each list is FOR (per detected technology):
#   WordPress  wordpress.fuzz.txt  -> core WP paths (wp-login, wp-admin, xmlrpc…)
#              wp-plugins.fuzz.txt -> ~14k plugin dirs (vuln plugin discovery)
#              wp-themes.fuzz.txt  -> theme dirs (theme-specific bugs / LFI)
#   Joomla     joomla-plugins/themes.fuzz.txt -> extensions & templates
#   Drupal     Drupal.txt / drupal-themes.fuzz.txt -> modules, admin, changelog
#   Magento    sitemap-magento.txt -> admin, downloader, RCE-prone endpoints
#   Umbraco    CMS/Umbraco.fuzz.txt -> .NET CMS admin/config surface
#   ColdFusion coldfusion.txt + CMS/ColdFusion.fuzz.txt -> CFIDE, admin, AdminAPI
#   PHP        (no heavy list) -> covered by the base list + .php/.phtml extensions
#   Java/JSP   JavaServlets-Common.fuzz.txt -> servlets, invoker, struts actions
#   (Tomcat/   vulnerability-scan_j2ee-websites_WEB-INF.txt -> WEB-INF, web.xml,
#    Spring/    class/jar leakage (source & credential disclosure)
#    Struts)
#   IIS/ASP    Microsoft-Frontpage.txt -> FrontPage/IIS extensions & _vti_ dirs
#   API/REST   api/api-endpoints.txt, api/objects.txt, api/actions.txt,
#   /Swagger   api/api-seen-in-wild.txt, common-api-endpoints-mazen160.txt
#              -> REST resources, verbs, versioned routes, doc endpoints
#   GraphQL    graphql.txt -> /graphql, /graphiql, playground, introspection
#   OAuth/OIDC oauth-oidc-scopes.txt -> auth endpoints, well-known, scopes
#   git/svn    versioning_metafiles.txt -> .git/.svn/.hg metadata (source leak)
#   Vault      hashicorp-vault.txt / hashicorp-consul-api.txt -> secrets APIs
#   SAP        CMS/SAP.fuzz.txt / SAP-NetWeaver.txt -> SAP web surface
seed_static_tech_map() {
  : > "$tech_map_file"
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    printf '%s\n' "$line" >> "$tech_map_file"
  done <<'STATIC'
wordpress	Discovery/Web-Content/CMS/wordpress.fuzz.txt
wordpress	Discovery/Web-Content/CMS/wp-plugins.fuzz.txt
wordpress	Discovery/Web-Content/CMS/wp-themes.fuzz.txt
joomla	Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt
joomla	Discovery/Web-Content/CMS/joomla-themes.fuzz.txt
drupal	Discovery/Web-Content/CMS/Drupal.txt
drupal	Discovery/Web-Content/CMS/drupal-themes.fuzz.txt
magento	Discovery/Web-Content/CMS/sitemap-magento.txt
umbraco	Discovery/Web-Content/CMS/Umbraco.fuzz.txt
coldfusion	Discovery/Web-Content/coldfusion.txt
coldfusion	Discovery/Web-Content/CMS/ColdFusion.fuzz.txt
java	Discovery/Web-Content/JavaServlets-Common.fuzz.txt
java	Discovery/Web-Content/vulnerability-scan_j2ee-websites_WEB-INF.txt
tomcat	Discovery/Web-Content/JavaServlets-Common.fuzz.txt
tomcat	Discovery/Web-Content/vulnerability-scan_j2ee-websites_WEB-INF.txt
spring	Discovery/Web-Content/JavaServlets-Common.fuzz.txt
struts	Discovery/Web-Content/JavaServlets-Common.fuzz.txt
iis	Discovery/Web-Content/Microsoft-Frontpage.txt
asp	Discovery/Web-Content/Microsoft-Frontpage.txt
frontpage	Discovery/Web-Content/Microsoft-Frontpage.txt
api	Discovery/Web-Content/api/api-endpoints.txt
api	Discovery/Web-Content/api/objects.txt
api	Discovery/Web-Content/api/actions.txt
api	Discovery/Web-Content/common-api-endpoints-mazen160.txt
swagger	Discovery/Web-Content/api/api-endpoints.txt
swagger	Discovery/Web-Content/api/api-seen-in-wild.txt
openapi	Discovery/Web-Content/api/api-endpoints.txt
rest	Discovery/Web-Content/api/api-endpoints.txt
graphql	Discovery/Web-Content/graphql.txt
oauth	Discovery/Web-Content/oauth-oidc-scopes.txt
oidc	Discovery/Web-Content/oauth-oidc-scopes.txt
git	Discovery/Web-Content/versioning_metafiles.txt
svn	Discovery/Web-Content/versioning_metafiles.txt
vault	Discovery/Web-Content/hashicorp-vault.txt
consul	Discovery/Web-Content/hashicorp-consul-api.txt
sap	Discovery/Web-Content/CMS/SAP.fuzz.txt
sap	Discovery/Web-Content/SAP-NetWeaver.txt
STATIC
}
# Seed the static map, but on resume keep a prior map (it may hold AI additions).
if [ "$RESUME" = 1 ] && [ -s "$tech_map_file" ]; then :
elif [ -n "$SECLISTS_DIR" ]; then seed_static_tech_map
else : > "$tech_map_file"; fi

# Ground the tag allowlist in the user's actually-installed templates before planning.
build_nuclei_tag_index

nuclei_tags="$DEFAULT_NUCLEI_TAGS"
if [ "$RESUME" = 1 ] && [ -s "$OUTDIR/ai_scan_plan.txt" ]; then
  nuclei_tags="$(cat "$OUTDIR/ai_scan_plan.txt")"
  set_stage $S_PLAN done "$nuclei_tags (resumed)"
elif [ "$AI_ENABLED" = "1" ] && ! budget_ok; then
  set_stage $S_PLAN skip "budget reached ($(cost_fmt)), using defaults"
elif [ "$AI_ENABLED" = "1" ] && [ -s "$tech_brief" ]; then
  sys_plan='You assist AUTHORIZED bug-bounty recon. Given an aggregated brief of the
technologies, servers and notable paths on live hosts, produce a scan plan.
Reply with ONLY a JSON object (no prose, no code fences) with exactly two keys:
  "nuclei_tags": array of 4-12 lowercase nuclei tags (always include cves, exposures,
     misconfiguration, plus tags matched to the observed stack),
  "wordlists": object mapping each relevant lowercase technology name to an array of
     content-discovery wordlist file paths RELATIVE to the SecLists root
     (e.g. "Discovery/Web-Content/CMS/wordpress.fuzz.txt"). Use only real, well-known
     SecLists paths; keep 1-3 paths per technology; omit technologies you are unsure of.
     Prefer small, tech-SPECIFIC lists (CMS/*, api/*, *.fuzz.txt). Do NOT use big generic
     lists (raft-*, big.txt, directory-list-*, combined_*, dirbuster) - those are excluded.'
  plan_out="$(mktemp)"
  run_ai_stage $S_PLAN "$LLM_MODEL_PLAN" "$LLM_MAX_TOKENS_PLAN" "$sys_plan" "Target: $domain
Live hosts: $alive_count
SecLists root: ${SECLISTS_DIR:-<not installed>}

$(head -c 12000 "$tech_brief")" "$plan_out"

  # Reasoning models (GLM/DeepSeek) often wrap JSON in ``` fences or prepend
  # "thinking". Prefer a {...} span that actually contains nuclei_tags, else any
  # {...}, else the whole reply (sanitize_tags salvages allowlisted words from prose).
  flat="$(tr -d '\r' < "$plan_out" | tr '\n' ' ')"
  plan_json="$(printf '%s' "$flat" | grep -oE '\{[^{}]*nuclei_tags.*\}' | head -1)"
  [ -z "$plan_json" ] && plan_json="$(printf '%s' "$flat" | grep -oE '\{.*\}' | head -1)"
  [ -z "$plan_json" ] && plan_json="$(cat "$plan_out")"

  # --- parse nuclei tags ---
  # Explicit JSON tags are trusted against the WIDE allowlist (so the AI can pick real
  # installed tags like weblogic). If JSON is absent, salvage from prose against the
  # STRICT base only, so reasoning words (target/dreamweaver/eol/json/legacy) can't leak in.
  ai_tags="$(printf '%s' "$plan_json" | jq -r '.nuclei_tags[]?' 2>/dev/null | paste -sd, -)"
  if [ -n "$ai_tags" ]; then ai_extra="$(printf '%s' "$ai_tags" | sanitize_tags)"
  else ai_extra="$(cat "$plan_out" | sanitize_tags "$NUCLEI_TAG_ALLOWLIST_BASE")"; fi
  # AI tags are ADDITIVE on top of the strong defaults, so a thin/unparseable reply
  # degrades to good defaults instead of discarding the core (cves/exposures/...).
  clean_plan="$(printf '%s,%s' "$DEFAULT_NUCLEI_TAGS" "$ai_extra" | sanitize_tags)"

  # --- parse wordlist map (append to tech map; heavy generic lists filtered out,
  #     existence checked at fuzz time) ---
  if [ -n "$SECLISTS_DIR" ]; then
    printf '%s' "$plan_json" \
       | jq -r '.wordlists // {} | to_entries[]? | (.key|ascii_downcase) as $k | .value[]? | "\($k)\t\(.)"' 2>/dev/null \
       | grep -viE 'raft-|big\.txt|directory-list|combined_|dirbuster|/all\.txt' \
       >> "$tech_map_file" || true
  fi
  rm -f "$plan_out"

  nuclei_tags="${clean_plan:-$DEFAULT_NUCLEI_TAGS}"
  printf '%s\n' "$nuclei_tags" > "$OUTDIR/ai_scan_plan.txt"
  if [ -n "$ai_extra" ]; then set_stage $S_PLAN done "$nuclei_tags"
  else set_stage $S_PLAN done "$nuclei_tags (defaults; AI added none)"; fi
else
  set_stage $S_PLAN skip "AI off (defaults)"
fi

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
  local t; t="$(printf '%s' "$1" | tr 'A-Z' 'a-z')"
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
      while IFS=$'\t' read -r key rel; do
        [ -z "$key" ] && continue
        case "$rel" in *raft-*|*big.txt|*directory-list*|*combined_*|*dirbuster*|*/all.txt) continue ;; esac
        case "$t" in *"$key"*) [ -f "$SECLISTS_DIR/$rel" ] && printf '%s\n' "$SECLISTS_DIR/$rel" ;; esac
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
      *php*)                                   tech="$tech,php,phtml,phps" ;;
      *asp*|*iis*|*aspnet*|*.net*)             tech="$tech,aspx,asp,ashx,config,cs" ;;
      *java*|*jsp*|*tomcat*|*spring*|*struts*) tech="$tech,jsp,jspx,war,properties,class" ;;
      *coldfusion*|*cfm*)                      tech="$tech,cfm,cfc" ;;
      *python*|*django*|*flask*)               tech="$tech,py,pyc" ;;
      *ruby*|*rails*)                          tech="$tech,rb,erb" ;;
      *node*|*express*|*javascript*)           tech="$tech,js,map,env" ;;
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
elif ! have ffuf; then
  set_stage $S_FUZZ skip "ffuf not installed"
elif [ "$fuzz_possible" != 1 ]; then
  set_stage $S_FUZZ skip "no wordlist / SecLists"
elif [ "$RESUME" = 1 ] && [ -f "$OUTDIR/.done_fuzz" ]; then
  set_stage $S_FUZZ done "$(grep -c . "$fuzz_plan_file" 2>/dev/null || echo 0) hosts (resumed)"
else
  set_stage $S_FUZZ running "indexing SecLists"
  build_seclists_index   # index real SecLists files once so tech matching is grounded in what's installed
  set_stage $S_FUZZ running "0 hosts ($(nlines "${seclists_index:-/dev/null}") lists indexed)"
  [ "$RESUME" = 1 ] || : > "$fuzz_plan_file"   # keep prior progress when resuming
  if [ "$DEDUPE_ORIGINS" = 1 ] && [ -s "$httpx_json" ]; then
    # One representative per (origin, response signature): origin = cname or first IP;
    # signature = status|content_length|title. Kills near-identical pages and shared
    # origins so we don't fuzz the same thing hundreds of times.
    hosts_tsv="$(jq -r '
        ((.cname // (.a[0]? // .host)) | tostring) as $origin
        | [ (.url),
            ((.tech // []) | map(ascii_downcase) | join(",")),
            ($origin + "|" + (.status_code|tostring) + "|" + ((.content_length//0)|tostring) + "|" + (.title//"")) ]
        | @tsv' "$httpx_json" 2>/dev/null \
      | awk -F'\t' '!seen[$3]++ {print $1"\t"$2}' | sort -u)"
  else
    hosts_tsv="$(jq -r '[.url, ((.tech // []) | map(ascii_downcase) | join(","))] | @tsv' \
                   "$httpx_json" 2>/dev/null | sort -u)"
  fi
  [ -n "$hosts_tsv" ] || hosts_tsv="$(sed 's/$/\t/' "$alive_file")"
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
      rm -f "$fuzz_dir/.wl_${sf}.txt"; unset 'JOB[$p]'; done_count=$((done_count + 1))
    done
  }
  fuzz_status() {
    ST_DETAIL[$S_FUZZ]="run:$(fuzz_running)/$p_eff done:$done_count/$cap${skipped_cdn:+ cdn:$skipped_cdn}${resumed:+ res:$resumed}$([ "$backoff" = 1 ] && echo ' ⚠backoff')"
  }

  while IFS=$'\t' read -r url techs; do
    [ -z "$url" ] && continue
    safe="$(printf '%s' "$url" | tr -c 'A-Za-z0-9._-' '_')"
    if [ "$RESUME" = 1 ] && [ -f "$fuzz_dir/${safe}.json" ]; then resumed=$((resumed + 1)); continue; fi
    if [ "$SKIP_CDN_FUZZ" = 1 ] && printf '%s' "$techs" | grep -qiE "$CDN_RE"; then
      skipped_cdn=$((skipped_cdn + 1)); continue
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
    cat "${wls[@]}" 2>/dev/null | sort -u | head -n "$MAX_FUZZ_WORDS" > "$combined"
    names="$(printf '%s\n' "${wls[@]}" | sed 's#.*/##' | paste -sd+ -)"
    ext_flag="$(build_ext_flag "$techs")"
    printf '%s\t%s\t(%s words) exts:[%s]\n' "$url" "$names" "$(wc -l < "$combined")" "$ext_flag" >> "$fuzz_plan_file"
    # -ac auto-calibration filters soft-404 / catch-all responses (huge quality boost:
    # without it a host that answers 200 to everything floods the results with junk).
    ffuf_args=(-u "$url/FUZZ" -w "$combined" -ac -mc 200,204,301,302,307,401,403,405,500
               -of json -o "$fuzz_dir/${safe}.json" -s)
    [ "${#FFUF_NET[@]}" -gt 0 ] && ffuf_args+=("${FFUF_NET[@]}")
    [ -n "$ext_flag" ] && ffuf_args+=(-e "$ext_flag")
    [ "$FFUF_RATE" -gt 0 ] 2>/dev/null && ffuf_args+=(-rate "$FFUF_RATE")
    [ "$FUZZ_MAX_TIME" -gt 0 ] 2>/dev/null && ffuf_args+=(-maxtime "$FUZZ_MAX_TIME")  # stop a slow host after N s
    [ "$TUI" = 1 ] || log "Fuzzing $fuzzed/$cap: $url"
    ffuf "${ffuf_args[@]}" >/dev/null 2>>"$llm_log" & JOB[$!]="$safe"
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
  # 1) gather JS URLs (subjs/getJS if present, else scrape roots)
  : > "$js_urls_file"
  scan_targets="$(sort -u "$alive_file" | head -n "$JS_HOSTS")"
  if have subjs; then
    printf '%s\n' "$scan_targets" | subjs 2>/dev/null | sort -u > "$js_urls_file"
  elif have getJS; then
    printf '%s\n' "$scan_targets" | while read -r u; do getJS --url "$u" 2>/dev/null; done | sort -u > "$js_urls_file"
  else
    printf '%s\n' "$scan_targets" | while read -r u; do
      curl -s -L --max-time 15 ${CURL_NET[@]+"${CURL_NET[@]}"} "$u" 2>/dev/null \
        | grep -oiE 'src="[^"]+\.js' | sed -E 's/^src="//' \
        | while read -r j; do case "$j" in http*) echo "$j";; /*) echo "${u%/}$j";; *) echo "${u%/}/$j";; esac; done
    done | sort -u > "$js_urls_file"
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
  # 2) fetch each JS and scan for secrets
  : > "$js_secrets_file"; ji=0
  while read -r j; do
    [ -z "$j" ] && continue
    ji=$((ji + 1)); [ "$ji" -gt "$JS_MAX" ] && break
    ST_DETAIL[$S_JS]="scanning JS $ji/$js_total  hits:$(nlines "$js_secrets_file")"; render
    curl -s -L --max-time 15 ${CURL_NET[@]+"${CURL_NET[@]}"} "$j" 2>/dev/null | grep -aoE "$SECRET_RE" 2>/dev/null \
      | sort -u | sed "s#^#${j}\t#" >> "$js_secrets_file"
  done < "$js_urls_file"
  sort -u -o "$js_secrets_file" "$js_secrets_file"
  # 3) param discovery (arjun if available) - arjun is slow, so background each host
  #    and keep the dashboard ticking instead of freezing.
  : > "$params_file"
  if have arjun; then
    PARAM_HOSTS="${PARAM_HOSTS:-20}"
    ptotal="$(printf '%s\n' "$scan_targets" | head -n "$PARAM_HOSTS" | grep -c .)"
    pi=0
    while read -r u; do
      [ -z "$u" ] && continue
      pi=$((pi + 1)); [ "$pi" -gt "$PARAM_HOSTS" ] && break
      ptmp="$(mktemp)"
      ( arjun -u "$u" -q -oT "$ptmp" 2>/dev/null ) & apid=$!
      ps=$SECONDS
      while kill -0 "$apid" 2>/dev/null; do
        ST_DETAIL[$S_JS]="param discovery $pi/$ptotal  $((SECONDS-ps))s"
        [ "$TUI" = 1 ] && render; sleep 0.3
      done
      wait "$apid" 2>/dev/null || true
      [ -s "$ptmp" ] && sed "s#^#${u}\t#" "$ptmp" >> "$params_file"
      rm -f "$ptmp"
    done <<< "$(printf '%s\n' "$scan_targets" | head -n "$PARAM_HOSTS")"
  fi
  touch "$OUTDIR/.done_js"
  sec_hits="$(nlines "$js_secrets_file")"
  set_stage $S_JS done "$js_total JS, $sec_hits secret hits$([ -s "$params_file" ] && echo ', params')"
fi

# Step 4.7: ACTIVE FUNNEL (-C): crawl (broad/passive) -> cluster -> AI picks juicy URLs
# -> dispatch paired specialists (parallel, capped) -> merge. The "bug-hunter brain".
has_spec() { case ",$ACT_SPECIALISTS," in *",$1,"*) return 0;; *) return 1;; esac; }
# Deterministic URL clustering: collapse ids/uuids/hashes/values so 5000 URLs -> ~N patterns.
cluster_urls() {  # stdin: urls -> stdout: pattern<TAB>example-url
  while IFS= read -r u; do
    [ -z "$u" ] && continue
    p="$(printf '%s' "$u" \
      | sed -E 's#/[0-9a-fA-F]{8}-[0-9a-fA-F-]{20,}#/{uuid}#g' \
      | sed -E 's#=[^&]*#={v}#g' \
      | sed -E 's#/[0-9]+(/|\?|$)#/{id}\1#g' \
      | sed -E 's#/[0-9a-fA-F]{12,}(/|\?|$)#/{hash}\1#g')"
    printf '%s\t%s\n' "$p" "$u"
  done
}

if [ "$CRAWL" != 1 ]; then
  set_stage $S_CRAWL skip "off (-C to enable)"
elif done_marker crawl && [ -f "$targets_active_file" ]; then
  set_stage $S_CRAWL done "$(nlines "$urls_file") urls, $(nlines "$targets_active_file") active, $(nlines "$dast_file") dast (resumed)"
else
  set_stage $S_CRAWL running "collecting URLs"
  esc_domain="$(printf '%s' "$domain" | sed 's/\./\\./g')"
  : > "$urls_file"
  # (A) Broad / passive URL collection - run exhaustively, it's cheap and WAF-safe.
  have gau         && { printf '%s\n' "$domain" | gau --subs 2>>"$llm_log" >> "$urls_file" || true; }
  have waybackurls && { printf '%s\n' "$domain" | waybackurls 2>>"$llm_log" >> "$urls_file" || true; }
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
  grep -iE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" "$urls_file" 2>/dev/null \
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
    # (a) specs already seen in collected URLs
    grep -iE '(swagger|openapi|api-docs|v[0-9]+/api-docs|/graphql|/graphiql|apispec|/\.well-known/)' \
      "$urls_file" 2>/dev/null | grep -iE 'https?://' | sort -u >> "$api_specs_file" || true
    # (b) probe common spec paths on each live host (capped, auth-aware)
    api_probe_paths=(/swagger.json /swagger/v1/swagger.json /openapi.json /v2/api-docs /v3/api-docs \
                     /api-docs /api/swagger.json /api/openapi.json /swagger-ui/index.html /graphql /api/graphql)
    while IFS= read -r h; do
      [ -n "$h" ] || continue
      base="${h%/}"
      for p in "${api_probe_paths[@]}"; do
        u="$base$p"
        code="$(curl -s -o /dev/null -w '%{http_code}' -L --max-time 10 \
                 ${CURL_NET[@]+"${CURL_NET[@]}"} "$u" 2>/dev/null || echo 000)"
        case "$code" in 200|401|403) printf '%s\n' "$u" >> "$api_specs_file" ;; esac
      done
    done < <(sort -u "$alive_file" 2>/dev/null | head -n 20)
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
      | while read -r h; do [ -n "$h" ] && arjun -u "$h" -q -oT /dev/stdout 2>/dev/null \
          | sed "s#^#${h}/?#; s#\$#=1#" ; done >> "$targets_active_file" 2>/dev/null || true
  fi
  # Final clean of the set that feeds every slow specialist: drop static assets that
  # may have entered via params/API folding, then dedupe.
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
    sort -u -o "$xq" "$xq"
    [ -s "$xq" ] || cp "$targets_active_file" "$xq"                             # fallback: whole active set
    dfx=(dalfox pipe --silence --skip-bav -o "$findings_dir/dalfox.txt"); [ "${#DALFOX_NET[@]}" -gt 0 ] && dfx+=("${DALFOX_NET[@]}")
    ( head -n "$ACT_MAX_DALFOX" "$xq" | "${dfx[@]}" >/dev/null 2>>"$llm_log" ) & SPIDS+=($!)
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
      ( sqlmap -m "$sq" --batch --smart --level=1 --risk=1 --technique=BEU \
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

  touch "$OUTDIR/.done_crawl"
  set_stage $S_CRAWL done "$url_total urls -> $pattern_total patterns -> $active_total active | api:$(nlines "$api_specs_file")spec/$(nlines "$api_tests_file")test dast:$(nlines "$dast_file") dalfox:$(nlines "$findings_dir/dalfox.txt") kxss:$(nlines "$findings_dir/kxss.txt") sqlmap:$(nlines "$findings_dir/sqlmap.txt")"
fi

# Step 5: Nuclei
# Cap the tag count (the AI sometimes returns 30+ tags -> thousands of templates ->
# hours of scanning). Keep the most relevant N.
nuclei_tags="$(printf '%s' "$nuclei_tags" | tr ',' '\n' | awk 'NF' | head -n "$MAX_TAGS" | paste -sd, -)"

# Build the nuclei target list: dedupe by (origin, response signature), then VALUE-RANK
# so the interesting hosts (admin/login/api/dev, auth-gated, notable tech) are scanned
# first - with the time cap, the important stuff gets covered even if it doesn't finish.
nuclei_targets_file="$OUTDIR/nuclei_targets.txt"
if [ "$NUCLEI_DEDUPE" = 1 ] && [ -s "$httpx_json" ]; then
  jq -r '
      ((.cname // (.a[0]? // .host)) | tostring) as $o
      | [ .url,
          ((.tech // []) | map(ascii_downcase) | join(",")),
          (.status_code|tostring),
          (.title // ""),
          ($o + "|" + (.status_code|tostring) + "|" + ((.content_length//0)|tostring) + "|" + (.title//"")) ]
      | @tsv' "$httpx_json" 2>/dev/null \
    | awk -F'\t' '!seen[$5]++' \
    | { [ "$NUCLEI_SKIP_CDN" = 1 ] && grep -viE "$CDN_RE" || cat; } \
    | awk -F'\t' -v stale="${stale_file:-}" '
        BEGIN{ if (stale != "") { while ((getline ln < stale) > 0) { n=split(ln,a,"\t"); if (n>=2) sc[a[2]]=a[1] } } }
        { url=$1; tech=$2; st=$3; l=tolower($1" "$4" "$2); s=0;
          if (l ~ /admin|login|portal|dashboard|dev|staging|test|internal|api|graphql|swagger|git|jenkins|grafana|kibana|vpn|auth|sso|jira|confluence|gitlab|panel|backend|secure|account|billing|payment|upload|debug|config/) s+=3;
          if (st=="401"||st=="403") s+=2;
          if (st=="500"||st=="503") s+=1;
          if (tech ~ /wordpress|drupal|joomla|magento|jira|confluence|gitlab|jenkins|grafana|tomcat|spring|php/) s+=2;
          if (tech ~ /cloudfront|cloudflare|akamai|fastly|imperva|incapsula|sucuri|edgecast/) s-=5;
          if (url in sc) s += sc[url];   # legacy/outdated hosts (stale score) rank higher here too
          printf "%d\t%s\n", s, url }' \
    | sort -t"$(printf '\t')" -k1,1nr -s \
    | cut -f2 > "$nuclei_targets_file"
  [ -s "$nuclei_targets_file" ] || cp "$alive_file" "$nuclei_targets_file"
else
  cp "$alive_file" "$nuclei_targets_file"
fi
# optional hard cap on host count (targets are already value-ranked)
if [ "$NUCLEI_MAX_HOSTS" -gt 0 ] 2>/dev/null; then
  head -n "$NUCLEI_MAX_HOSTS" "$nuclei_targets_file" > "$nuclei_targets_file.tmp" && mv "$nuclei_targets_file.tmp" "$nuclei_targets_file"
fi
nuclei_target_count="$(wc -l <"$nuclei_targets_file" 2>/dev/null || echo 0)"
if done_marker nuclei && [ -f "$nuclei_file" ]; then
  set_stage $S_NUCLEI done "$(wc -l <"$nuclei_file") findings (resumed)"
else
  # Bounded run with live stats (-stats-json): per-request timeout, 1 retry, skip
  # error-prone hosts, hard overall time cap. Stats JSON -> nuclei_stats_file (stderr).
  : > "$nuclei_stats_file"
  nuclei_cmd=(nuclei -silent -stats -stats-json -stats-interval "${NUCLEI_STATS_INTERVAL:-5}"
              -tags "$nuclei_tags" -severity "$NUCLEI_SEVERITY"
              -rate-limit "$NUCLEI_RATELIMIT" -timeout "$NUCLEI_TIMEOUT"
              -retries "$NUCLEI_RETRIES" -mhe "$NUCLEI_MHE"
              -c "$NUCLEI_CONC" -bulk-size "$NUCLEI_BULK"
              -l "$nuclei_targets_file" -o "$nuclei_file")
  [ "${#NUCLEI_NET[@]}" -gt 0 ] && nuclei_cmd+=("${NUCLEI_NET[@]}")
  if [ "$NUCLEI_MAX_TIME" -gt 0 ] 2>/dev/null && have timeout; then
    nuclei_cmd=(timeout "${NUCLEI_MAX_TIME}s" "${nuclei_cmd[@]}")
  fi
  set_stage $S_NUCLEI running "starting… ($nuclei_target_count hosts)"
  # no wrapping subshell, so $npid is timeout/nuclei directly and a kill reaches it
  "${nuclei_cmd[@]}" >/dev/null 2>>"$nuclei_stats_file" & npid=$!
  ns=$SECONDS; last_sup=0; sup_pid=""; sup_out=""
  while kill -0 "$npid" 2>/dev/null; do
    st="$(grep '^{' "$nuclei_stats_file" 2>/dev/null | tail -1)"
    if [ -n "$st" ]; then
      pct="$(printf '%s' "$st"  | jq -r '.percent // empty' 2>/dev/null)"
      req="$(printf '%s' "$st"  | jq -r '.requests // 0' 2>/dev/null)"
      errs="$(printf '%s' "$st" | jq -r '.errors // 0' 2>/dev/null)"
      rps="$(printf '%s' "$st"  | jq -r '.rps // 0' 2>/dev/null)"
      el=$((SECONDS - ns))
      eta=""; [ -n "$pct" ] && awk "BEGIN{exit !($pct>0)}" 2>/dev/null && \
        eta="$(awk -v e="$el" -v p="$pct" 'BEGIN{r=e*(100-p)/p; printf "%dm%02ds", r/60, r%60}')"
      hits="$(wc -l <"$nuclei_file" 2>/dev/null || echo 0)"
      ST_DETAIL[$S_NUCLEI]="${pct:-0}% req:$req err:$errs rps:$rps hits:$hits${eta:+ ETA:$eta}"
    else
      ST_DETAIL[$S_NUCLEI]="starting… $((SECONDS-ns))s"
    fi
    # AI supervisor: periodic plain-language status (background, non-blocking)
    if [ "$SUPERVISOR" = 1 ] && [ "$AI_ENABLED" = 1 ] && budget_ok; then
      if [ -n "$sup_pid" ] && ! kill -0 "$sup_pid" 2>/dev/null; then
        wait "$sup_pid" 2>/dev/null || true
        [ -s "$sup_out" ] && { SUP_NOTE="$(grep -v '^[[:space:]]*$' "$sup_out" | tail -1 | head -c 400)"; printf '[%s] %s\n' "$(date +%H:%M:%S)" "$SUP_NOTE" >>"$supervisor_log"; }
        rm -f "$sup_out"; sup_pid=""
      fi
      if [ -z "$sup_pid" ] && [ $((SECONDS - last_sup)) -ge "$SUPERVISOR_INTERVAL" ] && [ -n "$st" ]; then
        last_sup=$SECONDS; sup_out="$(mktemp)"
        sup_sys='You monitor a running nuclei scan (AUTHORIZED test). Output ONLY the final status as one short sentence (<=30 words): progress %, whether the error rate is concerning and the likely cause (WAF 429s, dead hosts, timeouts), and ETA. No reasoning, no preamble, no "Let me" - just the sentence.'
        sup_usr="tags: $nuclei_tags
hosts: $alive_count  elapsed: $((SECONDS-ns))s
recent stats: $(grep '^{' "$nuclei_stats_file" | tail -3)
error sample: $(grep -iv '^{' "$nuclei_stats_file" | grep -iE 'error|timeout|refused|denied|429' | tail -5 | head -c 1500)"
        ( ai_call "$LLM_MODEL_PLAN" 1200 "$sup_sys" "$sup_usr" >"$sup_out" 2>>"$llm_log" ) & sup_pid=$!
      fi
    fi
    render; sleep 3
  done
  wait "$npid" 2>/dev/null; nrc=$?
  if [ -n "$sup_pid" ]; then
    wait "$sup_pid" 2>/dev/null || true
    [ -s "$sup_out" ] && { SUP_NOTE="$(grep -v '^[[:space:]]*$' "$sup_out" | tail -1 | head -c 400)"; printf '[%s] %s\n' "$(date +%H:%M:%S)" "$SUP_NOTE" >>"$supervisor_log"; }
    rm -f "$sup_out"
  fi
  [ "$nrc" = 124 ] && SUP_NOTE="nuclei hit the ${NUCLEI_MAX_TIME}s time cap - partial results kept"
  render
  touch "$OUTDIR/.done_nuclei"
fi
find_count=$(wc -l < "$nuclei_file" 2>/dev/null || echo 0)
set_stage $S_NUCLEI done "$find_count findings$(done_marker nuclei && echo ' (resumed)')"

# Step 5.5: AGENT MODE (-A) - autonomous validation loop.
# The AI is handed the juicy situation and, each round, decides the next GET probes
# to confirm/escalate issues itself; 4tail fires them (scope-locked, GET-only, secrets
# redacted), feeds the responses back, and the AI either digs one level deeper or moves
# on. Bounded by rounds + a wall-clock cap so it never camps on a single host.
: > "$agent_file"; : > "$agent_log"
if [ "$AGENT" != 1 ]; then
  set_stage $S_AGENT skip "off (-A to enable)"
elif [ "$AI_ENABLED" != 1 ]; then
  set_stage $S_AGENT skip "needs an API key"
elif ! budget_ok; then
  set_stage $S_AGENT skip "budget reached ($(cost_fmt))"
else
  set_stage $S_AGENT running "building situation"
  agent_seen="$OUTDIR/.agent_seen"; : > "$agent_seen"
  # Compact "situation" brief: the juiciest, most actionable signals only.
  situation="$( {
      echo "TARGET SCOPE: *.$domain"
      [ -s "${stale_file:-/dev/null}" ] && { echo "LEGACY HOSTS (older=prioritize):"; head -5 "$stale_file"; }
      [ -s "$dast_file" ] && { echo "CONFIRMED DAST (nuclei):"; head -20 "$dast_file"; }
      [ -s "$nuclei_file" ] && { echo "CONFIRMED NUCLEI (cves/exposures/misconfig/tech):"; head -20 "$nuclei_file"; }
      [ -s "$js_secrets_file" ] && { echo "JS SECRET CANDIDATES (url<TAB>match):"; head -15 "$js_secrets_file"; }
      [ -s "${api_specs_file:-/dev/null}" ] && { echo "EXPOSED API SPECS (fetch + inspect):"; head -10 "$api_specs_file"; }
      [ -s "$findings_dir/kxss.txt" ] && { echo "REFLECTED PARAMS (kxss):"; head -15 "$findings_dir/kxss.txt"; }
      [ -s "$gf_file" ] && { echo "GF CANDIDATE BUCKETS (class<TAB>url):"; head -40 "$gf_file"; }
      [ -s "$fuzz_findings_file" ] && { echo "EMPTY/SMALL 200 ENDPOINTS (param-mine candidates):";
        awk -F'\t' '$1==200 && $2+0<80 {print $3}' "$fuzz_findings_file" | head -15; }
      [ -s "$fuzz_findings_file" ] && { echo "NOTABLE PATHS:";
        awk -F'\t' '$1~/^(200|301|302|401|403)$/{print $1" "$3}' "$fuzz_findings_file" | grep -ivE 'google\.com|etc.{0,3}passwd' | head -25; }
    } | head -c 12000 )"
  astart=$SECONDS; round=0; results="(none yet - this is the first round)"
  agent_notes="(none yet - first round; form your initial hypotheses from the situation)"
  while [ "$round" -lt "$AGENT_ROUNDS" ]; do
    round=$((round+1))
    budget_ok || { SUP_NOTE="agent: budget reached, stopping"; break; }
    [ "$AGENT_MAX_TIME" -gt 0 ] 2>/dev/null && [ $((SECONDS-astart)) -ge "$AGENT_MAX_TIME" ] && break
    set_stage $S_AGENT running "round $round/$AGENT_ROUNDS: AI thinking"
    aout="$(mktemp)"
    ai_call "$LLM_MODEL_PLAN" 2200 \
"You are an autonomous web-app pentester on an AUTHORIZED target, working in rounds. You keep a running NOTES block (your hypotheses: what you suspect, why, and what is confirmed / refuted / still-unconfirmed), update it each round from the latest probe results, then fire the next GET probes to chase the hottest lead. Then you decide whether to keep going.
Ideas: confirmed/possible LFI (e.g. Templatize.asp?item=) -> read ../web.config, ../../web.config, ../global.asa, ../../../windows/win.ini; empty/small 200 endpoints (e.g. db.asp) -> add likely params ?id=1 ?debug=1 ?action=list ?table=users; redirect params (RetURL/url/next) -> set value to //example.org/ and watch for a Location; IDOR -> walk adjacent numeric ids; exposed admin/config/backup paths -> fetch them.
Respond in EXACTLY this structure and nothing else:
NOTES:
<2-6 short lines: your updated hypotheses and their status>
PROBES:
<one absolute http(s) URL per line, target scope *.$domain only; optional ' | why | success-regex'>
DECISION: CONTINUE
(use 'DECISION: STOP' instead when your leads are exhausted or everything promising is already confirmed)" \
"SITUATION:
$situation

YOUR NOTES SO FAR:
$agent_notes

LATEST PROBE RESULTS:
$results" > "$aout" 2>>"$llm_log" || true
    # --- parse the structured reply (robust to reasoning-model wrapping) ---
    # NOTES: text between a NOTES marker and the PROBES/DECISION marker.
    new_notes="$(awk 'BEGIN{p=0} /^[[:space:]]*NOTES[[:space:]]*:/{p=1;next} /^[[:space:]]*(PROBES|DECISION)[[:space:]]*:/{p=0} p' "$aout" | sed '/^[[:space:]]*$/d' | head -n 8)"
    [ -n "$new_notes" ] && agent_notes="$new_notes"
    # DECISION: explicit STOP only (default is to continue while leads/probes remain).
    decision="$(grep -ioE 'DECISION[[:space:]]*:[[:space:]]*(CONTINUE|STOP)' "$aout" | head -1 | grep -ioE '(CONTINUE|STOP)' | tr 'a-z' 'A-Z')"
    # PROBES: prefer URLs under the PROBES section; fall back to any in-scope URL in the reply.
    probes="$(awk 'BEGIN{p=0} /^[[:space:]]*PROBES[[:space:]]*:/{p=1;next} /^[[:space:]]*DECISION[[:space:]]*:/{p=0} p' "$aout" | grep -iE 'https?://')"
    [ -n "$probes" ] || probes="$(grep -iE 'https?://' "$aout")"
    probes="$(printf '%s\n' "$probes" | head -n $((AGENT_MAX_PROBES * 3)))"; rm -f "$aout"
    printf '=== round %s notes ===\n%s\n' "$round" "$agent_notes" >> "$agent_log"
    [ -n "$probes" ] || { [ "$round" -eq 1 ] && SUP_NOTE="agent: no probes proposed"; break; }
    # Default "looks sensitive" markers so a probe can confirm even when the model gives no regex.
    agent_default_rx='connectionString|<configuration|<\?xml|root:.{0,40}:0:0:|\[fonts\]|\[extensions\]|16-bit app support|BEGIN [A-Z ]*PRIVATE KEY|DB_PASSWORD|SA_PASSWORD|Microsoft OLE DB|ODBC|SQL syntax.*MySQL|ORA-[0-9]{4,}|Directory of |<web-app|runtime error'
    results=""; np=0
    while IFS= read -r pline; do
      [ "$np" -ge "$AGENT_MAX_PROBES" ] && break
      url="$(printf '%s' "$pline" | grep -oiE 'https?://[^ "'"'"'`|<>]+' | head -1)"
      [ -n "$url" ] || continue
      why="$(printf '%s' "$pline" | awk -F'\\|' 'NF>=2{print $2}' | sed 's/^ *//;s/ *$//')"; [ -n "$why" ] || why="agent probe"
      rx="$(printf '%s'  "$pline" | awk -F'\\|' 'NF>=3{print $3}' | sed 's/^ *//;s/ *$//')"; [ -n "$rx" ] || rx="$agent_default_rx"
      # HARD GUARDRAILS: http(s) only, must be in target scope, no dup probes.
      printf '%s' "$url" | grep -qiE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" || continue
      grep -qxF "$url" "$agent_seen" 2>/dev/null && continue
      printf '%s\n' "$url" >> "$agent_seen"; np=$((np+1))
      set_stage $S_AGENT running "round $round: probing ($(nlines "$agent_seen") sent)"; render
      resp="$(curl -s -i -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} "$url" 2>/dev/null | head -c 6000)"
      # redact anything that looks like a secret before it is stored or sent back to the LLM
      red="$(printf '%s' "$resp" | sed -E 's/((pass(word|wd)?|connection[-_ ]?string|accountkey|secret|api[-_]?key|token|aws[_-]?secret[_-]?access[_-]?key)[^[:cntrl:]]{0,8}[:=])[^[:cntrl:]"'"'"']{1,}/\1<redacted>/Ig')"
      hit=""; [ -n "$rx" ] && printf '%s' "$resp" | grep -qiE -- "$rx" 2>/dev/null && hit="HIT"
      local_status="$(printf '%s' "$resp" | head -1 | tr -d '\r')"
      snippet="$(printf '%s' "$red" | tr '\n\r\t' '   ' | sed -E 's/  +/ /g' | head -c 240)"
      printf '[r%s] %-4s %s\n   why: %s\n   resp: %s | %s\n' "$round" "${hit:-...}" "$url" "$why" "$local_status" "$snippet" >> "$agent_log"
      results="$results"$'\n'"$url => ${hit:-no-match} [$local_status] $snippet"
      [ "$hit" = HIT ] && printf '[CONFIRMED] %s | %s\n' "$url" "$why" >> "$agent_file"
    done <<< "$probes"
    [ -n "$results" ] || break
    # The AI chases a hot lead across rounds, but stops itself when exhausted.
    if [ "$decision" = STOP ]; then SUP_NOTE="agent: stopping (leads exhausted)"; break; fi
  done
  # Persist the agent's final reasoning for the report/transcript.
  { echo "=== final hypotheses ==="; printf '%s\n' "$agent_notes"; } >> "$agent_log"
  set_stage $S_AGENT done "$(nlines "$agent_file") confirmed · $(nlines "$agent_seen") probes · ${round}r"
fi

# Report header
{
  echo "# 4tail recon report"; echo
  echo "- **Target:** \`$domain\`"
  echo "- **Generated:** $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "- **Subdomains:** $sub_count | **Live:** $alive_count | **Nuclei findings:** $find_count | **Fuzz hits:** ${fuzz_hits:-0}"
  [ "$JSMINE" = 1 ] && echo "- **JS mined:** $(nlines "$js_urls_file") files, $(nlines "$js_secrets_file") secret hits, $(nlines "$params_file") params"
  if [ "$CRAWL" = 1 ]; then
    echo "- **Active funnel (${BLUEPRINT_NAME:-defaults}):** $(nlines "$urls_file") urls → $(nlines "$url_patterns_file") patterns → **$(nlines "$targets_active_file") juicy**"
    echo "  - specialists → DAST:$(nlines "$dast_file") · dalfox:$(nlines "$findings_dir/dalfox.txt") · kxss:$(nlines "$findings_dir/kxss.txt") · sqlmap:$(nlines "$findings_dir/sqlmap.txt")"
  fi
  echo "- **Nuclei:** ${nuclei_target_count:-$alive_count} hosts scanned (deduped from $alive_count) | tags \`$nuclei_tags\` | severity \`$NUCLEI_SEVERITY\`"
  echo "- **AI models:** $([ "$AI_ENABLED" = 1 ] && echo "plan=$LLM_MODEL_PLAN, triage=$LLM_MODEL_TRIAGE" || echo "disabled")"
  [ "$AI_ENABLED" = 1 ] && echo "- **Estimated AI spend:** $(cost_fmt)$([ "${LLM_BUDGET_USD:-0}" != 0 ] && echo " (budget \$$LLM_BUDGET_USD)")"
  echo "- **SecLists:** ${SECLISTS_DIR:-not found} | **Base wordlist:** \`$WORDLIST\`"; echo
  if [ "$AGENT" = 1 ] && { [ -s "$agent_file" ] || [ -n "${agent_notes:-}" ]; }; then
    echo "## 🤖 Agent (autonomous probe loop)"; echo
    if [ -s "$agent_file" ]; then echo "**Confirmed / escalated:**"; echo '```'; cat "$agent_file"; echo '```'; echo; fi
    if [ -n "${agent_notes:-}" ]; then echo "**Final hypotheses:**"; echo '```'; printf '%s\n' "$agent_notes"; echo '```'; echo; fi
  fi
  if [ -s "$fuzz_findings_file" ]; then
    echo "## Content discovery hits (ffuf, top 100)"
    echo
    echo '| Status | Length | URL | Count |'
    echo '|--------|--------|-----|-------|'
    # group by response fingerprint (status,length) so WAF noise / case-variants collapse
    awk -F'\t' 'NF>=3{k=$1"\t"$2; c[k]++; if(!(k in r)) r[k]=$3}
        END{for(k in c) printf "%s\t%s\t%d\n", k, r[k], c[k]}' "$fuzz_findings_file" \
      | sort -t"$(printf '\t')" -k1,1n -k3,3nr | head -n 100 \
      | while IFS=$'\t' read -r st len u c; do
          echo "| $st | $len | \`$u\` | $([ "$c" -gt 1 ] && echo "×$c" || echo 1) |"
        done
    echo
  fi
  if [ -s "$dast_file" ]; then
    echo "## DAST findings (nuclei -dast)"; echo; echo '```'; head -n 100 "$dast_file"; echo '```'; echo
  fi
  if [ -s "$findings_dir/dalfox.txt" ]; then
    echo "## XSS (dalfox)"; echo; echo '```'; head -n 80 "$findings_dir/dalfox.txt"; echo '```'; echo
  fi
  if [ -s "$findings_dir/sqlmap.txt" ]; then
    echo "## SQLi confirmation (sqlmap)"; echo; echo '```'; head -n 80 "$findings_dir/sqlmap.txt"; echo '```'; echo
  fi
  if [ -s "$findings_dir/kxss.txt" ]; then
    echo "## Reflected-param candidates (kxss) — top 40"; echo; echo '```'; head -n 40 "$findings_dir/kxss.txt"; echo '```'; echo
  fi
} > "$report_file"

# Step 6: AI triage  (analyses nuclei + content-discovery + JS + crawl/DAST)
have_extra=0; { [ -s "$js_secrets_file" ] || [ -s "$params_file" ] || [ -s "$fuzz_findings_file" ] || [ -s "$dast_file" ] || [ -s "$gf_file" ] || [ -s "$findings_dir/dalfox.txt" ] || [ -s "$findings_dir/sqlmap.txt" ] || [ -s "$agent_file" ]; } && have_extra=1
if [ "$AI_ENABLED" = "1" ] && { [ "$find_count" -gt 0 ] || [ "$have_extra" = 1 ]; } && ! budget_ok; then
  { echo "## Findings (budget reached, no AI triage)"; echo '```'; cat "$nuclei_file" 2>/dev/null
    [ -s "$js_secrets_file" ] && { echo; echo "# JS secret candidates:"; cat "$js_secrets_file"; }; echo '```'; } >> "$report_file"
  set_stage $S_TRIAGE skip "budget reached ($(cost_fmt))"
elif [ "$AI_ENABLED" = "1" ] && { [ "$find_count" -gt 0 ] || [ "$have_extra" = 1 ]; }; then
  sorted_findings="$(
    for sev in critical high medium low info; do grep -iE "\[$sev\]" "$nuclei_file" 2>/dev/null; done
    grep -viE '\[(critical|high|medium|low|info)\]' "$nuclei_file" 2>/dev/null
  )"
  [ -z "$sorted_findings" ] && sorted_findings="$(cat "$nuclei_file" 2>/dev/null)"
  sys_triage='You are a senior security analyst on an AUTHORIZED bug-bounty engagement.
Given a technology brief, nuclei output, CONTENT-DISCOVERY hits (discovered URLs/paths),
JS secret candidates and discovered request parameters, produce a thorough report in
GitHub-flavored Markdown with:
"## Executive summary" (3-5 sentences),
"## Prioritised findings" (table: Severity | Host | Issue | Why it matters | Next step),
"## Notable discovered paths" (from the content-discovery hits, call out the juicy ones:
backups/.git/.env/config/admin/api/upload/debug endpoints; ignore generic assets; note
which 401/403 are worth auth testing),
"## Injection candidates (DAST & params)" (from nuclei -dast findings and gf-bucketed
parametered URLs: name the parameter, the suspected class (SQLi/XSS/SSRF/LFI/redirect),
and a concrete safe test),
"## Secrets & sensitive exposure" (assess each JS secret candidate: likely real vs false
positive, impact, safe verification - flag private keys / cloud creds as critical),
"## Interesting parameters to test" (map discovered params to bug classes: IDOR, SSRF,
LFI, SQLi, open-redirect - concrete test idea each),
"## Attack surface notes" and "## Recommended manual follow-ups".
Use ONLY the provided data - do not invent findings.
Output ONLY the final report starting exactly with the line "## Executive summary".
Do NOT include any reasoning, planning, or preamble before it.'
  triage_out="$(mktemp)"
  run_ai_stage $S_TRIAGE "$LLM_MODEL_TRIAGE" "$LLM_MAX_TOKENS_TRIAGE" "$sys_triage" "Target: $domain

=== technology brief ===
$(head -c 8000 "$tech_brief")

=== nuclei findings (severity-sorted) ===
$(printf '%s\n' "$sorted_findings" | head -n 400 | head -c 30000)

=== content-discovery hits (status  length  url  count; grouped by response fingerprint) ===
$(awk -F'\t' 'NF>=3{k=$1"\t"$2; c[k]++; if(!(k in r)) r[k]=$3} END{for(k in c) printf "%s\t%s\tx%d\n", k, r[k], c[k]}' "$fuzz_findings_file" 2>/dev/null | sort -t"$(printf '\t')" -k1,1n -k3,3r | head -n 150 | head -c 12000)

=== nuclei DAST findings ===
$(head -c 8000 "$dast_file" 2>/dev/null)

=== dalfox XSS findings ===
$(head -c 4000 "$findings_dir/dalfox.txt" 2>/dev/null)

=== sqlmap SQLi confirmation ===
$(head -c 3000 "$findings_dir/sqlmap.txt" 2>/dev/null)

=== gf injection-candidate URLs (pattern <TAB> url) ===
$(head -n 120 "$gf_file" 2>/dev/null | head -c 8000)

=== JS secret candidates (url <TAB> match) ===
$(head -c 8000 "$js_secrets_file" 2>/dev/null)

=== discovered parameters (url <TAB> param) ===
$(head -c 4000 "$params_file" 2>/dev/null)

=== agent-confirmed issues (autonomous probe loop; treat as CONFIRMED, rank high) ===
$(head -c 4000 "$agent_file" 2>/dev/null)" "$triage_out"
  if [ -s "$triage_out" ]; then
    # Drop any leading reasoning: keep from the LAST "## Executive summary" to the end
    # (reasoning models may restate the section names earlier while thinking).
    ln="$(grep -n '## Executive summary' "$triage_out" | tail -1 | cut -d: -f1)"
    if [ -n "$ln" ]; then sed -n "${ln},\$p" "$triage_out" >> "$report_file"
    else cat "$triage_out" >> "$report_file"; fi
    set_stage $S_TRIAGE done "report.md written"
  else
    { echo "## Raw findings"; echo '```'; cat "$nuclei_file" 2>/dev/null; echo '```'; } >> "$report_file"
    set_stage $S_TRIAGE warn "AI failed, raw findings saved"
  fi
  rm -f "$triage_out"
else
  {
    echo "## Findings"
    if [ "$find_count" -gt 0 ]; then echo '```'; cat "$nuclei_file"; echo '```'; else echo "_No nuclei findings._"; fi
    if [ -s "$js_secrets_file" ]; then echo; echo "## JS secret candidates"; echo '```'; cat "$js_secrets_file"; echo '```'; fi
    if [ -s "$params_file" ]; then echo; echo "## Discovered parameters"; echo '```'; cat "$params_file"; echo '```'; fi
  } >> "$report_file"
  set_stage $S_TRIAGE skip "$([ "$AI_ENABLED" = 1 ] && echo "nothing to triage" || echo "AI off")"
fi

# OOB: correlate any interactsh callbacks to the URLs we injected, then stop the listener.
oast_correlate
oast_stop

# Structured output: findings.json (and optional SARIF) for automation / ticketing.
findings_json="$OUTDIR/findings.json"
if have jq; then
  emit_f() { jq -nc --arg type "$1" --arg sev "$2" --arg src "$3" --arg url "$4" --arg detail "$5" \
      '{type:$type,severity:$sev,source:$src,url:$url,detail:$detail}'; }
  nsev() { printf '%s' "$1" | grep -oiE '\[(critical|high|medium|low|info|unknown)\]' | head -1 | tr -d '[]' | tr 'A-Z' 'a-z'; }
  nurl() { printf '%s' "$1" | grep -oE 'https?://[^ ]+' | head -1; }
  {
    [ -f "$nuclei_file" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f nuclei "$(nsev "$l")" nuclei "$(nurl "$l")" "$l"; done < "$nuclei_file"
    [ -f "$dast_file" ]   && while IFS= read -r l; do [ -n "$l" ] && emit_f dast "$(nsev "$l")" nuclei-dast "$(nurl "$l")" "$l"; done < "$dast_file"
    # Group ffuf hits by response fingerprint (status,length) - never by URL string -
    # so case-variants (db.asp/DB.asp on IIS) and WAF noise (32 identical 403/312
    # traversal blocks) collapse to one representative with a count.
    [ -f "$fuzz_findings_file" ] && awk -F'\t' 'NF>=3{k=$1"\t"$2; c[k]++; if(!(k in r)) r[k]=$3}
        END{for(k in c) printf "%s\t%s\t%d\n", k, r[k], c[k]}' "$fuzz_findings_file" \
      | while IFS=$'\t' read -r st len u c; do
          [ -n "$u" ] || continue
          note="status=$st length=$len"; [ "${c:-1}" -gt 1 ] && note="$note (×$c identical responses)"
          emit_f content-discovery info ffuf "$u" "$note"
        done
    [ -f "$findings_dir/dalfox.txt" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f xss high dalfox "$(nurl "$l")" "$l"; done < "$findings_dir/dalfox.txt"
    [ -f "$findings_dir/sqlmap.txt" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f sqli high sqlmap "" "$l"; done < "$findings_dir/sqlmap.txt"
    [ -f "$js_secrets_file" ] && while IFS=$'\t' read -r u m; do [ -n "$m" ] && emit_f secret medium js-mining "$u" "$m"; done < "$js_secrets_file"
    [ -f "$findings_dir/kxss.txt" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f reflected-param low kxss "$(nurl "$l")" "$l"; done < "$findings_dir/kxss.txt"
    [ -f "${api_specs_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f api-spec info api-discovery "$l" "exposed API spec: $l"; done < "$api_specs_file"
    [ -f "${oast_hits_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f blind-ssrf-redirect high oast "$(nurl "$l")" "$l"; done < "$oast_hits_file"
    [ -f "${agent_file:-}" ] && while IFS= read -r l; do [ -n "$l" ] && emit_f agent-confirmed high agent "$(nurl "$l")" "$l"; done < "$agent_file"
    true   # force group exit 0: a trailing false [ -f ] test must not (via pipefail) trip the || fallback and clobber jq's output
  } | jq -s "{target:\"$domain\", generated:\"$(date -u +%FT%TZ)\", blueprint:\"${BLUEPRINT_NAME:-}\", count:length, findings:.}" > "$findings_json" 2>/dev/null
  [ -s "$findings_json" ] || echo '{}' > "$findings_json"

  if [ "$EMIT_SARIF" = 1 ]; then
    jq '{version:"2.1.0", "$schema":"https://json.schemastore.org/sarif-2.1.0.json",
         runs:[{tool:{driver:{name:"4tail", rules:[]}},
                results:[.findings[] | {ruleId:.type, level:(if .severity=="critical" or .severity=="high" then "error" elif .severity=="medium" then "warning" else "note" end),
                                        message:{text:.detail}, properties:{source:.source,severity:.severity},
                                        locations:[{physicalLocation:{artifactLocation:{uri:.url}}}]}]}]}' \
       "$findings_json" > "$OUTDIR/findings.sarif" 2>/dev/null || true
  fi
fi

# Final summary
spend_note=""; [ "$AI_ENABLED" = 1 ] && spend_note="  ·  AI spend ~$(cost_fmt)"
tally="nuclei:$find_count  fuzz-hits:${fuzz_hits:-0}$([ "$JSMINE" = 1 ] && echo "  js-secrets:$(nlines "$js_secrets_file")  params:$(nlines "$params_file")")$([ "$CRAWL" = 1 ] && echo "  active:$(nlines "$targets_active_file")  api-specs:$(nlines "${api_specs_file:-/dev/null}")  dast:$(nlines "$dast_file")  dalfox:$(nlines "$findings_dir/dalfox.txt")  sqlmap:$(nlines "$findings_dir/sqlmap.txt")")$([ "$OAST" = 1 ] && echo "  oast-confirmed:$(nlines "${oast_hits_file:-/dev/null}")")$([ "$AGENT" = 1 ] && echo "  agent-confirmed:$(nlines "${agent_file:-/dev/null}")")"
if [ "$TUI" = 1 ]; then
  tui_end    # leave alt screen, reprint final panel into normal scrollback
  printf '\n %s✔ done in %ss%s%s\n   %s%s%s\n   report → %s%s%s\n' \
    "$c_green" "$((SECONDS-started))" "$c_reset" "$spend_note" \
    "$c_dim" "$tally" "$c_reset" "$c_cyan" "$report_file" "$c_reset"
  [ -f "$findings_json" ] && printf '   %sJSON   → %s%s%s\n' "$c_dim" "$c_cyan" "$findings_json" "$c_reset"
else
  ok "Done in $((SECONDS-started))s.$spend_note"
  ok "$tally"
  ok "Report: $report_file"
  [ -f "$findings_json" ] && ok "JSON:   $findings_json$([ "$EMIT_SARIF" = 1 ] && echo "  (+ findings.sarif)")"
fi
