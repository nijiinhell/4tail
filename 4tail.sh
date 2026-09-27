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

# ---------------------------------------------------------------------------
# LLM configuration (OpenAI-compatible; defaults = Together AI + cheap GLM)
# ---------------------------------------------------------------------------
LLM_API_KEY="${TOGETHER_API_KEY:-${LLM_API_KEY:-}}"
LLM_BASE_URL="${LLM_BASE_URL:-https://api.together.xyz/v1}"
LLM_MODEL="${LLM_MODEL:-zai-org/GLM-4.6}"
LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-1200}"
LLM_TEMPERATURE="${LLM_TEMPERATURE:-0.2}"
LLM_TIMEOUT="${LLM_TIMEOUT:-90}"
LLM_RETRIES="${LLM_RETRIES:-2}"

# ---------------------------------------------------------------------------
# Scan configuration
# ---------------------------------------------------------------------------
WORDLIST="${WORDLIST:-}"                   # base "juicy" list; auto-resolved below (Bo0oM/fuzz.txt preferred)
SECLISTS_DIR="${SECLISTS_DIR:-}"          # auto-detected below if empty
MAX_FUZZ_WORDS="${MAX_FUZZ_WORDS:-60000}" # cap per-host combined wordlist size
EXTENSIONS="${EXTENSIONS:-}"              # explicit ffuf -e list (overrides tech-aware exts)
MAX_EXTS="${MAX_EXTS:-10}"                # cap on per-host extensions (each multiplies requests)
FFUF_RATE="${FFUF_RATE:-0}"              # ffuf requests/sec (0 = unlimited)
FETCH_FUZZTXT="${FETCH_FUZZTXT:-0}"      # 1 = download Bo0oM/fuzz.txt if no base list found
DEFAULT_NUCLEI_TAGS="${DEFAULT_NUCLEI_TAGS:-cves,exposures,misconfiguration,tech,default-login,takeover}"
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-critical,high,medium,low}"
NUCLEI_RATELIMIT="${NUCLEI_RATELIMIT:-150}"
HTTPX_THREADS="${HTTPX_THREADS:-50}"
OUTDIR="${OUTDIR:-}"
ASSUME_YES="${ASSUME_YES:-0}"
NO_TUI="${NO_TUI:-0}"

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

Options:
  -w <file>   Wordlist for ffuf              (env WORDLIST)
  -o <dir>    Output directory               (env OUTDIR)
  -t <tags>   Fallback nuclei tags           (env DEFAULT_NUCLEI_TAGS)
  -S <sev>    Nuclei severities              (env NUCLEI_SEVERITY, default $NUCLEI_SEVERITY)
  -m <model>  LLM model id                   (env LLM_MODEL, default $LLM_MODEL)
  -y          Skip the authorization prompt  (env ASSUME_YES=1)
  -P          Plain output, no live dashboard(env NO_TUI=1)
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
while getopts ":w:o:t:S:m:yPh" opt; do
  case "$opt" in
    w) WORDLIST="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    t) DEFAULT_NUCLEI_TAGS="$OPTARG" ;;
    S) NUCLEI_SEVERITY="$OPTARG" ;;
    m) LLM_MODEL="$OPTARG" ;;
    y) ASSUME_YES=1 ;;
    P) NO_TUI=1 ;;
    h) usage; exit 0 ;;
    \?) err "Unknown option: -$OPTARG"; usage; exit 1 ;;
    :)  err "Option -$OPTARG requires an argument"; exit 1 ;;
  esac
done
shift $((OPTIND - 1))

domain="${1:-}"
if [ -z "$domain" ]; then err "No target domain provided."; usage; exit 1; fi
if ! printf '%s' "$domain" | grep -qE '^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$'; then
  err "That doesn't look like a bare domain (got: '$domain'). Use e.g. example.com"; exit 1
fi

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
missing=()
for tool in subfinder httpx nuclei; do have "$tool" || missing+=("$tool"); done
if [ "${#missing[@]}" -gt 0 ]; then
  err "Missing required tools: ${missing[*]} (see projectdiscovery.io)"; exit 1
fi
have ffuf || warn "ffuf not found - content-discovery step will be skipped."

AI_ENABLED=1
if [ -z "$LLM_API_KEY" ]; then
  warn "No API key (TOGETHER_API_KEY) - AI steps disabled, using static defaults."; AI_ENABLED=0
elif ! have curl || ! have jq; then
  warn "curl and jq are required for AI steps - disabling AI, using defaults."; AI_ENABLED=0
fi

# ---------------------------------------------------------------------------
# Authorization gate
# ---------------------------------------------------------------------------
if [ "$ASSUME_YES" != "1" ]; then
  printf '%s' "${c_yellow}Confirm you are AUTHORIZED to test '${domain}' [y/N]: ${c_reset}"
  read -r reply
  case "$reply" in y|Y|yes|YES) ;; *) err "Aborted - authorization not confirmed."; exit 1 ;; esac
fi

# ---------------------------------------------------------------------------
# Output layout
# ---------------------------------------------------------------------------
ts="$(date +%Y%m%d_%H%M%S)"
OUTDIR="${OUTDIR:-4tail_${domain}_${ts}}"
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
fuzz_plan_file="$OUTDIR/fuzz_plan.txt"        # host <TAB> wordlists used

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

# ===========================================================================
# LIVE TERMINAL DASHBOARD
# ===========================================================================
if [ -t 1 ] && [ "$NO_TUI" != "1" ]; then TUI=1; else TUI=0; fi

# Stages: label + state + detail. States: pending|running|done|warn|skip
ST_LABEL=("Subdomains" "Live hosts" "AI scan plan" "Fuzzing" "Nuclei scan" "AI triage")
ST_STATE=(pending pending pending pending pending pending)
ST_DETAIL=("" "" "" "" "" "")
PANEL_LINES=$(( ${#ST_LABEL[@]} + 3 ))   # top border + info + stages + bottom border
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

render() {
  [ "$TUI" = 1 ] || return 0
  spin_i=$(( (spin_i + 1) & 3 ))
  [ "$panel_drawn" = 1 ] && printf '\033[%dA' "$PANEL_LINES"
  local model_line="off"; [ "$AI_ENABLED" = 1 ] && model_line="$LLM_MODEL"
  printf ' %s╭─ 4tail ───────────────────────────────────────%s\033[K\n' "$c_cyan" "$c_reset"
  printf ' %s│%s target=%s  ai=%s  elapsed=%ss\033[K\n' "$c_cyan" "$c_reset" "$domain" "$model_line" "$((SECONDS-started))"
  local i
  for i in "${!ST_LABEL[@]}"; do
    printf ' %s│%s  %s  %-13s %s%s%s\033[K\n' \
      "$c_cyan" "$c_reset" "$(icon "${ST_STATE[$i]}")" "${ST_LABEL[$i]}" \
      "$c_dim" "${ST_DETAIL[$i]:-}" "$c_reset"
  done
  printf ' %s╰──────────────────────────────────────────────%s\033[K\n' "$c_cyan" "$c_reset"
  panel_drawn=1
}

set_stage() { ST_STATE[$1]="$2"; [ -n "${3+x}" ] && ST_DETAIL[$1]="$3"; render; }

cleanup() { [ "$TUI" = 1 ] && printf '\033[?25h\n'; }   # restore cursor
trap cleanup EXIT
trap 'cleanup; err "interrupted"; exit 130' INT TERM

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
# LLM helper: ai_call <system> <user> -> prints text; retry+backoff; frugal.
# ---------------------------------------------------------------------------
ai_call() {
  local system="$1" user="$2" payload response text attempt=0 delay=2
  payload="$(jq -n --arg model "$LLM_MODEL" --arg sys "$system" --arg usr "$user" \
    --argjson max "$LLM_MAX_TOKENS" --argjson temp "$LLM_TEMPERATURE" \
    '{model:$model, max_tokens:$max, temperature:$temp,
      messages:[{role:"system",content:$sys},{role:"user",content:$usr}]}')" || return 1
  while :; do
    attempt=$((attempt + 1))
    response="$(curl -sS --max-time "$LLM_TIMEOUT" "$LLM_BASE_URL/chat/completions" \
      -H "content-type: application/json" -H "authorization: Bearer $LLM_API_KEY" \
      -d "$payload" 2>/dev/null)"
    if [ -n "$response" ] && ! echo "$response" | jq -e '.error' >/dev/null 2>&1; then
      text="$(echo "$response" | jq -r '.choices[0].message.content // empty' 2>/dev/null)"
      if [ -n "$text" ]; then printf '%s' "$text"; return 0; fi
    fi
    if [ "$attempt" -gt "$LLM_RETRIES" ]; then
      echo "LLM error: $(echo "$response" | jq -r '.error.message // .error // "empty response"' 2>/dev/null)" >>"$llm_log"
      return 1
    fi
    sleep "$delay"; delay=$((delay * 2))
  done
}

# Background an AI call while spinning the given stage; result -> outfile.
run_ai_stage() {
  local idx="$1" sys="$2" usr="$3" outfile="$4"
  set_stage "$idx" running "querying ${LLM_MODEL##*/} · 0s"
  ( ai_call "$sys" "$usr" >"$outfile" 2>>"$llm_log" ) & local pid=$!
  local s=$SECONDS
  while kill -0 "$pid" 2>/dev/null; do
    ST_DETAIL[$idx]="querying ${LLM_MODEL##*/} · $((SECONDS-s))s"
    [ "$TUI" = 1 ] && render; sleep 0.25
  done
  wait "$pid"; return $?
}

[ "$TUI" = 1 ] && { printf '\033[?25l'; render; }   # hide cursor + first paint

# ===========================================================================
# PIPELINE
# ===========================================================================

# Step 1: Subdomains
run_stage 0 "$subdomains_file" " subs" subfinder -silent -d "$domain" -o "$subdomains_file"
sub_count=$(wc -l < "$subdomains_file" 2>/dev/null || echo 0)
if [ "$sub_count" -eq 0 ]; then
  set_stage 0 warn "none found"; [ "$TUI" = 1 ] || warn "No subdomains; stopping."; exit 0
fi
set_stage 0 done "$sub_count subs"

# Step 2: Live hosts + tech detection
run_stage 1 "$httpx_json" " live" \
  httpx -silent -json -tech-detect -status-code -title -web-server \
        -threads "$HTTPX_THREADS" -l "$subdomains_file" -o "$httpx_json"
if [ -s "$httpx_json" ]; then jq -r '.url' "$httpx_json" 2>/dev/null | sort -u > "$alive_file"; else : > "$alive_file"; fi
alive_count=$(wc -l < "$alive_file" 2>/dev/null || echo 0)
if [ "$alive_count" -eq 0 ]; then
  set_stage 1 warn "none live"; [ "$TUI" = 1 ] || warn "No live hosts; stopping."; exit 0
fi
set_stage 1 done "$alive_count live"

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

# Step 3: AI scan plan (with allowlist guardrail)
NUCLEI_TAG_ALLOWLIST="cves,cve,exposures,exposure,misconfiguration,misconfig,tech,\
default-login,takeover,subdomain-takeover,panel,login,exposed-panels,config,\
backup,files,logs,debug,git,svn,env,sqli,xss,ssrf,lfi,rce,injection,auth-bypass,\
wordpress,wp-plugin,joomla,drupal,magento,laravel,django,spring,struts,\
apache,nginx,tomcat,iis,php,jira,confluence,jenkins,gitlab,grafana,kibana,\
elasticsearch,kubernetes,docker,aws,azure,gcp,ssl,tls,cors,headers,\
oauth,jwt,api,graphql,swagger,firebase,s3,redis,mongodb,mysql,postgres"
sanitize_tags() {
  tr ',[:space:]' '\n\n' | tr 'A-Z' 'a-z' | grep -oE '[a-z0-9._-]+' \
    | while read -r t; do
        case ",${NUCLEI_TAG_ALLOWLIST//[[:space:]]/}," in *",$t,"*) echo "$t";; esac
      done | awk '!seen[$0]++' | paste -sd, -
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
#   PHP        raft-large-files.txt -> huge file list rich in .php config/backup
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
php	Discovery/Web-Content/raft-large-files.txt
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
[ -n "$SECLISTS_DIR" ] && seed_static_tech_map || : > "$tech_map_file"

nuclei_tags="$DEFAULT_NUCLEI_TAGS"
if [ "$AI_ENABLED" = "1" ] && [ -s "$tech_brief" ]; then
  sys_plan='You assist AUTHORIZED bug-bounty recon. Given an aggregated brief of the
technologies, servers and notable paths on live hosts, produce a scan plan.
Reply with ONLY a JSON object (no prose, no code fences) with exactly two keys:
  "nuclei_tags": array of 4-12 lowercase nuclei tags (always include cves, exposures,
     misconfiguration, plus tags matched to the observed stack),
  "wordlists": object mapping each relevant lowercase technology name to an array of
     content-discovery wordlist file paths RELATIVE to the SecLists root
     (e.g. "Discovery/Web-Content/CMS/wordpress.fuzz.txt"). Use only real, well-known
     SecLists paths; keep 1-3 paths per technology; omit technologies you are unsure of.'
  plan_out="$(mktemp)"
  run_ai_stage 2 "$sys_plan" "Target: $domain
Live hosts: $alive_count
SecLists root: ${SECLISTS_DIR:-<not installed>}

$(head -c 6000 "$tech_brief")" "$plan_out"

  # --- parse nuclei tags (JSON first, then salvage raw text) ---
  ai_tags="$(jq -r '.nuclei_tags[]?' "$plan_out" 2>/dev/null | paste -sd, -)"
  [ -z "$ai_tags" ] && ai_tags="$(cat "$plan_out")"
  clean_plan="$(printf '%s' "$ai_tags" | sanitize_tags)"

  # --- parse wordlist map (append to tech map; existence checked at fuzz time) ---
  if [ -n "$SECLISTS_DIR" ]; then
    jq -r '.wordlists // {} | to_entries[]? | (.key|ascii_downcase) as $k | .value[]? | "\($k)\t\(.)"' \
       "$plan_out" 2>/dev/null >> "$tech_map_file" || true
  fi
  rm -f "$plan_out"

  if [ -n "$clean_plan" ] && [ "$(printf '%s' "$clean_plan" | tr ',' '\n' | grep -c .)" -ge 2 ]; then
    nuclei_tags="$clean_plan"; printf '%s\n' "$nuclei_tags" > "$OUTDIR/ai_scan_plan.txt"
    set_stage 2 done "$nuclei_tags"
  else
    set_stage 2 warn "unusable, using defaults"
  fi
else
  set_stage 2 skip "AI off (defaults)"
fi

# Step 4: Fuzzing (tech-aware, per host)
# For each live host: base "juicy" wordlist  +  SecLists lists matched to its
# detected tech  ->  deduped combined list  ->  ffuf. Every AI/static path is
# existence-checked, so nothing bogus reaches ffuf.

# Collect the wordlist paths for a given comma-separated, lowercased tech string.
# Prints one absolute wordlist path per line (base list first, then tech lists).
host_wordlists() {
  local techs="$1" t key rel
  [ -f "$WORDLIST" ] && printf '%s\n' "$WORDLIST"
  # Bo0oM api-endpoints.txt (if present next to base list) for API-ish hosts
  if [ -n "$API_ENDPOINTS_EXTRA" ]; then
    case ",$techs," in *api*|*graphql*|*swagger*|*rest*|*json*) printf '%s\n' "$API_ENDPOINTS_EXTRA" ;; esac
  fi
  [ -n "$SECLISTS_DIR" ] && [ -s "$tech_map_file" ] || return 0
  IFS=',' read -ra _arr <<< "$techs"
  for t in "${_arr[@]}"; do
    [ -z "$t" ] && continue
    while IFS=$'\t' read -r key rel; do
      [ -z "$key" ] && continue
      case "$t" in *"$key"*) [ -f "$SECLISTS_DIR/$rel" ] && printf '%s\n' "$SECLISTS_DIR/$rel" ;; esac
    done < "$tech_map_file"
  done
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

if have ffuf && [ "$fuzz_possible" = 1 ]; then
  set_stage 3 running "0/$alive_count hosts"
  : > "$fuzz_plan_file"
  # host \t comma-tech  (dedup by url)
  hosts_tsv="$(jq -r '[.url, ((.tech // []) | map(ascii_downcase) | join(","))] | @tsv' \
                 "$httpx_json" 2>/dev/null | sort -u)"
  [ -n "$hosts_tsv" ] || hosts_tsv="$(sed 's/$/\t/' "$alive_file")"
  idx=0; total=$(printf '%s\n' "$hosts_tsv" | grep -c .)
  while IFS=$'\t' read -r url techs; do
    [ -z "$url" ] && continue
    idx=$((idx + 1))
    safe="$(printf '%s' "$url" | tr -c 'A-Za-z0-9._-' '_')"
    # assemble this host's combined wordlist
    mapfile -t wls < <(host_wordlists "$techs" | awk 'NF' | awk '!seen[$0]++')
    [ "${#wls[@]}" -eq 0 ] && continue
    combined="$fuzz_dir/wl_${idx}.txt"
    cat "${wls[@]}" 2>/dev/null | sort -u | head -n "$MAX_FUZZ_WORDS" > "$combined"
    names="$(printf '%s\n' "${wls[@]}" | sed 's#.*/##' | paste -sd+ -)"
    ext_flag="$(build_ext_flag "$techs")"
    printf '%s\t%s\t(%s words) exts:[%s]\n' "$url" "$names" "$(wc -l < "$combined")" "$ext_flag" >> "$fuzz_plan_file"
    ST_DETAIL[3]="host $idx/$total  [${techs:-generic}]"; render
    ffuf_args=(-u "$url/FUZZ" -w "$combined" -mc 200,204,301,302,307,401,403
               -of json -o "$fuzz_dir/${idx}_${safe}.json" -s)
    [ -n "$ext_flag" ] && ffuf_args+=(-e "$ext_flag")
    [ "$FFUF_RATE" -gt 0 ] 2>/dev/null && ffuf_args+=(-rate "$FFUF_RATE")
    ffuf "${ffuf_args[@]}" >/dev/null 2>>"$llm_log" || true
    rm -f "$combined"   # keep the run dir small; fuzz_plan.txt records what was used
  done <<< "$hosts_tsv"
  set_stage 3 done "$idx hosts (tech-aware)"
elif ! have ffuf; then
  set_stage 3 skip "ffuf not installed"
else
  set_stage 3 skip "no wordlist / SecLists"
fi

# Step 5: Nuclei
run_stage 4 "$nuclei_file" " hits" \
  nuclei -silent -tags "$nuclei_tags" -severity "$NUCLEI_SEVERITY" \
         -rate-limit "$NUCLEI_RATELIMIT" -l "$alive_file" -o "$nuclei_file"
find_count=$(wc -l < "$nuclei_file" 2>/dev/null || echo 0)
set_stage 4 done "$find_count findings"

# Report header
{
  echo "# 4tail recon report"; echo
  echo "- **Target:** \`$domain\`"
  echo "- **Generated:** $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "- **Subdomains:** $sub_count | **Live:** $alive_count | **Findings:** $find_count"
  echo "- **Nuclei tags:** \`$nuclei_tags\` | **Severity:** \`$NUCLEI_SEVERITY\`"
  echo "- **AI model:** $([ "$AI_ENABLED" = 1 ] && echo "$LLM_MODEL" || echo "disabled")"
  echo "- **SecLists:** ${SECLISTS_DIR:-not found} | **Base wordlist:** \`$WORDLIST\`"; echo
  if [ -s "$fuzz_plan_file" ]; then
    echo "## Fuzzing strategy (tech-aware wordlists)"
    echo
    echo "Each host was fuzzed with the base list plus SecLists lists matched to its detected tech:"
    echo
    echo '| Host | Wordlists |'
    echo '|------|-----------|'
    while IFS=$'\t' read -r h names words; do
      echo "| \`$h\` | $names $words |"
    done < "$fuzz_plan_file"
    echo
  fi
} > "$report_file"

# Step 6: AI triage
if [ "$AI_ENABLED" = "1" ] && [ "$find_count" -gt 0 ]; then
  sorted_findings="$(
    for sev in critical high medium low info; do grep -iE "\[$sev\]" "$nuclei_file"; done
    grep -viE '\[(critical|high|medium|low|info)\]' "$nuclei_file"
  )"
  [ -z "$sorted_findings" ] && sorted_findings="$(cat "$nuclei_file")"
  sys_triage='You are a senior security analyst on an AUTHORIZED bug-bounty engagement.
Given a technology brief and severity-sorted nuclei output, produce a concise report in
GitHub-flavored Markdown with exactly these sections:
"## Executive summary" (2-4 sentences),
"## Prioritised findings" (a table: Severity | Host | Issue | Why it matters | Next step),
"## Recommended manual follow-ups" (short bullet list).
Use ONLY the provided data - do not invent findings.'
  triage_out="$(mktemp)"
  run_ai_stage 5 "$sys_triage" "Target: $domain

=== technology brief ===
$(head -c 4000 "$tech_brief")

=== findings (severity-sorted) ===
$(printf '%s\n' "$sorted_findings" | head -n 120 | head -c 14000)" "$triage_out"
  if [ -s "$triage_out" ]; then
    cat "$triage_out" >> "$report_file"; set_stage 5 done "report.md written"
  else
    { echo "## Raw findings"; echo '```'; cat "$nuclei_file"; echo '```'; } >> "$report_file"
    set_stage 5 warn "AI failed, raw findings saved"
  fi
  rm -f "$triage_out"
else
  {
    echo "## Findings"
    if [ "$find_count" -gt 0 ]; then echo '```'; cat "$nuclei_file"; echo '```'; else echo "_No nuclei findings._"; fi
  } >> "$report_file"
  set_stage 5 skip "$([ "$AI_ENABLED" = 1 ] && echo "no findings" || echo "AI off")"
fi

# Final summary
if [ "$TUI" = 1 ]; then
  render
  printf '\n %s✔ done in %ss%s  →  %s%s%s\n' "$c_green" "$((SECONDS-started))" "$c_reset" "$c_cyan" "$report_file" "$c_reset"
else
  ok "Done in $((SECONDS-started))s. Report: $report_file"
fi
