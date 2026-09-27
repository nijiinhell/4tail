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
# Strip stray whitespace/newlines (a trailing newline corrupts the auth header -> 401).
LLM_API_KEY="$(printf '%s' "$LLM_API_KEY" | tr -d '[:space:]')"
LLM_BASE_URL="${LLM_BASE_URL:-https://api.together.xyz/v1}"
LLM_MODEL="${LLM_MODEL:-zai-org/GLM-5.3}"   # base default for every role
LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-4000}"    # reasoning models spend tokens thinking; leave room for real output
LLM_TEMPERATURE="${LLM_TEMPERATURE:-0.2}"
LLM_TIMEOUT="${LLM_TIMEOUT:-300}"
LLM_RETRIES="${LLM_RETRIES:-2}"

# --- Smart model routing (per-task "swarm"-style switching) -----------------
LLM_MODEL_PLAN="${LLM_MODEL_PLAN:-}"        # scan planner; default = LLM_MODEL
LLM_MODEL_TRIAGE="${LLM_MODEL_TRIAGE:-}"    # findings analyst; default = LLM_MODEL
LLM_MAX_TOKENS_PLAN="${LLM_MAX_TOKENS_PLAN:-4000}"   # headroom for reasoning models (GLM/DeepSeek think first)
LLM_MAX_TOKENS_TRIAGE="${LLM_MAX_TOKENS_TRIAGE:-}"  # default = LLM_MAX_TOKENS
LLM_FALLBACK_MODELS="${LLM_FALLBACK_MODELS:-}"       # tried in order if primary fails

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
MAX_FUZZ_WORDS="${MAX_FUZZ_WORDS:-60000}" # cap per-host combined wordlist size
MAX_FUZZ_HOSTS="${MAX_FUZZ_HOSTS:-0}"     # cap number of hosts to fuzz (0 = all)
SKIP_FUZZ="${SKIP_FUZZ:-0}"               # 1 = skip content discovery entirely (nuclei-only)
SKIP_CDN_FUZZ="${SKIP_CDN_FUZZ:-1}"       # 1 = don't fuzz CDN/WAF edges (cloudfront, cloudflare, …)
EXTENSIONS="${EXTENSIONS:-}"              # explicit ffuf -e list (overrides tech-aware exts)
MAX_EXTS="${MAX_EXTS:-10}"                # cap on per-host extensions (each multiplies requests)
FFUF_RATE="${FFUF_RATE:-0}"              # ffuf requests/sec (0 = unlimited)
FETCH_FUZZTXT="${FETCH_FUZZTXT:-0}"      # 1 = download Bo0oM/fuzz.txt if no base list found
DEFAULT_NUCLEI_TAGS="${DEFAULT_NUCLEI_TAGS:-cves,exposures,misconfiguration,tech,default-login,takeover}"
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-critical,high,medium,low}"
NUCLEI_RATELIMIT="${NUCLEI_RATELIMIT:-150}"
HTTPX_THREADS="${HTTPX_THREADS:-50}"
OUTDIR="${OUTDIR:-}"
RESUME="${RESUME:-0}"      # 1 = continue a previous run (reuse finished stages)
ASSUME_YES="${ASSUME_YES:-0}"
NO_TUI="${NO_TUI:-0}"
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

while getopts ":w:o:t:S:m:M:b:RqyPDh" opt; do
  case "$opt" in
    w) WORDLIST="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    t) DEFAULT_NUCLEI_TAGS="$OPTARG" ;;
    S) NUCLEI_SEVERITY="$OPTARG" ;;
    m) LLM_MODEL="$OPTARG" ;;
    M) MAX_FUZZ_HOSTS="$OPTARG" ;;
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
LLM_MAX_TOKENS_TRIAGE="${LLM_MAX_TOKENS_TRIAGE:-$LLM_MAX_TOKENS}"

domain="${1:-}"
if [ "$DOCTOR" != 1 ]; then
  if [ -z "$domain" ]; then err "No target domain provided."; usage; exit 1; fi
  if ! printf '%s' "$domain" | grep -qE '^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$'; then
    err "That doesn't look like a bare domain (got: '$domain'). Use e.g. example.com"; exit 1
  fi
fi

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
  fuzz_plan_file="$OUTDIR/fuzz_plan.txt"        # host <TAB> wordlists used
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
  printf ' %s╭─ 4tail ───────────────────────────────────────%s\033[K\n' "$c_cyan" "$c_reset"
  printf ' %s│%s %s\033[K\n' "$c_cyan" "$c_reset" "$info"
  local i d dw=$((width - 24))
  for i in "${!ST_LABEL[@]}"; do
    d="${ST_DETAIL[$i]:-}"
    [ "$dw" -gt 4 ] && [ "${#d}" -gt "$dw" ] && d="${d:0:dw}…"
    printf ' %s│%s  %s  %-13s %s%s%s\033[K\n' \
      "$c_cyan" "$c_reset" "$(icon "${ST_STATE[$i]}")" "${ST_LABEL[$i]}" \
      "$c_dim" "$d" "$c_reset"
  done
  printf ' %s╰──────────────────────────────────────────────%s\033[K\n' "$c_cyan" "$c_reset"
  panel_drawn=1
}

set_stage() { ST_STATE[$1]="$2"; [ -n "${3+x}" ] && ST_DETAIL[$1]="$3"; render; }

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

  dr_head "Optional tools"
  for t in ffuf curl jq anew; do
    if have "$t"; then dr_pass "$t found"; else dr_warn "$t not found ($([ "$t" = ffuf ] && echo 'fuzzing skipped' || echo 'AI/dedup limited'))"; fi
  done

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

[ "$TUI" = 1 ] && { printf '\033[?25l'; render; }   # hide cursor + first paint

# ===========================================================================
# PIPELINE
# ===========================================================================

# resume helper: was this stage already completed?
done_marker() { [ "$RESUME" = 1 ] && [ -f "$OUTDIR/.done_$1" ]; }

# Step 1: Subdomains
if done_marker subs && [ -s "$subdomains_file" ]; then
  set_stage 0 done "$(wc -l <"$subdomains_file") subs (resumed)"
else
  run_stage 0 "$subdomains_file" " subs" subfinder -silent -d "$domain" -o "$subdomains_file"
  touch "$OUTDIR/.done_subs"
fi
sub_count=$(wc -l < "$subdomains_file" 2>/dev/null || echo 0)
if [ "$sub_count" -eq 0 ]; then
  set_stage 0 warn "none found"; [ "$TUI" = 1 ] || warn "No subdomains; stopping."; exit 0
fi
set_stage 0 done "$sub_count subs$(done_marker subs && echo ' (resumed)')"

# Step 2: Live hosts + tech detection
if done_marker httpx && [ -s "$httpx_json" ]; then
  set_stage 1 done "resumed"
else
  run_stage 1 "$httpx_json" " live" \
    httpx -silent -json -tech-detect -status-code -title -web-server \
          -threads "$HTTPX_THREADS" -l "$subdomains_file" -o "$httpx_json"
  touch "$OUTDIR/.done_httpx"
fi
if [ -s "$httpx_json" ]; then jq -r '.url' "$httpx_json" 2>/dev/null | sort -u > "$alive_file"; else : > "$alive_file"; fi
alive_count=$(wc -l < "$alive_file" 2>/dev/null || echo 0)
if [ "$alive_count" -eq 0 ]; then
  set_stage 1 warn "none live"; [ "$TUI" = 1 ] || warn "No live hosts; stopping."; exit 0
fi
set_stage 1 done "$alive_count live$(done_marker httpx && echo ' (resumed)')"

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

nuclei_tags="$DEFAULT_NUCLEI_TAGS"
if [ "$RESUME" = 1 ] && [ -s "$OUTDIR/ai_scan_plan.txt" ]; then
  nuclei_tags="$(cat "$OUTDIR/ai_scan_plan.txt")"
  set_stage 2 done "$nuclei_tags (resumed)"
elif [ "$AI_ENABLED" = "1" ] && ! budget_ok; then
  set_stage 2 skip "budget reached ($(cost_fmt)), using defaults"
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
  run_ai_stage 2 "$LLM_MODEL_PLAN" "$LLM_MAX_TOKENS_PLAN" "$sys_plan" "Target: $domain
Live hosts: $alive_count
SecLists root: ${SECLISTS_DIR:-<not installed>}

$(head -c 12000 "$tech_brief")" "$plan_out"

  # Reasoning models (GLM/DeepSeek) often wrap JSON in ``` fences or prepend
  # "thinking". Extract the first {...} object so jq gets clean JSON.
  plan_json="$(tr -d '\r' < "$plan_out" | tr '\n' ' ' | grep -oE '\{.*\}' | head -1)"
  [ -z "$plan_json" ] && plan_json="$(cat "$plan_out")"

  # --- parse nuclei tags (JSON first, then salvage raw text) ---
  ai_tags="$(printf '%s' "$plan_json" | jq -r '.nuclei_tags[]?' 2>/dev/null | paste -sd, -)"
  [ -z "$ai_tags" ] && ai_tags="$(cat "$plan_out")"
  clean_plan="$(printf '%s' "$ai_tags" | sanitize_tags)"

  # --- parse wordlist map (append to tech map; heavy generic lists filtered out,
  #     existence checked at fuzz time) ---
  if [ -n "$SECLISTS_DIR" ]; then
    printf '%s' "$plan_json" \
       | jq -r '.wordlists // {} | to_entries[]? | (.key|ascii_downcase) as $k | .value[]? | "\($k)\t\(.)"' 2>/dev/null \
       | grep -viE 'raft-|big\.txt|directory-list|combined_|dirbuster|/all\.txt' \
       >> "$tech_map_file" || true
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
      # skip heavy/generic lists (bounty scans prefer small tech-specific lists)
      case "$rel" in *raft-*|*big.txt|*directory-list*|*combined_*|*dirbuster*|*/all.txt) continue ;; esac
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

CDN_RE='cloudfront|cloudflare|akamai|fastly|imperva|incapsula|sucuri|edgecast|stackpath|azure front door'
if [ "$SKIP_FUZZ" = 1 ]; then
  set_stage 3 skip "disabled (-q / SKIP_FUZZ)"
elif ! have ffuf; then
  set_stage 3 skip "ffuf not installed"
elif [ "$fuzz_possible" != 1 ]; then
  set_stage 3 skip "no wordlist / SecLists"
elif [ "$RESUME" = 1 ] && [ -f "$OUTDIR/.done_fuzz" ]; then
  set_stage 3 done "$(grep -c . "$fuzz_plan_file" 2>/dev/null || echo 0) hosts (resumed)"
else
  set_stage 3 running "0 hosts"
  [ "$RESUME" = 1 ] || : > "$fuzz_plan_file"   # keep prior progress when resuming
  # host \t comma-tech  (dedup by url)
  hosts_tsv="$(jq -r '[.url, ((.tech // []) | map(ascii_downcase) | join(","))] | @tsv' \
                 "$httpx_json" 2>/dev/null | sort -u)"
  [ -n "$hosts_tsv" ] || hosts_tsv="$(sed 's/$/\t/' "$alive_file")"
  total=$(printf '%s\n' "$hosts_tsv" | grep -c .)
  cap="$total"
  [ "$MAX_FUZZ_HOSTS" -gt 0 ] 2>/dev/null && cap="$MAX_FUZZ_HOSTS"
  fuzzed=0; skipped_cdn=0; resumed=0
  while IFS=$'\t' read -r url techs; do
    [ -z "$url" ] && continue
    safe="$(printf '%s' "$url" | tr -c 'A-Za-z0-9._-' '_')"
    # resume: skip hosts already fuzzed in a previous run
    if [ "$RESUME" = 1 ] && [ -f "$fuzz_dir/${safe}.json" ]; then resumed=$((resumed + 1)); continue; fi
    # skip CDN/WAF edges - fuzzing shared infrastructure is noise
    if [ "$SKIP_CDN_FUZZ" = 1 ] && printf '%s' "$techs" | grep -qiE "$CDN_RE"; then
      skipped_cdn=$((skipped_cdn + 1)); continue
    fi
    # stop once the host cap is reached
    if [ "$MAX_FUZZ_HOSTS" -gt 0 ] 2>/dev/null && [ "$fuzzed" -ge "$MAX_FUZZ_HOSTS" ]; then break; fi
    fuzzed=$((fuzzed + 1))
    mapfile -t wls < <(host_wordlists "$techs" | awk 'NF' | awk '!seen[$0]++')
    [ "${#wls[@]}" -eq 0 ] && { fuzzed=$((fuzzed - 1)); continue; }
    combined="$fuzz_dir/.wl_tmp.txt"
    cat "${wls[@]}" 2>/dev/null | sort -u | head -n "$MAX_FUZZ_WORDS" > "$combined"
    names="$(printf '%s\n' "${wls[@]}" | sed 's#.*/##' | paste -sd+ -)"
    ext_flag="$(build_ext_flag "$techs")"
    printf '%s\t%s\t(%s words) exts:[%s]\n' "$url" "$names" "$(wc -l < "$combined")" "$ext_flag" >> "$fuzz_plan_file"
    ffuf_args=(-u "$url/FUZZ" -w "$combined" -mc 200,204,301,302,307,401,403
               -of json -o "$fuzz_dir/${safe}.json" -s)
    [ -n "$ext_flag" ] && ffuf_args+=(-e "$ext_flag")
    [ "$FFUF_RATE" -gt 0 ] 2>/dev/null && ffuf_args+=(-rate "$FFUF_RATE")
    if [ "$TUI" = 1 ]; then
      # background ffuf so the dashboard keeps ticking while a host is fuzzed
      ffuf "${ffuf_args[@]}" >/dev/null 2>>"$llm_log" & fpid=$!
      fs=$SECONDS
      while kill -0 "$fpid" 2>/dev/null; do
        ST_DETAIL[3]="host $fuzzed/$cap [${techs:-generic}] $((SECONDS-fs))s${skipped_cdn:+ cdn:$skipped_cdn}${resumed:+ done:$resumed}"
        render; sleep 0.25
      done
      wait "$fpid" 2>/dev/null || true
    else
      log "Fuzzing $fuzzed/$cap: $url"
      ffuf "${ffuf_args[@]}" >/dev/null 2>>"$llm_log" || true
    fi
    rm -f "$combined"
  done <<< "$hosts_tsv"
  # mark complete only if we weren't cut short by the cap
  [ "$MAX_FUZZ_HOSTS" -gt 0 ] 2>/dev/null || touch "$OUTDIR/.done_fuzz"
  set_stage 3 done "$fuzzed fuzzed$([ "$resumed" -gt 0 ] && echo ", $resumed resumed")$([ "$skipped_cdn" -gt 0 ] && echo ", $skipped_cdn CDN skipped")"
fi

# Step 5: Nuclei
if done_marker nuclei && [ -f "$nuclei_file" ]; then
  set_stage 4 done "$(wc -l <"$nuclei_file") findings (resumed)"
else
  run_stage 4 "$nuclei_file" " hits" \
    nuclei -silent -tags "$nuclei_tags" -severity "$NUCLEI_SEVERITY" \
           -rate-limit "$NUCLEI_RATELIMIT" -l "$alive_file" -o "$nuclei_file"
  touch "$OUTDIR/.done_nuclei"
fi
find_count=$(wc -l < "$nuclei_file" 2>/dev/null || echo 0)
set_stage 4 done "$find_count findings$(done_marker nuclei && echo ' (resumed)')"

# Report header
{
  echo "# 4tail recon report"; echo
  echo "- **Target:** \`$domain\`"
  echo "- **Generated:** $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "- **Subdomains:** $sub_count | **Live:** $alive_count | **Findings:** $find_count"
  echo "- **Nuclei tags:** \`$nuclei_tags\` | **Severity:** \`$NUCLEI_SEVERITY\`"
  echo "- **AI models:** $([ "$AI_ENABLED" = 1 ] && echo "plan=$LLM_MODEL_PLAN, triage=$LLM_MODEL_TRIAGE" || echo "disabled")"
  [ "$AI_ENABLED" = 1 ] && echo "- **Estimated AI spend:** $(cost_fmt)$([ "${LLM_BUDGET_USD:-0}" != 0 ] && echo " (budget \$$LLM_BUDGET_USD)")"
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
if [ "$AI_ENABLED" = "1" ] && [ "$find_count" -gt 0 ] && ! budget_ok; then
  { echo "## Findings (budget reached, no AI triage)"; echo '```'; cat "$nuclei_file"; echo '```'; } >> "$report_file"
  set_stage 5 skip "budget reached ($(cost_fmt))"
elif [ "$AI_ENABLED" = "1" ] && [ "$find_count" -gt 0 ]; then
  sorted_findings="$(
    for sev in critical high medium low info; do grep -iE "\[$sev\]" "$nuclei_file"; done
    grep -viE '\[(critical|high|medium|low|info)\]' "$nuclei_file"
  )"
  [ -z "$sorted_findings" ] && sorted_findings="$(cat "$nuclei_file")"
  sys_triage='You are a senior security analyst on an AUTHORIZED bug-bounty engagement.
Given a technology brief and severity-sorted nuclei output, produce a thorough report in
GitHub-flavored Markdown with exactly these sections:
"## Executive summary" (3-5 sentences),
"## Prioritised findings" (a table: Severity | Host | Issue | Why it matters | Next step),
"## Attack surface notes" (grouped observations by technology/host cluster),
"## Recommended manual follow-ups" (bullet list, concrete and specific).
Use ONLY the provided data - do not invent findings.'
  triage_out="$(mktemp)"
  run_ai_stage 5 "$LLM_MODEL_TRIAGE" "$LLM_MAX_TOKENS_TRIAGE" "$sys_triage" "Target: $domain

=== technology brief ===
$(head -c 8000 "$tech_brief")

=== findings (severity-sorted) ===
$(printf '%s\n' "$sorted_findings" | head -n 400 | head -c 40000)" "$triage_out"
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
spend_note=""; [ "$AI_ENABLED" = 1 ] && spend_note="  ·  AI spend ~$(cost_fmt)"
if [ "$TUI" = 1 ]; then
  render
  printf '\n %s✔ done in %ss%s%s  →  %s%s%s\n' "$c_green" "$((SECONDS-started))" "$c_reset" "$spend_note" "$c_cyan" "$report_file" "$c_reset"
else
  ok "Done in $((SECONDS-started))s.$spend_note Report: $report_file"
fi
