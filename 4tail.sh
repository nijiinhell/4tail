#!/usr/bin/env bash
#
# 4tail - AI-assisted recon pipeline for AUTHORIZED bug-bounty / pentest work.
#
# Pipeline: subfinder -> httpx (tech detect) -> [AI plans the scan]
#           -> ffuf (content discovery) -> nuclei -> [AI triages findings].
#
# The AI steps use any OpenAI-compatible endpoint. Defaults target Together AI
# with a low-cost GLM model, and are tuned to keep token spend small:
#   * inputs are AGGREGATED (tech frequency brief) instead of raw host dumps,
#     so cost stays roughly flat no matter how big the target is;
#   * outputs are capped with a small max_tokens;
#   * AI is skipped entirely when there's nothing useful to reason about.
#
# USE ONLY against targets you are explicitly authorised to test.

set -u
set -o pipefail

# ---------------------------------------------------------------------------
# LLM configuration (OpenAI-compatible; defaults = Together AI + cheap GLM)
# ---------------------------------------------------------------------------
# API key: TOGETHER_API_KEY preferred, LLM_API_KEY accepted as an alias.
LLM_API_KEY="${TOGETHER_API_KEY:-${LLM_API_KEY:-}}"
LLM_BASE_URL="${LLM_BASE_URL:-https://api.together.xyz/v1}"
# Cheap default. Override with LLM_MODEL / -m. Browse IDs at together.ai/models
# (e.g. zai-org/GLM-4.6, zai-org/GLM-4.5-Air-FP8 for even lower cost).
LLM_MODEL="${LLM_MODEL:-zai-org/GLM-4.6}"
LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-1200}"   # small cap -> low output cost
LLM_TEMPERATURE="${LLM_TEMPERATURE:-0.2}"
LLM_TIMEOUT="${LLM_TIMEOUT:-90}"
LLM_RETRIES="${LLM_RETRIES:-2}"

# ---------------------------------------------------------------------------
# Scan configuration (override via environment or flags)
# ---------------------------------------------------------------------------
WORDLIST="${WORDLIST:-/usr/share/seclists/Discovery/Web-Content/common.txt}"
DEFAULT_NUCLEI_TAGS="${DEFAULT_NUCLEI_TAGS:-cves,exposures,misconfiguration,tech,default-login,takeover}"
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-critical,high,medium,low}"
NUCLEI_RATELIMIT="${NUCLEI_RATELIMIT:-150}"   # requests/sec, be a good citizen
HTTPX_THREADS="${HTTPX_THREADS:-50}"
OUTDIR="${OUTDIR:-}"
ASSUME_YES="${ASSUME_YES:-0}"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
c_reset=$'\033[0m'; c_blue=$'\033[1;34m'; c_green=$'\033[1;32m'
c_yellow=$'\033[1;33m'; c_red=$'\033[1;31m'; c_dim=$'\033[2m'
log()  { printf '%s[*]%s %s\n' "$c_blue"   "$c_reset" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$c_green"  "$c_reset" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_yellow" "$c_reset" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$c_red"    "$c_reset" "$*" >&2; }
ai()   { printf '%s[ai]%s %s\n' "$c_yellow" "$c_reset" "$*"; }

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
while getopts ":w:o:t:S:m:yh" opt; do
  case "$opt" in
    w) WORDLIST="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    t) DEFAULT_NUCLEI_TAGS="$OPTARG" ;;
    S) NUCLEI_SEVERITY="$OPTARG" ;;
    m) LLM_MODEL="$OPTARG" ;;
    y) ASSUME_YES=1 ;;
    h) usage; exit 0 ;;
    \?) err "Unknown option: -$OPTARG"; usage; exit 1 ;;
    :)  err "Option -$OPTARG requires an argument"; exit 1 ;;
  esac
done
shift $((OPTIND - 1))

domain="${1:-}"
if [ -z "$domain" ]; then err "No target domain provided."; usage; exit 1; fi
# Basic sanity check on the domain to avoid accidental garbage/URLs.
if ! printf '%s' "$domain" | grep -qE '^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$'; then
  err "That doesn't look like a bare domain (got: '$domain'). Use e.g. example.com"
  exit 1
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
  warn "No API key (TOGETHER_API_KEY) - AI steps disabled, using static defaults."
  AI_ENABLED=0
elif ! have curl || ! have jq; then
  warn "curl and jq are required for AI steps - disabling AI, using defaults."
  AI_ENABLED=0
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
log "Results -> $OUTDIR"

# ---------------------------------------------------------------------------
# LLM helper: ai_call <system> <user>  -> prints model text, or fails.
# OpenAI-compatible chat/completions with retry + backoff. Cost-conscious:
# low max_tokens, low temperature. Never logs the API key.
# ---------------------------------------------------------------------------
ai_call() {
  local system="$1" user="$2" payload response text attempt=0 delay=2
  payload="$(jq -n \
    --arg model "$LLM_MODEL" --arg sys "$system" --arg usr "$user" \
    --argjson max "$LLM_MAX_TOKENS" --argjson temp "$LLM_TEMPERATURE" \
    '{model:$model, max_tokens:$max, temperature:$temp,
      messages:[{role:"system",content:$sys},{role:"user",content:$usr}]}')" || return 1

  while :; do
    attempt=$((attempt + 1))
    response="$(curl -sS --max-time "$LLM_TIMEOUT" "$LLM_BASE_URL/chat/completions" \
      -H "content-type: application/json" \
      -H "authorization: Bearer $LLM_API_KEY" \
      -d "$payload" 2>/dev/null)"

    if [ -n "$response" ] && ! echo "$response" | jq -e '.error' >/dev/null 2>&1; then
      text="$(echo "$response" | jq -r '.choices[0].message.content // empty' 2>/dev/null)"
      if [ -n "$text" ]; then printf '%s' "$text"; return 0; fi
    fi

    if [ "$attempt" -gt "$LLM_RETRIES" ]; then
      local msg; msg="$(echo "$response" | jq -r '.error.message // .error // "no/empty response"' 2>/dev/null)"
      warn "LLM call failed after $attempt attempts: ${msg:-unknown}"
      return 1
    fi
    sleep "$delay"; delay=$((delay * 2))
  done
}

# ---------------------------------------------------------------------------
# Step 1: Subdomain enumeration
# ---------------------------------------------------------------------------
log "Enumerating subdomains for $domain ..."
subfinder -silent -d "$domain" -o "$subdomains_file" 2>/dev/null || warn "subfinder error."
sub_count=$(wc -l < "$subdomains_file" 2>/dev/null || echo 0)
ok "Subdomains: $sub_count"
[ "$sub_count" -eq 0 ] && { warn "No subdomains; stopping."; exit 0; }

# ---------------------------------------------------------------------------
# Step 2: Live-host probing + tech detection
# ---------------------------------------------------------------------------
log "Probing live hosts + detecting tech (httpx) ..."
httpx -silent -json -tech-detect -status-code -title -web-server \
      -threads "$HTTPX_THREADS" -l "$subdomains_file" -o "$httpx_json" 2>/dev/null \
      || warn "httpx error."
if [ -s "$httpx_json" ]; then
  jq -r '.url' "$httpx_json" 2>/dev/null | sort -u > "$alive_file"
else
  : > "$alive_file"
fi
alive_count=$(wc -l < "$alive_file" 2>/dev/null || echo 0)
ok "Live hosts: $alive_count"
[ "$alive_count" -eq 0 ] && { warn "No live hosts; stopping."; exit 0; }

# Cost-frugal AGGREGATE brief: technology + server + status frequencies.
# This is what we feed the AI (small & bounded), NOT the raw host list.
build_tech_brief() {
  {
    echo "== technologies (count) =="
    jq -r '(.tech // [])[]' "$httpx_json" 2>/dev/null | sort | uniq -c | sort -rn | head -40
    echo "== web servers (count) =="
    jq -r '.webserver // empty' "$httpx_json" 2>/dev/null | sort | uniq -c | sort -rn | head -15
    echo "== status codes (count) =="
    jq -r '.status_code // empty' "$httpx_json" 2>/dev/null | sort | uniq -c | sort -rn
    echo "== notable hosts (admin/login/api/dev) =="
    jq -r '.url' "$httpx_json" 2>/dev/null \
      | grep -iE 'admin|login|portal|api|dev|staging|test|git|jenkins|grafana|kibana|vpn' \
      | sort -u | head -25
  } > "$tech_brief"
}
if [ -s "$httpx_json" ]; then build_tech_brief; else cp "$alive_file" "$tech_brief"; fi

# ---------------------------------------------------------------------------
# Step 3: AI plans the scan (chooses nuclei tags from the tech brief)
# Guardrail: intersect the AI's tags with a known allowlist so a hallucinated
# tag can't silently make nuclei scan nothing. Fall back to defaults if needed.
# ---------------------------------------------------------------------------
NUCLEI_TAG_ALLOWLIST="cves,cve,exposures,exposure,misconfiguration,misconfig,tech,\
default-login,takeover,subdomain-takeover,panel,login,exposed-panels,config,\
backup,files,logs,debug,git,svn,env,sqli,xss,ssrf,lfi,rce,injection,auth-bypass,\
wordpress,wp-plugin,joomla,drupal,magento,laravel,django,spring,struts,\
apache,nginx,tomcat,iis,php,jira,confluence,jenkins,gitlab,grafana,kibana,\
elasticsearch,kubernetes,docker,aws,azure,gcp,ssl,tls,cors,headers,\
oauth,jwt,api,graphql,swagger,firebase,s3,redis,mongodb,mysql,postgres"

sanitize_tags() {
  # stdin: comma/space separated tags -> stdout: allowlisted, deduped, comma list
  tr ',[:space:]' '\n\n' | tr 'A-Z' 'a-z' | grep -oE '[a-z0-9._-]+' \
    | while read -r t; do
        case ",${NUCLEI_TAG_ALLOWLIST//[[:space:]]/}," in *",$t,"*) echo "$t";; esac
      done | awk '!seen[$0]++' | paste -sd, -
}

nuclei_tags="$DEFAULT_NUCLEI_TAGS"
if [ "$AI_ENABLED" = "1" ] && [ -s "$tech_brief" ]; then
  ai "Planning scan with $LLM_MODEL (choosing nuclei tags from detected tech) ..."
  sys_plan='You assist AUTHORIZED bug-bounty recon. Given an aggregated brief of the
technologies, servers and notable paths observed on live hosts, choose the most
relevant nuclei tags to scan with. Reply with ONLY a single comma-separated list of
lowercase nuclei tags (4-12 tags), no prose, no code fences. Always include high-value
general tags (cves, exposures, misconfiguration) plus tags matched to the observed stack.'
  raw_plan="$(ai_call "$sys_plan" "Target: $domain
Live hosts: $alive_count

$(head -c 6000 "$tech_brief")")" || raw_plan=""

  clean_plan="$(printf '%s' "$raw_plan" | sanitize_tags)"
  # require at least 2 allowlisted tags, else keep defaults
  if [ -n "$clean_plan" ] && [ "$(printf '%s' "$clean_plan" | tr ',' '\n' | grep -c .)" -ge 2 ]; then
    nuclei_tags="$clean_plan"
    ok "AI-selected tags: $nuclei_tags"
    printf '%s\n' "$nuclei_tags" > "$OUTDIR/ai_scan_plan.txt"
  else
    warn "AI plan unusable; using defaults: $nuclei_tags"
  fi
else
  log "Nuclei tags (default): $nuclei_tags"
fi

# ---------------------------------------------------------------------------
# Step 4: Content discovery (ffuf) - optional
# ---------------------------------------------------------------------------
if have ffuf; then
  if [ -f "$WORDLIST" ]; then
    log "Content discovery with ffuf (wordlist: $WORDLIST) ..."
    idx=0
    while read -r url; do
      [ -z "$url" ] && continue
      idx=$((idx + 1))
      safe="$(printf '%s' "$url" | tr -c 'A-Za-z0-9._-' '_')"
      printf '%s    fuzzing %s%s\n' "$c_dim" "$url" "$c_reset"
      ffuf -u "$url/FUZZ" -w "$WORDLIST" -mc 200,204,301,302,307,401,403 \
           -of json -o "$fuzz_dir/${idx}_${safe}.json" -s 2>/dev/null \
           || warn "ffuf failed for $url"
    done < "$alive_file"
    ok "Fuzzing results -> $fuzz_dir"
  else
    warn "Wordlist not found ($WORDLIST) - skipping fuzzing. Set -w / WORDLIST."
  fi
fi

# ---------------------------------------------------------------------------
# Step 5: Vulnerability scanning (nuclei)
# ---------------------------------------------------------------------------
log "Scanning with nuclei (tags: $nuclei_tags | severity: $NUCLEI_SEVERITY) ..."
nuclei -silent -tags "$nuclei_tags" -severity "$NUCLEI_SEVERITY" \
       -rate-limit "$NUCLEI_RATELIMIT" -l "$alive_file" -o "$nuclei_file" 2>/dev/null \
       || warn "nuclei error."
find_count=$(wc -l < "$nuclei_file" 2>/dev/null || echo 0)
ok "Nuclei findings: $find_count"

# ---------------------------------------------------------------------------
# Step 6: AI triage -> prioritised report
# Cost technique: pre-sort findings by severity and cap what we send.
# ---------------------------------------------------------------------------
{
  echo "# 4tail recon report"
  echo
  echo "- **Target:** \`$domain\`"
  echo "- **Generated:** $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "- **Subdomains:** $sub_count | **Live:** $alive_count | **Findings:** $find_count"
  echo "- **Nuclei tags:** \`$nuclei_tags\` | **Severity:** \`$NUCLEI_SEVERITY\`"
  echo "- **AI model:** $([ "$AI_ENABLED" = 1 ] && echo "$LLM_MODEL" || echo "disabled")"
  echo
} > "$report_file"

if [ "$AI_ENABLED" = "1" ] && [ "$find_count" -gt 0 ]; then
  ai "Triaging findings with $LLM_MODEL ..."
  # severity-sorted, capped subset (keeps tokens - and cost - bounded)
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
Use ONLY the provided data - do not invent findings. Be specific and practical.'
  triage="$(ai_call "$sys_triage" "Target: $domain

=== technology brief ===
$(head -c 4000 "$tech_brief")

=== findings (severity-sorted) ===
$(printf '%s\n' "$sorted_findings" | head -n 120 | head -c 14000)")" || triage=""

  if [ -n "$triage" ]; then
    printf '%s\n' "$triage" >> "$report_file"
    ok "AI triage written."
  else
    warn "AI triage failed; appending raw findings."
    { echo "## Raw findings"; echo '```'; cat "$nuclei_file"; echo '```'; } >> "$report_file"
  fi
else
  {
    echo "## Findings"
    if [ "$find_count" -gt 0 ]; then echo '```'; cat "$nuclei_file"; echo '```'
    else echo "_No nuclei findings._"; fi
  } >> "$report_file"
fi

echo
ok "Done. Report: $report_file"
