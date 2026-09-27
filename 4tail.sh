#!/usr/bin/env bash
#
# 4tail - AI-assisted recon pipeline for authorized bug-bounty / pentest work.
#
# Pipeline: subfinder -> httpx (with tech detection) -> [AI decides scan plan]
#           -> ffuf (content discovery) -> nuclei -> [AI triages findings].
#
# The AI steps use the Anthropic API (Claude) to make two decisions:
#   1. Which nuclei tags to run, given the technologies httpx detected.
#   2. How to prioritise / triage the raw findings into an actionable report.
#
# Both AI steps are optional: if no ANTHROPIC_API_KEY (or no curl/jq) is
# available, the script falls back to sensible static defaults and still runs.
#
# USE ONLY against targets you are explicitly authorised to test.

set -u
set -o pipefail

# ---------------------------------------------------------------------------
# Configuration (override via environment variables)
# ---------------------------------------------------------------------------
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"
ANTHROPIC_MODEL="${ANTHROPIC_MODEL:-claude-opus-5}"
ANTHROPIC_VERSION="${ANTHROPIC_VERSION:-2023-06-01}"
ANTHROPIC_BASE_URL="${ANTHROPIC_BASE_URL:-https://api.anthropic.com}"

# Wordlist for ffuf. Override with WORDLIST=/path/to/list.txt
WORDLIST="${WORDLIST:-/usr/share/seclists/Discovery/Web-Content/common.txt}"

# Default nuclei tags used when the AI step is unavailable.
DEFAULT_NUCLEI_TAGS="${DEFAULT_NUCLEI_TAGS:-cves,exposures,misconfiguration,tech}"

OUTDIR="${OUTDIR:-}"          # results directory (default: 4tail_<domain>_<ts>)
ASSUME_YES="${ASSUME_YES:-0}" # set to 1 (or pass -y) to skip authorisation prompt

# ---------------------------------------------------------------------------
# Pretty output helpers
# ---------------------------------------------------------------------------
c_reset=$'\033[0m'; c_blue=$'\033[1;34m'; c_green=$'\033[1;32m'
c_yellow=$'\033[1;33m'; c_red=$'\033[1;31m'; c_dim=$'\033[2m'

log()  { printf '%s[*]%s %s\n' "$c_blue"  "$c_reset" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$c_green" "$c_reset" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_yellow" "$c_reset" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$c_red"   "$c_reset" "$*" >&2; }
ai()   { printf '%s[ai]%s %s\n' "$c_yellow" "$c_reset" "$*"; }

usage() {
  cat <<EOF
4tail - AI-assisted recon for authorized security testing

Usage: $0 [options] <target_domain>

Options:
  -w <file>   Wordlist for ffuf         (env WORDLIST)
  -o <dir>    Output directory          (env OUTDIR)
  -t <tags>   Fallback nuclei tags      (env DEFAULT_NUCLEI_TAGS)
  -m <model>  Anthropic model           (env ANTHROPIC_MODEL, default $ANTHROPIC_MODEL)
  -y          Skip the authorization confirmation prompt
  -h          Show this help

Environment:
  ANTHROPIC_API_KEY   Enables the AI decision + triage steps. If unset, the
                      script runs with static defaults (no AI).

Example:
  ANTHROPIC_API_KEY=sk-ant-... $0 -w wordlist.txt example.com
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while getopts ":w:o:t:m:yh" opt; do
  case "$opt" in
    w) WORDLIST="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    t) DEFAULT_NUCLEI_TAGS="$OPTARG" ;;
    m) ANTHROPIC_MODEL="$OPTARG" ;;
    y) ASSUME_YES=1 ;;
    h) usage; exit 0 ;;
    \?) err "Unknown option: -$OPTARG"; usage; exit 1 ;;
    :) err "Option -$OPTARG requires an argument"; exit 1 ;;
  esac
done
shift $((OPTIND - 1))

domain="${1:-}"
if [ -z "$domain" ]; then
  err "No target domain provided."
  usage
  exit 1
fi

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

missing=()
for tool in subfinder httpx nuclei; do
  have "$tool" || missing+=("$tool")
done
if [ "${#missing[@]}" -gt 0 ]; then
  err "Missing required tools: ${missing[*]}"
  err "Install them (projectdiscovery.io) and ensure they are on your PATH."
  exit 1
fi
have ffuf   || warn "ffuf not found - content-discovery (fuzzing) step will be skipped."
have anew   || warn "anew not found - falling back to sort -u for dedup."

AI_ENABLED=1
if [ -z "$ANTHROPIC_API_KEY" ]; then
  warn "ANTHROPIC_API_KEY not set - AI decision/triage steps disabled (using defaults)."
  AI_ENABLED=0
elif ! have curl || ! have jq; then
  warn "curl and jq are required for the AI steps - disabling AI (using defaults)."
  AI_ENABLED=0
fi

# ---------------------------------------------------------------------------
# Authorization gate
# ---------------------------------------------------------------------------
if [ "$ASSUME_YES" != "1" ]; then
  printf '%s' "${c_yellow}Confirm you are AUTHORIZED to test '${domain}' [y/N]: ${c_reset}"
  read -r reply
  case "$reply" in
    y|Y|yes|YES) ;;
    *) err "Aborted - authorization not confirmed."; exit 1 ;;
  esac
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
fuzz_dir="$OUTDIR/fuzz"; mkdir -p "$fuzz_dir"
nuclei_file="$OUTDIR/nuclei.txt"
report_file="$OUTDIR/report.md"
log "Results will be written to: $OUTDIR"

dedup() { if have anew; then anew "$1"; else sort -u -o "$1" - <(cat - "$1" 2>/dev/null); fi; }

# ---------------------------------------------------------------------------
# AI helper: send a prompt, print the model's text answer to stdout.
#   $1 = system prompt   $2 = user prompt
# Returns non-zero and prints nothing on failure.
# ---------------------------------------------------------------------------
ai_call() {
  local system="$1" user="$2" payload response text
  payload="$(jq -n \
    --arg model "$ANTHROPIC_MODEL" \
    --arg system "$system" \
    --arg user "$user" \
    '{model: $model, max_tokens: 4096, system: $system,
      messages: [{role: "user", content: $user}]}')" || return 1

  response="$(curl -sS --max-time 120 "$ANTHROPIC_BASE_URL/v1/messages" \
    -H "content-type: application/json" \
    -H "x-api-key: $ANTHROPIC_API_KEY" \
    -H "anthropic-version: $ANTHROPIC_VERSION" \
    -d "$payload")" || return 1

  if echo "$response" | jq -e '.error' >/dev/null 2>&1; then
    warn "AI API error: $(echo "$response" | jq -r '.error.message // "unknown"')"
    return 1
  fi
  text="$(echo "$response" | jq -r '.content[]? | select(.type=="text") | .text')"
  [ -n "$text" ] || return 1
  printf '%s' "$text"
}

# ---------------------------------------------------------------------------
# Step 1: Subdomain enumeration
# ---------------------------------------------------------------------------
log "Enumerating subdomains for $domain ..."
subfinder -silent -d "$domain" -o "$subdomains_file" || warn "subfinder returned an error."
sub_count=$(wc -l < "$subdomains_file" 2>/dev/null || echo 0)
ok "Found $sub_count subdomains -> $subdomains_file"
[ "$sub_count" -eq 0 ] && { warn "No subdomains found; nothing more to do."; exit 0; }

# ---------------------------------------------------------------------------
# Step 2: Probe for live hosts + technology detection
# ---------------------------------------------------------------------------
log "Probing live hosts and detecting technologies (httpx) ..."
httpx -silent -json -tech-detect -status-code -title -web-server \
      -l "$subdomains_file" -o "$httpx_json" || warn "httpx returned an error."

# Extract plain URL list for downstream tools.
if [ -s "$httpx_json" ]; then
  jq -r '.url' "$httpx_json" 2>/dev/null | sort -u > "$alive_file"
else
  : > "$alive_file"
fi
alive_count=$(wc -l < "$alive_file" 2>/dev/null || echo 0)
ok "Live hosts: $alive_count -> $alive_file"
[ "$alive_count" -eq 0 ] && { warn "No live hosts; nothing more to do."; exit 0; }

# Build a compact "host -> tech/status/title" summary for the AI.
tech_summary="$OUTDIR/tech_summary.txt"
if have jq && [ -s "$httpx_json" ]; then
  jq -r '"\(.url) [\(.status_code // "?")] server=\(.webserver // "?") tech=\((.tech // []) | join(","))  title=\(.title // "")"' \
     "$httpx_json" 2>/dev/null | sort -u > "$tech_summary"
else
  cp "$alive_file" "$tech_summary"
fi

# ---------------------------------------------------------------------------
# Step 3: AI decides the scan plan (which nuclei tags to focus on)
# ---------------------------------------------------------------------------
nuclei_tags="$DEFAULT_NUCLEI_TAGS"
if [ "$AI_ENABLED" = "1" ]; then
  ai "Asking Claude to choose nuclei tags based on detected technologies ..."
  sys_prompt='You are a bug-bounty recon assistant helping with AUTHORIZED security testing.
Given a list of live hosts with their detected technologies, choose the most relevant
nuclei tags to scan with. Reply with ONLY a single comma-separated list of valid nuclei
tags (lowercase, no spaces, no prose, no code fences). Prefer tags matched to the observed
stack (e.g. wordpress, jira, apache, nginx, php, gitlab) plus general high-value tags like
cves, exposures, misconfiguration, default-login, takeover. Return between 4 and 12 tags.'
  ai_plan="$(ai_call "$sys_prompt" "Target: $domain

Live hosts and detected technologies:
$(head -c 12000 "$tech_summary")")" || ai_plan=""

  # Sanitise: keep only a tidy comma-separated tag list.
  ai_plan="$(printf '%s' "$ai_plan" | tr -d '\r' | grep -oE '[a-z0-9,._-]+' | head -n1)"
  if [ -n "$ai_plan" ]; then
    nuclei_tags="$ai_plan"
    ok "AI-selected nuclei tags: $nuclei_tags"
    printf '%s\n' "$nuclei_tags" > "$OUTDIR/ai_scan_plan.txt"
  else
    warn "AI scan-plan step failed; using default tags: $nuclei_tags"
  fi
else
  log "Using default nuclei tags: $nuclei_tags"
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
      out="$fuzz_dir/${idx}_${safe}.json"
      printf '%s    fuzzing %s\n' "$c_dim" "$url$c_reset"
      ffuf -u "$url/FUZZ" -w "$WORDLIST" -mc 200,204,301,302,307,401,403 \
           -of json -o "$out" -s 2>/dev/null || warn "ffuf failed for $url"
    done < "$alive_file"
    ok "Fuzzing results in $fuzz_dir"
  else
    warn "Wordlist not found ($WORDLIST) - skipping fuzzing. Set -w or WORDLIST."
  fi
fi

# ---------------------------------------------------------------------------
# Step 5: Vulnerability scanning (nuclei)
# ---------------------------------------------------------------------------
log "Running nuclei with tags: $nuclei_tags ..."
nuclei -silent -tags "$nuclei_tags" -l "$alive_file" -o "$nuclei_file" \
  || warn "nuclei returned an error."
find_count=$(wc -l < "$nuclei_file" 2>/dev/null || echo 0)
ok "nuclei findings: $find_count -> $nuclei_file"

# ---------------------------------------------------------------------------
# Step 6: AI triage - turn raw findings into a prioritised report
# ---------------------------------------------------------------------------
{
  echo "# 4tail recon report"
  echo
  echo "- **Target:** \`$domain\`"
  echo "- **Generated:** $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "- **Subdomains:** $sub_count | **Live hosts:** $alive_count | **Findings:** $find_count"
  echo "- **Nuclei tags:** \`$nuclei_tags\`"
  echo
} > "$report_file"

if [ "$AI_ENABLED" = "1" ] && [ "$find_count" -gt 0 ]; then
  ai "Asking Claude to triage and prioritise the findings ..."
  sys_prompt='You are a senior security analyst assisting with an AUTHORIZED bug-bounty engagement.
You are given raw nuclei output plus a list of live hosts and their technologies.
Produce a concise triage report in GitHub-flavored Markdown with these sections:
"## Executive summary" (2-4 sentences),
"## Prioritised findings" (a table sorted by severity: Severity | Host | Issue | Why it matters | Suggested next step),
"## Recommended manual follow-ups" (bullet list).
Only use the data provided; do not invent findings. Be practical and specific. Do NOT include remediation you cannot justify from the data.'
  triage="$(ai_call "$sys_prompt" "Target: $domain

=== Live hosts / technologies ===
$(head -c 8000 "$tech_summary")

=== Raw nuclei findings ===
$(head -c 20000 "$nuclei_file")")" || triage=""

  if [ -n "$triage" ]; then
    printf '%s\n' "$triage" >> "$report_file"
    ok "AI triage written to $report_file"
  else
    warn "AI triage failed; appending raw findings instead."
    { echo "## Raw findings"; echo '```'; cat "$nuclei_file"; echo '```'; } >> "$report_file"
  fi
else
  {
    echo "## Findings"
    if [ "$find_count" -gt 0 ]; then
      echo '```'; cat "$nuclei_file"; echo '```'
    else
      echo "_No nuclei findings._"
    fi
  } >> "$report_file"
fi

echo
ok "Done. Report: $report_file"
