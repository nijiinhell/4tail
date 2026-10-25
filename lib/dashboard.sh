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
  loot_scan "${bypass_file:-}"             bypass  sqlmap
  loot_scan "${idor_file:-}"               idor    sqlmap
  loot_scan "${corsy_file:-}"              cors    secret
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

