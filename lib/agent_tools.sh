# ---- Agent tool dispatch: the agent invokes REAL tools, not just GET -----------
_cap() { if have timeout; then timeout "$AGENT_TOOL_TIMEOUT" "$@"; else "$@"; fi; }
# Whitelisted tools, limited to those actually installed (offered to the agent).
agent_tool_list() {
  local t out=""
  for t in curl sqlmap dalfox nuclei nuclei-dast ffuf arjun katana gau waybackurls crlfuzz x8 git-dumper trufflehog; do
    case "$t" in
      nuclei-dast) have nuclei && out="$out nuclei-dast" ;;
      git-dumper)  { have git-dumper || have gitdumper; } && out="$out git-dumper" ;;
      *)           have "$t" && out="$out $t" ;;
    esac
  done
  printf '%s' "${out# }"
}
# Run ONE whitelisted tool against an in-scope target (capped + redacted). Prints a short
# result line for the agent; records a [CONFIRMED]/[FINDING] in agent_file on a hit.
agent_tool_run() {   # name  target  extra
  local name="$1" tgt="$2" extra="${3:-}" raw="" res="" hit="" wl
  case "$name" in
    gau|waybackurls|subfinder)
      printf '%s' "$tgt" | grep -qiE "^([a-z0-9._-]+\.)?${esc_domain}\$" || { echo "rejected: out-of-scope host"; return 0; } ;;
    *)
      printf '%s' "$tgt" | grep -qiE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|\$)" || { echo "rejected: out-of-scope url"; return 0; } ;;
  esac
  case "$name" in
    curl)
      raw="$(_cap curl -s -i -L --max-time 15 ${CURL_NET[@]+"${CURL_NET[@]}"} "$tgt" 2>/dev/null | head -c 6000)"
      printf '%s' "$raw" | grep -qiE 'connectionString|<configuration|\[fonts\]|root:.{0,40}:0:0:|BEGIN [A-Z ]*PRIVATE KEY|SQL syntax.*(MySQL|ODBC|OLE DB)|ORA-[0-9]{4,}' && hit="FINDING"
      res="$(printf '%s' "$raw" | head -1 | tr -d '\r')" ;;
    sqlmap)
      have sqlmap || { echo "sqlmap: not installed"; return 0; }
      # The agent may pass extra sqlmap flags, but escalation and OS/file access are forced off:
      # any --level/--risk it asks for is dropped and we always run --level=1 --risk=1, and the
      # dangerous flags (shells, file read/write, tamper, eval) are stripped. So "try level=5" no-ops.
      local sqx=() _tok
      for _tok in $extra; do
        case "$_tok" in
          --dbs|--tables|--current-db|--current-user|--banner|-p|--dump) sqx+=("$_tok") ;;  # allow a few safe enumeration flags
          *) ;;  # ignore everything else: escalation (--level/--risk), shells, file R/W, tamper, technique (stays BEU)
        esac
      done
      # Agent calls sqlmap on ONE high-suspicion URL, so drop --smart and use --level=2 --risk=2
      # (tests parenthesis closures like ') and ')) that --level=1 skips). Still capped and BEU-only.
      raw="$(_cap sqlmap -u "$tgt" --batch --level=2 --risk=2 --technique=BEU --disable-coloring ${sqx[@]+"${sqx[@]}"} 2>/dev/null | tail -c 4000)"
      printf '%s' "$raw" | grep -qiE 'is vulnerable|is injectable|Parameter:.*|Type: ' && hit="CONFIRMED sqli"
      res="$(printf '%s' "$raw" | grep -iE 'vulnerable|injectable|Type:|back-end DBMS' | head -3 | tr '\n' ';')" ;;
    dalfox)
      have dalfox || { echo "dalfox: not installed"; return 0; }
      raw="$(_cap dalfox url "$tgt" --silence --skip-bav 2>/dev/null | head -c 4000)"
      printf '%s' "$raw" | grep -qiE '\[POC\]|triggered|\[VULN\]' && hit="CONFIRMED xss"
      res="$(printf '%s' "$raw" | grep -iE 'POC|VULN|reflect' | head -3 | tr '\n' ';')" ;;
    nuclei)
      have nuclei || { echo "nuclei: not installed"; return 0; }
      local nt=(); extra="$(printf '%s' "$extra" | grep -oiE 'tags=[a-z0-9,._-]+' | cut -d= -f2)"; [ -n "$extra" ] && nt=(-tags "$extra")
      raw="$(_cap nuclei -u "$tgt" -silent "${nt[@]}" ${NUCLEI_NET[@]+"${NUCLEI_NET[@]}"} 2>/dev/null | head -c 4000)"
      [ -n "$raw" ] && hit="FINDING"; res="$(printf '%s' "$raw" | head -3 | tr '\n' ';')" ;;
    nuclei-dast)
      have nuclei || { echo "nuclei: not installed"; return 0; }
      raw="$(_cap nuclei -u "$tgt" -dast -silent ${NUCLEI_NET[@]+"${NUCLEI_NET[@]}"} 2>/dev/null | head -c 4000)"
      [ -n "$raw" ] && hit="FINDING"; res="$(printf '%s' "$raw" | head -3 | tr '\n' ';')" ;;
    ffuf)
      have ffuf || { echo "ffuf: not installed"; return 0; }
      wl="$WORDLIST"; [ -f "${SECLISTS_DIR:-}/Discovery/Web-Content/quickhits.txt" ] && wl="$SECLISTS_DIR/Discovery/Web-Content/quickhits.txt"
      raw="$(_cap ffuf -u "${tgt%/}/FUZZ" -w "$wl" -ac -mc 200,204,301,302,401,403 -s ${FFUF_NET[@]+"${FFUF_NET[@]}"} 2>/dev/null | head -c 3000)"
      [ -n "$raw" ] && hit="FINDING"; res="hits: $(printf '%s' "$raw" | head -8 | tr '\n' ' ')" ;;
    arjun|x8)
      # Param discovery with automatic fallback: if the requested tool is missing OR returns
      # nothing (arjun often gets rate-limited), try the other one before giving up.
      local pwl2="${SECLISTS_DIR:+$SECLISTS_DIR/Discovery/Web-Content/burp-parameter-names.txt}"
      _run_arjun() { _cap arjun -u "$1" -q -oT /dev/stdout 2>/dev/null | head -c 2000; }
      _run_x8()    { _cap x8 -u "$1" ${pwl2:+-w "$pwl2"} 2>/dev/null | grep -oiE '[a-z0-9_.-]{2,40}' | head -c 2000; }
      if [ "$name" = x8 ]; then
        have x8 && raw="$(_run_x8 "$tgt")"; [ -n "$raw" ] || { have arjun && { raw="$(_run_arjun "$tgt")"; name="arjun(fallback)"; }; }
      else
        have arjun && raw="$(_run_arjun "$tgt")"; [ -n "$raw" ] || { have x8 && { raw="$(_run_x8 "$tgt")"; name="x8(fallback)"; }; }
      fi
      [ -n "$raw" ] || { echo "param discovery: no arjun/x8 result (both tried)"; return 0; }
      res="params ($name): $(printf '%s' "$raw" | tr '\n' ' ' | head -c 300)" ;;
    katana)
      have katana || { echo "katana: not installed"; return 0; }
      raw="$(_cap katana -u "$tgt" -silent -d 1 -jc ${KATANA_NET[@]+"${KATANA_NET[@]}"} 2>/dev/null | head -c 3000)"
      res="urls: $(printf '%s' "$raw" | tr '\n' ' ' | head -c 300)" ;;
    gau|waybackurls)
      raw="$(printf '%s\n' "$tgt" | _cap "$name" 2>/dev/null | head -c 3000)"
      res="historical: $(printf '%s' "$raw" | tr '\n' ' ' | head -c 300)" ;;
    crlfuzz)
      have crlfuzz || { echo "crlfuzz: not installed (go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest)"; return 0; }
      raw="$(printf '%s\n' "$tgt" | _cap crlfuzz -s 2>/dev/null | head -c 2000)"
      [ -n "$raw" ] && hit="CONFIRMED crlf"; res="$(printf '%s' "$raw" | head -3 | tr '\n' ';')" ;;
    git-dumper|gitdumper)
      { have git-dumper || have gitdumper; } || { echo "git-dumper: not installed (pipx install git-dumper)"; return 0; }
      local gd="git-dumper"; have git-dumper || gd="gitdumper"; mkdir -p "$findings_dir/gitdump"
      # strip any trailing /.git the AI appended so we don't request /.git/.git/
      local gbase="${tgt%/}"; gbase="${gbase%/.git}"
      raw="$(_cap "$gd" "$gbase/.git/" "$findings_dir/gitdump" 2>&1 | tail -c 1500)"
      # Confirm ONLY on real dumped content - git-dumper lays down a .git skeleton (HEAD/config)
      # even on a failed 403/404, so "dir non-empty" alone is a false positive. Require fetched
      # objects/packs or checked-out source files.
      if find "$findings_dir/gitdump/.git/objects" -type f 2>/dev/null | grep -q . \
         || find "$findings_dir/gitdump" -type f -not -path '*/.git/*' 2>/dev/null | grep -q .; then
        hit="CONFIRMED source-disclosure"
      fi
      res="$(printf '%s' "$raw" | tail -3 | tr '\n' ';')" ;;
    trufflehog)
      have trufflehog || { echo "trufflehog: not installed"; return 0; }
      raw="$(_cap trufflehog --no-update filesystem "$findings_dir/gitdump" 2>/dev/null | head -c 2000)"
      printf '%s' "$raw" | grep -qiE 'Found|verified' && hit="CONFIRMED secret"
      res="$(printf '%s' "$raw" | head -3 | tr '\n' ';')" ;;
    *) echo "unknown/unavailable tool: $name"; return 0 ;;
  esac
  res="$(printf '%s' "$res" | sed -E 's/((pass(word|wd)?|secret|api[-_]?key|token|connection[-_ ]?string)[^[:cntrl:]]{0,8}[:=])[^[:cntrl:]"'"'"']{1,}/\1<redacted>/Ig' | head -c 320)"
  if [ -n "$hit" ]; then
    printf '[%s] %s | via %s | %s\n' "${hit%% *}" "$tgt" "$name" "$res" >> "$agent_file"
    printf 'TOOL %s %s => %s | %s' "$name" "$tgt" "$hit" "$res"
  else
    printf 'TOOL %s %s => %s' "$name" "$tgt" "${res:-no notable output}"
  fi
}

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

