# --- Cost ledger (estimated USD spent on the LLM) ---------------------------
# Cost ledger is APPEND-only (one cost per line) so concurrent background ai_call writes
# (triage + the nuclei supervisor) can't clobber each other; cost_now sums the lines.
cost_now() { [ -n "$cost_ledger" ] && awk '{s+=$1} END{printf "%.6f\n", s+0}' "$cost_ledger" 2>/dev/null || echo 0; }
add_cost() { # $1 = usd to add
  [ -n "$cost_ledger" ] || return 0
  printf '%.6f\n' "$1" >> "$cost_ledger"   # single short line -> atomic append
}
budget_ok() { # 0 (true) if under budget or unlimited
  [ "${LLM_BUDGET_USD:-0}" = 0 ] && return 0
  awk -v c="$(cost_now)" -v b="$LLM_BUDGET_USD" 'BEGIN{exit !(c<b)}'
}
cost_fmt() { awk -v c="$(cost_now)" 'BEGIN{printf "$%.4f", c}'; }
nlines() { [ -f "$1" ] && wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }
# Run a command under a wall-clock cap (no-op if `timeout` is unavailable). Keeps any
# single external tool from stalling the whole scan for hours.
tmo() { local s="$1"; shift; if have timeout; then timeout "$s" "$@"; else "$@"; fi; }
# Capability-aware counter: a 0 should mean "ran, found nothing", never silently hide
# "tool not installed" or "phase off". Prints  name:N  |  name:off  |  name:n/a(no <bin>).
cov() {  # name  bin(or "")  enabled(0/1)  count
  local name="$1" bin="$2" en="$3" n="$4"
  if [ "$en" != 1 ]; then printf '%s:off' "$name"
  elif [ -n "$bin" ] && ! have "$bin"; then printf '%s:n/a(no %s)' "$name" "$bin"
  else printf '%s:%s' "$name" "$n"; fi
}
# Distinct content-discovery hits (fingerprint-grouped), vs the raw line count.
fuzz_distinct() { [ -f "$1" ] && awk -F'\t' 'NF>=2 && !s[$1"-"$2]++{c++} END{print c+0}' "$1" || echo 0; }
# Severity for an agent-confirmed line: HIGH only for real secret/exec reads; public/known
# files (robots/sitemap/about/favicon) are not high just because traversal reached them.
agent_sev() {
  local l; l="$(printf '%s' "$1" | tr 'A-Z' 'a-z')"
  case "$l" in
    *web.config*|*global.asa*|*machinekey*|*connectionstring*|*/.git*|*id_rsa*|*.env*|*win.ini*|*/etc/passwd*|*boot.ini*|*.sql*|*wp-config*|*application.properties*|*.pem*) printf 'high' ;;
    *robots.txt*|*sitemap*|*about.htm*|*favicon*|*.css*|*.png*|*.jpg*|*.svg*|*humans.txt*) printf 'low' ;;
    *) printf 'medium' ;;
  esac
}
# Drop static-asset URLs (stdin->stdout), testing the extension on the PATH only so a
# file-ish query value (?file=app.js) is kept. Used to clean input to the slow scanners.
drop_static() { awk -v re="$STATIC_URL_RE" '{ p=tolower($0); sub(/[?#].*/,"",p); if (p !~ re) print }'; }

# ---- Correlation / exploitation helpers (all GET/HEAD, scope-locked, capped) ----
# Two response "sizes" are the same resource if within 10% (Autorize-style diff).
_near() { awk -v a="${1:-0}" -v b="${2:-0}" 'BEGIN{d=a-b;if(d<0)d=-d;m=(a>b?a:b);exit !(a==b || (m>0 && d<=0.10*m))}'; }

# (#2) 403/401 -> proven access-control bypasses. Reads "status<TAB>len<TAB>url"; a trick
# that turns the 401/403 into a 2xx/3xx is recorded. Only the handful of tricks that
# actually work in the wild - no spray.
try_403_bypass() {
  [ "$BYPASS" = 1 ] || { cat >/dev/null; return 0; }
  local st len url rest host scheme origin path r code sz bctl bcode bsz n=0 t h
  while IFS=$'\t' read -r st len url; do
    case "$st" in 401|403) ;; *) continue ;; esac
    [ -n "$url" ] || continue
    [ "$n" -ge "$BYPASS_MAX" ] && break; n=$((n+1))
    scheme="${url%%://*}"; rest="${url#*://}"; host="${rest%%/*}"
    case "$rest" in */*) path="/${rest#*/}" ;; *) path="/" ;; esac
    origin="$scheme://$host"
    # Soft-404/catch-all baseline: a bogus path on this origin. Many servers route unknown
    # paths (and X-Original-URL) to the homepage (200), which would look like a fake bypass.
    bctl="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -L --max-time 8 ${CURL_NET[@]+"${CURL_NET[@]}"} "$origin/4tbz${RANDOM}x" 2>/dev/null || echo '000 0')"
    bcode="${bctl%% *}"; bsz="${bctl##* }"
    for t in "$path/" "$path/." "/.$path" "$path%2e" "$path%20" "$path%09" "$path..;/" "$path?" ; do
      r="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -L --max-time 8 ${CURL_NET[@]+"${CURL_NET[@]}"} "$origin$t" 2>/dev/null || echo '000 0')"
      code="${r%% *}"; sz="${r##* }"
      case "$code" in 200|201|202|203|206|301|302|307) ;; *) continue ;; esac
      { [ "$bcode" = "$code" ] && _near "$sz" "$bsz"; } && continue   # same as catch-all -> not a bypass
      printf '%s -> %s via path trick %s\n' "$url" "$code" "$origin$t" >> "$bypass_file"; break
    done
    for h in "X-Forwarded-For: 127.0.0.1" "X-Original-URL: $path" "X-Rewrite-URL: $path" "X-Custom-IP-Authorization: 127.0.0.1" ; do
      r="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 8 ${CURL_NET[@]+"${CURL_NET[@]}"} -H "$h" "$url" 2>/dev/null || echo '000 0')"
      code="${r%% *}"; sz="${r##* }"
      case "$code" in 200|201|202|203|206) ;; *) continue ;; esac
      { [ "$bcode" = 200 ] && _near "$sz" "$bsz"; } && continue       # homepage echo -> not a bypass
      printf '%s -> %s via header %s\n' "$url" "$code" "$h" >> "$bypass_file"; break
    done
  done
}

# (#3) Cross-host propagation: paths found on ANY host, replayed on every other live
# host that doesn't already have them. Finds shared endpoints a per-host fuzz missed.
propagate_paths() {
  [ "$PROPAGATE" = 1 ] || return 0
  local hosts
  if have unfurl; then hosts="$(unfurl -u format '%s://%d' < "$alive_file" 2>/dev/null | sort -u | head -n 40)"
  else hosts="$(awk -F/ 'NF>=3{print $1"//"$3}' "$alive_file" 2>/dev/null | sort -u | head -n 40)"; fi
  [ "$(printf '%s\n' "$hosts" | grep -c .)" -ge 2 ] || return 0   # pointless with one host
  local paths; paths="$(awk -F'\t' '$1~/^(200|301|302|401|403)$/{print $3}' "$fuzz_findings_file" 2>/dev/null \
      | sed -E 's#^[a-z]+://[^/]+##' | grep -E '^/.' | drop_static | sort -u | head -n "$PROP_MAX_PATHS")"
  [ -n "$paths" ] || return 0
  local origin p r code sz bctl bcode bsz
  while IFS= read -r origin; do
    [ -n "$origin" ] || continue
    # per-origin soft-404/catch-all baseline (a sibling that 302->/login or serves an SPA
    # shell for everything would otherwise report all propagated paths as "live").
    bctl="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 8 ${CURL_NET[@]+"${CURL_NET[@]}"} "$origin/4tprop${RANDOM}x" 2>/dev/null || echo '000 0')"
    bcode="${bctl%% *}"; bsz="${bctl##* }"
    while IFS= read -r p; do
      [ -n "$p" ] || continue
      grep -qF "$origin$p" "$fuzz_findings_file" 2>/dev/null && continue  # already known on this host
      r="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 8 ${CURL_NET[@]+"${CURL_NET[@]}"} "$origin$p" 2>/dev/null || echo '000 0')"
      code="${r%% *}"; sz="${r##* }"
      case "$code" in 200|301|302|401|403) ;; *) continue ;; esac
      { [ "$bcode" = "$code" ] && _near "$sz" "$bsz"; } && continue     # matches catch-all -> skip
      printf '%s\t%s\n' "$code" "$origin$p" >> "$prop_file"
    done <<< "$paths"
  done <<< "$hosts"
}

# (#1) Dual-identity IDOR / broken-authz (Autorize-style): replay A's authorized requests
# as user B and as anon; same successful response = per-user authz not enforced.
# Looks-like-an-auth-wall/error body, not a real resource (SPA shell, login page, JSON error
# envelope that still returns 200). Used to reject IDOR false positives.
_looks_denied() { printf '%s' "$1" | grep -qiE 'please (log|sign)[ -]?in|name=["'"'"']?password|type=["'"'"']?password|<title>[^<]*(log[ -]?in|sign[ -]?in)|"(error|errors|message)"[[:space:]]*:[[:space:]]*"?[^"]*(unauthori|forbidden|denied|invalid|not allowed|must (log|sign)|authentication)|\baccess denied\b|\bunauthorized\b|\bforbidden\b'; }
# Fetch body + "code size" trailer in one request. $1=url, rest=extra curl args.
_fetch_bs() { local u="$1"; shift; curl -s --max-time 10 "$@" -w $'\n4TSTAT %{http_code} %{size_download}' "$u" 2>/dev/null; }

idor_check() {
  [ "$IDOR" = 1 ] && [ -n "$AUTH_A" ] || return 0
  # Candidates = URLs A can actually read, ANY id shape. The key idea: with a real session we
  # don't need to GUESS ids - we replay A's own object/accessor URLs as anon and as B. So we
  # take id-bearing query params (int/uuid/hex/slug/email), object-accessor paths (/users/<x>),
  # and implicit-context endpoints (/me, /account, /profile, /billing) from the active set + JS.
  local cand; cand="$( {
      grep -iE '^(idor|ssrf)\t' "$gf_file" 2>/dev/null | cut -f2
      grep -hiE '[?&](id|uid|guid|uuid|user|userid|username|account|acct|order|orderid|invoice|doc|docid|file|fileid|num|no|pid|gid|key|ref|object|item|cart|basket|profile|email)=[^&[:space:]]+' "$targets_active_file" 2>/dev/null
      grep -haoiE 'https?://[^ "]+/(users?|accounts?|orders?|invoices?|baskets?|carts?|documents?|files?|products?|customers?|profiles?|messages?|tickets?|addresses?)/[^/ ?"]+' "$targets_active_file" "${js_endpoints_file:-/dev/null}" 2>/dev/null
      grep -haoiE 'https?://[^ "]+/(me|profile|account|settings|billing|whoami|dashboard)([/?][^ "]*)?' "$targets_active_file" "${js_endpoints_file:-/dev/null}" 2>/dev/null
    } | sort -u | head -n "$IDOR_MAX" )"
  [ -n "$cand" ] || return 0
  local u out abody acode asz nbody ncode nsz bbody bcode bsz
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    out="$(_fetch_bs "$u" ${CURL_PROXY[@]+"${CURL_PROXY[@]}"} -H "$AUTH_A")"
    acode="$(printf '%s' "$out" | tail -1 | awk '{print $2}')"; asz="$(printf '%s' "$out" | tail -1 | awk '{print $3}')"
    abody="$(printf '%s' "$out" | sed '$d')"
    { [ "$acode" = 200 ] && [ "${asz:-0}" -gt 0 ] 2>/dev/null; } || continue   # A must actually read it
    _looks_denied "$abody" && continue                                         # ...and it must be a real resource
    # ANON leg: proxy ONLY, no auth header (CURL_NET would leak A's session here).
    out="$(_fetch_bs "$u" ${CURL_PROXY[@]+"${CURL_PROXY[@]}"})"
    ncode="$(printf '%s' "$out" | tail -1 | awk '{print $2}')"; nsz="$(printf '%s' "$out" | tail -1 | awk '{print $3}')"; nbody="$(printf '%s' "$out" | sed '$d')"
    if [ "$ncode" = 200 ] && _near "$asz" "$nsz" && ! _looks_denied "$nbody"; then
      printf '[ANON-ACCESS] %s | A-authorized content served with NO session (A=200/%sB anon=200/%sB)\n' "$u" "$asz" "$nsz" >> "$idor_file"
    fi
    if [ -n "$AUTH_B" ]; then
      out="$(_fetch_bs "$u" ${CURL_PROXY[@]+"${CURL_PROXY[@]}"} -H "$AUTH_B")"
      bcode="$(printf '%s' "$out" | tail -1 | awk '{print $2}')"; bsz="$(printf '%s' "$out" | tail -1 | awk '{print $3}')"; bbody="$(printf '%s' "$out" | sed '$d')"
      if [ "$bcode" = 200 ] && _near "$asz" "$bsz" && ! _looks_denied "$bbody"; then
        printf '[IDOR?] %s | user B reads the same resource as user A (A=200/%sB B=200/%sB) - verify object ownership\n' "$u" "$asz" "$bsz" >> "$idor_file"
      fi
    fi
  done <<< "$cand"

  # Single-session fallback (no B): path-based BOLA by NEIGHBOUR-walking a guessable id in the
  # path (/api/Users/1 -> /2). Only int ids are walkable; uuid/hex can't be guessed, so those
  # rely on the A/B replay above. Guarded by a bogus-id control so blanket-200 APIs don't FP.
  local pcand purl pid alt alturl cid ralt calt salt rcc ccc scc ra ca sa
  pcand="$( { grep -haoiE 'https?://[^ "]+/[0-9]{1,9}(/[a-z0-9._-]+)?/?$' "$targets_active_file" "${js_endpoints_file:-/dev/null}" 2>/dev/null
            } | sort -u | head -n "$IDOR_MAX" )"
  while IFS= read -r purl; do
    [ -n "$purl" ] || continue
    pid="$(printf '%s' "$purl" | grep -oE '/[0-9]{1,9}(/|$)' | tail -1 | tr -dc '0-9')"
    [ -n "$pid" ] || continue
    ra="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 10 ${CURL_PROXY[@]+"${CURL_PROXY[@]}"} -H "$AUTH_A" "$purl" 2>/dev/null || echo '000 0')"
    ca="${ra%% *}"; sa="${ra##* }"
    [ "$ca" = 200 ] && [ "${sa:-0}" -gt 0 ] 2>/dev/null || continue
    alt=$((pid + 1)); [ "$alt" = "$pid" ] && alt=$((pid + 2))
    alturl="$(printf '%s' "$purl" | sed -E "s#/${pid}(/|\$)#/${alt}\1#")"
    cid="$(printf '%s' "$purl" | sed -E "s#/${pid}(/|\$)#/99999987\1#")"   # unlikely id -> blanket-200 guard
    ralt="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 10 ${CURL_PROXY[@]+"${CURL_PROXY[@]}"} -H "$AUTH_A" "$alturl" 2>/dev/null || echo '000 0')"
    calt="${ralt%% *}"; salt="${ralt##* }"
    [ "$calt" = 200 ] && [ "${salt:-0}" -gt 0 ] 2>/dev/null || continue
    rcc="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 10 ${CURL_PROXY[@]+"${CURL_PROXY[@]}"} -H "$AUTH_A" "$cid" 2>/dev/null || echo '000 0')"
    ccc="${rcc%% *}"; scc="${rcc##* }"
    if [ "$ccc" = 200 ] && _near "$salt" "$scc"; then continue; fi
    printf '[PATH-IDOR?] %s -> %s | identity A reads neighbour object id %s (200/%sB; bogus id -> %s/%sB) - verify ownership\n' "$purl" "$alturl" "$alt" "$salt" "$ccc" "$scc" >> "$idor_file"
  done <<< "$pcand"
}

# Deterministic <form> field harvest (page<TAB>method<TAB>action<TAB>field-names) from auth /
# state-changing pages. Run BEFORE the agent so its POST probes use real field names, and
# reused by the PoC generator. Idempotent: skips if forms_file is already populated.
harvest_forms() {
  [ "${POC_GEN:-1}" = 1 ] || return 0
  [ -s "${forms_file:-/dev/null}" ] && return 0
  : > "$forms_file"
  local form_cand pg html frm m a names
  form_cand="$( { sort -u "$alive_file" 2>/dev/null; cat "${targets_active_file:-/dev/null}" 2>/dev/null; } \
                 | grep -iE 'login|signin|sign-in|register|signup|sign-up|reset|password|forgot|account|profile|checkout|cart|upload|contact|comment|graphql' \
                 | sort -u | head -n "${POC_FORM_HOSTS:-12}" )"
  [ -n "$form_cand" ] || form_cand="$(sort -u "$alive_file" 2>/dev/null | head -n 3)"
  while IFS= read -r pg; do
    [ -n "$pg" ] || continue
    html="$(curl -s -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} "$pg" 2>/dev/null | tr '\n' ' ' | head -c 200000)"
    [ -n "$html" ] || continue
    printf '%s' "$html" | awk 'BEGIN{IGNORECASE=1; RS="<form"} NR>1{ e=index(tolower($0),"</form>"); print (e>0?substr($0,1,e):$0) }' 2>/dev/null \
      | while IFS= read -r frm; do
          [ -n "$frm" ] || continue
          m="$(printf '%s' "$frm" | grep -oiE 'method=["'"'"']?[a-z]+' | head -1 | grep -oiE '[a-z]+$' | tr 'a-z' 'A-Z')"; [ -n "$m" ] || m=GET
          a="$(printf '%s' "$frm" | grep -oiE 'action=["'"'"'][^"'"'"']*' | head -1 | sed -E 's/^action=["'"'"']//')"; [ -n "$a" ] || a="$pg"
          names="$(printf '%s' "$frm" | grep -oiE 'name=["'"'"'][^"'"'"']+' | sed -E 's/^name=["'"'"']//' | sort -u | paste -sd, -)"
          [ -n "$names" ] && printf '%s\t%s\t%s\t%s\n' "$pg" "$m" "$a" "$names" >> "$forms_file"
        done
  done <<< "$form_cand"
}

# Verification pass (anti-false-positive, per 2026 AI-pentest research): re-test each
# CONFIRMED finding and require it to be (a) stable across two fetches and (b) DIFFERENT
# from a bogus-sibling control - which weeds out soft-404 / catch-all pages that answer
# 200 to everything. Survivors go to verified_file; the rest stay as candidates.
verify_findings() {
  [ "$VERIFY" = 1 ] || return 0
  : > "$verified_file"
  local u r1 r2 rc s1 z1 s2 z2 sc zc cu
  # Only verify findings where a plain GET re-test is MEANINGFUL: DAST (LFI/path reflection),
  # GET-confirmed agent probes, and IDOR candidates. We deliberately SKIP:
  #   - access-control bypasses (bypass_file): need the exact header/path trick, not a bare GET;
  #   - CORS (corsy_file): only manifests in response headers to an Origin request;
  #   - agent POST confirms + SECRET-LOOT lines: re-testing with GET is the wrong method.
  { [ -f "${agent_file:-}" ]  && grep -ivE '(^|[[:space:]])POST |SECRET-LOOT' "$agent_file" | grep -oiE 'https?://[^ |]+'
    [ -f "${idor_file:-}" ]   && grep -oiE 'https?://[^ |]+' "$idor_file"
    [ -f "${dast_file:-}" ]   && grep -oiE 'https?://[^ |]+' "$dast_file"
  } 2>/dev/null | sort -u | head -n 60 | while IFS= read -r u; do
    [ -n "$u" ] || continue
    r1="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} "$u" 2>/dev/null || echo '000 0')"
    r2="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} "$u" 2>/dev/null || echo '000 0')"
    s1="${r1%% *}"; z1="${r1##* }"; s2="${r2%% *}"; z2="${r2##* }"
    # Control = a nonexistent LEAF in the SAME directory, query preserved. (The old form inserted
    # a path segment before the query -> /page.php/ctl?id=1 still executes page.php via PathInfo
    # on PHP/IIS and returned the real page, falsely nuking valid findings.)
    cu="$(printf '%s' "$u" | sed -E 's#^(https?://[^/]+/([^?]*/)?)[^/?]*(\?.*)?$#\14tctl'"${RANDOM}"'\3#')"
    rc="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} "$cu" 2>/dev/null || echo '000 0')"
    sc="${rc%% *}"; zc="${rc##* }"
    if [ "$s1" = "$s2" ] && _near "$z1" "$z2" && [ "$s1" != 000 ] && { [ "$s1" != "$sc" ] || ! _near "$z1" "$zc"; }; then
      printf 'VERIFIED %s [%s, %sB] (bogus control -> %s/%sB, differs)\n' "$u" "$s1" "$z1" "$sc" "$zc" >> "$verified_file"
    fi
  done
}

# Change-detection: remember each target's attack surface + findings between runs and
# show what's NEW this time (newly-deployed endpoints are disproportionately buggy).
diff_state() {
  [ "$DIFF_STATE" = 1 ] || return 0
  mkdir -p "$STATE_DIR" 2>/dev/null || return 0
  local snap="$STATE_DIR/$(printf '%s' "$domain" | tr -c 'A-Za-z0-9._-' '_').snapshot"
  local cur="$OUTDIR/.surface.txt"
  { [ -f "$alive_file" ] && sed 's#^#host #' "$alive_file"
    [ -f "$fuzz_findings_file" ] && awk -F'\t' 'NF>=3{print "path "$3}' "$fuzz_findings_file"
    [ -f "$targets_active_file" ] && sed 's#^#url #' "$targets_active_file"
    [ -f "${findings_json:-}" ] && jq -r '.findings[]? | "finding "+.type+" "+(.url//"")' "$findings_json" 2>/dev/null
  } 2>/dev/null | sort -u > "$cur"
  : > "$diff_file"
  if [ -s "$snap" ]; then
    comm -13 "$snap" "$cur" > "$diff_file" 2>/dev/null || true
  else
    echo "(first run for $domain — baseline saved; nothing to diff yet)" > "$diff_file"
  fi
  # UNION the baseline with this run (never shrink it), so a quick/partial scan (-q) or a
  # resumed run can't erase surface a previous full scan recorded. Skip the write entirely on
  # a resumed run (it's the same run, not a new observation).
  if [ "$RESUME" != 1 ]; then
    sort -u "$snap" "$cur" 2>/dev/null > "$snap.new" && mv "$snap.new" "$snap"
  fi
  rm -f "$cur"
}

