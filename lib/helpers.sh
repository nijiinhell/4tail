# --- Host value-ranking (shared across every capped stage) -------------------
# Rank live hosts ONCE by likely value (admin/api/dev/auth-gated/notable tech first,
# CDN last, legacy-stack bonus) into $alive_ranked_file, so fuzz/js/api-spec/nuclei all
# spend their caps on the interesting hosts instead of the alphabetical first N.
build_alive_ranked() {
  alive_ranked_file="${alive_ranked_file:-$OUTDIR/alive_ranked.txt}"
  if have jq && [ -s "$httpx_json" ]; then
    jq -r '[ .url, ((.tech // [])|map(ascii_downcase)|join(",")), (.status_code|tostring), (.title // "") ] | @tsv' \
        "$httpx_json" 2>/dev/null \
      | awk -F'\t' '!seen[$1]++' \
      | awk -F'\t' -v stale="${stale_file:-}" '
          BEGIN{ if (stale!=""){ while((getline ln<stale)>0){ n=split(ln,a,"\t"); if(n>=2) sc[a[2]]=a[1] } } }
          { url=$1; tech=$2; st=$3; l=tolower($1" "$4" "$2); s=0;
            if (l ~ /admin|login|portal|dashboard|dev|staging|test|internal|api|graphql|swagger|git|jenkins|grafana|kibana|vpn|auth|sso|jira|confluence|gitlab|panel|backend|secure|account|billing|payment|upload|debug|config/) s+=3;
            if (st=="401"||st=="403") s+=2;
            if (st=="500"||st=="503") s+=1;
            if (tech ~ /wordpress|drupal|joomla|magento|jira|confluence|gitlab|jenkins|grafana|tomcat|spring|php/) s+=2;
            if (tech ~ /cloudfront|cloudflare|akamai|fastly|imperva|incapsula|sucuri|edgecast/) s-=5;
            if (url in sc) s += sc[url];
            printf "%d\t%s\n", s, url }' \
      | sort -t"$(printf '\t')" -k1,1nr -s | cut -f2 > "$alive_ranked_file" 2>/dev/null || true
  fi
  [ -s "$alive_ranked_file" ] || { [ -s "${alive_file:-}" ] && sort -u "$alive_file" > "$alive_ranked_file" 2>/dev/null; }
  [ -f "$alive_ranked_file" ] || : > "$alive_ranked_file"
}
# Emit the top-N value-ranked alive hosts (plain URLs), falling back to the alphabetical
# alive list if ranking never ran. N omitted = all.
ranked_hosts() {
  local n="${1:-0}"
  if [ -s "${alive_ranked_file:-}" ]; then
    if [ "$n" -gt 0 ] 2>/dev/null; then head -n "$n" "$alive_ranked_file"; else cat "$alive_ranked_file"; fi
  elif [ -s "${alive_file:-}" ]; then
    if [ "$n" -gt 0 ] 2>/dev/null; then sort -u "$alive_file" | head -n "$n"; else sort -u "$alive_file"; fi
  fi
}
# Reorder stdin (field 1 = url) to match $alive_ranked_file, de-duped by url, unknown urls last.
# Falls back to a plain de-dupe when no ranking exists. Preserves each line's own tabs.
rank_filter() {
  local rf="${1:-${alive_ranked_file:-}}"
  if [ -n "$rf" ] && [ -s "$rf" ]; then
    awk -F'\t' -v rf="$rf" '
      BEGIN{ r=0; while((getline u<rf)>0){ if(!(u in rank)) rank[u]=++r } }
      !seen[$1]++ { print (($1 in rank) ? rank[$1] : 1000000+NR) "\t" $0 }' \
    | sort -k1,1n -s | cut -f2-
  else
    awk '!seen[$0]++'
  fi
}

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
    *secret-loot*|*union*select*|*sqli*|*sql*injection*|*auth*bypass*|*rce*|*machinekey*|*connectionstring*|*id_rsa*|*.pem*|*private?key*) printf 'critical' ;;
    *bola*|*idor*|*mass*assign*|*privilege*|*priv*esc*|*pii*|*/admin*|*web.config*|*global.asa*|*/.git*|*.env*|*win.ini*|*/etc/passwd*|*wp-config*|*application.properties*) printf 'high' ;;
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
    # No -L: a 302->/login(200) must NOT be followed into a fake 200 bypass. --path-as-is: send
    # the dot-segment tricks literally (curl would otherwise normalize /./ and /. client-side,
    # turning the trick into a plain request before it leaves the machine).
    bctl="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --path-as-is --max-time 8 ${CURL_NET[@]+"${CURL_NET[@]}"} "$origin/4tbz${RANDOM}x" 2>/dev/null || echo '000 0')"
    bcode="${bctl%% *}"; bsz="${bctl##* }"
    for t in "$path/" "$path/." "/.$path" "$path%2e" "$path%20" "$path%09" "$path..;/" "$path?" ; do
      r="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --path-as-is --max-time 8 ${CURL_NET[@]+"${CURL_NET[@]}"} "$origin$t" 2>/dev/null || echo '000 0')"
      code="${r%% *}"; sz="${r##* }"
      case "$code" in 200|201|202|203|206) ;; *) continue ;; esac   # a real bypass serves the resource; a 3xx is a redirect, not access
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
  if have unfurl; then hosts="$(unfurl -u format '%s://%d' < "$alive_file" 2>/dev/null | sort -u | head -n "${PROP_MAX_HOSTS:-15}")"
  else hosts="$(awk -F/ 'NF>=3{print $1"//"$3}' "$alive_file" 2>/dev/null | sort -u | head -n "${PROP_MAX_HOSTS:-15}")"; fi
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
  # Run once (marker, not "file non-empty") so OpenAPI request-body schemas appended earlier by the
  # funnel are preserved - and so re-calls (agent then PoC-gen) don't duplicate the HTML harvest.
  [ -f "$OUTDIR/.forms_done" ] && return 0
  touch "$OUTDIR/.forms_done"
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
    [ -f "${nuclei_file:-}" ] && grep -oiE 'https?://[^ |]+' "$nuclei_file"
    [ -f "${unauth_api_file:-}" ] && grep -oiE 'https?://[^ |]+' "$unauth_api_file"
  } 2>/dev/null | sort -u | head -n 60 | while IFS= read -r u; do
    [ -n "$u" ] || continue
    r1="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} ${agent_captured_auth:+-H "$agent_captured_auth"} "$u" 2>/dev/null || echo '000 0')"
    r2="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} ${agent_captured_auth:+-H "$agent_captured_auth"} "$u" 2>/dev/null || echo '000 0')"
    s1="${r1%% *}"; z1="${r1##* }"; s2="${r2%% *}"; z2="${r2##* }"
    # A client-error rejection (400/403/404/405/406/410/...) is NOT a finding, even when its body
    # echoes our input and so differs from the SPA catch-all. Only verify success/redirect codes.
    case "$s1" in 200|201|202|203|206|301|302|303|307|308|500) ;; *) continue ;; esac
    # Control = a nonexistent LEAF in the SAME directory, query preserved. (The old form inserted
    # a path segment before the query -> /page.php/ctl?id=1 still executes page.php via PathInfo
    # on PHP/IIS and returned the real page, falsely nuking valid findings.)
    cu="$(printf '%s' "$u" | sed -E 's#^(https?://[^/]+/([^?]*/)?)[^/?]*(\?.*)?$#\14tctl'"${RANDOM}"'\3#')"
    rc="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} ${agent_captured_auth:+-H "$agent_captured_auth"} "$cu" 2>/dev/null || echo '000 0')"
    sc="${rc%% *}"; zc="${rc##* }"
    if [ "$s1" = "$s2" ] && _near "$z1" "$z2" && [ "$s1" != 000 ] && { [ "$s1" != "$sc" ] || ! _near "$z1" "$zc"; }; then
      printf 'VERIFIED %s [%s, %sB] (bogus control -> %s/%sB, differs)\n' "$u" "$s1" "$z1" "$sc" "$zc" >> "$verified_file"
    fi
  done
}

# --- OWASP / API Top-10 lightweight detectors (GET-only, capped, non-destructive) ----------
# A05: open directory listings -> flag + extract linked confidential files into the URL pool.
open_dir_scan() {
  [ "${OPEN_DIR_CHECK:-1}" = 1 ] || return 0
  : > "$open_dir_file"
  local u body href fu origin
  { [ -s "${fuzz_findings_file:-/dev/null}" ] && awk -F'\t' '$1==200{print $3}' "$fuzz_findings_file" 2>/dev/null
    [ -s "${urls_file:-/dev/null}" ] && grep -iE '/$' "$urls_file" 2>/dev/null
  } | awk 'NF && !seen[$0]++' | head -n "${OPEN_DIR_MAX:-60}" | while IFS= read -r u; do
    [ -n "$u" ] || continue
    body="$(curl -s -L --max-time 10 ${CURL_NET[@]+"${CURL_NET[@]}"} "$u" 2>/dev/null | head -c 20000)"
    printf '%s' "$body" | grep -qiE 'Index of /|<title>Directory listing|Directory listing for|Parent Directory|\[To Parent Directory\]' || continue
    printf '[open-directory] %s\n' "$u" >> "$open_dir_file"
    origin="$(printf '%s' "$u" | sed -E 's#(https?://[^/]+).*#\1#')"
    printf '%s' "$body" | grep -aoE 'href="[^"]+"' | sed -E 's/^href="//; s/"$//' \
      | grep -iE '\.(bak|old|sql|env|ya?ml|zip|conf|cfg|json|md|log|tar|gz|tgz|pem|key|ini)$' \
      | while IFS= read -r href; do
          case "$href" in http*) fu="$href";; /*) fu="$origin$href";; *) fu="${u%/}/$href";; esac
          printf '%s\n' "$fu" >> "$urls_file"
          printf '  -> %s\n' "$fu" >> "$open_dir_file"
        done
  done
}
# A05/A03: 500 pages leaking stack traces / DB errors.
stacktrace_harvest() {
  [ "${STACKTRACE_CHECK:-1}" = 1 ] || return 0
  : > "$stacktrace_file"
  [ -s "${fuzz_findings_file:-/dev/null}" ] || return 0
  local u body m
  awk -F'\t' '$1==500{print $3}' "$fuzz_findings_file" 2>/dev/null | awk 'NF && !seen[$0]++' \
    | head -n "${STACKTRACE_MAX:-5}" | while IFS= read -r u; do
    body="$(curl -s -L --max-time 10 ${CURL_NET[@]+"${CURL_NET[@]}"} "$u" 2>/dev/null | head -c 12000)"
    m="$(printf '%s' "$body" | grep -aoiE 'SQLITE_[A-Z]+|SQLSTATE|ORA-[0-9]{4,}|SQL syntax.*(MySQL|MariaDB)|PDOException|Sequelize[A-Za-z]*Error|SyntaxError|ReferenceError|TypeError:|at Object\.<anonymous>|Traceback \(most recent call last\)|java\.lang\.[A-Za-z.]+Exception|System\.[A-Za-z.]+Exception' | head -1)"
    [ -n "$m" ] || continue
    printf '[stack-trace] %s | %s\n' "$u" "$m" >> "$stacktrace_file"
  done
}
# API1/A01: unauthenticated REST/API data exposure (BOLA candidates). Probes ANONYMOUSLY
# (CURL_PROXY carries no auth header) so it works even when no session was supplied.
unauth_api_scan() {
  [ "${UNAUTH_API_CHECK:-1}" = 1 ] || return 0
  : > "$unauth_api_file"
  local u resp body f sz
  { [ -s "${js_endpoints_file:-/dev/null}" ] && grep -iE '/api/|/rest/|/admin|/config|/internal|/debug|/actuator|/env|/settings' "$js_endpoints_file" 2>/dev/null
    [ -s "${targets_active_file:-/dev/null}" ] && grep -iE '/api/|/rest/|/admin|/config|/internal|/debug|/actuator|/env|/settings' "$targets_active_file" 2>/dev/null
  } | awk 'NF && !seen[$0]++' | head -n "${UNAUTH_API_MAX:-60}" | while IFS= read -r u; do
    [ -n "$u" ] || continue
    resp="$(curl -s -i -L --max-time 10 ${CURL_PROXY[@]+"${CURL_PROXY[@]}"} "$u" 2>/dev/null | head -c 40000)"
    printf '%s' "$resp" | head -1 | grep -qE ' 20[0-6]' || continue
    printf '%s' "$resp" | grep -qiE '^content-type:.*json' || continue
    body="$(printf '%s' "$resp" | sed -E '1,/^\r{0,1}$/d')"
    sz="$(printf '%s' "$body" | wc -c | tr -d ' ')"; [ "${sz:-0}" -gt 100 ] || continue   # ignore tiny/empty JSON
    # Broader PII / ownership / credential key set (not just login fields).
    f="$(printf '%s' "$body" | grep -aoiE '"(email|password|passwd|hash|totpSecret|role|isAdmin|is_admin|permissions|UserId|userId|BasketId|cardNum|creditCard|ssn|balance|wallet|apiKey|secret|secretKey|privateKey|token|jwt|smtp|dbHost)"' | sort -u | tr -d '"' | tr '\n' ',' | sed 's/,$//' | head -c 160)"
    if [ -n "$f" ]; then
      printf '[unauth-api-exposure] %s (%sB) | sensitive fields: %s\n' "$u" "$sz" "$f" >> "$unauth_api_file"
    elif printf '%s' "$u" | grep -qiE '/(admin|config|configuration|internal|debug|actuator|env|users|accounts|settings)(/|\?|$)'; then
      # Privileged route name returning a sizeable unauthenticated JSON body is itself a finding.
      printf '[unauth-api-exposure] %s (%sB) | unauthenticated JSON on a privileged route\n' "$u" "$sz" >> "$unauth_api_file"
    fi
  done
}
# A01: deterministic open-redirect confirmation via a canary (no OAST needed).
openredir_confirm() {
  [ "${OPENREDIR_CHECK:-1}" = 1 ] || return 0
  : > "$openredir_file"
  local u inj loc canary='https://4tail-canary.example.org/'
  local rparams='(to|redirect|redir|next|url|uri|return|returnurl|return_url|dest|destination|continue|out|goto)'
  { [ -f "${gf_file:-/dev/null}" ] && grep -iE '^redirect\t' "$gf_file" 2>/dev/null | cut -f2
    [ -s "${targets_active_file:-/dev/null}" ] && grep -aiE "[?&]${rparams}=" "$targets_active_file" 2>/dev/null
  } | awk 'NF && !seen[$0]++' | head -n "${OPENREDIR_MAX:-25}" | while IFS= read -r u; do
    [ -n "$u" ] || continue
    inj="$(printf '%s' "$u" | sed -E "s#([?&]${rparams})=[^&]*#\1=${canary//#/\\#}#Ig")"
    [ "$inj" = "$u" ] && continue
    loc="$(curl -s -o /dev/null -D - --max-time 8 ${CURL_NET[@]+"${CURL_NET[@]}"} "$inj" 2>/dev/null | grep -iE '^location:' | head -1 | tr -d '\r')"
    printf '%s' "$loc" | grep -qiE '4tail-canary\.example\.org' && printf '[open-redirect] %s | %s\n' "$u" "$loc" >> "$openredir_file"
  done
}
# A07: passive JWT weakness analysis (alg=none, symmetric HS*, missing exp, sensitive claims).
_b64url_decode() { local s="$1" pad; pad=$(( (4 - ${#s} % 4) % 4 )); s="$s$(printf '%*s' "$pad" '' | tr ' ' '=')"; printf '%s' "$s" | tr '_-' '/+' | base64 -d 2>/dev/null; }
jwt_analyze() {
  [ "${JWT_CHECK:-1}" = 1 ] || return 0
  : > "$jwt_file"; have jq || return 0
  local tok hdr pl hj pj alg exp issues sens
  { [ -s "${js_secrets_file:-/dev/null}" ] && grep -aoE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' "$js_secrets_file" 2>/dev/null
    [ -s "${agent_file:-/dev/null}" ] && grep -aoE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' "$agent_file" 2>/dev/null
    printf '%s\n%s\n%s' "${AUTH_HEADER:-}" "${AUTH_COOKIE:-}" "${AUTH_A:-}" | grep -aoE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
  } 2>/dev/null | awk 'NF && !seen[$0]++' | head -n 20 | while IFS= read -r tok; do
    hdr="${tok%%.*}"; pl="${tok#*.}"; pl="${pl%%.*}"
    hj="$(_b64url_decode "$hdr")"; pj="$(_b64url_decode "$pl")"
    alg="$(printf '%s' "$hj" | jq -r '.alg // empty' 2>/dev/null)"
    exp="$(printf '%s' "$pj" | jq -r '.exp // empty' 2>/dev/null)"
    issues=""
    case "$alg" in none|None|NONE) issues="$issues alg=none(!)";; HS256|HS384|HS512) issues="$issues symmetric-$alg";; esac
    [ -z "$exp" ] && issues="$issues missing-exp"
    sens="$(printf '%s' "$pj" | grep -aoiE '"(password|hash|totpSecret|role|isAdmin|secret)"' | tr -d '"' | tr '\n' ',' | sed 's/,$//')"
    [ -n "$sens" ] && issues="$issues sensitive-claims:$sens"
    [ -n "$issues" ] && printf '[jwt] %.48s… | alg=%s |%s\n' "$tok" "${alg:-?}" "$issues" >> "$jwt_file"
  done
}
# Status-probe the endpoints mined from JS bundles / source maps (they were only STRING
# literals until now - never actually requested). Fold the results into fuzz_findings so every
# downstream pass sees the real REST/API surface: 401/403 -> try_403_bypass, 500 -> stack-trace
# harvester, 200 -> content-discovery + open-dir, all -> katana seed. The anonymous JSON check
# is handled separately by unauth_api_scan.
probe_mined_endpoints() {
  [ "${PROBE_MINED:-1}" = 1 ] || return 0
  have httpx || return 0
  local infile="$OUTDIR/.mined_in.txt"
  { [ -s "${js_endpoints_file:-/dev/null}" ] && cat "$js_endpoints_file"
    [ -s "${smap_endpoints_file:-/dev/null}" ] && cat "$smap_endpoints_file"
  } 2>/dev/null \
    | grep -iE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" \
    | grep -ivE '\.(png|jpe?g|gif|svg|woff2?|ttf|eot|css|ico|map|js)([?#]|$)' \
    | awk 'NF && !seen[$0]++' \
    | awk '{ p=2; if ($0 ~ /\?|\/rest\/|\/api\/|\/graphql|\/v[0-9]+\/|\/auth|\/admin|\/user|\/account|\/config|\/internal/) p=0; print p"\t"$0 }' \
    | sort -k1,1n -s | cut -f2- | head -n "${PROBE_MINED_MAX:-250}" > "$infile"
  [ -s "$infile" ] || { rm -f "$infile"; return 0; }
  # SPA catch-all fingerprint: a single-page app serves index.html (same status+length) for EVERY
  # unknown path, so probe one random nonexistent path first and drop any mined result matching it
  # (otherwise 50+ bogus paths all show as 200/<shell-size>).
  local corigin cfp cs cl
  corigin="$(head -1 "$infile" | sed -E 's#(https?://[^/]+).*#\1#')"
  cfp="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -L --max-time 10 ${CURL_NET[@]+"${CURL_NET[@]}"} "$corigin/4tail_spa_${RANDOM}${RANDOM}" 2>/dev/null || echo '')"
  cs="${cfp%% *}"; cl="${cfp##* }"; case "$cs" in ''|*[!0-9]*) cs=""; esac
  local catch="$OUTDIR/.spa_catchall_urls.txt"; : > "$catch"
  httpx -silent -status-code -content-length -l "$infile" ${HTTPX_NET[@]+"${HTTPX_NET[@]}"} 2>/dev/null \
    | sed -E 's/\x1b\[[0-9;]*m//g' \
    | awk -v cs="$cs" -v cl="$cl" -v catch="$catch" '{ u=$1; sc=$2; c=$3; gsub(/[][]/,"",sc); gsub(/[][]/,"",c);
             if (sc !~ /^[0-9]+$/) next; if (c=="") c=0;
             if (cs!="" && sc==cs && c+0>=cl-64 && c+0<=cl+64) { print u > catch; next }   # SPA catch-all shell
             print sc"\t"c"\t"u }' >> "$fuzz_findings_file"
  rm -f "$infile"
  [ -s "$fuzz_findings_file" ] && sort -u -o "$fuzz_findings_file" "$fuzz_findings_file"
  # Purge the catch-all URLs (and their synthetic ?param= variants) from the sets that feed the
  # specialists, gf buckets and the triage tables, so /b2b/v2/orders etc. don't flood the report.
  if [ -s "$catch" ]; then
    cut -d'?' -f1 "$catch" | sort -u > "$catch.base"
    local f
    for f in "${urls_file:-}" "${targets_active_file:-}"; do
      [ -n "$f" ] && [ -f "$f" ] && awk -F'?' 'NR==FNR{bad[$1]=1;next}{ if($1 in bad) next; print }' "$catch.base" "$f" > "$f.t" 2>/dev/null && mv "$f.t" "$f"
    done
    [ -f "${gf_file:-/dev/null}" ] && awk -F'\t' 'NR==FNR{bad[$1]=1;next}{u=$2; sub(/\?.*/,"",u); if(u in bad) next; print}' "$catch.base" "$gf_file" > "$gf_file.t" 2>/dev/null && mv "$gf_file.t" "$gf_file"
    rm -f "$catch.base"
  fi
}
# Run all lightweight detectors (called from the funnel correlation pass).
run_owasp_detectors() {
  open_dir_scan; render 2>/dev/null || true
  stacktrace_harvest; render 2>/dev/null || true
  unauth_api_scan; render 2>/dev/null || true
  openredir_confirm; render 2>/dev/null || true
  jwt_analyze; render 2>/dev/null || true
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

