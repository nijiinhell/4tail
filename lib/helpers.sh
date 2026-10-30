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
  local st len url rest host scheme origin path code n=0 t trick h
  while IFS=$'\t' read -r st len url; do
    case "$st" in 401|403) ;; *) continue ;; esac
    [ -n "$url" ] || continue
    [ "$n" -ge "$BYPASS_MAX" ] && break; n=$((n+1))
    scheme="${url%%://*}"; rest="${url#*://}"; host="${rest%%/*}"
    case "$rest" in */*) path="/${rest#*/}" ;; *) path="/" ;; esac
    origin="$scheme://$host"
    for t in "$path/" "$path/." "/.$path" "$path%2e" "$path%20" "$path%09" "$path..;/" "$path?" ; do
      code="$(curl -s -o /dev/null -w '%{http_code}' -L --max-time 8 ${CURL_NET[@]+"${CURL_NET[@]}"} "$origin$t" 2>/dev/null || echo 000)"
      case "$code" in 200|201|202|203|206|301|302|307) printf '%s -> %s via path trick %s\n' "$url" "$code" "$origin$t" >> "$bypass_file"; n=$n ; break ;; esac
    done
    for h in "X-Forwarded-For: 127.0.0.1" "X-Original-URL: $path" "X-Rewrite-URL: $path" "X-Custom-IP-Authorization: 127.0.0.1" "X-Forwarded-Host: localhost" "X-Host: localhost" "X-Real-IP: 127.0.0.1" ; do
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 ${CURL_NET[@]+"${CURL_NET[@]}"} -H "$h" "$url" 2>/dev/null || echo 000)"
      case "$code" in 200|201|202|203|206) printf '%s -> %s via header %s\n' "$url" "$code" "$h" >> "$bypass_file"; break ;; esac
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
  # Harvest real application paths only: ignore static assets, traversal tokens, and probe artifacts
  local paths; paths="$(awk -F'\t' '$1=="200"{print $3}' "$fuzz_findings_file" 2>/dev/null \
      | sed -E 's#^[a-z]+://[^/]+##' \
      | grep -E '^/[a-zA-Z0-9_-]+' \
      | grep -vE '(\.\.|%2e|%20|%5c|aspxspy|google\.com|;|^\/[.:])' \
      | drop_static | sort -u | head -n "$PROP_MAX_PATHS")"
  [ -n "$paths" ] || return 0
  local origin p code
  while IFS= read -r origin; do
    [ -n "$origin" ] || continue
    while IFS= read -r p; do
      [ -n "$p" ] || continue
      grep -qF "$origin$p" "$fuzz_findings_file" 2>/dev/null && continue  # already known on this host
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 ${CURL_NET[@]+"${CURL_NET[@]}"} "$origin$p" 2>/dev/null || echo 000)"
      # Only record genuine 200 OK hits (never 401/403 WAF blocks or generic redirects)
      [ "$code" = 200 ] && printf '%s\t%s\n' "$code" "$origin$p" >> "$prop_file"
    done <<< "$paths"
  done <<< "$hosts"
}

# (#1) Dual-identity IDOR / broken-authz (Autorize-style): replay A's authorized requests
# as user B and as anon; same successful response = per-user authz not enforced.
idor_check() {
  [ "$IDOR" = 1 ] && [ -n "$AUTH_A" ] || return 0
  local cand; cand="$( { grep -iE '^idor\t' "$gf_file" 2>/dev/null | cut -f2
      grep -iE '[?&](id|uid|user|userid|account|acct|order|invoice|doc|docid|file|fileid|num|no|pid|gid|key|ref)=[0-9]+' "$targets_active_file" 2>/dev/null
    } | sort -u | head -n "$IDOR_MAX" )"
  [ -n "$cand" ] || return 0
  local u ra rx rb ca sa cx sx cb sb
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    ra="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 10 ${CURL_NET[@]+"${CURL_NET[@]}"} -H "$AUTH_A" "$u" 2>/dev/null || echo '000 0')"
    ca="${ra%% *}"; sa="${ra##* }"
    [ "$ca" = 200 ] && [ "${sa:-0}" -gt 0 ] 2>/dev/null || continue   # only resources A can actually read
    rx="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 10 ${CURL_NET[@]+"${CURL_NET[@]}"} "$u" 2>/dev/null || echo '000 0')"
    cx="${rx%% *}"; sx="${rx##* }"
    [ "$cx" = 200 ] && _near "$sa" "$sx" && printf '[ANON-ACCESS] %s | authorized content served with NO session (A=200/%s anon=200/%s)\n' "$u" "$sa" "$sx" >> "$idor_file"
    if [ -n "$AUTH_B" ]; then
      rb="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 10 ${CURL_NET[@]+"${CURL_NET[@]}"} -H "$AUTH_B" "$u" 2>/dev/null || echo '000 0')"
      cb="${rb%% *}"; sb="${rb##* }"
      [ "$cb" = 200 ] && _near "$sa" "$sb" && printf '[IDOR?] %s | user B gets the same resource as user A (A=200/%s B=200/%s) - verify object ownership\n' "$u" "$sa" "$sb" >> "$idor_file"
    fi
  done <<< "$cand"

  # Path-based IDOR / BOLA: REST object ids live in the path (/api/Users/1, /rest/basket/42),
  # not the query string. With identity A, read object N, then try a NEIGHBOUR id - if A can
  # read it too (and the endpoint isn't just answering 200 to every id), that's a BOLA lead.
  local pcand purl pid alt alturl cid ralt calt salt rcc ccc scc
  pcand="$( { grep -aoiE 'https?://[^ "]+/[0-9]{1,9}(/[a-z0-9._-]+)?/?$' "$targets_active_file" 2>/dev/null
              grep -aoiE 'https?://[^ "]+/[0-9]{1,9}(/[a-z0-9._-]+)?/?$' "${js_endpoints_file:-/dev/null}" 2>/dev/null
            } | sort -u | head -n "$IDOR_MAX" )"
  while IFS= read -r purl; do
    [ -n "$purl" ] || continue
    pid="$(printf '%s' "$purl" | grep -oE '/[0-9]{1,9}(/|$)' | tail -1 | tr -dc '0-9')"
    [ -n "$pid" ] || continue
    ra="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 10 ${CURL_NET[@]+"${CURL_NET[@]}"} -H "$AUTH_A" "$purl" 2>/dev/null || echo '000 0')"
    ca="${ra%% *}"; sa="${ra##* }"
    [ "$ca" = 200 ] && [ "${sa:-0}" -gt 0 ] 2>/dev/null || continue
    alt=$((pid + 1)); [ "$alt" = "$pid" ] && alt=$((pid + 2))
    alturl="$(printf '%s' "$purl" | sed -E "s#/${pid}(/|\$)#/${alt}\1#")"
    cid="$(printf '%s' "$purl" | sed -E "s#/${pid}(/|\$)#/99999987\1#")"   # unlikely id -> blanket-200 guard
    ralt="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 10 ${CURL_NET[@]+"${CURL_NET[@]}"} -H "$AUTH_A" "$alturl" 2>/dev/null || echo '000 0')"
    calt="${ralt%% *}"; salt="${ralt##* }"
    [ "$calt" = 200 ] && [ "${salt:-0}" -gt 0 ] 2>/dev/null || continue
    rcc="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 10 ${CURL_NET[@]+"${CURL_NET[@]}"} -H "$AUTH_A" "$cid" 2>/dev/null || echo '000 0')"
    ccc="${rcc%% *}"; scc="${rcc##* }"
    # skip if the endpoint 200s even for a bogus id with a similar body (not id-scoped)
    if [ "$ccc" = 200 ] && _near "$salt" "$scc"; then continue; fi
    printf '[PATH-IDOR?] %s -> %s | identity A reads neighbour object id %s (200/%sB; bogus id -> %s/%sB) - verify ownership\n' "$purl" "$alturl" "$alt" "$salt" "$ccc" "$scc" >> "$idor_file"
  done <<< "$pcand"
}

# Verification pass (anti-false-positive, per 2026 AI-pentest research): re-test each
# CONFIRMED finding and require it to be (a) stable across two fetches and (b) DIFFERENT
# from a bogus-sibling control - which weeds out soft-404 / catch-all pages that answer
# 200 to everything. Survivors go to verified_file; the rest stay as candidates.
verify_findings() {
  [ "$VERIFY" = 1 ] || return 0
  : > "$verified_file"
  local u r1 r2 rc s1 z1 s2 z2 sc zc cu
  { [ -f "${agent_file:-}" ]  && grep -oiE 'https?://[^ |]+' "$agent_file"
    [ -f "${bypass_file:-}" ] && grep -oiE 'https?://[^ |]+' "$bypass_file"
    [ -f "${idor_file:-}" ]   && grep -oiE 'https?://[^ |]+' "$idor_file"
    [ -f "${dast_file:-}" ]   && grep -oiE 'https?://[^ |]+' "$dast_file"
    [ -f "${corsy_file:-}" ]  && grep -oiE 'https?://[^ |]+' "$corsy_file"
  } 2>/dev/null | sort -u | head -n 60 | while IFS= read -r u; do
    [ -n "$u" ] || continue
    r1="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} "$u" 2>/dev/null || echo '000 0')"
    r2="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} "$u" 2>/dev/null || echo '000 0')"
    s1="${r1%% *}"; z1="${r1##* }"; s2="${r2%% *}"; z2="${r2##* }"
    cu="$(printf '%s' "$u" | sed -E "s#(\?.*)?\$#/4tailctl${RANDOM}&#")"
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
  cp "$cur" "$snap" 2>/dev/null; rm -f "$cur"
}

