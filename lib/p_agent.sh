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
  agent_seen="$OUTDIR/.agent_seen"; : > "$agent_seen"; : > "$OUTDIR/.agent_loot_urls"
  agent_loot_dir="$OUTDIR/agent_loot"; agent_post_n=0
  # Harvest real <form> fields NOW (before the probe loop) so the agent's POST probes use the
  # actual login/register field names instead of guessing. (PoC gen later reuses forms_file.)
  [ "$CRAWL" = 1 ] && harvest_forms
  # Secret value patterns: when a response matches, the RAW body is saved locally for the
  # human (never sent to the LLM) so a cred read via LFI is actually captured, not just noted.
  AGENT_SECRET_RE='connection[-_ ]?string|<add[^>]*connectionString|Data Source=|Server=.*;.*(Password|Pwd)=|Initial Catalog=|Provider=|machineKey|validationKey=|decryptionKey=|BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|password["'"'"' ]*[:=]|SA_PASSWORD|DB_PASSWORD'
  agent_capture_secret() {  # $1=url $2=raw-response ; saves raw locally if it carries a secret
    [ "$AGENT_LOOT" = 1 ] || return 0
    printf '%s' "$2" | grep -qiE -- "$AGENT_SECRET_RE" 2>/dev/null || return 0
    mkdir -p "$agent_loot_dir"
    local f="$agent_loot_dir/$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_' | tail -c 120).txt"
    { echo "# $1"; printf '%s\n' "$2"; } > "$f"
    grep -qF "[SECRET-LOOT] $1 " "$agent_file" 2>/dev/null && return 0   # already looted this url
    printf '[SECRET-LOOT] %s | raw response with credentials saved -> %s\n' "$1" "$f" >> "$agent_file"
    printf '%s\n' "$1" >> "$OUTDIR/.agent_loot_urls" 2>/dev/null || true   # so confirm doesn't double-log it
  }
  # curl -i responses carry the HTTP headers first; Juice Shop's headers alone are ~330 bytes, so
  # head -c 240 of the whole thing never reached the JSON body. These split headers from body
  # (last block, so -L redirects resolve) so the agent actually SEES the body (JWT, "role":"admin").
  _http_body() { printf '%s' "$1" | awk '/^HTTP\//{h=NR;b=0} {l[NR]=$0} (h&&!b&&NR>h&&$0~/^\r?$/){b=NR} END{for(i=b+1;i<=NR;i++)print l[i]}'; }
  _http_status() { printf '%s' "$1" | grep -aiE '^HTTP/' | tail -1 | tr -d '\r'; }
  _http_keyhdrs() { printf '%s' "$1" | grep -aiE '^(location|set-cookie|content-type):' | tr -d '\r' | tr '\n' ' ' | head -c 220; }
  _status_code() { printf '%s' "$1" | grep -aoE '[0-9]{3}' | head -1; }   # 3-digit code from a status line
  # Body snippet for the LLM: small bodies in full; large ones as head + tail, so UNION-appended
  # rows at the END of a JSON array (e.g. a dumped Users table after the products) are still seen.
  _body_snip() {
    local b="$1"
    if [ "${#b}" -le 600 ]; then printf '%s' "$b" | tr '\n\r\t' '   ' | sed -E 's/  +/ /g' | head -c 520
    else { printf '%s' "$b" | head -c 260; printf ' … [%sB body, tail:] ' "${#b}"; printf '%s' "$b" | tail -c 260; } | tr '\n\r\t' '   ' | sed -E 's/  +/ /g'; fi
  }
  # Autonomous auth capture: when the user supplied NO session, a token/cookie the agent earns from
  # a 200/201 (register/login/leak) is captured ONCE and applied to every later probe, so it can
  # pivot into authenticated BOLA/IDOR/priv-esc on its own. Reads the UNREDACTED response.
  agent_autoauth=0; { [ -z "${AUTH_HEADER:-}" ] && [ -z "${AUTH_COOKIE:-}" ] && [ -z "${AUTH_A:-}" ]; } && agent_autoauth=1
  agent_captured_auth=""
  agent_try_capture_auth() {  # $1 = raw (unredacted) response
    [ "$agent_autoauth" = 1 ] && [ -z "$agent_captured_auth" ] || return 0
    local tok ck
    tok="$(printf '%s' "$1" | grep -aoiE '"(access[_-]?token|id[_-]?token|jwt|token)"[[:space:]]*:[[:space:]]*"[A-Za-z0-9._-]{20,}"' | head -1 | grep -aoE '[A-Za-z0-9._-]{20,}' | head -1)"
    if [ -n "$tok" ]; then
      agent_captured_auth="Authorization: Bearer $tok"
      # Decode the JWT payload: label the privilege level (so the agent knows admin vs low-priv for
      # BOLA/BFLA), flag sensitive claims leaked in the token, and save a token that carries secrets.
      local _pj _role _uid _claims
      _pj="$(_b64url_decode "$(printf '%s' "$tok" | cut -d. -f2)" 2>/dev/null)"
      _role="$(printf '%s' "$_pj" | jq -r '(.role // .isAdmin // .admin // .data.role // "?")' 2>/dev/null)"; [ -n "$_role" ] || _role="?"
      _uid="$(printf '%s' "$_pj" | jq -r '(.id // .userId // .data.id // .sub // "?")' 2>/dev/null)"; [ -n "$_uid" ] || _uid="?"
      _claims="$(printf '%s' "$_pj" | grep -aoiE '"(password|hash|totpSecret|secret|privateKey|ssn|card|role|isAdmin)"' | tr -d '"' | sort -u | tr '\n' ',' | sed 's/,$//')"
      printf '[auth-captured] bearer token acquired (role=%s, id=%s) - applied to subsequent probes\n' "$_role" "$_uid" >> "$agent_log"
      if [ -n "$_claims" ] && [ "$AGENT_LOOT" = 1 ]; then
        mkdir -p "$agent_loot_dir"; printf '# JWT from %s\n%s\n' "$1" "$_pj" > "$agent_loot_dir/jwt_claims.txt" 2>/dev/null
        printf '[JWT-CLAIMS-EXPOSURE] token payload carries sensitive claims: %s (saved to agent_loot/jwt_claims.txt)\n' "$_claims" >> "$agent_file"
      fi
      results="$results"$'\n'"[auth-captured role=$_role id=$_uid] bearer token applied to all further probes - re-test the 401/403 endpoints and id-walk resource paths (role=$_role means $([ "$_role" = "?" ] && echo 'unknown privilege' || echo "privilege=$_role"))"
      return 0
    fi
    ck="$(printf '%s' "$1" | grep -aoiE '^set-cookie:[[:space:]]*[^;[:space:]]+' | head -1 | sed -E 's/^set-cookie:[[:space:]]*//I')"
    if [ -n "$ck" ]; then
      agent_captured_auth="Cookie: $ck"
      printf '[auth-captured] session cookie acquired - applied to subsequent probes\n' >> "$agent_log"
      results="$results"$'\n'"[auth-captured] a session cookie was captured and is now applied to all further probes - re-test the 401/403 endpoints and id-walk resource paths"
    fi
  }
  # Scope string for the AI: in single-host / custom-port mode, hand it the exact seed URL
  # (http://localhost:3000) so it keeps the scheme+port; otherwise the wildcard host scope.
  agent_scope="*.$domain"; [ "${SINGLE:-0}" = 1 ] && agent_scope="${SEED_URL:-$agent_scope}"
  # Compact "situation" brief: the juiciest, most actionable signals only.
  situation="$( {
      echo "TARGET SCOPE: $agent_scope"
      [ -s "${stale_file:-/dev/null}" ] && { echo "LEGACY HOSTS (older=prioritize):"; head -5 "$stale_file"; }
      [ -s "$dast_file" ] && { echo "CONFIRMED DAST (nuclei):"; head -20 "$dast_file"; }
      [ -s "$nuclei_file" ] && { echo "CONFIRMED NUCLEI (cves/exposures/misconfig/tech):"; head -20 "$nuclei_file"; }
      [ -s "$js_secrets_file" ] && { echo "JS SECRET CANDIDATES (url<TAB>match):"; head -15 "$js_secrets_file"; }
      [ -s "${sourcemap_file:-/dev/null}" ] && { echo "SOURCE MAPS RECOVERED (.js.map -> original source leaked; reconstructed source mined for secrets/endpoints above):"; head -10 "$sourcemap_file"; }
      [ -s "${api_specs_file:-/dev/null}" ] && { echo "EXPOSED API SPECS (fetch + inspect):"; head -10 "$api_specs_file"; }
      [ -s "${gql_schema_file:-/dev/null}" ] && { echo "GRAPHQL INTROSPECTION OPEN (full schema readable - map authz/IDOR per field):"; head -60 "$gql_schema_file"; }
      [ -s "${bypass_file:-/dev/null}" ] && { echo "ACCESS-CONTROL BYPASSES (403->200):"; head -10 "$bypass_file"; }
      [ -s "${idor_file:-/dev/null}" ] && { echo "IDOR / AUTHZ CANDIDATES:"; head -10 "$idor_file"; }
      [ -s "${unauth_api_file:-/dev/null}" ] && { echo "UNAUTH API EXPOSURE (anon GET returned sensitive JSON - escalate: id-walk, confirm BOLA):"; head -10 "$unauth_api_file"; }
      [ -s "${open_dir_file:-/dev/null}" ] && { echo "OPEN DIRECTORIES + EXPOSED FILES (GET the listed files):"; head -12 "$open_dir_file"; }
      [ -s "${openredir_file:-/dev/null}" ] && { echo "CONFIRMED OPEN REDIRECTS:"; head -8 "$openredir_file"; }
      [ -s "${jwt_file:-/dev/null}" ] && { echo "JWT WEAKNESSES (forge/replay candidates):"; head -8 "$jwt_file"; }
      [ -s "${stacktrace_file:-/dev/null}" ] && { echo "STACK TRACES / DB ERRORS (verbose errors - probe the failing param deeper):"; head -8 "$stacktrace_file"; }
      [ -s "$findings_dir/kxss.txt" ] && { echo "REFLECTED PARAMS (kxss):"; head -15 "$findings_dir/kxss.txt"; }
      [ -s "${js_endpoints_file:-/dev/null}" ] && { echo "MINED API ENDPOINTS (from JS bundles - the SPA's real /rest + /api surface; GET them, POST login/register bodies, id-walk numeric path segments):"; head -40 "$js_endpoints_file"; }
      [ -s "$gf_file" ] && { echo "GF CANDIDATE BUCKETS (class<TAB>url):"; head -40 "$gf_file"; }
      [ -s "$fuzz_findings_file" ] && { echo "EMPTY/SMALL 200 ENDPOINTS (param-mine candidates):";
        awk -F'\t' '$1==200 && $2+0<80 {print $3}' "$fuzz_findings_file" | head -15; }
      [ -s "$fuzz_findings_file" ] && { echo "NOTABLE PATHS:";
        awk -F'\t' '$1~/^(200|301|302|401|403)$/{print $1" "$3}' "$fuzz_findings_file" | grep -ivE 'google\.com|etc.{0,3}passwd' | head -25; }
      [ -s "$fuzz_findings_file" ] && { echo "AUTH-GATED ENDPOINTS (401/403 - re-probe these once you capture a token/cookie):";
        awk -F'\t' '$1==401||$1==403{print $3}' "$fuzz_findings_file" | head -20; }
      [ -s "${forms_file:-/dev/null}" ] && { echo "HARVESTED FORMS (page<TAB>method<TAB>action<TAB>fields - use these REAL field names for POST probes: auth SQLi, mass assignment, CSRF):"; head -20 "$forms_file"; }
      [ -s "${js_fields_file:-/dev/null}" ] && { echo "MINED REQUEST FIELD NAMES (from JS bundles - the app's real body/param vocabulary; prefer these over guessing, and send {} to an unknown POST to learn the rest from its 400/422 error):"; paste -sd, "$js_fields_file" | head -c 1000; echo; }
      [ -s "${spa_routes_file:-/dev/null}" ] && { echo "SPA CLIENT ROUTES (from the JS router - hidden/privileged views to GET; guards are client-side only, so the API behind them may be open):"; grep -iE '/(admin|account|internal|debug|config|audit|score|board|wallet|payment|deluxe|b2b|support|logs|sandbox|web3)' "$spa_routes_file" 2>/dev/null | head -15 || head -15 "$spa_routes_file"; }
      [ -s "${dom_xss_file:-/dev/null}" ] && { echo "DOM-XSS SINKS (client-side; a URL/hash param flowing into one of these is DOM XSS):"; head -6 "$dom_xss_file"; }
      [ "$OAST" = 1 ] && [ -n "${OAST_DOMAIN:-}" ] && echo "OAST DOMAIN: you have an out-of-band collaborator. Put a unique subdomain like agent-r<round>.$OAST_DOMAIN into url/redirect/callback params or SSRF-able fields; a DNS/HTTP callback to it CONFIRMS blind SSRF/RCE."
    } | head -c 12000 )"
  astart=$SECONDS; round=0; results="(none yet - this is the first round)"
  agent_notes="(none yet - first round; form your initial hypotheses from the situation)"
  toolcalls=0
  agent_tools=""; [ "$AGENT_TOOLS" = 1 ] && agent_tools="$(agent_tool_list)"
  while [ "$round" -lt "$AGENT_ROUNDS" ]; do
    round=$((round+1))
    budget_ok || { SUP_NOTE="agent: budget reached, stopping"; break; }
    [ "$AGENT_MAX_TIME" -gt 0 ] 2>/dev/null && [ $((SECONDS-astart)) -ge "$AGENT_MAX_TIME" ] && break
    set_stage $S_AGENT running "round $round/$AGENT_ROUNDS: AI thinking"
    aout="$(mktemp)"
    # Reasoning models (GLM/DeepSeek) spend tokens on internal CoT before emitting .content;
    # too small a budget => finish_reason=length with empty content => "no probes proposed".
    ai_call "$LLM_MODEL_PLAN" "${LLM_MAX_TOKENS_PLAN:-6000}" \
"You are an autonomous web-app pentester on an AUTHORIZED target, working in rounds. You keep a running NOTES block (your hypotheses: what you suspect, why, and what is confirmed / refuted / still-unconfirmed), update it each round from the latest results, then take the next ACTIONS to chase the hottest lead, then decide whether to keep going.
Three kinds of action:
  GET <url> | why | success-regex            -> a passive fetch you confirm by regex (LFI reads, redirects, param mining, IDOR id-walking).
  POST|PUT|PATCH <url> | body | why | success-regex  -> a body-based write to test login/register logic, body IDOR/SQLi, mass assignment, forged-review / product-tampering (PUT/PATCH on a REST item you do not own). body is raw urlencoded, JSON, or XML. Content-Type is auto-set: {/[ -> json, </<?xml -> xml, else form. NON-DESTRUCTIVE only: benign markers, id=1/id=2, a single quote for SQLi - never DROP/DELETE/TRUNCATE/SHUTDOWN/xp_cmdshell or mass writes (refused).
  TOOL <name> <url> | tags=...               -> run a real tool. ONLY these are installed: ${agent_tools:-none}. Use them to CONFIRM, e.g. sqlmap on a SQLi-looking param (it always runs capped at --level=1 --risk=1; higher levels are ignored), dalfox on a reflecting param, nuclei <url> tags=iis,cve on a fingerprinted host, git-dumper on an exposed /.git, nuclei-dast to fuzz a param URL. Prefer a TOOL to prove a lead over guessing.
Work from first principles on THIS target - do not assume any framework's specific paths or field names. Methodology:
- SCHEMA FIRST: before POSTing to an endpoint whose body fields you do not already know from the DISCOVERED FORMS/FIELDS or an API spec, send an empty JSON body {} (or a single dummy field) once. A 400/422 validation error usually names the required fields (e.g. a message like: field NAME is required); use those exact names next round. Do NOT invent field names.
- LFI / path traversal: on a param that names a file/template/page, read common sensitive files relative to it (../ up to the web root: app config, env files, /etc/passwd, source) and confirm with a content signature (connectionString, root:.*:0:0:, BEGIN PRIVATE KEY). 4tail saves any raw credential file for the human.
- empty/small 200 endpoints -> add plausible params (?id=1&debug=1); redirect-looking params -> set an off-site absolute URL and watch the Location header; an exposed /.git -> git-dumper.
For the MINED API ENDPOINTS go further than GET: (a) PATH-IDOR/BOLA - a numeric or UUID path segment is an object id, so GET a neighbour id and compare; a readable record you should not own is a lead; (b) AUTH/SQLi - POST to a login/auth endpoint with a single quote in the identifier field and look for a SQL error or an unexpected auth success; (c) MASS ASSIGNMENT - when registering or updating a profile, add standard privilege attributes alongside the REAL required fields: role (e.g. admin), isAdmin/is_admin true, permissions, group, plan; (d) BFLA/WRITE-AUTHZ - try PUT/PATCH on a REST item you do not own (e.g. a product or another user's review) to change it (forged review / product tampering); (e) NoSQLi - if a login/search endpoint ignores a SQL quote, POST a JSON operator body like {"email":{"\$gt":""},"password":{"\$gt":""}} or {"\$ne":null}; (f) SSTI - on a reflected text field, send {{7*7}} or #{7*7} and check if 49 appears; (g) XXE - on a B2B/order/import/upload route that takes XML, POST a body starting with <?xml declaring an external entity reading a benign file (file:///etc/hostname) and look for the file content echoed back. Use POST/PUT/PATCH for these.
If an unauthenticated probe returns a session token or creates an account, 4tail auto-captures it and applies it to your later probes - so next round PIVOT to re-testing the 401/403 endpoints and sequential/UUID resource paths for BOLA/IDOR with that new access.
All URLs MUST be on the target scope $agent_scope (keep the scheme and port exactly as given). Respond in EXACTLY this structure, nothing else:
NOTES:
<2-6 short lines: updated hypotheses + status>
ACTIONS:
<one GET, POST or TOOL line each>
DECISION: CONTINUE
(use 'DECISION: STOP' when leads are exhausted or everything promising is already confirmed)" \
"SITUATION:
$situation

AVAILABLE TOOLS: ${agent_tools:-none}

YOUR NOTES SO FAR:
$agent_notes

LATEST RESULTS:
$results" > "$aout" 2>>"$llm_log" || true
    # Round 1: log the head of what the model actually received, so a broken/empty situation brief
    # (e.g. an arg-shift bug) is immediately visible in agent.log instead of silently failing.
    [ "$round" -eq 1 ] && { printf '=== round 1 user-prompt head ===\n'; head -c 500 <<<"SITUATION:
$situation"; printf '\n=== end head ===\n'; } >> "$agent_log" 2>/dev/null
    # Strip markdown code fences first so headings like ``` ### NOTES ### ``` parse cleanly.
    sed -i '/^[[:space:]]*```/d' "$aout" 2>/dev/null || true
    # --- parse the structured reply (robust to reasoning-model + markdown wrapping) ---
    # Match NOTES:/## NOTES/### NOTES ###/**NOTES** between it and the ACTIONS/PROBES/DECISION marker.
    new_notes="$(awk 'BEGIN{p=0} /^[[:space:]#*]*NOTES[[:space:]#*:]*$|^[[:space:]#*]*NOTES[[:space:]]*:/{p=1;next} /^[[:space:]#*]*(ACTIONS|PROBES|DECISION)[[:space:]#*:]*$|^[[:space:]#*]*(ACTIONS|PROBES|DECISION)[[:space:]]*:/{p=0} p' "$aout" | sed '/^[[:space:]]*$/d' | head -n 8)"
    [ -n "$new_notes" ] && agent_notes="$new_notes"
    # DECISION: explicit STOP only (default is to continue while leads/probes remain).
    decision="$(grep -ioE 'DECISION[[:space:]#*]*:?[[:space:]#*]*(CONTINUE|STOP)' "$aout" | head -1 | grep -ioE '(CONTINUE|STOP)' | tr 'a-z' 'A-Z')"
    # ACTIONS: lines under the ACTIONS/PROBES section (GET or TOOL); fall back to any URL line.
    probes="$(awk 'BEGIN{p=0} /^[[:space:]#*]*(ACTIONS|PROBES)[[:space:]#*:]*$|^[[:space:]#*]*(ACTIONS|PROBES)[[:space:]]*:/{p=1;next} /^[[:space:]#*]*DECISION[[:space:]#*:]*$|^[[:space:]#*]*DECISION[[:space:]]*:/{p=0} p' "$aout" | grep -iE 'https?://|^[[:space:]]*TOOL ')"
    [ -n "$probes" ] || probes="$(grep -iE 'https?://|^[[:space:]]*TOOL ' "$aout")"
    probes="$(printf '%s\n' "$probes" | head -n $((AGENT_MAX_PROBES * 3)))"; rm -f "$aout"
    printf '=== round %s notes ===\n%s\n' "$round" "$agent_notes" >> "$agent_log"
    [ -n "$probes" ] || { [ "$round" -eq 1 ] && SUP_NOTE="agent: no probes proposed"; break; }
    # Default "looks sensitive" markers so a probe can confirm even when the model gives no regex.
    agent_default_rx='connectionString|<configuration|<\?xml|root:.{0,40}:0:0:|\[fonts\]|\[extensions\]|16-bit app support|BEGIN [A-Z ]*PRIVATE KEY|DB_PASSWORD|SA_PASSWORD|Microsoft OLE DB|ODBC|SQL syntax.*MySQL|ORA-[0-9]{4,}|Directory of |<web-app|runtime error|SQLITE_ERROR|SequelizeDatabaseError|MongoError|CastError|BSONTypeError|\$where|SyntaxError: Unexpected token|ReferenceError|Traceback \(most recent call last\)|\b49\b.{0,10}(result|output|eval)|<!DOCTYPE[^>]*ENTITY'
    results=""; np=0
    while IFS= read -r pline; do
      # TOOL action: the agent runs a real tool itself (capped, scope-locked, whitelisted).
      if [ "$AGENT_TOOLS" = 1 ] && printf '%s' "$pline" | grep -qiE '(^|[^a-z])TOOL[: ]+[a-z]'; then
        [ "$toolcalls" -ge "$AGENT_MAX_TOOLCALLS" ] && continue
        tname="$(printf '%s' "$pline" | sed -E 's/.*TOOL[: ]+//I' | awk '{print tolower($1)}')"
        ttgt="$(printf '%s' "$pline" | grep -oiE 'https?://[^ "'"'"'`|<>]+' | head -1)"
        [ -n "$ttgt" ] || ttgt="$(printf '%s' "$pline" | grep -oiE '([a-z0-9-]+\.)+[a-z]{2,}' | head -1)"
        # Everything after the first '|' is the tool's extra args (tags= for nuclei, or the
        # safe sqlmap enum flags) - not just tags=, so the agent can actually pass them.
        textra="$(printf '%s' "$pline" | awk -F'|' 'NF>=2{sub(/^[^|]*\|/,""); print; exit}' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [ -n "$tname" ] && [ -n "$ttgt" ] || continue
        case " $agent_tools " in *" $tname "*) ;; *) continue ;; esac   # only offered tools
        grep -qxF "TOOL $tname $ttgt" "$agent_seen" 2>/dev/null && continue
        printf 'TOOL %s %s\n' "$tname" "$ttgt" >> "$agent_seen"; toolcalls=$((toolcalls+1))
        set_stage $S_AGENT running "round $round: TOOL $tname ($toolcalls/$AGENT_MAX_TOOLCALLS)"; render
        tr_out="$(agent_tool_run "$tname" "$ttgt" "$textra")"
        printf '[r%s] %s\n' "$round" "$tr_out" >> "$agent_log"
        results="$results"$'\n'"$tr_out"
        continue
      fi
      # POST probe: the agent tests a BODY-based bug itself (login/register logic, body
      # IDOR/SQLi, mass assignment). Scope-locked, capped, destructive bodies refused.
      if [ "$AGENT_POST" = 1 ] && printf '%s' "$pline" | grep -qiE '(^|[^a-z])(POST|PUT|PATCH)[: ]+https?://'; then
        [ "$np" -ge "$AGENT_MAX_PROBES" ] && continue
        [ "$agent_post_n" -ge "$AGENT_MAX_POST" ] && continue
        pmethod="$(printf '%s' "$pline" | grep -oiE '(POST|PUT|PATCH)[: ]+https?://' | head -1 | grep -oiE '^(POST|PUT|PATCH)' | tr 'a-z' 'A-Z')"
        purl="$(printf '%s' "$pline" | sed -E 's/.*(POST|PUT|PATCH)[: ]+//I' | awk -F'|' '{print $1}' | grep -oiE 'https?://[^ "'"'"'`<>]+' | head -1)"
        pbody="$(printf '%s' "$pline" | awk -F'|' 'NF>=2{print $2}' | sed 's/^ *//;s/ *$//')"
        pwhy="$(printf '%s'  "$pline" | awk -F'|' 'NF>=3{print $3}' | sed 's/^ *//;s/ *$//')"; [ -n "$pwhy" ] || pwhy="agent $pmethod probe"
        prx="$(printf '%s'   "$pline" | awk -F'|' 'NF>=4{print $4}' | sed 's/^ *//;s/ *$//')"; [ -n "$prx" ] || prx="$agent_default_rx"
        [ -n "$purl" ] || continue
        printf '%s' "$purl" | grep -qiE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" || continue   # scope lock
        # refuse clearly destructive bodies (quote probes / OR 1=1 / mass-assignment / NoSQL ops ok)
        if printf '%s' "$pbody" | grep -qiE 'drop[[:space:]]+table|truncate[[:space:]]+table|delete[[:space:]]+from|shutdown|xp_cmdshell|sp_configure|;[[:space:]]*drop|rm[[:space:]]+-rf|format[[:space:]]+c:'; then
          printf '[r%s] %s refused (destructive body): %s\n' "$round" "$pmethod" "$purl" >> "$agent_log"; continue
        fi
        grep -qxF "$pmethod $purl $pbody" "$agent_seen" 2>/dev/null && continue
        printf '%s %s %s\n' "$pmethod" "$purl" "$pbody" >> "$agent_seen"; np=$((np+1)); agent_post_n=$((agent_post_n+1))
        set_stage $S_AGENT running "round $round: $pmethod probe ($agent_post_n/$AGENT_MAX_POST)"; render
        # content-type by body shape: JSON for {/[ (incl. NoSQL operators like {"$gt":""}), XML for
        # <?xml/< (so XXE/SOAP payloads reach the XML parser), else form-urlencoded.
        pct="application/x-www-form-urlencoded"
        case "$pbody" in \{*|\[*) pct="application/json" ;; \<*) pct="application/xml" ;; esac
        presp="$(_cap curl -s -i -L -X "$pmethod" --max-time 15 ${CURL_NET[@]+"${CURL_NET[@]}"} ${agent_captured_auth:+-H "$agent_captured_auth"} -H "Content-Type: $pct" --data "$pbody" "$purl" 2>/dev/null | head -c 65536)"
        agent_capture_secret "$purl" "$presp"
        phit=""; printf '%s' "$presp" | grep -qiE -- "$prx" 2>/dev/null && phit="HIT"
        pstatus="$(_http_status "$presp")"; pcode="$(_status_code "$pstatus")"
        case "$pcode" in 200|201) agent_try_capture_auth "$presp" ;; esac
        pbody_raw="$(_http_body "$presp")"; pkeyh="$(_http_keyhdrs "$presp")"
        pbody_red="$(printf '%s' "$pbody_raw" | sed -E 's/((pass(word|wd)?|connection[-_ ]?string|accountkey|secret|api[-_]?key|token)[^[:cntrl:]]{0,8}[:=])[^[:cntrl:]"'"'"']{1,}/\1<redacted>/Ig')"
        psnip="$(_body_snip "$pbody_red")"
        printf '[r%s] %s %-4s %s (body: %.60s)\n   why: %s\n   resp: %s | %s | %s\n' "$round" "$pmethod" "${phit:-...}" "$purl" "$pbody" "$pwhy" "$pstatus" "$pkeyh" "$psnip" >> "$agent_log"
        results="$results"$'\n'"$pmethod $purl => ${phit:-no-match} [$pstatus] ${pkeyh} ${psnip}"
        # Record CONFIRMED once per (method,url); never on a 4xx; and not when the match is only the
        # SPA catch-all HTML shell (auth-bypass/mass-assignment artifacts are JSON/headers, not index.html).
        if [ "$phit" = HIT ]; then
          _pshell=0; printf '%s' "$pbody_raw" | head -c 80 | grep -qiE '^[[:space:]]*<(!doctype|html)' \
            && ! printf '%s' "$prx" | grep -qiE 'html|doctype|<' && _pshell=1
          case "$pcode" in 4[0-9][0-9]) : ;; *) [ "$_pshell" = 1 ] || grep -qxF "$purl" "$OUTDIR/.agent_loot_urls" 2>/dev/null \
              || grep -qF "[CONFIRMED] $pmethod $purl " "$agent_file" 2>/dev/null \
              || printf '[CONFIRMED] %s %s (body: %s) | %s\n' "$pmethod" "$purl" "$pbody" "$pwhy" >> "$agent_file" ;; esac
        fi
        continue
      fi
      # GET probe (passive fetch, regex-confirmed).
      [ "$np" -ge "$AGENT_MAX_PROBES" ] && continue
      url="$(printf '%s' "$pline" | grep -oiE 'https?://[^ "'"'"'`|<>]+' | head -1)"
      [ -n "$url" ] || continue
      why="$(printf '%s' "$pline" | awk -F'\\|' 'NF>=2{print $2}' | sed 's/^ *//;s/ *$//')"; [ -n "$why" ] || why="agent probe"
      rx="$(printf '%s'  "$pline" | awk -F'\\|' 'NF>=3{print $3}' | sed 's/^ *//;s/ *$//')"; [ -n "$rx" ] || rx="$agent_default_rx"
      # HARD GUARDRAILS: http(s) only, must be in target scope, no dup probes.
      printf '%s' "$url" | grep -qiE "^https?://([a-z0-9._-]+\.)?${esc_domain}([:/]|$)" || continue
      grep -qxF "$url" "$agent_seen" 2>/dev/null && continue
      printf '%s\n' "$url" >> "$agent_seen"; np=$((np+1))
      set_stage $S_AGENT running "round $round: probing ($(nlines "$agent_seen") sent)"; render
      resp="$(curl -s -i -L --max-time 12 ${CURL_NET[@]+"${CURL_NET[@]}"} ${agent_captured_auth:+-H "$agent_captured_auth"} "$url" 2>/dev/null | head -c 65536)"
      agent_capture_secret "$url" "$resp"   # save raw creds locally (not to the LLM) if present
      # (body is redacted below before it is shown to the LLM)
      hit=""; [ -n "$rx" ] && printf '%s' "$resp" | grep -qiE -- "$rx" 2>/dev/null && hit="HIT"
      local_status="$(_http_status "$resp")"; gcode="$(_status_code "$local_status")"
      case "$gcode" in 200|201) agent_try_capture_auth "$resp" ;; esac
      gbody="$(_http_body "$resp")"; gkeyh="$(_http_keyhdrs "$resp")"
      gbody_red="$(printf '%s' "$gbody" | sed -E 's/((pass(word|wd)?|connection[-_ ]?string|accountkey|secret|api[-_]?key|token|aws[_-]?secret[_-]?access[_-]?key)[^[:cntrl:]]{0,8}[:=])[^[:cntrl:]"'"'"']{1,}/\1<redacted>/Ig')"
      snippet="$(_body_snip "$gbody_red")"
      printf '[r%s] %-4s %s\n   why: %s\n   resp: %s | %s | %s\n' "$round" "${hit:-...}" "$url" "$why" "$local_status" "$gkeyh" "$snippet" >> "$agent_log"
      results="$results"$'\n'"$url => ${hit:-no-match} [$local_status] ${gkeyh} ${snippet}"
      # CONFIRM only once per url; never on a 4xx rejection; and not when the regex only matched the
      # SPA catch-all HTML shell (a real data/LFI leak is not the app's index.html).
      if [ "$hit" = HIT ]; then
        _shell=0; printf '%s' "$gbody" | head -c 80 | grep -qiE '^[[:space:]]*<(!doctype|html)' \
          && ! printf '%s' "$rx" | grep -qiE 'html|doctype|<' && _shell=1
        case "$gcode" in
          4[0-9][0-9]) : ;;
          *) [ "$_shell" = 1 ] || grep -qxF "$url" "$OUTDIR/.agent_loot_urls" 2>/dev/null \
               || grep -qF "[CONFIRMED] $url |" "$agent_file" 2>/dev/null \
               || printf '[CONFIRMED] %s | %s\n' "$url" "$why" >> "$agent_file" ;;
        esac
      fi
    done <<< "$probes"
    [ -n "$results" ] || break
    # The AI chases a hot lead across rounds, but stops itself when exhausted.
    if [ "$decision" = STOP ]; then SUP_NOTE="agent: stopping (leads exhausted)"; break; fi
  done
  # Persist the agent's final reasoning for the report/transcript.
  { echo "=== final hypotheses ==="; printf '%s\n' "$agent_notes"; } >> "$agent_log"
  set_stage $S_AGENT done "$(nlines "$agent_file") confirmed · $(nlines "$agent_seen") actions (${toolcalls:-0} tool runs) · ${round}r"
fi

# OOB: correlate any interactsh callbacks to the URLs we injected, then stop the listener -
# BEFORE verify/report/triage, so confirmed blind SSRF/redirect hits reach report.md and the
# AI analyst (not just findings.json).
oast_correlate
oast_stop

# Verification: re-test confirmed findings so the report/triage lead with proven ones.
if [ "$VERIFY" = 1 ]; then set_stage $S_TRIAGE running "verifying findings"; verify_findings; fi

# Report header
{
  echo "# 4tail recon report"; echo
  echo "- **Target:** \`$domain\`"
  echo "- **Generated:** $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "- **Subdomains:** $sub_count | **Live:** $alive_count | **Nuclei findings:** $find_count | **Fuzz hits:** $(fuzz_distinct "$fuzz_findings_file") distinct (${fuzz_hits:-0} raw)"
  [ "$JSMINE" = 1 ] && echo "- **JS mined:** $(nlines "$js_urls_file") files, $(nlines "$js_secrets_file") secret hits, $(nlines "$params_file") params, $(nlines "${js_endpoints_file:-/dev/null}") endpoints, $(nlines "${sourcemap_file:-/dev/null}") source maps recovered"
  if [ "$CRAWL" = 1 ]; then
    echo "- **Active funnel (${BLUEPRINT_NAME:-defaults}):** $(nlines "$urls_file") urls → $(nlines "$url_patterns_file") patterns → **$(nlines "$targets_active_file") juicy**"
    echo "  - specialists → DAST:$(nlines "$dast_file") · dalfox:$(nlines "$findings_dir/dalfox.txt") · kxss:$(nlines "$findings_dir/kxss.txt") · sqlmap:$(nlines "$findings_dir/sqlmap.txt")"
  fi
  echo "- **Nuclei:** ${nuclei_target_count:-$alive_count} hosts scanned (deduped from $alive_count) | tags \`$nuclei_tags\` | severity \`$NUCLEI_SEVERITY\`"
  echo "- **AI models:** $([ "$AI_ENABLED" = 1 ] && echo "plan=$LLM_MODEL_PLAN, triage=$LLM_MODEL_TRIAGE" || echo "disabled")"
  [ "$AI_ENABLED" = 1 ] && echo "- **Estimated AI spend:** $(cost_fmt)$([ "${LLM_BUDGET_USD:-0}" != 0 ] && echo " (budget \$$LLM_BUDGET_USD)")"
  echo "- **SecLists:** ${SECLISTS_DIR:-not found} | **Base wordlist:** \`$WORDLIST\`"; echo
  if [ -s "${verified_file:-/dev/null}" ]; then
    echo "## ✅ Verified findings (survived an independent re-test)"; echo; echo '```'; cat "$verified_file"; echo '```'; echo
  fi
  if [ -s "${corsy_file:-/dev/null}" ]; then
    echo "## CORS misconfiguration (Corsy)"; echo; echo '```'; cat "$corsy_file"; echo '```'; echo
  fi
  if [ "$AGENT" = 1 ] && { [ -s "$agent_file" ] || [ -n "${agent_notes:-}" ]; }; then
    echo "## 🤖 Agent (autonomous probe loop)"; echo
    if [ -s "$agent_file" ]; then echo "**Confirmed / escalated:**"; echo '```'; cat "$agent_file"; echo '```'; echo; fi
    if [ -n "${agent_notes:-}" ]; then echo "**Final hypotheses:**"; echo '```'; printf '%s\n' "$agent_notes"; echo '```'; echo; fi
  fi
  if [ -s "$fuzz_findings_file" ]; then
    echo "## Content discovery hits (ffuf, top 100)"
    echo
    echo '| Status | Length | URL(s) | Count |'
    echo '|--------|--------|--------|-------|'
    # Group by response fingerprint. 500/403 dynamic error pages (lengths differ by a few bytes)
    # bucket by 64 and show 3 samples. For other statuses keep exact length and list ALL urls when
    # the bucket is <=10 (so a critical API endpoint is never hidden behind "×5"); only collapse to
    # 3 samples when a bucket has >10 urls. 0-byte 200s sort below non-empty 200s.
    awk -F'\t' '
      NF>=3 {
        st=$1; len=$2+0; u=$3
        if (st==500 || st==403) { b=int(len/64)*64; k=st SUBSEP "b" b; disp="~"b; cap=3 }
        else { k=st SUBSEP len; disp=len; cap=10 }
        c[k]++; d[k]=disp; stv[k]=st; zero[k]=(len==0?1:0); lim[k]=cap
        if (ns[k]<cap) { smp[k]=(smp[k]==""?u:smp[k]" , "u); ns[k]++ }
      }
      END{ for(k in c) printf "%s\t%s\t%d\t%d\t%s\n", stv[k], d[k], c[k], zero[k], smp[k] }' "$fuzz_findings_file" \
      | sort -t"$(printf '\t')" -k1,1n -k4,4n -k3,3nr | head -n 120 \
      | while IFS=$'\t' read -r st len c z samples; do
          scell="$(printf '%s' "$samples" | sed -E 's# , #` `#g')"
          # show ×count only when there are more urls than we listed
          more=""; shown="$(printf '%s' "$samples" | awk -F' , ' '{print NF}')"; [ "$c" -gt "${shown:-1}" ] && more="×$c"
          echo "| $st | $len | \`$scell\` | ${more:-$c} |"
        done
    echo
  fi
  if [ -s "$dast_file" ]; then
    echo "## DAST findings (nuclei -dast)"; echo; echo '```'; head -n 100 "$dast_file"; echo '```'; echo
  fi
  if [ -s "${bypass_file:-/dev/null}" ]; then
    echo "## Access-control bypasses (403/401 → 2xx)"; echo; echo '```'; cat "$bypass_file"; echo '```'; echo
  fi
  if [ -s "${idor_file:-/dev/null}" ]; then
    echo "## IDOR / broken-authz candidates (verify object ownership)"; echo; echo '```'; cat "$idor_file"; echo '```'; echo
  fi
  if [ -s "${prop_file:-/dev/null}" ]; then
    echo "## Cross-host paths (found on one host, live on another)"; echo; echo '```'; head -n 60 "$prop_file"; echo '```'; echo
  fi
  if [ -s "${open_dir_file:-/dev/null}" ]; then
    echo "## Open directory listings + exposed files (OWASP A05)"; echo; echo '```'; cat "$open_dir_file"; echo '```'; echo
  fi
  if [ -s "${stacktrace_file:-/dev/null}" ]; then
    echo "## Verbose errors / stack traces (OWASP A05/A03)"; echo; echo '```'; cat "$stacktrace_file"; echo '```'; echo
  fi
  if [ -s "${unauth_api_file:-/dev/null}" ]; then
    echo "## Unauthenticated API data exposure / BOLA candidates (OWASP API1/A01)"; echo; echo '```'; cat "$unauth_api_file"; echo '```'; echo
  fi
  if [ -s "${openredir_file:-/dev/null}" ]; then
    echo "## Open redirects (confirmed) (OWASP A01)"; echo; echo '```'; cat "$openredir_file"; echo '```'; echo
  fi
  if [ -s "${jwt_file:-/dev/null}" ]; then
    echo "## JWT weaknesses (OWASP A07)"; echo; echo '```'; cat "$jwt_file"; echo '```'; echo
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
  # Raw deterministic evidence that the AI prose summarises but used to omit from the report.
  # Always printed so report.md preserves the primary evidence above/below the commentary.
  if [ -s "${nuclei_file:-/dev/null}" ]; then
    echo "## Nuclei findings (raw)"; echo; echo '```'; head -n 100 "$nuclei_file"; echo '```'; echo
  fi
  if [ -s "${js_secrets_file:-/dev/null}" ]; then
    echo "## JS secret candidates (url — match)"; echo; echo '```'; head -n 60 "$js_secrets_file"; echo '```'; echo
  fi
  if [ -s "${api_specs_file:-/dev/null}" ]; then
    echo "## Exposed API specs"; echo; echo '```'; head -n 40 "$api_specs_file"; echo '```'; echo
  fi
  if [ -s "${sourcemap_file:-/dev/null}" ]; then
    echo "## Recovered source maps (.js.map)"; echo; echo '```'; head -n 40 "$sourcemap_file"; echo '```'; echo
  fi
  if [ -s "${spa_routes_file:-/dev/null}" ]; then
    echo "## SPA client routes (from JS router — client-side guards only)"; echo; echo '```'; head -n 60 "$spa_routes_file"; echo '```'; echo
  fi
  if [ -s "${dom_xss_file:-/dev/null}" ]; then
    echo "## DOM-XSS sinks (client-side; review param/hash flow into these)"; echo; echo '```'; head -n 40 "$dom_xss_file"; echo '```'; echo
  fi
  if [ -s "${dns_hygiene_file:-/dev/null}" ]; then
    echo "## DNS hygiene (SPF/DMARC/zone-transfer)"; echo; echo '```'; cat "$dns_hygiene_file"; echo '```'; echo
  fi
  if [ -s "${sec_headers_file:-/dev/null}" ]; then
    echo "## Missing security headers"; echo; echo '```'; head -n 60 "$sec_headers_file"; echo '```'; echo
  fi
  if [ -s "${diff_file:-/dev/null}" ]; then
    echo "## New since last run (diff)"; echo; echo '```'; head -n 80 "$diff_file"; echo '```'; echo
  fi
} > "$report_file"

