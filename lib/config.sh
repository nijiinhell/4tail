
# ---------------------------------------------------------------------------
# LLM configuration (OpenAI-compatible; defaults = Together AI + cheap GLM)
# ---------------------------------------------------------------------------
LLM_API_KEY="${TOGETHER_API_KEY:-${LLM_API_KEY:-}}"
# Strip stray whitespace/newlines (a trailing newline corrupts the auth header -> 401).
LLM_API_KEY="$(printf '%s' "$LLM_API_KEY" | tr -d '[:space:]')"
LLM_BASE_URL="${LLM_BASE_URL:-https://api.together.xyz/v1}"
LLM_MODEL="${LLM_MODEL:-zai-org/GLM-5.3-Flash}"   # base default for every role (Flash = ~9x cheaper output than non-Flash GLM-5.3, same quality for these tasks)
LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-4000}"    # reasoning models spend tokens thinking; leave room for real output
LLM_TEMPERATURE="${LLM_TEMPERATURE:-0.2}"
LLM_TIMEOUT="${LLM_TIMEOUT:-300}"
LLM_RETRIES="${LLM_RETRIES:-2}"

# --- Smart model routing (per-task "swarm"-style switching) -----------------
LLM_MODEL_PLAN="${LLM_MODEL_PLAN:-}"        # scan planner; default = LLM_MODEL
LLM_MODEL_TRIAGE="${LLM_MODEL_TRIAGE:-}"    # findings analyst; default = LLM_MODEL
LLM_MAX_TOKENS_PLAN="${LLM_MAX_TOKENS_PLAN:-6000}"   # headroom for reasoning models (GLM/DeepSeek think first)
LLM_MAX_TOKENS_TRIAGE="${LLM_MAX_TOKENS_TRIAGE:-}"  # default = LLM_MAX_TOKENS
LLM_FALLBACK_MODELS="${LLM_FALLBACK_MODELS:-deepseek-ai/DeepSeek-V4.1-Flash}"  # tried in order if the primary errors (resilience; only billed when used)
# AI supervisor: periodic plain-language status during the long nuclei stage.
SUPERVISOR="${SUPERVISOR:-1}"                        # 1 = on (needs API key); report-only
SUPERVISOR_INTERVAL="${SUPERVISOR_INTERVAL:-120}"   # seconds between supervisor notes

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
SECLISTS_DYNAMIC="${SECLISTS_DYNAMIC:-1}" # 1 = also match detected tech against REAL SecLists filenames (not just the static map)
SECLISTS_MATCH_MAX="${SECLISTS_MATCH_MAX:-3}" # cap dynamically-matched lists per tech token
MAX_FUZZ_WORDS="${MAX_FUZZ_WORDS:-18000}" # cap per-host combined wordlist size (bounty-sized; raise for deep runs)
MAX_FUZZ_HOSTS="${MAX_FUZZ_HOSTS:-0}"     # cap number of hosts to fuzz (0 = all)
FUZZ_MAX_TIME="${FUZZ_MAX_TIME:-300}"     # hard per-host ffuf time cap (s) so a slow host can't stall the stage; 0 = unlimited
SKIP_FUZZ="${SKIP_FUZZ:-0}"               # 1 = skip content discovery entirely (nuclei-only)
SKIP_CDN_FUZZ="${SKIP_CDN_FUZZ:-1}"       # 1 = don't fuzz CDN/WAF edges (cloudfront, cloudflare, …)
EXTENSIONS="${EXTENSIONS:-}"              # explicit ffuf -e list (overrides tech-aware exts)
MAX_EXTS="${MAX_EXTS:-4}"                 # cap on per-host extensions (each one multiplies total requests)
FFUF_RATE="${FFUF_RATE:-0}"              # ffuf requests/sec per host (0 = unlimited)
FUZZ_PARALLEL="${FUZZ_PARALLEL:-1}"      # fuzz N hosts at once (-p); auto-backoff on WAF blocks
FETCH_FUZZTXT="${FETCH_FUZZTXT:-0}"      # 1 = download Bo0oM/fuzz.txt if no base list found
DEDUPE_ORIGINS="${DEDUPE_ORIGINS:-1}"    # 1 = one fuzz target per IP/CNAME + response cluster
USE_DNSX="${USE_DNSX:-1}"                # 1 = use dnsx (if installed) to resolve + drop wildcards
JSMINE="${JSMINE:-0}"                    # 1 = JS/secret mining + param discovery (-j)
CRAWL="${CRAWL:-0}"                       # 1 = active funnel: crawl -> cluster -> AI juicy -> specialists (-C)
SINGLE="${SINGLE:-0}"                     # 1 = single-host mode (-s): no subdomain enum; test exactly the given host:port (localhost/IP/port OK)
# Static assets never hold injection bugs - strip them before the slow tools (dalfox/
# nuclei-dast/kxss/sqlmap) so caps and time are spent on real endpoints, not app.js?v=1.
# Matched against the PATH only (query stripped first by drop_static), so a file-ish
# VALUE like ?file=app.js is KEPT - that's an LFI lead, not a static asset.
STATIC_URL_RE="${STATIC_URL_RE:-[.](js|css|png|jpe?g|gif|svg|ico|webp|avif|bmp|tiff?|woff2?|ttf|eot|otf|map|mp4|webm|mp3|ogg|wav|pdf|zip|t?gz|rar|7z|bz2|swf)$}"
CRAWL_MAX_URLS="${CRAWL_MAX_URLS:-8000}" # cap collected URLs
CRAWL_MAX_TIME="${CRAWL_MAX_TIME:-1200}" # hard cap on crawling (s); 0 = unlimited
DAST="${DAST:-1}"                        # run nuclei -dast on selected URLs
DAST_MAX_URLS="${DAST_MAX_URLS:-1500}"   # cap URLs sent to DAST

# --- Preferred faster tools (used when installed; else the classic falls back) ---
USE_WAYMORE="${USE_WAYMORE:-1}"           # waymore (more sources) instead of gau+waybackurls
PREFER_X8="${PREFER_X8:-1}"               # x8 (faster/accurate) instead of arjun for param discovery
TRUFFLEHOG_JS="${TRUFFLEHOG_JS:-1}"       # trufflehog --only-verified on saved JS instead of brittle regex
SOURCEMAPS="${SOURCEMAPS:-1}"             # 1 = recover .js.map source maps -> reconstruct original source for secrets + endpoints
SOURCEMAP_MAX="${SOURCEMAP_MAX:-40}"      # cap JS files probed for a source map
SOURCEMAP_SRC_MAX="${SOURCEMAP_SRC_MAX:-200}"  # cap reconstructed source files per map (skip giant vendor bundles)
USE_KITERUNNER="${USE_KITERUNNER:-1}"     # kiterunner (kr) API-route discovery when installed
FUZZ_ENGINE="${FUZZ_ENGINE:-ffuf}"        # 'ffuf' (default, tech-aware) or 'feroxbuster' (Rust+recursion)
FEROX_DEPTH="${FEROX_DEPTH:-2}"           # feroxbuster recursion depth (bounded - recursion can balloon)

# --- Extra recon/surface tools (all optional; skipped if not installed) ------
USE_TLSX="${USE_TLSX:-1}"                 # harvest cert SAN hostnames (more in-scope subs)
USE_CDNCHECK="${USE_CDNCHECK:-1}"         # accurate CDN/WAF/cloud classification of live hosts
CDNCHECK_MIN_HOSTS="${CDNCHECK_MIN_HOSTS:-10}"  # only worth it on bigger scopes (it refreshes CDN ranges + resolves); the regex skip covers small ones
USE_PERMUTE="${USE_PERMUTE:-1}"           # dnsgen/gotator permutation of known subs (ONLY on big scopes - see below)
PERMUTE_MIN_SUBS="${PERMUTE_MIN_SUBS:-25}" # skip permutation unless at least this many real subs exist (it's a wildcard-scope tool; pointless on a handful of hosts)
PERMUTE_MAX="${PERMUTE_MAX:-2000}"        # hard cap on generated permutations to resolve
CORS_SCAN="${CORS_SCAN:-1}"              # Corsy CORS-misconfig pass on live hosts
CORS_MAX="${CORS_MAX:-50}"               # cap hosts sent to Corsy
TAKEOVER_CHECK="${TAKEOVER_CHECK:-1}"    # flag dangling CNAMEs (subdomain takeover) that httpx drops because they don't answer HTTP
TAKEOVER_RE="${TAKEOVER_RE:-s3\\.amazonaws\\.com|s3-website|cloudfront\\.net|github\\.io|herokuapp\\.com|herokudns|azurewebsites\\.net|trafficmanager\\.net|cloudapp\\.(net|azure)|blob\\.core\\.windows|fastly\\.net|readthedocs\\.io|ghost\\.io|wpengine|pantheonsite|surge\\.sh|bitbucket\\.io|netlify\\.(app|com)|shopify|myshopify|zendesk\\.com|statuspage\\.io|helpscoutdocs|unbouncepages|wixdns|firebaseapp\\.com|appspot\\.com|gitlab\\.io}"
DNS_HYGIENE="${DNS_HYGIENE:-1}"          # SPF/DMARC (email spoofing) + zone-transfer (AXFR) check on the apex
SEC_HEADERS="${SEC_HEADERS:-1}"          # clickjacking / HSTS / CSP / cookie-flag checks on live hosts
SEC_HEADERS_MAX="${SEC_HEADERS_MAX:-25}" # cap hosts checked for security headers
VERIFY="${VERIFY:-1}"                     # re-test each CONFIRMED finding (anti-false-positive) before reporting
DIFF_STATE="${DIFF_STATE:-1}"            # remember each target's surface and show what changed since last run
STATE_DIR="${STATE_DIR:-$HOME/.4tail/state}"  # where per-target snapshots live

# --- Blueprint (strategy profile) + active-phase caps -----------------------
# BLUEPRINT: "auto" = AI picks from blueprints/ after recon; or a name / path.
BLUEPRINT="${BLUEPRINT:-auto}"
BLUEPRINTS_DIR="${BLUEPRINTS_DIR:-}"      # auto-detected next to the script if empty
# Active-phase caps/specialists (filled from the blueprint; env here overrides it).
ACT_MAX_JUICY="${ACT_MAX_JUICY:-100}"     # cap URLs that reach the active specialists
ACT_MAX_DALFOX="${ACT_MAX_DALFOX:-50}"
ACT_MAX_KXSS="${ACT_MAX_KXSS:-400}"
ACT_MAX_SQLMAP="${ACT_MAX_SQLMAP:-3}"     # sqlmap = confirmation only, tightly capped
ACT_MAX_ARJUN="${ACT_MAX_ARJUN:-25}"
ACT_SPECIALISTS="${ACT_SPECIALISTS:-nuclei-dast,dalfox,kxss,arjun,sqlmap}"
ACT_FOCUS="${ACT_FOCUS:-idor,sqli,xss,ssrf,lfi,redirect,ssti}"
ACT_DAST_TAGS="${ACT_DAST_TAGS:-}"        # empty = all nuclei fuzzing (DAST) templates
FUZZING_STRATEGY="${FUZZING_STRATEGY:-normal}"  # normal | light (trim wordlist/exts/time) | off (skip path fuzzing) - set by blueprint for SPA/CDN targets
SQLMAP_CONFIRM="${SQLMAP_CONFIRM:-1}"     # allow sqlmap when the blueprint lists it (0 to hard-disable)
SQLMAP_MAX_TIME="${SQLMAP_MAX_TIME:-180}" # per funnel-sqlmap run cap (s) - sqlmap can run for hours otherwise
DALFOX_MAX_TIME="${DALFOX_MAX_TIME:-180}" # dalfox pipe cap (s)
GAU_MAX_TIME="${GAU_MAX_TIME:-120}"       # gau / waybackurls each (s) - historical fetch can hang on big domains
ARJUN_MAX_TIME="${ARJUN_MAX_TIME:-60}"    # per-host arjun cap (s, JS stage)
API_SPECS="${API_SPECS:-1}"               # 1 = detect Swagger/OpenAPI/GraphQL specs -> AI builds targeted tests (part of -C)
API_MAX_SPECS="${API_MAX_SPECS:-5}"       # cap spec documents fetched + fed to the AI
API_MAX_TESTS="${API_MAX_TESTS:-60}"      # cap AI-generated API test URLs folded into the active set
GRAPHQL_MAX="${GRAPHQL_MAX:-5}"           # cap GraphQL endpoints probed for open introspection

# --- Correlation / exploitation passes (active, part of -C) -----------------
BYPASS="${BYPASS:-1}"                      # 403/401 -> try proven access-control bypasses
BYPASS_MAX="${BYPASS_MAX:-20}"             # cap how many 403/401 URLs to probe
PROPAGATE="${PROPAGATE:-1}"                # replay interesting discovered paths across all live hosts
PROP_MAX_PATHS="${PROP_MAX_PATHS:-25}"     # cap paths replayed per host (serial curl; keep modest)
PROP_MAX_HOSTS="${PROP_MAX_HOSTS:-15}"     # cap hosts replayed across (PROP_MAX_HOSTS x PROP_MAX_PATHS serial requests)
# Dual-identity IDOR / broken-authz: supply one or two sessions; each is a header line
# ("Cookie: ..." or "Authorization: Bearer ...").  A is required; B optional (horizontal test).
AUTH_A="${AUTH_A:-}"
AUTH_B="${AUTH_B:-}"
IDOR="${IDOR:-1}"                          # 1 = run the A/B/anon access-control diff when AUTH_A is set
IDOR_MAX="${IDOR_MAX:-40}"                 # cap id-bearing URLs tested
# When scanning authenticated, never REQUEST logout/session-kill paths (katana/ffuf/specialists
# hitting /logout silently drops the session and the rest of the scan runs unauthenticated).
AVOID_LOGOUT="${AVOID_LOGOUT:-1}"
LOGOUT_RE="${LOGOUT_RE:-logout|signout|sign-out|log-out|logoff|log-off|deauth|revoke|/destroy|session/(delete|destroy|end)|/(exit|quit)(/|\\?|$)}"
# PoC generation for body-based bug classes 4tail cannot safely fire itself (POST login/
# register logic, body IDOR/SQLi, mass assignment, GraphQL mutations, CSRF). 4tail harvests
# real form fields deterministically, then the AI writes runnable curl PoCs for the HUMAN to
# review and run - 4tail never fires them, so the GET-only active invariant holds.
POC_GEN="${POC_GEN:-1}"
POC_FORM_HOSTS="${POC_FORM_HOSTS:-12}"     # cap pages scraped for <form> fields

# --- Authentication + proxy (cascade to all active tools) -------------------
AUTH_HEADER="${AUTH_HEADER:-}"            # one or more "Header: value" (newline-separated); also -H
AUTH_COOKIE="${AUTH_COOKIE:-}"           # "name=val; name2=val2"  -> sent as Cookie header
PROXY="${PROXY:-}"                       # http(s)://host:port routed through httpx/nuclei/ffuf/katana/dalfox/curl
UPDATE_TEMPLATES="${UPDATE_TEMPLATES:-0}" # 1 = nuclei -update-templates before scanning (self-heal)
EMIT_SARIF="${EMIT_SARIF:-0}"            # 1 = also write findings.sarif
NUCLEI_TAG_INDEX="${NUCLEI_TAG_INDEX:-1}" # 1 = index REAL category tags from the installed templates so the AI plan isn't limited to the hardcoded allowlist
NUCLEI_TEMPLATES_DIR="${NUCLEI_TEMPLATES_DIR:-}" # override template store path; auto-located if empty

# --- Staleness ranking + OAST (blind-bug confirmation) ----------------------
STALE_RANK="${STALE_RANK:-1}"            # 1 = compute a per-host "legacy" score; AI funnels budget to older stacks first
OAST="${OAST:-0}"                        # 1 = start interactsh in the background + inject OOB payloads into redirect/SSRF params
OAST_SERVER="${OAST_SERVER:-}"           # optional self-hosted interactsh server (-s); empty = public (oast.fun)
OAST_MAX_INJECT="${OAST_MAX_INJECT:-40}" # cap URLs we inject an OOB payload into

# --- Agent mode (autonomous AI validation loop) -----------------------------
# The AI looks at the juicy findings and fires its own GET probes to confirm/escalate
# them (read web.config via LFI, param-mine empty 200s, test redirects, walk IDOR ids),
# sees the responses, and decides the next move - bounded so it never camps on one host.
AGENT="${AGENT:-0}"                       # 1 = run the autonomous probe loop (-A)
AGENT_ROUNDS="${AGENT_ROUNDS:-8}"         # max observe->decide->act rounds (AI stops itself when leads run out)
AGENT_MAX_PROBES="${AGENT_MAX_PROBES:-12}" # max GET/POST probes the AI may fire per round
AGENT_MAX_TIME="${AGENT_MAX_TIME:-600}"   # hard wall-clock cap (s) for the whole loop; 0 = unlimited
AGENT_TOOLS="${AGENT_TOOLS:-1}"           # 1 = agent may invoke real tools (sqlmap/nuclei/dalfox/...), not just GET
AGENT_MAX_TOOLCALLS="${AGENT_MAX_TOOLCALLS:-16}" # cap tool invocations across the whole loop
AGENT_TOOL_TIMEOUT="${AGENT_TOOL_TIMEOUT:-90}"   # per tool-call wall-clock cap (s)
# POST / body probing: the agent may fire POST requests to test body-based bugs itself
# (login/register logic, body IDOR/SQLi, mass assignment). Still scope-locked; bodies with
# clearly destructive payloads (DROP/DELETE/TRUNCATE/SHUTDOWN/xp_cmdshell/...) are refused.
AGENT_POST="${AGENT_POST:-1}"             # 1 = allow agent POST probes; 0 = GET-only agent
AGENT_MAX_POST="${AGENT_MAX_POST:-12}"    # cap POST probes across the whole loop
# Secrets the agent reads (e.g. a connection string via LFI) are NEVER sent to the LLM -
# the model sees a redacted snippet, but the raw response is saved locally for the human.
AGENT_LOOT="${AGENT_LOOT:-1}"             # 1 = save raw secret-bearing responses to agent_loot/ for manual review
DEFAULT_NUCLEI_TAGS="${DEFAULT_NUCLEI_TAGS:-cves,exposures,misconfiguration,tech,default-login,takeover}"
MAX_TAGS="${MAX_TAGS:-15}"                # cap nuclei tags (more tags = far more templates = much slower)
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-critical,high,medium,low}"
NUCLEI_RATELIMIT="${NUCLEI_RATELIMIT:-150}"
NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-8}"    # per-request timeout (s) - stops hanging on dead/slow hosts
NUCLEI_RETRIES="${NUCLEI_RETRIES:-1}"
NUCLEI_MHE="${NUCLEI_MHE:-15}"           # skip a host after this many errors (kills dead-host error spam)
NUCLEI_MAX_TIME="${NUCLEI_MAX_TIME:-3600}"  # hard cap on the whole nuclei stage (s); 0 = unlimited
NUCLEI_CONC="${NUCLEI_CONC:-40}"         # template concurrency (-c); higher = faster, more load/errors
NUCLEI_BULK="${NUCLEI_BULK:-25}"         # hosts scanned in parallel per template (-bulk-size)
NUCLEI_DEDUPE="${NUCLEI_DEDUPE:-1}"      # 1 = scan one representative per origin+response signature
NUCLEI_SKIP_CDN="${NUCLEI_SKIP_CDN:-0}"  # 1 = also drop CDN/WAF edges from nuclei (keeps takeover if 0)
NUCLEI_MAX_HOSTS="${NUCLEI_MAX_HOSTS:-100}" # cap hosts scanned (0 = all). Hosts are value-ranked, so this keeps the top-N most interesting.
HTTPX_THREADS="${HTTPX_THREADS:-50}"
OUTDIR="${OUTDIR:-}"
RESUME="${RESUME:-0}"      # 1 = continue a previous run (reuse finished stages)
ASSUME_YES="${ASSUME_YES:-0}"
NO_TUI="${NO_TUI:-0}"
LOOT_FEED="${LOOT_FEED:-1}"  # 1 = live "loot" feed panel (findings stream into the dashboard)
LOOT_ROWS="${LOOT_ROWS:-6}"  # rows reserved for the loot feed (fixed height keeps the redraw stable)
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
  -p <n>      Fuzz N hosts in parallel        (env FUZZ_PARALLEL, default 1; auto-backoff)
  -j          JS/secret mining + param discovery (env JSMINE=1)
  -C          Active funnel: crawl -> cluster -> AI juicy -> API specs -> specialists (env CRAWL=1)
  -s          Single host: no subdomain enum; test exactly the given host incl. port/localhost/IP (env SINGLE=1)
  -B <name>   Blueprint/strategy (env BLUEPRINT; "auto"=AI picks; or webapp_bounty/api_bounty/wordpress/stealth/deep)
  -H <hdr>    Auth header, repeatable (e.g. -H "Authorization: Bearer X"); env AUTH_HEADER/AUTH_COOKIE
  -x <proxy>  Route tools through http(s) proxy (env PROXY)
  -O          OAST: start interactsh, inject OOB payloads, confirm blind SSRF/redirect (env OAST=1)
  -A          Agent: autonomous AI probe loop - confirms/escalates juicy findings itself (env AGENT=1)
              (-C also runs: 403/401 bypass, cross-host path replay, and A/B/anon IDOR when AUTH_A/AUTH_B are set)
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

