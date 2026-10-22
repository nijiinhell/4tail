# 4tail

An AI-assisted recon pipeline for **authorized** bug-bounty and penetration-testing
work. It chains popular ProjectDiscovery tools — **Subfinder → Httpx → Ffuf → Nuclei**
— and adds a layer of LLM-powered decision-making so the scan adapts to what it
actually finds instead of running a fixed recipe.

The AI layer uses any **OpenAI-compatible** endpoint. Defaults target **Together AI**
with a low-cost **GLM** model, and the prompts are deliberately engineered to keep
token spend tiny.

> ⚠️ Only run 4tail against targets you are explicitly authorized to test.
> The script asks you to confirm authorization before it starts (skip with `-y`).

## What makes it "smart"

The script calls the LLM to make two real decisions:

1. **Adaptive scan planning** — after Httpx probes live hosts *with technology
   detection*, the model reads the detected stack (WordPress, nginx, Jira, PHP, …)
   and returns a JSON plan with **(a)** the most relevant Nuclei tags and **(b)** a
   `tech → SecLists wordlist` mapping. The AI's tags are **added on top of** strong
   defaults (`cves,exposures,misconfiguration,…`) — never replacing them — and are
   validated against an allowlist that is **widened at runtime with the real category
   tags found in your installed nuclei templates** (`NUCLEI_TAG_INDEX=1`), so the plan
   can select any tag your template store actually supports (e.g. `weblogic`,
   `fortinet`) without ever referencing one it doesn't have. Wordlist paths are
   existence-checked on disk. A bogus/empty reply simply degrades to the defaults.
2. **Finding triage** — after Nuclei runs, the model turns the raw output into a
   prioritized Markdown report (executive summary, severity-sorted table, and
   recommended manual follow-ups).

### Tech-aware fuzzing (smart wordlists)

Fuzzing is no longer "one wordlist for everything". For **each live host**, 4tail:

- always includes your **base "juicy" wordlist** (`WORDLIST`) for high-value findings,
- **adds the SecLists lists that match that host's detected tech** — e.g. a WordPress
  host also gets `CMS/wordpress.fuzz.txt` + `wp-plugins.fuzz.txt`, a PHP host gets
  `Common-PHP-Filenames.txt`, an Apache host gets `Apache.fuzz.txt`,
- **dedups** the combined list (capped at `MAX_FUZZ_WORDS`) and fuzzes with it.

The tech→wordlist map comes from **three** layers: a built-in static map, the AI plan, and
a **dynamic index of your actual SecLists install** (`SECLISTS_DYNAMIC=1`, default on).
The dynamic layer indexes every real list under `Discovery/Web-Content` once and matches
detected tech tokens against real filenames — so a `jenkins`, `grafana`, or `weblogic` host
automatically pulls `jenkins.txt` / `grafana.txt` / `weblogic.txt` even though those aren't
hardcoded, and nothing ever references a path that isn't installed. Big generic lists
(`raft-*`, `big.txt`, `directory-list-*`, `common.txt`, …) are excluded, and each tech token
pulls at most `SECLISTS_MATCH_MAX` (3) lists. It works tech-aware even with no API key.
SecLists is auto-detected (`SECLISTS_DIR`), every path is existence-checked, and which lists
each host received is recorded in `fuzz_plan.txt` and the report.

Fuzzing is bounded so it can't run away on a slow host: `MAX_FUZZ_WORDS` (18k) caps the
combined per-host list, `MAX_EXTS` (4) caps extensions, and `FUZZ_MAX_TIME` (300s) is a hard
ffuf `-maxtime` per host. Raise them for deep runs (`MAX_FUZZ_WORDS=60000 FUZZ_MAX_TIME=0`).

> **`apt install seclists`** installs to `/usr/share/seclists`, which 4tail auto-detects.
> If yours is elsewhere, set `SECLISTS_DIR=/path/to/SecLists`.

#### Base "juicy" list: Bo0oM/fuzz.txt

The base list (used for **every** host) defaults to [Bo0oM/fuzz.txt](https://github.com/Bo0oM/fuzz.txt)
if found — a hand-curated "quick win" list of *potentially dangerous files*: dotfiles
(`.git/config`, `.env`, `.bash_history`), backups, config leaks, cloud creds
(`.aws/credentials`), and path-traversal / WAF-bypass payloads (`%2e%2e//`, `..;/`,
`%c0%ae`). 4tail auto-detects it at common paths (including
`/root/Desktop/bugs/tools/fuzz.txt/fuzz.txt`, `~/tools/fuzz.txt/fuzz.txt`, …), and if a
sibling `api-endpoints.txt` is present it's added for API/GraphQL/Swagger hosts. If none
is found it falls back to SecLists `common.txt`. Resolution order: `-w` / `WORDLIST` →
Bo0oM `fuzz.txt` locations → (optional `FETCH_FUZZTXT=1` download) → SecLists `common.txt`.

#### Tech-aware extension fuzzing (from fuzz.txt's extensions.txt)

Bo0oM's `extensions.txt` (juicy suffixes like `.bak .old .zip .sql .conf .swp`) is the
key to finding files like `config.php.bak` or `web.config.old`. 4tail turns this into
**per-host `ffuf -e` extension sets**: the highest-signal **tech extensions first**
(so they survive the cap), then generic juicy ones:

| Detected tech | Extensions appended (before generic juicy) |
|---|---|
| PHP | `.php .phtml .phps` |
| IIS / ASP / ASP.NET | `.aspx .asp .ashx .config .cs` |
| Java / JSP / Tomcat / Spring / Struts | `.jsp .jspx .war .properties .class` |
| ColdFusion | `.cfm .cfc` |
| Python / Django / Flask | `.py .pyc` |
| Ruby / Rails | `.rb .erb` |
| Node / Express | `.js .map .env` |
| Perl | `.pl .cgi` |
| *(every host also gets)* | `.bak .old .zip .sql .conf .config .txt .log …` |

Tune with `EXTENSIONS` (explicit list, overrides tech logic), `MAX_EXTS` (cap, default 10 —
each extension multiplies requests), and `FFUF_RATE` (req/sec).

#### Built-in tech → SecLists wordlist map (paths verified against SecLists)

| Detected tech | Wordlist(s) | What it's for |
|---|---|---|
| WordPress | `CMS/wordpress.fuzz.txt`, `wp-plugins.fuzz.txt`, `wp-themes.fuzz.txt` | Core WP paths, ~14k plugin dirs, theme dirs (vuln plugin/theme discovery) |
| Joomla | `CMS/joomla-plugins.fuzz.txt`, `joomla-themes.fuzz.txt` | Extensions & templates |
| Drupal | `CMS/Drupal.txt`, `drupal-themes.fuzz.txt` | Modules, admin, CHANGELOG |
| Magento | `CMS/sitemap-magento.txt` | Admin, downloader, RCE-prone endpoints |
| Umbraco | `CMS/Umbraco.fuzz.txt` | .NET CMS admin/config surface |
| ColdFusion | `coldfusion.txt`, `CMS/ColdFusion.fuzz.txt` | CFIDE, Administrator, AdminAPI |
| PHP | *(no heavy list)* | Covered by the base list + `.php`/`.phtml` extensions |
| Java / Tomcat / Spring / Struts | `JavaServlets-Common.fuzz.txt`, `vulnerability-scan_j2ee-websites_WEB-INF.txt` | Servlets/invoker/Struts actions; `WEB-INF`, `web.xml`, class/jar leakage |
| IIS / ASP / ASP.NET | `Microsoft-Frontpage.txt` | FrontPage/IIS extensions & `_vti_` dirs |
| API / REST / Swagger / OpenAPI | `api/api-endpoints.txt`, `api/objects.txt`, `api/actions.txt`, `api/api-seen-in-wild.txt`, `common-api-endpoints-mazen160.txt` | REST resources, verbs, versioned routes, doc endpoints |
| GraphQL | `graphql.txt` | `/graphql`, `/graphiql`, playground, introspection |
| OAuth / OIDC | `oauth-oidc-scopes.txt` | Auth endpoints, `.well-known`, scopes |
| git / svn | `versioning_metafiles.txt` | `.git` / `.svn` / `.hg` metadata (source-code leak) |
| Vault / Consul | `hashicorp-vault.txt`, `hashicorp-consul-api.txt` | Secrets-management APIs |
| SAP | `CMS/SAP.fuzz.txt`, `SAP-NetWeaver.txt` | SAP web surface |

The AI planner can add more mappings on top of this (also existence-checked). All are
relative to `SECLISTS_DIR` and unioned with your base list per host.

> **Bounty-friendly by design:** heavy generic lists (`raft-*`, `big.txt`,
> `directory-list-*`, `combined_*`, `dirbuster`) are deliberately **excluded** — from
> both the static map and anything the AI suggests — so fuzzing stays fast and
> tech-focused rather than brute-forcing huge dictionaries.

### Cost-control techniques

The AI steps are engineered to stay cheap regardless of target size:

- **Aggregated inputs, not raw dumps.** The planner is fed a *frequency brief*
  (technology counts, server counts, status-code counts, a handful of notable
  paths) rather than the full host list — so prompt size stays roughly flat whether
  the target has 10 or 10,000 hosts.
- **Small output cap** (`LLM_MAX_TOKENS`, default 1200) and low temperature.
- **Severity-sorted, capped findings** are sent for triage (top ~120 lines).
- **AI is skipped when there's nothing to reason about** (no detected tech, or zero
  findings), so you're never billed for an empty call.
- **Retry with backoff** on transient API errors.

Both AI steps are **optional**. Without an API key (or without `curl`/`jq`), 4tail
degrades gracefully: it uses sensible default tags and writes the raw findings to
the report.

### The Active Funnel (`-C`) — the "bug-hunter brain"

A funnel: run broad/passive recon exhaustively (it's cheap and WAF-safe), then spend the
expensive active budget **only** on the highest-value endpoints. With `-C`:

1. **Collect URLs (broad)** — `gau`/`waybackurls` (historical) + `katana` (live crawl),
   scoped to target, deduped, capped (`CRAWL_MAX_URLS`). → `urls.txt`
2. **Cluster** — deterministic normalization collapses `/users/12345?id=7` and
   `/users/98765?id=9` into one pattern `/users/{id}?id={v}`. Thousands of URLs → a few
   hundred **endpoint patterns**. → `url_patterns.txt`
3. **AI picks the juicy ones** — a cheap model ranks the patterns against the blueprint's
   focus areas and returns the top `max_juicy_urls`, expanded back to real URLs. →
   `targets_active.txt` (hard-capped — this is the cost/noise control).
4. **API specs → AI-built tests** (`API_SPECS=1`, default on with `-C`) — finds
   Swagger/OpenAPI (`/swagger.json`, `/v3/api-docs`, …) and GraphQL (`/graphql`,
   `/graphiql`) endpoints, both from the collected URLs and by probing common paths on the
   live hosts (auth-aware). Each spec is fetched and handed to the AI, which writes concrete
   GET test URLs that exercise the riskiest endpoints for IDOR / broken-authz / SQLi / SSRF
   (realistic probe values substituted for path & query params). These are folded into
   `targets_active.txt` so they flow through all the specialists below. → `api_specs.txt`,
   `api_tests.txt`
5. **Dispatch paired specialists** (parallel, each capped, each optional):

   | Bug class | Tool(s) | Role |
   |-----------|---------|------|
   | XSS | `kxss`/`Gxss` → `dalfox` | reflection probe → confirm |
   | all injection | `nuclei -dast` | broad fuzzing (xss/sqli/ssti/ssrf/lfi/crlf/redirect) |
   | SQLi | `sqlmap` | **confirmation only** on gf-flagged SQLi URLs, `≤ max_sqlmap`, `--level=1 --risk=1` |
   | params | `arjun` | discover hidden params on juicy hosts |

Findings (`findings/dalfox.txt`, `dast_findings.txt`, `findings/sqlmap.txt`, …) flow into
the report and the **AI triage**. Each tool is optional — the funnel uses whatever is
installed. `doctor` shows what's present.

### Blueprints (strategy profiles)

`blueprints/*.json` set the active-phase strategy: focus areas, which specialists to run,
and the caps. With `-B auto` (default) the **AI reads the detected tech surface and picks
the blueprint** (webapp_bounty / api_bounty / wordpress / stealth / deep); or force one
with `-B wordpress`. Your explicit env/flags always override a blueprint's values.

```bash
./4tail.sh -C -j -b 2 example.com                 # auto blueprint, full deep pass
./4tail.sh -C -B stealth example.com              # low-and-slow, no sqlmap
SQLMAP_CONFIRM=0 ./4tail.sh -C example.com        # never run sqlmap
```

### Content-discovery results (ffuf) are now first-class

Fuzzing hits are aggregated across all hosts into `fuzz_findings.txt`
(`status  length  url`, prioritised: 200s → 401/403 → rest), shown in the report as a
**"Content discovery hits"** table, and **fed to the AI triage** so the model calls out
the juicy paths (`.git`, `.env`, backups, admin/api/upload/debug). ffuf runs with `-ac`
(auto-calibration) to drop soft-404 / catch-all noise, so the hits are real.

### JS mining scans first-party only

JS/secret mining now keeps only scripts hosted on the target's own domain
(`JS_FIRST_PARTY=1`, default) — third-party analytics/CDN scripts (google-analytics,
gtag, jsdelivr, jquery cdn…) carry public keys and generate false positives that aren't
yours to fix. Set `JS_FIRST_PARTY=0` to scan everything.

### Live nuclei stats + AI supervisor

The long nuclei stage is no longer a black box. It runs with `-stats-json`, so the
dashboard shows **live progress**: `45% req:540 err:18 rps:37 hits:2 ETA:3m20s`. You can
see immediately how many requests errored and when it will finish.

On top of that, an **AI supervisor** (`SUPERVISOR=1`, default on when a key is set) reads
those stats + a sample of the error log every `SUPERVISOR_INTERVAL` seconds (default 120)
and writes a one-line plain-language status on the `🤖` line — e.g. *"Scan ~50% done,
error rate high — mostly 429s from CloudFront, ETA ~2m."* It's **report-only** (never
changes the scan) and budget-gated (uses the cheap planner model, ~200 tokens/note). Notes
are also saved to `supervisor.log`. Turn it off with `SUPERVISOR=0`.

### Authenticated scanning + proxy pass-through

Bugs behind a login (IDOR, broken authz, account-level logic) are invisible to an
unauthenticated scan. Pass session auth and it **cascades to every active tool** — httpx,
ffuf, katana, nuclei (main + `-dast`), dalfox, and the API-spec/JS `curl` fetches:

```bash
# header auth (repeat -H for more than one)
./4tail.sh -C -H "Authorization: Bearer eyJ…" example.com
# cookie auth
AUTH_COOKIE="session=abc; csrf=xyz" ./4tail.sh -C example.com
# route everything through Burp/mitmproxy for inspection or replay
./4tail.sh -C -x http://127.0.0.1:8080 example.com
```

`-H`/`AUTH_HEADER` (newline-separated for several), `AUTH_COOKIE`, and `-x`/`PROXY`.

### Structured output (JSON + SARIF)

Every run writes `findings.json` — a normalized, deduped list of all findings (nuclei,
nuclei-dast, ffuf content-discovery, dalfox, sqlmap, kxss, JS secrets, exposed API specs)
with `type`, `severity`, `source`, `url`, and `detail`, plus run metadata (target,
timestamp, blueprint). Feed it straight into ticketing/automation. Set `EMIT_SARIF=1` to
also emit `findings.sarif` (SARIF 2.1.0) for GitHub code-scanning / IDE ingestion.

### Self-heal preflight

`UPDATE_TEMPLATES=1` runs `nuclei -update-templates` before scanning, so a stale template
store can't silently cost you findings. `doctor` already flags missing tools; this keeps
the ones you have current.

### Staleness ranking (old stacks first)

Legacy stacks are disproportionately more likely to hold bugs, so 4tail scores every live
host by how outdated it looks — EOL servers (IIS ≤8.5, Apache 2.2, old nginx), EOL runtimes
(PHP 4/5), and dated libraries (TinyMCE, jQuery, FrontPage, ColdFusion, legacy CMS). The
ranking (`stale.tsv`: `score  url  evidence`) is fed to the AI so it **funnels the active
budget to the oldest hosts first** — both in scan planning and in juicy-URL selection. On by
default (`STALE_RANK=0` to disable); no extra tools needed — it reads httpx's tech detection.

### OAST — confirm blind SSRF / open redirect (`-O`)

Reflected bugs are easy to confirm; **blind** ones (server-side redirects/SSRF that never
echo back) are not. With `-O` (`OAST=1`), 4tail starts an **interactsh** listener in the
background as it launches, then injects a unique per-URL out-of-band payload into
redirect/SSRF-style params (`url`, `redirect`, `next`, `RetURL`, `callback`, …). Any DNS/HTTP
callback is correlated back to the exact URL and promoted to a **Confirmed blind
SSRF/redirect** finding in `findings.json` and the loot feed.

```bash
./4tail.sh -C -O example.com                 # public collaborator (oast.fun)
OAST_SERVER=oast.mine.net ./4tail.sh -C -O example.com   # self-hosted interactsh
```

Needs `interactsh-client` (ProjectDiscovery). It sends target-derived callbacks to the
collaborator server, so keep it to authorized targets; off by default.

### Correlation passes — connecting findings into verdicts (`-C`)

Beyond collecting findings, the active funnel now turns them into action:

- **403/401 → access-control bypass.** Every `401`/`403` from content discovery is retried
  with the handful of bypass tricks that actually work in the wild — path tweaks (`/x/`,
  `/x/.`, `/x%2e`, `/x..;/`) and header spoofs (`X-Forwarded-For`, `X-Original-URL`,
  `X-Rewrite-URL`, `X-Custom-IP-Authorization`). Anything that flips to `2xx`/`3xx` is a
  **confirmed bypass** (`BYPASS=1`, cap `BYPASS_MAX`).
- **Cross-host path propagation.** Interesting paths discovered on *any* live host are
  replayed on *every other* host that didn't have them — so a `/admin/debug.asp` found on
  one box is tried across the whole scope (`PROPAGATE=1`, needs >1 live host).
- **Dual-identity IDOR / broken authz** (Autorize-style). Supply one or two sessions and
  4tail replays each id-bearing request as user A, user B, and anon; when B or anon get the
  **same successful response** as A, per-user authorization isn't enforced — a confirmed
  anon-access finding or an IDOR candidate to verify. This is where most real bounties live.
  ```bash
  AUTH_A="Cookie: session=AAA" AUTH_B="Cookie: session=BBB" ./4tail.sh -C example.com
  AUTH_A="Authorization: Bearer eyJ…" ./4tail.sh -C example.com   # A + anon only
  ```
  Caps via `IDOR_MAX`; GET-only, scope-locked, behind the authorization gate.

All three feed the loot feed, `findings.json`, the agent's situation, and the report.

### Agent mode — autonomous validation loop (`-A`)

This is the "live AI hunter": instead of stopping at *candidates*, the AI looks at the
juicy findings and **fires its own follow-up probes to confirm or escalate them**, sees the
responses, and decides the next move — then moves on. Each round it proposes concrete GET
requests (read `web.config`/`global.asa` through a confirmed LFI, param-mine an empty-`200`
`db.asp`, set a redirect param to a canary and watch for a `Location`, walk adjacent IDOR
ids, fetch exposed admin/backup paths), 4tail executes them and feeds the (redacted)
responses back, and anything matching the AI's own success check becomes an
**agent-confirmed** finding — surfaced in the loot feed, `findings.json`, and a `🤖
Agent-confirmed` section at the top of the report.

```bash
./4tail.sh -C -A example.com                         # funnel + autonomous agent
AGENT_ROUNDS=4 AGENT_MAX_TIME=360 ./4tail.sh -C -A example.com
```

**It reasons with continuity (a "self-brain").** Each round the AI rewrites a running
**NOTES block of its hypotheses** — what it suspects, why, and what's confirmed / refuted /
still-unconfirmed — and that memory is fed back in, so it chases a hot lead across rounds
(e.g. *LFI confirmed → suspect `web.config` readable → machineKey → RCE*) instead of
starting cold each time. It also decides for itself when to keep going (`DECISION: CONTINUE`)
or quit (`DECISION: STOP`), and the final hypotheses are written to the report and
`agent_log.txt`.

**Bounded by design so it never camps on one host:** `AGENT_ROUNDS` (default 6, but the AI
usually stops itself earlier), `AGENT_MAX_PROBES` (8) GET requests per round, and a hard
`AGENT_MAX_TIME` wall-clock cap (240s). **Hard guardrails:** GET-only, every probe
scope-locked to the target domain (off-scope/non-http URLs are dropped), duplicate probes
skipped, and secrets (passwords, connection strings, keys, tokens) redacted before anything
is stored or sent back to the model. Off by default; runs behind the authorization gate.

### Response-fingerprint dedup

Content-discovery hits are deduped by **response fingerprint — `(status, length)` — never by
URL string**, which is the RFC-correct approach: on case-insensitive IIS, `db.asp` and
`DB.asp` collapse to one entry, and WAF noise (e.g. 32 identical `403`/`312b` traversal
blocks) collapses to one representative with a `(×N identical responses)` count. This keeps
the report and the loot feed clean and cuts triage-LLM tokens, without ever hiding a genuinely
distinct path on a case-sensitive Linux target.

## Features

- **Subdomain enumeration** with Subfinder.
- **Live-host probing + tech detection** with Httpx (JSON output).
- **AI scan planning**: the model selects Nuclei tags from the detected technologies
  (allowlist-validated, with a safe fallback).
- **Content discovery** with Ffuf (configurable wordlist).
- **Vulnerability scanning** with Nuclei (configurable severity + rate limit).
- **AI triage report**: a prioritized `report.md` per run.
- **Live terminal dashboard** that tracks every stage in real time (status icon,
  live counts, elapsed time), with a plain-log fallback for pipes/CI.
- All artifacts written to a timestamped results directory.

## The live dashboard

When run in a terminal, 4tail shows a self-updating panel instead of scrolling logs:

```
 ╭─ 4tail ───────────────────────────────────────
 │ target=example.com  ai=zai-org/GLM-5.3  elapsed=41s  spent=$0.01/$2
 │  ✔  Subdomains    128 subs
 │  ✔  Live hosts    37 live
 │  ✔  AI scan plan  cves,exposures,wordpress,php,nginx
 │  ⠹  Fuzzing       host 12/37
 │  ○  Nuclei scan
 │  ○  AI triage
 │  🤖 Scan ~40% done, error rate low — mostly 404s, ETA ~3m.
 ├─ loot ─────────────────────────────────────────
 │  [INFO] 200 http://example.com/.git/config (ffuf)
 │  [HIGH] http://example.com/x?f=../../etc/passwd (dast)
 │  [LOW] http://example.com/search?q=… (kxss)
 │  [INFO] spec: http://api.example.com/openapi.json (api)
 │
 │
 ╰──────────────────────────────────────────────
```

Icons: `○` pending · spinner running · `✔` done · `▲` warning · `–` skipped.

**Loot feed** — findings stream into the `loot` panel in real time as each tool
produces them (ffuf content-discovery, nuclei/-dast, dalfox, kxss, sqlmap, JS secrets,
exposed API specs), color-coded by severity (red=high/crit, yellow=medium, cyan=low). It's
a fixed-height panel (`LOOT_ROWS`, default 6) so the in-place redraw stays perfectly
synced — no scroll-duplication, and the borders adapt to the terminal width. Turn it off
with `LOOT_FEED=0`.

The dashboard renders in the terminal's **alternate screen buffer** (like `htop`/`less`),
redrawing from a fixed home position each frame — so it never scroll-duplicates or leaves
orphaned lines, even on narrow terminals or when a tool writes stray output. On exit it
leaves the alt screen and reprints the final panel into your normal scrollback. It
auto-disables (falling back to plain `[*]/[+]/[!]` logs) when output isn't a terminal —
e.g. piped to a file or run in CI. Force plain mode with `-P` or `NO_TUI=1`.

## Prerequisites

- [Subfinder](https://github.com/projectdiscovery/subfinder) (add your API keys after install)
- [Httpx](https://github.com/projectdiscovery/httpx)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Ffuf](https://github.com/ffuf/ffuf) *(optional — fuzzing is skipped if absent)*
- `curl` and `jq` *(required only for the AI steps)*
- A wordlist for fuzzing (e.g. from [SecLists](https://github.com/danielmiessler/SecLists))
- A [Together AI API key](https://api.together.xyz/) *(optional, enables the AI steps)* —
  or any other OpenAI-compatible endpoint.

## Install on Linux

```bash
# 1. Get the code
git clone https://github.com/nijiinhell/4tail.git
cd 4tail
chmod +x 4tail.sh

# 2. Install the ProjectDiscovery tools (needs Go >= 1.21)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest         # optional (fuzzing)
export PATH="$PATH:$(go env GOPATH)/bin"             # add to ~/.bashrc to persist
nuclei -update-templates                             # pull nuclei templates

# 3. Small helpers used by the AI steps + a wordlist
sudo apt install -y jq curl                          # Debian/Ubuntu
sudo apt install -y seclists                         # or download a wordlist yourself

# 4. (optional) an API key for the AI steps
export TOGETHER_API_KEY="your-together-ai-key"
```

> The script checks its dependencies on startup and tells you exactly what's
> missing, so you can install as you go. `subfinder`, `httpx`, `nuclei` are
> required; `ffuf`, `jq`, `curl` and the API key are optional.

## Usage

```bash
# Simplest run (you'll be asked to confirm authorization):
./4tail.sh example.com

# With AI decision-making + triage (Together AI + GLM by default):
TOGETHER_API_KEY=... ./4tail.sh -w /usr/share/seclists/Discovery/Web-Content/common.txt example.com

# Skip the confirmation prompt, custom output dir, higher severities only:
TOGETHER_API_KEY=... ./4tail.sh -y -o run1 -S critical,high example.com

# Plain output (no live dashboard), e.g. when logging to a file:
./4tail.sh -P example.com | tee run.log
```

### Resume an interrupted run

If you Ctrl-C or a run dies partway, continue it without redoing finished stages:

```bash
./4tail.sh -R wolt.com                       # resume newest run for the domain
./4tail.sh -R -o 4tail_wolt.com_20260927_101500 wolt.com   # or a specific dir
```

Resume reuses completed stages (subdomains, live hosts, the AI plan, nuclei) and, for
fuzzing, **skips hosts already done** and continues with the rest. Progress is tracked
with per-stage markers and per-host output files inside the run directory.

### Credit budget (cap AI spend)

Put a ceiling on LLM spend so a run (or a series of resumed runs) can't run away:

```bash
./4tail.sh -b 2 wolt.com          # stop calling the AI once ~$2 is estimated spent
```

Cost is estimated from each response's token usage × price. **Set the prices to your
model's real Together rate** for an accurate cap:

```bash
export LLM_PRICE_IN=0.30 LLM_PRICE_OUT=0.30   # USD per 1M tokens (in / out)
./4tail.sh -b 2 wolt.com
```

It's a **soft cap**: 4tail checks the running total before each AI call and stops
starting new ones once the budget is reached (falling back to default tags / raw
findings). The running total persists across resumed runs (ledger in the run dir, or
set `LLM_COST_LEDGER` to a global file), and the live dashboard + report show spend.
Typical real spend per run is a few cents (two small calls).

### Origin dedupe & response clustering

On big targets most "hosts" are the same origin behind a CDN or share an identical
default page. 4tail resolves IP/CNAME (via httpx, and drops wildcard DNS with `dnsx`
when installed) and fuzzes **one representative per (origin, response signature)** —
signature = status + content-length + title. This kills the 80% of fuzzing that would
just re-hit the same thing. Disable with `DEDUPE_ORIGINS=0`; disable dnsx with `USE_DNSX=0`.

### Parallel fuzzing with auto-backoff

Fuzz several hosts at once (off by default):

```bash
./4tail.sh -p 5 wolt.com     # 5 hosts in parallel
```

It watches ffuf results for HTTP 429 and, once a few hosts get rate-limited, **auto-backs
off** to serial with spacing between hosts (so a WAF doesn't ban you). Tune with
`FUZZ_BACKOFF_TRIGGER` (default 3 hosts) and `FUZZ_BACKOFF_SLEEP` (default 15s), and keep
`FFUF_RATE` modest so total load = parallel × rate stays sane.

### JS & secret mining + param discovery

```bash
./4tail.sh -j wolt.com       # collect JS, grep for leaked secrets, discover params
```

Collects JS (via `subjs`/`getJS` if installed, else scrapes page roots), greps for leaked
secrets (AWS/Google/Slack/GitHub keys, JWTs, private keys, S3 buckets, `api_key=`/`secret=`
assignments), and — if `arjun` is installed — discovers hidden request parameters. Results
go to `js_urls.txt`, `js_secrets.txt`, `params.txt`.

**The AI then analyses this real content** (not just tags): the triage report gains a
"Secrets & sensitive exposure" section (real vs false-positive, impact, how to verify) and
an "Interesting parameters to test" section (mapping params to IDOR/SSRF/LFI/SQLi ideas).

### Big targets (many subdomains)

A target with hundreds of live hosts makes exhaustive fuzzing impractical (hosts ×
wordlist × extensions = millions of requests), and most hosts are often shared CDN
edges. 4tail handles this:

- **CDN/WAF edges are skipped for fuzzing by default** (`SKIP_CDN_FUZZ=1`) — no point
  brute-forcing CloudFront/Cloudflare.
- **Quick pass** (nuclei-only, no fuzzing): `./4tail.sh -q wolt.com`
- **Cap fuzzed hosts**: `./4tail.sh -M 25 wolt.com` (fuzz the 25 most relevant)
- Combine with `FFUF_RATE`, `MAX_EXTS`, `MAX_FUZZ_WORDS` to bound request volume.

```bash
# Fast, polite first pass on a large scope:
./4tail.sh -y -q -S critical,high wolt.com          # recon + nuclei, no fuzz
# Then a bounded fuzz run on the interesting hosts:
FFUF_RATE=40 MAX_EXTS=6 ./4tail.sh -y -M 25 wolt.com
```

When it finishes, open the report:

```bash
cat 4tail_example.com_*/report.md
```

## Health check (`doctor`)

Before your first real run, verify everything is wired up — including that your LLM
**model ids actually work on your account**:

```bash
./4tail.sh doctor      # or: ./4tail.sh -D
```

It checks required tools (subfinder/httpx/nuclei), optional tools (ffuf/curl/jq/anew),
SecLists + key wordlists, the Bo0oM base list, and then **pings every configured model**
(planner, analyst, and each fallback) reporting reachability + latency. Example:

```
== AI / LLM (Together AI or compatible) ==
  [PASS] API key present; endpoint: https://api.together.xyz/v1
  routes plan=Qwen/Qwen2.5-7B-Instruct  triage=deepseek-ai/DeepSeek-V3.1  fallbacks=zai-org/GLM-5.3
  [PASS] model 'Qwen/Qwen2.5-7B-Instruct' reachable (0.42s)
  [PASS] model 'deepseek-ai/DeepSeek-V3.1' reachable (0.55s)
  [PASS] model 'zai-org/GLM-5.3' reachable (0.40s)
== Summary ==
  All good - 4tail is fully operational.
```

Exit code is non-zero if any check FAILs, so it's CI-friendly. It needs no target domain
and (each ping uses `max_tokens: 16`) costs almost nothing.

### Options

| Flag | Description | Env var |
|------|-------------|---------|
| `-w <file>` | Wordlist for Ffuf | `WORDLIST` |
| `-o <dir>`  | Output directory | `OUTDIR` |
| `-t <tags>` | Fallback Nuclei tags (used when AI is off) | `DEFAULT_NUCLEI_TAGS` |
| `-S <sev>`  | Nuclei severities | `NUCLEI_SEVERITY` (default `critical,high,medium,low`) |
| `-m <model>`| LLM model id | `LLM_MODEL` (default `zai-org/GLM-5.3`) |
| `-y`        | Skip the authorization prompt | `ASSUME_YES=1` |
| `-h`        | Show help | |

### LLM environment variables (OpenAI-compatible)

- `TOGETHER_API_KEY` (or `LLM_API_KEY`) — enables the AI decision + triage steps.
- `LLM_BASE_URL` — API base (default `https://api.together.xyz/v1`). Point this at any
  OpenAI-compatible provider (e.g. Zhipu, OpenRouter, a local server) to switch backends.
- `LLM_MODEL` — base model id used for every role unless overridden (default `zai-org/GLM-5.3`).
- `LLM_MAX_TOKENS` — default output cap (default `2000`).
- `LLM_BUDGET_USD` — cap estimated AI spend (`-b`, 0 = unlimited).
- `LLM_PRICE_IN` / `LLM_PRICE_OUT` — USD per 1M tokens, for the budget estimate.
- `LLM_COST_LEDGER` — path to a persistent cost tally (default: per-run in the output dir).
- `LLM_TEMPERATURE`, `LLM_TIMEOUT`, `LLM_RETRIES` — request tuning.

### Smart model routing ("swarm"-style switching)

**With only a key set, both AI steps use `zai-org/GLM-5.3`.** But 4tail routes each task
to its own model + token budget, so you can run a **cheap planner + a stronger analyst**:

| Role | What it does | Env var | Default |
|------|--------------|---------|---------|
| Planner | Pick nuclei tags + wordlist map (structured, light) | `LLM_MODEL_PLAN` | `LLM_MODEL` |
| Analyst | Triage & prioritise findings (reasoning-heavy) | `LLM_MODEL_TRIAGE` | `LLM_MODEL` |

Token budgets are per-role too: `LLM_MAX_TOKENS_PLAN` (default 700) and
`LLM_MAX_TOKENS_TRIAGE` (default `LLM_MAX_TOKENS`). And `LLM_FALLBACK_MODELS` (comma list)
is tried, in order, if a role's model call fails — automatic model switching for
reliability.

Example: cheap/fast planner, strong reasoning analyst, GLM as the safety net:

```bash
export TOGETHER_API_KEY=...
export LLM_MODEL_PLAN="Qwen/Qwen2.5-7B-Instruct"      # fast + cheap for the plan
export LLM_MODEL_TRIAGE="deepseek-ai/DeepSeek-V3.1"           # stronger for analysis
export LLM_FALLBACK_MODELS="zai-org/GLM-5.3"                # used if either fails
./4tail.sh example.com
```

> Model ids drift — verify the exact strings on [together.ai/models](https://www.together.ai/models)
> before use. Good cheap planners: `Qwen/Qwen2.5-7B-Instruct`,
> `meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo`. Good analysts: `deepseek-ai/DeepSeek-V3.1`,
> `Qwen/Qwen2.5-72B-Instruct-Turbo`, `zai-org/GLM-5.3`. The startup line and `report.md`
> both show which models were routed.

### Scan tuning env vars

- `WORDLIST` — base "juicy" wordlist (auto-resolves to Bo0oM/fuzz.txt if unset).
- `FETCH_FUZZTXT=1` — download Bo0oM/fuzz.txt to `~/.4tail/` if no base list is found.
- `SECLISTS_DIR` — SecLists root (auto-detected if unset) used for tech-specific lists.
- `MAX_FUZZ_WORDS` — cap on each host's combined wordlist size (default 60000).
- `MAX_FUZZ_HOSTS` — fuzz at most N hosts (`-M`, default 0 = all). Essential on big targets.
- `SKIP_FUZZ=1` — skip content discovery entirely (`-q`, nuclei-only quick pass).
- `SKIP_CDN_FUZZ` — skip fuzzing CDN/WAF edges (default 1; cloudfront, cloudflare, akamai, …).
- `EXTENSIONS` — explicit ffuf `-e` list, overrides tech-aware extensions.
- `MAX_EXTS` — cap on per-host extensions (default 10).
- `FFUF_RATE` — ffuf requests/sec (0 = unlimited).
- `NUCLEI_SEVERITY`, `NUCLEI_RATELIMIT`, `HTTPX_THREADS`, `OUTDIR`, `DEFAULT_NUCLEI_TAGS`.
- `MAX_TAGS` — cap nuclei tags (default 15; more tags = far more templates = much slower).
- `NUCLEI_TIMEOUT` (per-request s, default 8), `NUCLEI_RETRIES` (1), `NUCLEI_MHE` (skip a
  host after N errors, default 30), `NUCLEI_MAX_TIME` (hard cap on the whole nuclei stage
  in seconds, default 3600; 0 = unlimited) — these stop nuclei grinding for hours on big,
  CDN-heavy targets.

## Output

Each run creates a directory `4tail_<domain>_<timestamp>/` containing:

```
subdomains.txt      # Subfinder results
httpx.jsonl         # raw Httpx JSON (status, title, server, tech)
alive.txt           # deduped live URLs
tech_brief.txt      # aggregated tech/server/status frequencies (fed to the AI)
ai_scan_plan.txt    # the Nuclei tags the model chose
tech_wordlists.tsv  # tech → SecLists wordlist map (static + AI, used for fuzzing)
fuzz_plan.txt       # which wordlists each host was fuzzed with
fuzz/               # per-host Ffuf JSON results
nuclei.txt          # raw Nuclei findings
report.md           # AI-triaged, prioritized report
```

## Notes

- The AI steps only send recon metadata (aggregated technologies and Nuclei
  output) to the LLM endpoint. Review what you send if your engagement has data-
  handling restrictions.
- Always follow the rules and scope of the program you are testing, and practice
  responsible disclosure.
