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
   `tech → SecLists wordlist` mapping. Tags are validated against an allowlist and
   wordlist paths are existence-checked on disk, so a bogus/hallucinated value can
   never break the scan — anything unusable falls back to sane defaults. It's a
   single API call, so adding wordlist intelligence costs nothing extra.
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

The tech→wordlist map comes from the AI plan **and** a built-in static map, so it works
tech-aware even with no API key. SecLists is auto-detected (`SECLISTS_DIR`), and every
path is existence-checked — lists missing in your SecLists version are simply skipped.
Which lists each host received is recorded in `fuzz_plan.txt` and in the report.

> **`apt install seclists`** installs to `/usr/share/seclists`, which 4tail auto-detects.
> If yours is elsewhere, set `SECLISTS_DIR=/path/to/SecLists`. When no base wordlist is
> given, 4tail falls back to `…/Discovery/Web-Content/common.txt`.

#### Built-in tech → SecLists wordlist map (paths verified against SecLists)

| Detected tech | Wordlist(s) | What it's for |
|---|---|---|
| WordPress | `CMS/wordpress.fuzz.txt`, `wp-plugins.fuzz.txt`, `wp-themes.fuzz.txt` | Core WP paths, ~14k plugin dirs, theme dirs (vuln plugin/theme discovery) |
| Joomla | `CMS/joomla-plugins.fuzz.txt`, `joomla-themes.fuzz.txt` | Extensions & templates |
| Drupal | `CMS/Drupal.txt`, `drupal-themes.fuzz.txt` | Modules, admin, CHANGELOG |
| Magento | `CMS/sitemap-magento.txt` | Admin, downloader, RCE-prone endpoints |
| Umbraco | `CMS/Umbraco.fuzz.txt` | .NET CMS admin/config surface |
| ColdFusion | `coldfusion.txt`, `CMS/ColdFusion.fuzz.txt` | CFIDE, Administrator, AdminAPI |
| PHP | `raft-large-files.txt` | Large file list rich in `.php` config/backup files |
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
 │ target=example.com  ai=zai-org/GLM-4.6  elapsed=41s
 │  ✔  Subdomains    128 subs
 │  ✔  Live hosts    37 live
 │  ✔  AI scan plan  cves,exposures,wordpress,php,nginx
 │  ⠹  Fuzzing       host 12/37
 │  ○  Nuclei scan
 │  ○  AI triage
 ╰──────────────────────────────────────────────
```

Icons: `○` pending · spinner running · `✔` done · `▲` warning · `–` skipped.
It auto-disables (falling back to plain `[*]/[+]/[!]` logs) when output isn't a
terminal — e.g. piped to a file or run in CI. Force plain mode with `-P` or `NO_TUI=1`.

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

When it finishes, open the report:

```bash
cat 4tail_example.com_*/report.md
```

### Options

| Flag | Description | Env var |
|------|-------------|---------|
| `-w <file>` | Wordlist for Ffuf | `WORDLIST` |
| `-o <dir>`  | Output directory | `OUTDIR` |
| `-t <tags>` | Fallback Nuclei tags (used when AI is off) | `DEFAULT_NUCLEI_TAGS` |
| `-S <sev>`  | Nuclei severities | `NUCLEI_SEVERITY` (default `critical,high,medium,low`) |
| `-m <model>`| LLM model id | `LLM_MODEL` (default `zai-org/GLM-4.6`) |
| `-y`        | Skip the authorization prompt | `ASSUME_YES=1` |
| `-h`        | Show help | |

### LLM environment variables (OpenAI-compatible)

- `TOGETHER_API_KEY` (or `LLM_API_KEY`) — enables the AI decision + triage steps.
- `LLM_BASE_URL` — API base (default `https://api.together.xyz/v1`). Point this at any
  OpenAI-compatible provider (e.g. Zhipu, OpenRouter, a local server) to switch backends.
- `LLM_MODEL` — model id (default `zai-org/GLM-4.6`). For even lower cost try a smaller
  GLM variant such as `zai-org/GLM-4.5-Air-FP8`; browse ids at
  [together.ai/models](https://www.together.ai/models).
- `LLM_MAX_TOKENS` — output cap (default `1200`, kept low for cost).
- `LLM_TEMPERATURE`, `LLM_TIMEOUT`, `LLM_RETRIES` — request tuning.

### Scan tuning env vars

- `WORDLIST` — base "juicy" wordlist, always used for every host.
- `SECLISTS_DIR` — SecLists root (auto-detected if unset) used for tech-specific lists.
- `MAX_FUZZ_WORDS` — cap on each host's combined wordlist size (default 60000).
- `NUCLEI_SEVERITY`, `NUCLEI_RATELIMIT`, `HTTPX_THREADS`, `OUTDIR`, `DEFAULT_NUCLEI_TAGS`.

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
