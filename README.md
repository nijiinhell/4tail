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
   and picks the most relevant Nuclei tags, instead of a fixed tag list. Its output
   is validated against an allowlist so a bogus/hallucinated tag can never silently
   make Nuclei scan nothing — if the result is unusable, it falls back to defaults.
2. **Finding triage** — after Nuclei runs, the model turns the raw output into a
   prioritized Markdown report (executive summary, severity-sorted table, and
   recommended manual follow-ups).

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
- All artifacts written to a timestamped results directory.

## Prerequisites

- [Subfinder](https://github.com/projectdiscovery/subfinder) (add your API keys after install)
- [Httpx](https://github.com/projectdiscovery/httpx)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Ffuf](https://github.com/ffuf/ffuf) *(optional — fuzzing is skipped if absent)*
- `curl` and `jq` *(required only for the AI steps)*
- A wordlist for fuzzing (e.g. from [SecLists](https://github.com/danielmiessler/SecLists))
- A [Together AI API key](https://api.together.xyz/) *(optional, enables the AI steps)* —
  or any other OpenAI-compatible endpoint.

## Usage

```bash
chmod +x 4tail.sh

# With AI decision-making + triage (Together AI + GLM by default):
TOGETHER_API_KEY=... ./4tail.sh -w /path/to/wordlist.txt example.com

# Without an API key (static defaults, no AI):
./4tail.sh example.com
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

- `NUCLEI_SEVERITY`, `NUCLEI_RATELIMIT`, `HTTPX_THREADS`, `WORDLIST`, `OUTDIR`,
  `DEFAULT_NUCLEI_TAGS`.

## Output

Each run creates a directory `4tail_<domain>_<timestamp>/` containing:

```
subdomains.txt      # Subfinder results
httpx.jsonl         # raw Httpx JSON (status, title, server, tech)
alive.txt           # deduped live URLs
tech_brief.txt      # aggregated tech/server/status frequencies (fed to the AI)
ai_scan_plan.txt    # the Nuclei tags the model chose
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
