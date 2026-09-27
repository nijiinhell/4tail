# 4tail

An AI-assisted recon pipeline for **authorized** bug-bounty and penetration-testing
work. It chains popular ProjectDiscovery tools — **Subfinder → Httpx → Ffuf → Nuclei**
— and adds a layer of Claude-powered decision-making so the scan adapts to what it
actually finds instead of running a fixed recipe.

> ⚠️ Only run 4tail against targets you are explicitly authorized to test.
> The script asks you to confirm authorization before it starts (skip with `-y`).

## What makes it "smart"

The script calls the Anthropic API (Claude) to make two real decisions:

1. **Adaptive scan planning** — after Httpx probes live hosts *with technology
   detection*, Claude reads the detected stack (WordPress, nginx, Jira, PHP, …)
   and picks the most relevant Nuclei tags to scan with, instead of a fixed tag list.
2. **Finding triage** — after Nuclei runs, Claude turns the raw output into a
   prioritized Markdown report (executive summary, severity-sorted table, and
   recommended manual follow-ups).

Both AI steps are **optional**. Without an API key (or without `curl`/`jq`), 4tail
degrades gracefully: it uses sensible default tags and writes the raw findings to
the report.

## Features

- **Subdomain enumeration** with Subfinder.
- **Live-host probing + tech detection** with Httpx (JSON output).
- **AI scan planning**: Claude selects Nuclei tags from the detected technologies.
- **Content discovery** with Ffuf (configurable wordlist).
- **Vulnerability scanning** with Nuclei.
- **AI triage report**: a prioritized `report.md` per run.
- All artifacts written to a timestamped results directory.

## Prerequisites

- [Subfinder](https://github.com/projectdiscovery/subfinder) (add your API keys after install)
- [Httpx](https://github.com/projectdiscovery/httpx)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Ffuf](https://github.com/ffuf/ffuf) *(optional — fuzzing is skipped if absent)*
- `curl` and `jq` *(required only for the AI steps)*
- A wordlist for fuzzing (e.g. from [SecLists](https://github.com/danielmiessler/SecLists))
- An [Anthropic API key](https://console.anthropic.com/) *(optional, enables the AI steps)*

## Usage

```bash
chmod +x 4tail.sh

# With AI decision-making + triage:
ANTHROPIC_API_KEY=sk-ant-... ./4tail.sh -w /path/to/wordlist.txt example.com

# Without an API key (static defaults, no AI):
./4tail.sh example.com
```

### Options

| Flag | Description | Env var |
|------|-------------|---------|
| `-w <file>` | Wordlist for Ffuf | `WORDLIST` |
| `-o <dir>`  | Output directory | `OUTDIR` |
| `-t <tags>` | Fallback Nuclei tags (used when AI is off) | `DEFAULT_NUCLEI_TAGS` |
| `-m <model>`| Anthropic model | `ANTHROPIC_MODEL` (default `claude-opus-5`) |
| `-y`        | Skip the authorization prompt | `ASSUME_YES=1` |
| `-h`        | Show help | |

### Environment variables

- `ANTHROPIC_API_KEY` — enables the AI decision + triage steps.
- `ANTHROPIC_MODEL` — model to use (default `claude-opus-5`).
- `WORDLIST`, `OUTDIR`, `DEFAULT_NUCLEI_TAGS` — see the table above.

## Output

Each run creates a directory `4tail_<domain>_<timestamp>/` containing:

```
subdomains.txt      # Subfinder results
httpx.jsonl         # raw Httpx JSON (status, title, server, tech)
alive.txt           # deduped live URLs
tech_summary.txt    # host → tech/status/title (fed to the AI)
ai_scan_plan.txt    # the Nuclei tags Claude chose
fuzz/               # per-host Ffuf JSON results
nuclei.txt          # raw Nuclei findings
report.md           # AI-triaged, prioritized report
```

## Notes

- The AI steps only send recon metadata (hosts, detected technologies, and Nuclei
  output) to the Anthropic API. Review what you send if your engagement has data-
  handling restrictions.
- Always follow the rules and scope of the program you are testing, and practice
  responsible disclosure.
