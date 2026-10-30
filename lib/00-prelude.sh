#!/usr/bin/env bash
#
# 4tail - AI-assisted recon pipeline for AUTHORIZED bug-bounty / pentest work.
#
# Pipeline: subfinder -> httpx (tech detect) -> [AI plans the scan]
#           -> ffuf (content discovery) -> nuclei -> [AI triages findings].
#
# Features a LIVE terminal dashboard that tracks each stage in real time.
# The AI steps use any OpenAI-compatible endpoint (defaults: Together AI + GLM),
# tuned to keep token spend small.
#
# USE ONLY against targets you are explicitly authorised to test.

set -u
set -o pipefail

# Snapshot which tuning vars the user set explicitly, BEFORE we apply any defaults,
# so a loaded blueprint never overrides a value the user chose on the CLI/env.
for _v in CRAWL_MAX_URLS CRAWL_MAX_TIME DAST_MAX_URLS NUCLEI_MAX_HOSTS NUCLEI_SEVERITY \
          MAX_TAGS ACT_MAX_JUICY ACT_MAX_DALFOX ACT_MAX_KXSS ACT_MAX_SQLMAP ACT_MAX_ARJUN \
          ACT_DAST_TAGS ACT_SPECIALISTS ACT_FOCUS FUZZING_STRATEGY \
          MAX_FUZZ_WORDS MAX_EXTS FUZZ_MAX_TIME; do
  eval "_user_set_$_v=\${$_v+1}"
done
