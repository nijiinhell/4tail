#!/usr/bin/env bash
#
# 4tail - AI-assisted recon pipeline for AUTHORIZED bug-bounty / pentest work.
#
# Pipeline: subfinder -> httpx (tech detect) -> [AI plans the scan]
#           -> ffuf (content discovery) -> nuclei -> [AI triages findings].
#
# This is the MODULAR entrypoint: the script is split into lib/*.sh sections for
# easier maintenance and troubleshooting, loaded here in dependency order. The
# split is purely structural - `make build` concatenates the sections back into a
# single-file dist/4tail.sh identical to the classic standalone script, so you can
# still copy one file to a box.
#
# USE ONLY against targets you are explicitly authorised to test.

# Resolve the directory this script lives in, so lib/ is found regardless of CWD.
_4T_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
_4T_LIB="$_4T_DIR/lib"

# Sections, in load order. 00-prelude sets -u/pipefail and snapshots the user's
# explicit tuning vars BEFORE config applies defaults; the rest define helpers and
# then run the pipeline top-to-bottom (same order as the monolith).
_4T_MODS="00-prelude config cli dashboard helpers agent_tools blueprints ai doctor \
          p_recon p_js p_plan p_fuzz p_funnel p_nuclei p_agent p_report"

# Fail clearly if a section is missing (e.g. only 4tail.sh was copied without lib/).
for _4t_mod in $_4T_MODS; do
  if [ ! -f "$_4T_LIB/$_4t_mod.sh" ]; then
    echo "4tail: missing section lib/$_4t_mod.sh - copy the whole repo, or use the single-file build (make build -> dist/4tail.sh)" >&2
    exit 1
  fi
done

# shellcheck source=/dev/null
for _4t_mod in $_4T_MODS; do . "$_4T_LIB/$_4t_mod.sh"; done
