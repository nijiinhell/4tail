# Step 3: AI scan plan (with allowlist guardrail)
NUCLEI_TAG_ALLOWLIST="cves,cve,exposures,exposure,misconfiguration,misconfig,tech,\
default-login,takeover,subdomain-takeover,panel,login,exposed-panels,config,\
backup,files,logs,debug,git,svn,env,sqli,xss,ssrf,lfi,rce,injection,auth-bypass,\
wordpress,wp-plugin,joomla,drupal,magento,laravel,django,spring,struts,\
apache,nginx,tomcat,iis,php,jira,confluence,jenkins,gitlab,grafana,kibana,\
elasticsearch,kubernetes,docker,aws,azure,gcp,ssl,tls,cors,headers,\
oauth,jwt,api,graphql,swagger,firebase,s3,redis,mongodb,mysql,postgres"
# Curated base kept separate from the runtime-widened list: explicit JSON tag choices
# are checked against the (wide) NUCLEI_TAG_ALLOWLIST, but loose prose salvage is checked
# against this strict base only, so reasoning words (target/dreamweaver/eol/...) can't leak.
NUCLEI_TAG_ALLOWLIST_BASE="$NUCLEI_TAG_ALLOWLIST"
sanitize_tags() {  # [allowlist]  (reads tags on stdin; defaults to the widened allowlist)
  local allow="${1:-$NUCLEI_TAG_ALLOWLIST}"
  tr ',[:space:]' '\n\n' | tr 'A-Z' 'a-z' | grep -oE '[a-z0-9._-]+' \
    | while read -r t; do
        case ",${allow//[[:space:]]/}," in *",$t,"*) echo "$t";; esac
      done | awk '!seen[$0]++' | paste -sd, -
}
# Index the REAL category tags present in the installed templates, dropping the
# thousands of per-CVE id tags (cve-YYYY-N) so we keep the useful ~few-hundred
# (iis, weblogic, rce, lfi, fortinet, ...). Then widen the tag allowlist with them,
# so the AI plan can select any tag the user's template store actually supports -
# grounded in what's installed, never hallucinated.
build_nuclei_tag_index() {
  [ "$NUCLEI_TAG_INDEX" = 1 ] && have nuclei && have grep || return 0
  [ -s "$nuclei_tag_index" ] && return 0   # cached (e.g. resume)
  local tpl; tpl="$(locate_nuclei_templates)"
  [ -n "$tpl" ] || return 0
  grep -rhoE '^[[:space:]]*tags:[[:space:]]*.*' "$tpl" 2>/dev/null \
    | sed -E 's/^[[:space:]]*tags:[[:space:]]*//; s/["'"'"']//g' \
    | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | tr 'A-Z' 'a-z' \
    | grep -E '^[a-z0-9._-]{2,40}$' \
    | grep -vE '^cve-[0-9]{4}-[0-9]+$|^[0-9]{4}$' \
    | sort -u > "$nuclei_tag_index" 2>/dev/null || true
  if [ -s "$nuclei_tag_index" ]; then
    NUCLEI_TAG_ALLOWLIST="$NUCLEI_TAG_ALLOWLIST,$(paste -sd, "$nuclei_tag_index")"
  fi
}
# Seed a built-in tech -> SecLists wordlist map. Every path below was verified to
# exist in SecLists (github.com/danielmiessler/SecLists). Paths are still
# existence-checked at fuzz time, so any that are absent in a given SecLists
# version are simply skipped. This makes fuzzing tech-aware even with no API key.
#
# What each list is FOR (per detected technology):
#   WordPress  wordpress.fuzz.txt  -> core WP paths (wp-login, wp-admin, xmlrpc…)
#              wp-plugins.fuzz.txt -> ~14k plugin dirs (vuln plugin discovery)
#              wp-themes.fuzz.txt  -> theme dirs (theme-specific bugs / LFI)
#   Joomla     joomla-plugins/themes.fuzz.txt -> extensions & templates
#   Drupal     Drupal.txt / drupal-themes.fuzz.txt -> modules, admin, changelog
#   Magento    sitemap-magento.txt -> admin, downloader, RCE-prone endpoints
#   Umbraco    CMS/Umbraco.fuzz.txt -> .NET CMS admin/config surface
#   ColdFusion coldfusion.txt + CMS/ColdFusion.fuzz.txt -> CFIDE, admin, AdminAPI
#   PHP        (no heavy list) -> covered by the base list + .php/.phtml extensions
#   Java/JSP   JavaServlets-Common.fuzz.txt -> servlets, invoker, struts actions
#   (Tomcat/   vulnerability-scan_j2ee-websites_WEB-INF.txt -> WEB-INF, web.xml,
#    Spring/    class/jar leakage (source & credential disclosure)
#    Struts)
#   IIS/ASP    Microsoft-Frontpage.txt -> FrontPage/IIS extensions & _vti_ dirs
#   API/REST   api/api-endpoints.txt, api/objects.txt, api/actions.txt,
#   /Swagger   api/api-seen-in-wild.txt, common-api-endpoints-mazen160.txt
#              -> REST resources, verbs, versioned routes, doc endpoints
#   GraphQL    graphql.txt -> /graphql, /graphiql, playground, introspection
#   OAuth/OIDC oauth-oidc-scopes.txt -> auth endpoints, well-known, scopes
#   git/svn    versioning_metafiles.txt -> .git/.svn/.hg metadata (source leak)
#   Vault      hashicorp-vault.txt / hashicorp-consul-api.txt -> secrets APIs
#   SAP        CMS/SAP.fuzz.txt / SAP-NetWeaver.txt -> SAP web surface
seed_static_tech_map() {
  : > "$tech_map_file"
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    printf '%s\n' "$line" >> "$tech_map_file"
  done <<'STATIC'
wordpress	Discovery/Web-Content/CMS/wordpress.fuzz.txt
wordpress	Discovery/Web-Content/CMS/wp-plugins.fuzz.txt
wordpress	Discovery/Web-Content/CMS/wp-themes.fuzz.txt
joomla	Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt
joomla	Discovery/Web-Content/CMS/joomla-themes.fuzz.txt
drupal	Discovery/Web-Content/CMS/Drupal.txt
drupal	Discovery/Web-Content/CMS/drupal-themes.fuzz.txt
magento	Discovery/Web-Content/CMS/sitemap-magento.txt
umbraco	Discovery/Web-Content/CMS/Umbraco.fuzz.txt
coldfusion	Discovery/Web-Content/coldfusion.txt
coldfusion	Discovery/Web-Content/CMS/ColdFusion.fuzz.txt
java	Discovery/Web-Content/JavaServlets-Common.fuzz.txt
java	Discovery/Web-Content/vulnerability-scan_j2ee-websites_WEB-INF.txt
tomcat	Discovery/Web-Content/JavaServlets-Common.fuzz.txt
tomcat	Discovery/Web-Content/vulnerability-scan_j2ee-websites_WEB-INF.txt
spring	Discovery/Web-Content/JavaServlets-Common.fuzz.txt
struts	Discovery/Web-Content/JavaServlets-Common.fuzz.txt
iis	Discovery/Web-Content/Microsoft-Frontpage.txt
asp	Discovery/Web-Content/Microsoft-Frontpage.txt
frontpage	Discovery/Web-Content/Microsoft-Frontpage.txt
api	Discovery/Web-Content/api/api-endpoints.txt
api	Discovery/Web-Content/api/objects.txt
api	Discovery/Web-Content/api/actions.txt
api	Discovery/Web-Content/common-api-endpoints-mazen160.txt
swagger	Discovery/Web-Content/api/api-endpoints.txt
swagger	Discovery/Web-Content/api/api-seen-in-wild.txt
openapi	Discovery/Web-Content/api/api-endpoints.txt
rest	Discovery/Web-Content/api/api-endpoints.txt
graphql	Discovery/Web-Content/graphql.txt
oauth	Discovery/Web-Content/oauth-oidc-scopes.txt
oidc	Discovery/Web-Content/oauth-oidc-scopes.txt
git	Discovery/Web-Content/versioning_metafiles.txt
svn	Discovery/Web-Content/versioning_metafiles.txt
vault	Discovery/Web-Content/hashicorp-vault.txt
consul	Discovery/Web-Content/hashicorp-consul-api.txt
sap	Discovery/Web-Content/CMS/SAP.fuzz.txt
sap	Discovery/Web-Content/SAP-NetWeaver.txt
STATIC
}
# Seed the static map, but on resume keep a prior map (it may hold AI additions).
if [ "$RESUME" = 1 ] && [ -s "$tech_map_file" ]; then :
elif [ -n "$SECLISTS_DIR" ]; then seed_static_tech_map
else : > "$tech_map_file"; fi

# Ground the tag allowlist in the user's actually-installed templates before planning.
build_nuclei_tag_index

nuclei_tags="$DEFAULT_NUCLEI_TAGS"
scan_plan_file="${logs_dir:-$OUTDIR}/ai_scan_plan.txt"
if [ "$RESUME" = 1 ] && { [ -s "$scan_plan_file" ] || [ -s "$OUTDIR/ai_scan_plan.txt" ]; }; then
  [ -s "$scan_plan_file" ] || scan_plan_file="$OUTDIR/ai_scan_plan.txt"
  nuclei_tags="$(cat "$scan_plan_file")"
  set_stage $S_PLAN done "$nuclei_tags (resumed)"
elif [ "$AI_ENABLED" = "1" ] && ! budget_ok; then
  set_stage $S_PLAN skip "budget reached ($(cost_fmt)), using defaults"
elif [ "$AI_ENABLED" = "1" ] && [ -s "$tech_brief" ]; then
  sys_plan='You assist AUTHORIZED bug-bounty recon. Given an aggregated brief of the
technologies, servers and notable paths on live hosts, produce a scan plan.
Reply with ONLY a JSON object (no prose, no code fences) with exactly two keys:
  "nuclei_tags": array of 4-12 lowercase nuclei tags (always include cves, exposures,
     misconfiguration, plus tags matched to the observed stack),
  "wordlists": object mapping each relevant lowercase technology name to an array of
     content-discovery wordlist file paths RELATIVE to the SecLists root
     (e.g. "Discovery/Web-Content/CMS/wordpress.fuzz.txt"). Use only real, well-known
     SecLists paths; keep 1-3 paths per technology; omit technologies you are unsure of.
     Prefer small, tech-SPECIFIC lists (CMS/*, api/*, *.fuzz.txt). Do NOT use big generic
     lists (raft-*, big.txt, directory-list-*, combined_*, dirbuster) - those are excluded.'
  plan_out="$(mktemp)"
  js_brief=""
  if [ -s "${js_endpoints_file:-/dev/null}" ] || [ -s "${js_secrets_file:-/dev/null}" ] || [ -s "${sourcemap_file:-/dev/null}" ]; then
    js_brief="$( {
      echo "=== Mined JS & API surface ==="
      [ -s "$js_secrets_file" ] && { echo "Mined Secrets:"; head -5 "$js_secrets_file"; }
      [ -s "${sourcemap_file:-/dev/null}" ] && { echo "Source Maps Leaked:"; head -5 "$sourcemap_file"; }
      [ -s "$js_endpoints_file" ] && { echo "Mined API Routes:"; head -15 "$js_endpoints_file"; }
    } )"
  fi
  run_ai_stage $S_PLAN "$LLM_MODEL_PLAN" "$LLM_MAX_TOKENS_PLAN" "$sys_plan" "Target: $domain
Live hosts: $alive_count
SecLists root: ${SECLISTS_DIR:-<not installed>}

$(head -c 10000 "$tech_brief")
${js_brief:+$'\n'$js_brief}" "$plan_out"

  # Strip multi-line thinking tags (<think>...</think>) from reasoning models (DeepSeek-R1, Qwen, Claude 3.7)
  clean_reply="$(awk '
    /<think>/ { in_think=1; next }
    /<\/think>/ { in_think=0; next }
    !in_think { print }
  ' "$plan_out" 2>/dev/null | sed -E 's/```(json)?//g; s/```//g')"

  # Extract valid JSON containing nuclei_tags or wordlists using jq/awk
  plan_json=""
  if have jq; then
    if printf '%s\n' "$clean_reply" | jq -e . >/dev/null 2>&1; then
      plan_json="$clean_reply"
    else
      cand="$(printf '%s\n' "$clean_reply" | awk '/^[[:space:]]*\{/{p=1} p{print} /^[[:space:]]*\}/{if(p){print; exit}}' 2>/dev/null)"
      if [ -n "$cand" ] && printf '%s\n' "$cand" | jq -e . >/dev/null 2>&1; then
        plan_json="$cand"
      fi
    fi
  fi

  if [ -z "$plan_json" ]; then
    flat="$(printf '%s' "$clean_reply" | tr '\r\n' '  ')"
    plan_json="$(printf '%s' "$flat" | grep -oE '\{.*\}' | head -1)"
    [ -z "$plan_json" ] && plan_json="$(cat "$plan_out")"
  fi

  # --- parse nuclei tags ---
  # Explicit JSON tags are trusted against the WIDE allowlist (so the AI can pick real
  # installed tags like weblogic). If JSON is absent, salvage from prose against the
  # STRICT base only, so reasoning words (target/dreamweaver/eol/json/legacy) can't leak in.
  ai_tags="$(printf '%s' "$plan_json" | jq -r '.nuclei_tags[]?' 2>/dev/null | paste -sd, -)"
  if [ -n "$ai_tags" ]; then ai_extra="$(printf '%s' "$ai_tags" | sanitize_tags)"
  else ai_extra="$(cat "$plan_out" | sanitize_tags "$NUCLEI_TAG_ALLOWLIST_BASE")"; fi
  # AI tags are ADDITIVE on top of the strong defaults, so a thin/unparseable reply
  # degrades to good defaults instead of discarding the core (cves/exposures/...).
  clean_plan="$(printf '%s,%s' "$DEFAULT_NUCLEI_TAGS" "$ai_extra" | sanitize_tags)"

  # --- parse wordlist map (append to tech map; heavy generic lists filtered out,
  #     existence checked at fuzz time) ---
  if [ -n "$SECLISTS_DIR" ]; then
    printf '%s' "$plan_json" \
       | jq -r '.wordlists // {} | to_entries[]? | (.key|ascii_downcase) as $k | .value[]? | "\($k)\t\(.)"' 2>/dev/null \
       | grep -viE 'raft-|big\.txt|directory-list|combined_|dirbuster|/all\.txt' \
       >> "$tech_map_file" || true
  fi
  rm -f "$plan_out"

  nuclei_tags="${clean_plan:-$DEFAULT_NUCLEI_TAGS}"
  printf '%s\n' "$nuclei_tags" > "${scan_plan_file:-$OUTDIR/ai_scan_plan.txt}"
  if [ -n "$ai_extra" ]; then set_stage $S_PLAN done "$nuclei_tags"
  else set_stage $S_PLAN done "$nuclei_tags (defaults; AI added none)"; fi
else
  set_stage $S_PLAN skip "AI off (defaults)"
fi

