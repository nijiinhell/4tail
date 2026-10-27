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
if [ "$RESUME" = 1 ] && [ -s "$OUTDIR/ai_scan_plan.txt" ]; then
  nuclei_tags="$(cat "$OUTDIR/ai_scan_plan.txt")"
  set_stage $S_PLAN done "$nuclei_tags (resumed)"
elif [ "$AI_ENABLED" = "1" ] && ! budget_ok; then
  set_stage $S_PLAN skip "budget reached ($(cost_fmt)), using defaults"
elif [ "$AI_ENABLED" = "1" ] && [ -s "$tech_brief" ]; then
  sys_plan='You assist AUTHORIZED bug-bounty recon. Given an aggregated brief of the
technologies, servers and notable paths on live hosts, produce a scan plan.
Reply with ONLY a JSON object (no prose, no code fences) with exactly three keys:
  "nuclei_tags": array of 4-12 lowercase nuclei tags (always include cves, exposures,
     misconfiguration, plus tags matched to the observed stack),
  "wordlists": object mapping each relevant lowercase technology name to an array of
     content-discovery wordlist file paths RELATIVE to the SecLists root
     (e.g. "Discovery/Web-Content/CMS/wordpress.fuzz.txt"). Use only real, well-known
     SecLists paths; keep 1-3 paths per technology; omit technologies you are unsure of.
     Prefer small, tech-SPECIFIC lists (CMS/*, api/*, *.fuzz.txt). Do NOT use big generic
     lists (raft-*, big.txt, directory-list-*, combined_*, dirbuster) - those are excluded.
  "custom_words": array of 15-30 short org/product-specific path tokens inferred from the
     subdomain names, page titles and product names in the brief (e.g. "payments-v2",
     "partner-portal", "internal", "acme", "portal-api"). Single path segments only
     (lowercase, [a-z0-9._-], no slashes/spaces) - words a generic wordlist would NOT contain.'
  plan_out="$(mktemp)"
  run_ai_stage $S_PLAN "$LLM_MODEL_PLAN" "$LLM_MAX_TOKENS_PLAN" "$sys_plan" "Target: $domain
Live hosts: $alive_count
SecLists root: ${SECLISTS_DIR:-<not installed>}

$(head -c 12000 "$tech_brief")" "$plan_out"

  # Reasoning models (GLM/DeepSeek) often wrap JSON in ``` fences or prepend
  # "thinking". Prefer a {...} span that actually contains nuclei_tags, else any
  # {...}, else the whole reply (sanitize_tags salvages allowlisted words from prose).
  flat="$(tr -d '\r' < "$plan_out" | tr '\n' ' ')"
  plan_json="$(printf '%s' "$flat" | grep -oE '\{[^{}]*nuclei_tags.*\}' | head -1)"
  [ -z "$plan_json" ] && plan_json="$(printf '%s' "$flat" | grep -oE '\{.*\}' | head -1)"
  [ -z "$plan_json" ] && plan_json="$(cat "$plan_out")"

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
  # --- parse org/product-specific custom words (sanitized to single path segments) ---
  printf '%s' "$plan_json" \
    | jq -r '.custom_words[]? | select(type=="string")' 2>/dev/null \
    | tr 'A-Z' 'a-z' \
    | sed -E 's#^/+##; s#/+$##' \
    | grep -E '^[a-z0-9._/-]{2,40}$' | grep -vF '..' \
    | awk '!seen[$0]++' | head -n 40 > "$custom_words_file" 2>/dev/null || true
  rm -f "$plan_out"

  nuclei_tags="${clean_plan:-$DEFAULT_NUCLEI_TAGS}"
  printf '%s\n' "$nuclei_tags" > "$OUTDIR/ai_scan_plan.txt"
  if [ -n "$ai_extra" ]; then set_stage $S_PLAN done "$nuclei_tags"
  else set_stage $S_PLAN done "$nuclei_tags (defaults; AI added none)"; fi
else
  set_stage $S_PLAN skip "AI off (defaults)"
fi

