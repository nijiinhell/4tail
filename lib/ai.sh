# ---------------------------------------------------------------------------
# LLM helper: ai_call <model> <max_tokens> <system> <user> -> prints text.
# Retry+backoff per model; if the primary model keeps failing, fall through to
# LLM_FALLBACK_MODELS in order (smart model switching for reliability).
# ---------------------------------------------------------------------------
ai_call() {
  local model="$1" maxtok="$2" system="$3" user="$4"
  local candidates m payload response text attempt delay
  candidates="$model"; [ -n "$LLM_FALLBACK_MODELS" ] && candidates="$model,$LLM_FALLBACK_MODELS"
  IFS=',' read -ra _models <<< "$candidates"
  for m in "${_models[@]}"; do
    m="$(printf '%s' "$m" | tr -d '[:space:]')"; [ -z "$m" ] && continue
    payload="$(jq -n --arg model "$m" --arg sys "$system" --arg usr "$user" \
      --argjson max "$maxtok" --argjson temp "$LLM_TEMPERATURE" \
      '{model:$model, max_tokens:$max, temperature:$temp,
        messages:[{role:"system",content:$sys},{role:"user",content:$usr}]}')" || continue
    attempt=0; delay=2
    while :; do
      attempt=$((attempt + 1))
      local http_code curl_rc
      response="$(curl -sS --max-time "$LLM_TIMEOUT" -w $'\n__HTTP__%{http_code}' \
        "$LLM_BASE_URL/chat/completions" \
        -H "content-type: application/json" -H "authorization: Bearer $LLM_API_KEY" \
        -d "$payload" 2>>"$llm_log")"; curl_rc=$?
      http_code="$(printf '%s' "$response" | sed -n 's/.*__HTTP__//p' | tail -1)"
      response="$(printf '%s' "$response" | sed 's/__HTTP__[0-9]*$//')"
      if [ "$curl_rc" != 0 ] || [ -z "$response" ]; then
        echo "[fail] model=$m curl_rc=$curl_rc http=${http_code:-none} (timeout/connection/empty)" >>"$llm_log"
      elif echo "$response" | jq -e '.error' >/dev/null 2>&1; then
        echo "[fail] model=$m http=${http_code:-?}: $(echo "$response" | jq -r '.error.message // .error' 2>/dev/null)" >>"$llm_log"
      fi
      if [ "$curl_rc" = 0 ] && [ -n "$response" ] && ! echo "$response" | jq -e '.error' >/dev/null 2>&1; then
        # Reasoning models (GLM/DeepSeek) may leave .content empty and put text in
        # .reasoning_content, especially if truncated (finish_reason=length).
        text="$(echo "$response" | jq -r '.choices[0].message.content // empty' 2>/dev/null)"
        local _fr; _fr="$(echo "$response" | jq -r '.choices[0].finish_reason // empty' 2>/dev/null)"
        # Only trust .reasoning_content as the ANSWER when the model actually FINISHED. A
        # length-truncated reasoning_content is an unfinished chain-of-thought, not output -
        # returning it would dump raw CoT into report.md and confuse the funnel's parsers.
        if [ -z "$text" ] && [ "$_fr" != "length" ]; then
          text="$(echo "$response" | jq -r '.choices[0].message.reasoning_content // empty' 2>/dev/null)"
        fi
        if [ -z "$text" ] && [ "$_fr" = "length" ]; then
          echo "[warn] model=$m truncated (finish_reason=length) with empty content - discarding partial reasoning, retrying/falling back. Raise LLM_MAX_TOKENS_PLAN/TRIAGE." >>"$llm_log"
        fi
        if [ -n "$text" ]; then
          # accrue estimated cost from token usage
          local uin uout ucost
          uin="$(echo "$response"  | jq -r '.usage.prompt_tokens // 0' 2>/dev/null)"
          uout="$(echo "$response" | jq -r '.usage.completion_tokens // 0' 2>/dev/null)"
          ucost="$(awk -v i="$uin" -v o="$uout" -v pi="$LLM_PRICE_IN" -v po="$LLM_PRICE_OUT" \
                   'BEGIN{printf "%.6f",(i*pi+o*po)/1000000}')"
          add_cost "$ucost"
          echo "[ok] model=$m tokens_in=$uin tokens_out=$uout cost=\$$ucost total=$(cost_now)" >>"$llm_log"
          printf '%s' "$text"; return 0
        fi
      fi
      if [ "$attempt" -gt "$LLM_RETRIES" ]; then
        echo "[fail] model=$m: $(echo "$response" | jq -r '.error.message // .error // "empty response"' 2>/dev/null)" >>"$llm_log"
        break   # give up on this model, try the next candidate
      fi
      sleep "$delay"; delay=$((delay * 2))
    done
  done
  return 1
}

# Background an AI call while spinning the given stage; result -> outfile.
#   run_ai_stage <idx> <model> <max_tokens> <system> <user> <outfile>
run_ai_stage() {
  local idx="$1" model="$2" maxtok="$3" sys="$4" usr="$5" outfile="$6"
  set_stage "$idx" running "querying ${model##*/} · 0s"
  ( ai_call "$model" "$maxtok" "$sys" "$usr" >"$outfile" 2>>"$llm_log" ) & local pid=$!
  local s=$SECONDS
  while kill -0 "$pid" 2>/dev/null; do
    ST_DETAIL[$idx]="querying ${model##*/} · $((SECONDS-s))s"
    [ "$TUI" = 1 ] && render; sleep 0.25
  done
  wait "$pid"; return $?
}

