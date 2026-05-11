#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

TARGET=""
SCOPE_FILE=""
OUT_DIR="${OUT_DIR:-intel}"
PROXY=""
FAST_MODE=false
ENTROPY_MODE=false
RUN_ID="$(date +%Y%m%d-%H%M%S)"

usage() {
  cat <<'HELP'
Usage:
  squirm -t domain.com
  squirm --scope scope.txt

Options:
  --fast
  --entropy
  --proxy URL
  --out-dir DIR
HELP
}

die(){ echo "[!] $*" >&2; exit 1; }
log(){ echo "[*] $*"; }
need(){ command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

HTTPX_BIN=""

resolve_httpx() {
  if command -v httpx >/dev/null 2>&1; then
    HTTPX_BIN="httpx"
  elif command -v httpx-toolkit >/dev/null 2>&1; then
    HTTPX_BIN="httpx-toolkit"
  else
    die "missing dependency: httpx"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="${2:-}"; shift 2 ;;
    --scope) SCOPE_FILE="${2:-}"; shift 2 ;;
    --proxy) PROXY="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    --fast) FAST_MODE=true; shift ;;
    --entropy) ENTROPY_MODE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$TARGET" && -n "$SCOPE_FILE" ]] && die "choose target OR scope"
[[ -z "$TARGET" && -z "$SCOPE_FILE" ]] && die "missing target"

for cmd in subfinder gau jq curl grep sed awk sort uniq head; do
  need "$cmd"
done

resolve_httpx

HTTPX_PROXY_FLAGS=()
CURL_PROXY_FLAGS=()

if [[ -n "$PROXY" ]]; then
  HTTPX_PROXY_FLAGS=(-proxy "$PROXY")
  CURL_PROXY_FLAGS=(-x "$PROXY")
fi

tool_version() {
  "$@" 2>&1 | head -n 1 || true
}

valid_target() {
  [[ "$1" =~ ^[A-Za-z0-9.-]+$ ]]
}

normalize() {
  grep '^https\?://' \
  | sed 's/[?#].*$//' \
  | sed 's#//$#/#' \
  | sed '/^[[:space:]]*$/d' \
  | sort -u
}

filter_noise() {
  grep -Evi \
'(\.svg$|\.png$|\.jpg$|\.jpeg$|\.gif$|\.css$|\.woff$|\.woff2$|\.ico$|\.map$|\.mp4$|\.webp$|\.mp3$|author/|/blog/|/case-studies/|/careers/|/events/|/community/|/resources/|/webinar/|/ebook/|/podcast/|/customer|/customers|/pricing|/privacy|/terms|/cookies|googletagmanager|google-analytics|doubleclick|tracking|analytics|utm_|fbclid=|gclid=|_next/static|webpack|polyfills|framework|bootstrap|autoptimize|chunk|component---|page-data/|build/routes/|withSessionRecording)'
}

classify_urls() {
  local infile="$1"
  local outdir="$2"

  grep -Ei '(/api/|graphql|openid|oauth|token|session|auth|login|signin|callback|authorize)' "$infile" \
    | sort -u > "$outdir/auth.txt" || true

  grep -Ei '(proxy|internal|admin|governance|acl|registry|connector|schema|mirror|mirrormaker)' "$infile" \
    | sort -u > "$outdir/platform.txt" || true

  grep -Ei '(kafka|kafka-connect|kafka-ui|unlockAsset|submitTrialForm)' "$infile" \
    | sort -u > "$outdir/features.txt" || true

  grep -Ei '(\.js$|remix-entries|assets/)' "$infile" \
    | sort -u > "$outdir/frontend.txt" || true
}

entropy_scan() {
  local infile="$1"
  local outfile="$2"

  : > "$outfile"

  while read -r url; do
    [[ -z "$url" ]] && continue

    curl -sS -k -L -m 8 --max-filesize 524288 "${CURL_PROXY_FLAGS[@]}" "$url" 2>/dev/null \
      | grep -oE '[A-Za-z0-9_-]{25,}' \
      | sort -u \
      | while read -r token; do
          if [[ "$token" =~ [A-Z] && "$token" =~ [a-z] && "$token" =~ [0-9] ]]; then
            printf '%s::%s...\n' "$url" "${token:0:10}" >> "$outfile"
          fi
        done || true
  done < "$infile"
}

run_one() {
  local target="$1"

  valid_target "$target" || die "invalid target"

  local OUTPATH="$OUT_DIR/$target/$RUN_ID"
  local RAW="$OUTPATH/raw"
  local CLASSIFIED="$OUTPATH/classified"
  local FLAGS="$OUTPATH/flags"

  mkdir -p "$RAW" "$CLASSIFIED" "$FLAGS"

  local SUBS="$RAW/subdomains.txt"
  local ALIVE="$RAW/alive.txt"
  local ENDPOINTS="$RAW/endpoints.txt"
  local CLEAN="$RAW/cleaned-endpoints.txt"
  local REPORT="$OUTPATH/report.json"

  log "target: $target"

  log "collecting subdomains"
  subfinder -d "$target" -silent \
    | sort -u > "$SUBS"

  log "probing alive hosts"

  {
    printf '%s\n' "$target"
    cat "$SUBS" 2>/dev/null || true
  } | sort -u \
    | "$HTTPX_BIN" -silent "${HTTPX_PROXY_FLAGS[@]}" \
    | sort -u > "$ALIVE"

  if $FAST_MODE; then
    : > "$ENDPOINTS"
    : > "$CLEAN"
  else
    log "collecting endpoints"

    gau "$target" 2>/dev/null \
      | normalize > "$ENDPOINTS"

    log "reducing noise"

    cat "$ENDPOINTS" \
      | filter_noise \
      | awk 'length($0) < 180' \
      | sort -u > "$CLEAN"
  fi

  log "classifying"

  classify_urls "$CLEAN" "$CLASSIFIED"

  if $ENTROPY_MODE; then
    log "entropy scanning auth + platform"

    cat \
      "$CLASSIFIED/auth.txt" \
      "$CLASSIFIED/platform.txt" \
      2>/dev/null \
      | sort -u \
      > "$FLAGS/entropy-input.txt"

    entropy_scan \
      "$FLAGS/entropy-input.txt" \
      "$FLAGS/entropy-candidates.txt"
  else
    : > "$FLAGS/entropy-candidates.txt"
  fi

  jq -n \
    --arg target "$target" \
    --arg run_id "$RUN_ID" \
    --arg timestamp "$(date -Iseconds)" \
    --arg subfinder "$(tool_version subfinder -version)" \
    --arg httpx "$(tool_version "$HTTPX_BIN" -version)" \
    --arg gau "$(tool_version gau --version)" \
    --slurpfile clean <(jq -Rsc 'split("\n") | map(select(length > 0))' "$CLEAN") \
    --slurpfile auth <(jq -Rsc 'split("\n") | map(select(length > 0))' "$CLASSIFIED/auth.txt") \
    --slurpfile platform <(jq -Rsc 'split("\n") | map(select(length > 0))' "$CLASSIFIED/platform.txt") \
    --slurpfile features <(jq -Rsc 'split("\n") | map(select(length > 0))' "$CLASSIFIED/features.txt") \
'{
  target: $target,
  run_id: $run_id,
  timestamp: $timestamp,
  tools: {
    subfinder: $subfinder,
    httpx: $httpx,
    gau: $gau
  },
  counts: {
    cleaned: ($clean[0] | length),
    auth: ($auth[0] | length),
    platform: ($platform[0] | length),
    features: ($features[0] | length)
  }
}' > "$REPORT"

  log "complete"

  find "$OUTPATH" -maxdepth 3 -type f | sort
}

if [[ -n "$SCOPE_FILE" ]]; then
  [[ -f "$SCOPE_FILE" ]] || die "scope file not found"

  while read -r target; do
    target="$(echo "$target" | sed 's/#.*//' | xargs)"
    [[ -z "$target" ]] && continue
    run_one "$target"
  done < "$SCOPE_FILE"
else
  run_one "$TARGET"
fi
