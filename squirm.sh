#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

TARGET=""
OUT_DIR="${OUT_DIR:-intel}"
PROXY=""
FAST_MODE=false
NO_ENDPOINTS=false
ENTROPY_MODE=false

usage() {
  cat << 'HELP'
Usage: squirm -t <target> [options]

Required:
  -t,--target      Target domain

Options:
  --out-dir PATH   Output dir (default: intel/)
  --proxy URL      HTTP proxy
  --fast           Skip endpoint collection
  --no-endpoints   Skip endpoint collection
  --entropy        Scan qualified endpoints for high-entropy tokens
  -h,--help        Show help
HELP
}

die() { echo "[!] $*" >&2; exit 1; }
log() { echo "[*] $*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--target) TARGET="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    --proxy) PROXY="${2:-}"; shift 2 ;;
    --fast) FAST_MODE=true; shift ;;
    --no-endpoints) NO_ENDPOINTS=true; shift ;;
    --entropy) ENTROPY_MODE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -z "$TARGET" ]] && die "-t required"
[[ "$TARGET" =~ ^[A-Za-z0-9.-]+$ ]] || die "invalid target format"

for cmd in subfinder httpx-toolkit gau jq curl grep sort sed; do
  need "$cmd"
done

OUTPATH="$OUT_DIR/$TARGET"
RAW="$OUTPATH/raw"
NORM="$OUTPATH/normalized"
FLAGS="$OUTPATH/flags"

mkdir -p "$RAW" "$NORM" "$FLAGS"

SUBS="$RAW/subdomains.txt"
ALIVE="$RAW/alive.txt"
ENDPOINTS="$RAW/endpoints.txt"
QUALIFIED="$NORM/qualified-endpoints.txt"
REPORT="$OUTPATH/report.json"

HTTPX_PROXY_FLAGS=()
CURL_PROXY_FLAGS=()

if [[ -n "$PROXY" ]]; then
  HTTPX_PROXY_FLAGS=(-proxy "$PROXY")
  CURL_PROXY_FLAGS=(-x "$PROXY")
fi

run_subdomains() {
  log "collecting subdomains"

  subfinder -d "$TARGET" -silent \
    | sed '/^[[:space:]]*$/d' \
    | sort -u > "$SUBS"
}

run_alive() {
  log "probing alive hosts"

  if [[ ! -s "$SUBS" ]]; then
    : > "$ALIVE"
    return
  fi

  httpx-toolkit -silent "${HTTPX_PROXY_FLAGS[@]}" < "$SUBS" \
    | sed '/^[[:space:]]*$/d' \
    | sort -u > "$ALIVE"
}

run_endpoints() {
  if $NO_ENDPOINTS || $FAST_MODE; then
    log "skipping endpoint collection"
    : > "$ENDPOINTS"
    : > "$QUALIFIED"
    return
  fi

  log "collecting endpoints"

  gau "$TARGET" \
    | grep -Ei '(\.js(\?|$)|\.json(\?|$)|/api/|graphql|oauth|authorize|callback|redirect|login|signin|signup|register|password-reset|forgot-password|forgot-email|reset|verify|token|session|auth|upload|webhook|proxy|fetch|download|export|import|bank|payment|wallet|transaction|account|settings|profile|move-money|transfer)' \
    | grep -Evi '(_next/static|_buildManifest|_ssgManifest|webpack|framework|polyfills|favicon|robots\.txt|sitemap|\.svg(\?|$)|\.png(\?|$)|\.jpg(\?|$)|\.jpeg(\?|$)|\.gif(\?|$)|\.css(\?|$)|\.woff2?(\?|$)|\.ico(\?|$)|\.map(\?|$))' \
    | sed '/^[[:space:]]*$/d' \
    | sort -u > "$ENDPOINTS" || true

  log "qualifying endpoints"

  grep -Ei '(api|graphql|oauth|authorize|callback|redirect|login|signin|signup|register|password-reset|forgot-password|forgot-email|reset|verify|token|session|auth|upload|webhook|proxy|fetch|download|export|import|bank|payment|wallet|transaction|account|settings|profile|move-money|transfer)' "$ENDPOINTS" \
    | grep -Evi '(_next/static|_buildManifest|_ssgManifest|webpack|framework|polyfills|favicon|robots\.txt|sitemap|\.svg(\?|$)|\.png(\?|$)|\.jpg(\?|$)|\.jpeg(\?|$)|\.gif(\?|$)|\.css(\?|$)|\.woff2?(\?|$)|\.ico(\?|$)|\.map(\?|$))' \
    | sort -u > "$QUALIFIED" || true
}

write_report() {
  log "writing report"

  jq -n \
    --arg target "$TARGET" \
    --arg ts "$(date -Iseconds)" \
    --slurpfile subs <(jq -Rsc 'split("\n") | map(select(length > 0))' "$SUBS") \
    --slurpfile alive <(jq -Rsc 'split("\n") | map(select(length > 0))' "$ALIVE") \
    --slurpfile endpoints <(jq -Rsc 'split("\n") | map(select(length > 0))' "$ENDPOINTS") \
    --slurpfile qualified <(jq -Rsc 'split("\n") | map(select(length > 0))' "$QUALIFIED") \
    '{
      target: $target,
      timestamp: $ts,
      counts: {
        subdomains: ($subs[0] | length),
        alive: ($alive[0] | length),
        endpoints: ($endpoints[0] | length),
        qualified_endpoints: ($qualified[0] | length)
      },
      recon: {
        subdomains: $subs[0],
        alive: $alive[0],
        endpoints: $endpoints[0],
        qualified_endpoints: $qualified[0]
      }
    }' > "$REPORT"
}

run_entropy() {
  if ! $ENTROPY_MODE; then
    return
  fi

  if [[ ! -s "$QUALIFIED" ]]; then
    log "entropy skipped: no qualified endpoints"
    return
  fi

  log "entropy scan on qualified endpoints only"

  ENTROPY_OUT="$FLAGS/entropy-candidates.txt"
  : > "$ENTROPY_OUT"

  while read -r url; do
    [[ -z "$url" ]] && continue

    curl -sS -k -L -m 10 "${CURL_PROXY_FLAGS[@]}" "$url" 2>/dev/null \
      | grep -oE '[A-Za-z0-9_-]{25,}' \
      | sort -u \
      | while read -r token; do
          if [[ "$token" =~ [A-Z] && "$token" =~ [a-z] && "$token" =~ [0-9] ]]; then
            printf '%s::%s\n' "$url" "$token" >> "$ENTROPY_OUT"
          fi
        done || true
  done < "$QUALIFIED"
}

log "target: $TARGET"
log "output: $OUTPATH"

run_subdomains
run_alive
run_endpoints
write_report
run_entropy

log "complete"
find "$OUTPATH" -maxdepth 3 -type f -print
