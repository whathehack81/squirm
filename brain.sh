#!/bin/bash

set -euo pipefail

TARGET="${1:-}"
BASE_DIR="${2:-intel}"
INPUT="$BASE_DIR/$TARGET/endpoints.txt"
OUTPUT="$BASE_DIR/$TARGET/brain-output.txt"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target>"
  exit 1
fi

mkdir -p "$BASE_DIR/$TARGET"

echo "[+] Squirm Brain v2.0 - $TARGET"

classify() {
  local ep="$1"

  # Normalize
  ep=$(echo "$ep" | tr '[:upper:]' '[:lower:]')

  ## 1. HARD NOISE
  case "$ep" in
    *pr-news*|*blog*|*press*|*news*|*marketing*|*campaign*)
      echo "noise|0|marketing-content"; return ;;
  esac

  ## 2. STATIC
  case "$ep" in
    *.png|*.jpg|*.jpeg|*.gif|*.css|*.js|*.svg|*.ico|*.woff|*.ttf)
      echo "static|5|asset-file"; return ;;
  esac

  ## 3. CRITICAL SURFACES (highest first)

  # SSRF / callbacks
  case "$ep" in
    *url=*|*uri=*|*redirect=*|*callback=*|*returnurl=*)
      echo "ssrf|90|user-controlled-callback"; return ;;
  esac

  # File interaction
  case "$ep" in
    *file=*|*path=*|*download=*|*upload=*)
      echo "file|88|file-interaction"; return ;;
  esac

  # Actuator / internal config
  case "$ep" in
    *actuator*|*env*|*heapdump*|*jolokia*)
      echo "config|92|internal-config-exposure"; return ;;
  esac

  # Financial
  case "$ep" in
    *payment*|*billing*|*checkout*|*cart*)
      echo "financial|85|money-flow"; return ;;
  esac

  # Admin / internal
  case "$ep" in
    *admin*|*internal*|*manage*)
      echo "admin|80|privileged-surface"; return ;;
  esac

  # Auth
  case "$ep" in
    *oauth*|*openid*|*token*|*auth*)
      echo "auth|75|authentication"; return ;;
  esac

  # IDOR patterns
  case "$ep" in
    */user/*|*/account/*|*/profile/*|*/order/*|*/invoice/*)
      echo "idor|70|object-access"; return ;;
  esac

  # Debug/dev
  case "$ep" in
    *debug*|*test*|*dev*|*staging*)
      echo "debug|60|non-prod-surface"; return ;;
  esac

  ## 4. DEFAULT
  echo "generic|25|unknown"
}

# Safety checks
if [[ ! -f "$INPUT" ]]; then
  echo "[!] Missing input: $INPUT"
  exit 1
fi

# Header
echo "score|category|endpoint|reason" > "$OUTPUT"

# Process
sort -u "$INPUT" | while IFS= read -r ep; do
  [[ -z "$ep" ]] && continue

  result=$(classify "$ep")
  category=$(echo "$result" | cut -d'|' -f1)
  score=$(echo "$result" | cut -d'|' -f2)
  reason=$(echo "$result" | cut -d'|' -f3)

  echo "$score|$category|$ep|$reason"
done | sort -t'|' -nr >> "$OUTPUT"

echo "[+] Output written to $OUTPUT"

# Show top targets
echo
echo "[🔥 Top High-Value Targets]"
awk -F'|' '$1 >= 80 {print}' "$OUTPUT" | head -n 10
