#!/bin/bash
# SQUIRM v2 - Clean Recon (Fixed)

set -euo pipefail

TARGET=""
OUT_DIR="${OUT_DIR:-intel}"
PROXY=""
FAST_MODE=false
NO_ENDPOINTS=false
ENTROPY_MODE=false

# Parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    -t|--target) TARGET="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --proxy) PROXY="$2"; shift 2 ;;
    --fast) FAST_MODE=true; shift ;;
    --no-endpoints) NO_ENDPOINTS=true; shift ;;
    --entropy) ENTROPY_MODE=true; shift ;;
    -h|--help)
      cat << 'EOF'
Usage: squirm -t <target> [options]
  -t,--target      Target domain
  --out-dir PATH   Output dir (default: intel/)
  --proxy URL      HTTP proxy
  --fast           Skip gau endpoints
  --no-endpoints   Skip endpoint collection
  --entropy        Flag high-entropy tokens
EOF
      exit 0
      ;;
    *) echo "Error: unknown $1" >&2; exit 1 ;;
  esac
done

[[ -z $TARGET ]] && { echo "Error: -t required" >&2; exit 1; }

# Setup
OUTPATH="$OUT_DIR/$TARGET"
mkdir -p "$OUTPATH"
echo "[+] squirm $TARGET → $OUTPATH"

# Proxy flags
PROXY_FLAGS=()
[[ -n $PROXY ]] && PROXY_FLAGS=(-proxy "$PROXY")

# Dep checks
for cmd in subfinder httpx-toolkit gau jq; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Error: $cmd missing" >&2; exit 1; }
done

# 1. Subdomains
echo "[*] Subdomains..."
subfinder -d "$TARGET" -silent -o "$OUTPATH/subs.txt"

# 2. Alive hosts  
echo "[*] HTTP probe..."
cat "$OUTPATH/subs.txt" | httpx-toolkit -silent -o "$OUTPATH/alive.txt" "${PROXY_FLAGS[@]}"

# 3. Endpoints (if enabled)
if ! $NO_ENDPOINTS && ! $FAST_MODE; then
  echo "[*] Endpoints..."
  gau "$TARGET" "${PROXY_FLAGS[@]}" | grep -E '\\.(js|json|api|php|jsp|asp)' | sort -u > "$OUTPATH/endpoints.txt"
elif $FAST_MODE; then
  echo "[!] --fast: skipping endpoints"
fi

# 4. JSON report
echo "[*] Report..."
jq -n \\
  --arg t "$TARGET" \\
  --arg ts "$(date -Iseconds)" \\
  --arg subs "$(cat "$OUTPATH/subs.txt")" \\
  --arg alive "$(cat "$OUTPATH/alive.txt")" \\
  --arg endpoints "$(cat "$OUTPATH/endpoints.txt" 2>/dev/null || echo '')" \\
  '{target:$t, subs:($subs|split("\\n")), live:($alive|split("\\n")), endpoints:($endpoints|split("\\n")), ts:$ts}' \\
  > "$OUTPATH/report.json"

# 5. Entropy (if enabled)
if $ENTROPY_MODE && [[ -s "$OUTPATH/endpoints.txt" ]]; then
  echo "[*] Entropy scan..."
  mkdir -p "$OUTPATH/flags"
  > "$OUTPATH/flags/entropy-candidates.txt"
  
  while read -r url; do
    [[ -z $url ]] && continue
    curl -s -k -m 10 "${PROXY_FLAGS[@]}" "$url" 2>/dev/null | \\
      grep -oE '[a-zA-Z0-9]{20,}' | sort -u | \\
      while read tok; do
        [[ ${#tok} -ge 25 && $tok =~ [A-Z] && $tok =~ [0-9] ]] && \\
          echo "$url::$tok" >> "$OUTPATH/flags/entropy-candidates.txt"
      done
  done < <(grep '\\.' "$OUTPATH/endpoints.txt")
fi

echo "[+] Done: $OUTPATH/"
ls -la "$OUTPATH/"
