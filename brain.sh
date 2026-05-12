#!/bin/bash

set -euo pipefail

TARGET="${1:-}"
BASE_DIR="${2:-intel}"
INPUT="$BASE_DIR/$TARGET/endpoints.txt"
OUTPUT="$BASE_DIR/$TARGET/brain-output.txt"
WHITELIST="$BASE_DIR/$TARGET/whitelist.txt"
BLACKLIST="$BASE_DIR/$TARGET/blacklist.txt"
CONFIG="$BASE_DIR/$TARGET/classify.conf"
VERBOSE="${VERBOSE:-0}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <target> [base_dir]"
  echo "Optional environment variables:"
  echo "  VERBOSE=1  - Enable debug output"
  exit 1
fi

mkdir -p "$BASE_DIR/$TARGET"

debug_log() {
  if [[ $VERBOSE -eq 1 ]]; then
    echo -e "${BLUE}[DEBUG]${NC} $1" >&2
  fi
}

echo -e "${GREEN}[+] Squirm Brain v3.0 - $TARGET${NC}"

# Load custom config if exists
declare -A KEYWORD_SCORES
KEYWORD_SCORES[marketing]=0
KEYWORD_SCORES[static]=5
KEYWORD_SCORES[ssrf]=90
KEYWORD_SCORES[file]=88
KEYWORD_SCORES[config]=92
KEYWORD_SCORES[financial]=85
KEYWORD_SCORES[admin]=80
KEYWORD_SCORES[auth]=75
KEYWORD_SCORES[idor]=70
KEYWORD_SCORES[debug]=60
KEYWORD_SCORES[generic]=25

if [[ -f "$CONFIG" ]]; then
  debug_log "Loading config from $CONFIG"
  source "$CONFIG"
fi

# Extract HTTP method from endpoint string
extract_method() {
  local ep="$1"
  # Format: "METHOD /path" or just "/path"
  if [[ "$ep" =~ ^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\ / ]]; then
    echo "${BASH_REMATCH[1]}"
  else
    echo "GET"  # Default assumption
  fi
}

# Extract path from endpoint string
extract_path() {
  local ep="$1"
  # Remove method if present
  ep=$(echo "$ep" | sed 's/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\ //')
  # Remove query parameters and fragments
  ep=$(echo "$ep" | cut -d'?' -f1 | cut -d'#' -f1)
  echo "$ep"
}

# Calculate path depth (nested level indicator)
calculate_depth() {
  local path="$1"
  echo "$path" | tr -cd '/' | wc -c
}

# Check if endpoint is in whitelist
is_whitelisted() {
  local ep="$1"
  if [[ -f "$WHITELIST" ]]; then
    if grep -qF "$ep" "$WHITELIST" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

# Check if endpoint is in blacklist
is_blacklisted() {
  local ep="$1"
  if [[ -f "$BLACKLIST" ]]; then
    if grep -qF "$ep" "$BLACKLIST" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

classify() {
  local ep="$1"
  local method="${2:-GET}"
  local original_ep="$ep"

  # Validate input
  if [[ ${#ep} -gt 2000 ]]; then
    debug_log "URL too long (>2000 chars), skipping: ${ep:0:50}..."
    echo "error|0|url-too-long"
    return
  fi

  # Check whitelist first
  if is_whitelisted "$ep"; then
    debug_log "Endpoint whitelisted: $ep"
    echo "whitelisted|0|known-safe"
    return
  fi

  # Check blacklist
  if is_blacklisted "$ep"; then
    debug_log "Endpoint blacklisted: $ep"
    echo "blacklisted|95|known-dangerous"
    return
  fi

  # Normalize
  ep=$(echo "$ep" | tr '[:upper:]' '[:lower:]')

  local path=$(extract_path "$ep")
  local depth=$(calculate_depth "$path")

  debug_log "Processing: $path (method: $method, depth: $depth)"

  ## 1. HARD NOISE
  case "$ep" in
    *pr-news*|*blog*|*press*|*news*|*marketing*|*campaign*|*newsletter*|*branding*)
      debug_log "Classified as: marketing noise"
      echo "noise|0|marketing-content"
      return
      ;;
  esac

  ## 2. STATIC ASSETS
  case "$ep" in
    *.png|*.jpg|*.jpeg|*.gif|*.css|*.js|*.svg|*.ico|*.woff|*.ttf|*.woff2|*.eot|*.webp|*.mp4|*.webm|*.pdf)
      debug_log "Classified as: static asset"
      echo "static|5|asset-file"
      return
      ;;
  esac

  ## 3. CRITICAL SURFACES (highest priority)

  # SSRF / callbacks / redirects
  case "$ep" in
    *url=*|*uri=*|*redirect=*|*callback=*|*returnurl=*|*return_url=*|*target=*|*dest=*)
      debug_log "Classified as: SSRF/callback"
      echo "ssrf|90|user-controlled-callback"
      return
      ;;
  esac

  # File interaction
  case "$ep" in
    *file=*|*path=*|*download=*|*upload=*|*filename=*|*filepath=*|*/upload*|*/download*)
      # Avoid false positives
      if [[ ! "$ep" =~ .*downloadable_content.* ]]; then
        debug_log "Classified as: file interaction"
        echo "file|88|file-interaction"
        return
      fi
      ;;
  esac

  # Actuator / internal config / Spring Boot specific
  case "$ep" in
    *actuator*|*/env*|*/heapdump*|*/jolokia*|*/metrics*|*/health*|*/prometheus*|*/.env*|*/config*)
      # Exclude false positives
      if [[ ! "$ep" =~ .*environment_config_info.* ]]; then
        debug_log "Classified as: internal config exposure"
        echo "config|92|internal-config-exposure"
        return
      fi
      ;;
  esac

  # Financial / payment flow
  case "$ep" in
    *payment*|*billing*|*checkout*|*cart*|*transaction*|*invoice*|*refund*|*subscription*|*/pay*)
      debug_log "Classified as: financial"
      echo "financial|85|money-flow"
      return
      ;;
  esac

  # Admin / internal / management
  case "$ep" in
    */admin*|*/internal*|*/manage*|*/dashboard*|*/control*|*/panel*)
      # Exclude false positives like /contact or /admin-resources/public
      if [[ ! "$ep" =~ .*public.* ]] && [[ ! "$ep" =~ .*contact.* ]]; then
        debug_log "Classified as: admin/privileged"
        echo "admin|80|privileged-surface"
        return
      fi
      ;;
  esac

  # Authentication / authorization
  case "$ep" in
    *oauth*|*openid*|*/token*|*/auth*|*/login*|*/signin*|*/register*|*/sso*|*/saml*)
      debug_log "Classified as: authentication"
      echo "auth|75|authentication"
      return
      ;;
  esac

  # IDOR patterns (object-level access)
  case "$ep" in
    */user/*|*/account/*|*/profile/*|*/order/*|*/invoice/*|*/document/*|*/report/*|*/team/*|*/group/*|*/org/*)
      debug_log "Classified as: IDOR/object-access"
      echo "idor|70|object-access"
      return
      ;;
  esac

  # Debug/dev/staging (with better context)
  case "$ep" in
    */debug*|*/test/*|*_test_*|*/dev/*|*/staging*|*/qa/*|*test-data*|*test-fixture*)
      # More specific than just "test" in the name
      if [[ "$path" =~ /test/ ]] || [[ "$path" =~ _test_ ]] || [[ "$path" =~ /dev/ ]]; then
        debug_log "Classified as: non-production"
        echo "debug|60|non-prod-surface"
        return
      fi
      ;;
  esac

  # SQL/NoSQL injection patterns
  case "$ep" in
    *query=*|*search=*|*filter=*|*where=*|*sql=*|*db=*|*mongo=*|*sql_*)
      debug_log "Classified as: injection-prone"
      echo "injection|82|injection-vector"
      return
      ;;
  esac

  # API versioning / internal APIs
  case "$ep" in
    */api/v[0-9]*/*|*/internal*|*/private*)
      # Version-specific endpoints worth investigating
      if [[ "$path" =~ /api/v[0-9]+ ]]; then
        debug_log "Classified as: versioned-api (depth bonus)"
        local score=$((65 + (depth * 2)))
        [[ $score -gt 80 ]] && score=80
        echo "$score|versioned-api|version-specific-endpoint"
        return
      fi
      ;;
  esac

  ## 4. GENERIC + DEPTH-BASED SCORING
  # Deeper paths are often more specific and riskier
  local generic_score=25
  if [[ $depth -gt 4 ]]; then
    generic_score=$((generic_score + 15))
  elif [[ $depth -gt 3 ]]; then
    generic_score=$((generic_score + 8))
  fi

  # POST/PUT/DELETE are higher risk than GET
  case "$method" in
    POST|PUT|DELETE|PATCH)
      generic_score=$((generic_score + 10))
      ;;
  esac

  debug_log "Classified as: generic (score: $generic_score, method: $method)"
  echo "$generic_score|generic|unknown-endpoint"
}

# Validate input file
if [[ ! -f "$INPUT" ]]; then
  echo -e "${RED}[!] Missing input: $INPUT${NC}"
  exit 1
fi

# Initialize output
echo "score|category|method|endpoint|reason" > "$OUTPUT"

# Process endpoints
line_count=0
skipped_count=0
processed_count=0

while IFS= read -r line; do
  ((line_count++))
  
  # Skip empty lines and comments
  [[ -z "$line" || "$line" =~ ^[[:space:]]*$ ]] && continue
  [[ "$line" =~ ^# ]] && continue
  
  # Extract method and endpoint
  method=$(extract_method "$line")
  ep=$(extract_path "$line")
  
  # Validate endpoint
  if [[ ${#ep} -lt 2 ]]; then
    ((skipped_count++))
    debug_log "Skipped invalid endpoint: $line"
    continue
  fi
  
  result=$(classify "$ep" "$method")
  category=$(echo "$result" | cut -d'|' -f1)
  score=$(echo "$result" | cut -d'|' -f2)
  reason=$(echo "$result" | cut -d'|' -f3)
  
  echo "$score|$category|$method|$ep|$reason"
  ((processed_count++))
  
done < <(sort -u "$INPUT") | sort -t'|' -nr >> "$OUTPUT"

echo -e "${GREEN}[+] Output written to $OUTPUT${NC}"
echo -e "${GREEN}[+] Processed: $processed_count, Skipped: $skipped_count, Total lines: $line_count${NC}"
echo

# Show statistics
echo -e "${YELLOW}[📊 Classification Summary]${NC}"
awk -F'|' '{category[$2]++; score[$2]+=$1} END {for (cat in category) printf "%s: %d endpoints (avg score: %.1f)\n", cat, category[cat], score[cat]/category[cat]}' "$OUTPUT" | sort

echo
echo -e "${RED}[🔥 Top High-Value Targets (Score >= 80)]${NC}"
awk -F'|' 'NR>1 && $1 >= 80 {printf "%3d | %-12s | %-6s | %-50s | %s\n", $1, $2, $3, $4, $5}' "$OUTPUT" | head -n 15

echo
echo -e "${YELLOW}[⚠️  Medium-Risk Targets (Score 60-79)]${NC}"
awk -F'|' 'NR>1 && $1 >= 60 && $1 < 80 {printf "%3d | %-12s | %-6s | %-50s | %s\n", $1, $2, $3, $4, $5}' "$OUTPUT" | head -n 10

# Show config info
if [[ -f "$WHITELIST" ]]; then
  whitelist_count=$(wc -l < "$WHITELIST")
  echo -e "${GREEN}[ℹ️  Whitelist: $whitelist_count entries]${NC}"
fi

if [[ -f "$BLACKLIST" ]]; then
  blacklist_count=$(wc -l < "$BLACKLIST")
  echo -e "${RED}[ℹ️  Blacklist: $blacklist_count entries]${NC}"
fi
