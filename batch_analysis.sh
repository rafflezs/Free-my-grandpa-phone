#!/bin/bash
# =============================================================================
# APK Batch Analysis Script
# =============================================================================
#
# DESCRIPTION:
#   Analyzes Android packages installed on a connected device via ADB.
#   Detects dangerous permissions and potential credential/URL leaks.
#
# USAGE:
#   ./batch_analysis.sh --stream           # Streaming mode (recommended)
#   ./batch_analysis.sh --stream-all       # Include system packages
#   ./batch_analysis.sh --pull ./dir       # Download all APKs first
#   ./batch_analysis.sh ./existing_dir     # Analyze local APKs
#
# ENVIRONMENT VARIABLES:
#   SKIP_SECRETS=true      Skip apkleaks analysis (faster)
#   SECRETS_TIMEOUT=120    Timeout in seconds for apkleaks (default: 120)
#
# OUTPUT:
#   ./analysis_results/SUMMARY_REPORT.md   Consolidated report
#   ./analysis_results/<pkg>_permissions.txt   Dangerous permissions found
#   ./analysis_results/<pkg>_secrets.txt       Leaked credentials/URLs
#
# DEPENDENCIES:
#   - adb (Android Debug Bridge)
#   - androguard (pip install androguard)
#   - apkleaks (pip install apkleaks)
#
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================
# Default paths and runtime settings. RESULTS_DIR stores all output files.
# LOG_FILE captures timestamped execution log for debugging.

APKS_DIR="${1:-}"
RESULTS_DIR="./analysis_results"
PERMISSIONS_DIR="$RESULTS_DIR/permissions"
SECRETS_DIR="$RESULTS_DIR/secrets"
LOG_FILE="$RESULTS_DIR/analysis_$(date +%Y%m%d_%H%M%S).log"
RECOMMENDED_FILE="$RESULTS_DIR/recommended_removal.txt"

# -----------------------------------------------------------------------------
# Parallel processing configuration
# Set PARALLEL_JOBS to number of concurrent analyses (0 = auto-detect)
# Parallelism only works in --pull mode (local files)
# Streaming mode is inherently sequential due to ADB limitations
# -----------------------------------------------------------------------------
PARALLEL_JOBS="${PARALLEL_JOBS:-0}"  # 0 = auto (nproc/2), or set manually
ENABLE_PARALLEL="${ENABLE_PARALLEL:-false}"  # Set to 'true' to enable

# -----------------------------------------------------------------------------
# Cleanup configuration
# Controls whether to delete downloaded APKs after analysis (saves disk space)
# Options: ask (interactive), yes (auto-delete), no (keep files)
# -----------------------------------------------------------------------------
CLEANUP_AFTER_ANALYSIS="${CLEANUP_AFTER_ANALYSIS:-ask}"

# -----------------------------------------------------------------------------
# Terminal color codes for formatted output
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color - reset

# =============================================================================
# SKIP LISTS
# =============================================================================
# Packages matching these patterns are skipped during analysis to save time
# and reduce false positives. These are known-safe system components.
#
# Matching is partial: "com.android.systemui" matches any package containing
# that string (e.g., com.android.systemui.plugins).

# Get packages to skip from file ignored-packages.txt
SKIP_PACKAGES=()
while IFS= read -r line || [ -n "$line" ]; do
  # Ignore comments and empty lines
  [[ "$line" =~ ^#.*$ ]] && continue
  [[ -z "$line" ]] && continue
  SKIP_PACKAGES+=("$line")
done < "ignored-packages.txt"

# =============================================================================
# DANGEROUS PERMISSIONS
# =============================================================================
# Permissions that may indicate privacy or security risks. Finding these does
# not necessarily mean the app is malicious - legitimate apps may require them.
# The script flags them for manual review.

DANGEROUS_PERMISSIONS=(
  # -------------------------------------------------------------------------
  # Critical: Can enable complete device control or surveillance
  # -------------------------------------------------------------------------
  "BIND_ACCESSIBILITY_SERVICE"    # Can read/control all screen content
  "BIND_DEVICE_ADMIN"             # Device administrator privileges
  "BIND_VPN_SERVICE"              # Can intercept all network traffic
  
  # -------------------------------------------------------------------------
  # High: Access to communications and personal data
  # -------------------------------------------------------------------------
  "READ_SMS"
  "SEND_SMS"
  "RECEIVE_SMS"
  "READ_CALL_LOG"
  "WRITE_CALL_LOG"
  "PROCESS_OUTGOING_CALLS"
  "READ_CONTACTS"
  "WRITE_CONTACTS"
  "GET_ACCOUNTS"
  "MANAGE_ACCOUNTS"
  
  # -------------------------------------------------------------------------
  # Medium: Sensor and storage access
  # -------------------------------------------------------------------------
  "RECORD_AUDIO"
  "CAMERA"
  "ACCESS_FINE_LOCATION"
  "ACCESS_BACKGROUND_LOCATION"
  "READ_EXTERNAL_STORAGE"
  "WRITE_EXTERNAL_STORAGE"
  "READ_PHONE_STATE"
  "READ_PHONE_NUMBERS"
  "ANSWER_PHONE_CALLS"
  "CALL_PHONE"
  
  # -------------------------------------------------------------------------
  # System: Can modify device behavior or install software
  # -------------------------------------------------------------------------
  "BIND_NOTIFICATION_LISTENER_SERVICE"
  "REQUEST_INSTALL_PACKAGES"
  "INSTALL_PACKAGES"
  "DELETE_PACKAGES"
  "WRITE_SETTINGS"
  "WRITE_SECURE_SETTINGS"
  "QUERY_ALL_PACKAGES"
  "REQUEST_DELETE_PACKAGES"
  "READ_LOGS"
  "DUMP"
)

# =============================================================================
# SUSPICIOUS PATTERNS
# =============================================================================
# Regex patterns to search for in apkleaks output. These indicate potentially
# hardcoded credentials, API keys, or suspicious URLs that should be reviewed.

SUSPICIOUS_PATTERNS=(
  # API credentials
  "api[_-]?key"
  "api[_-]?secret"
  "secret[_-]?key"
  "private[_-]?key"
  "access[_-]?token"
  "auth[_-]?token"
  
  # Authentication
  "password"
  "passwd"
  "bearer"
  "credential"
  
  # Cloud services (may indicate data exfiltration targets)
  "firebase"
  "amazonaws"
  "cloudinary"
  "sendgrid"
  "twilio"
  "stripe"
  "paypal"
  
  # Suspicious URLs
  "\.onion"           # Tor hidden services
  "pastebin"          # Often used for data dumps
  "ngrok"             # Tunneling service
  "webhook"           # Data forwarding endpoints
)

# =============================================================================
# FUNCTIONS
# =============================================================================

# -----------------------------------------------------------------------------
# Logging functions
# Output to both terminal and log file with timestamps and color coding
# -----------------------------------------------------------------------------
log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
  echo -e "$msg" | tee -a "$LOG_FILE"
}

log_info() { log "${BLUE}[INFO]${NC} $1"; }
log_warn() { log "${YELLOW}[WARN]${NC} $1"; }
log_error() { log "${RED}[ERROR]${NC} $1"; }
log_success() { log "${GREEN}[OK]${NC} $1"; }

# -----------------------------------------------------------------------------
# should_skip_package
# Checks if a package name matches any entry in SKIP_PACKAGES array
# Args: $1 - package name or filename to check
# Returns: 0 if should skip, 1 if should analyze
# -----------------------------------------------------------------------------
should_skip_package() {
  local filename="$1"
  for skip in "${SKIP_PACKAGES[@]}"; do
    if [[ "$filename" == *"$skip"* ]]; then
      return 0
    fi
  done
  return 1
}

# -----------------------------------------------------------------------------
# check_dependencies
# Verifies required tools are installed before starting analysis
# Exits with error if androguard or apkleaks are missing
# -----------------------------------------------------------------------------
check_dependencies() {
  local missing=()
  
  if ! command -v androguard &> /dev/null; then
    missing+=("androguard")
  fi
  
  if ! command -v apkleaks &> /dev/null; then
    missing+=("apkleaks")
  fi
  
  if [ ${#missing[@]} -gt 0 ]; then
    log_error "Missing dependencies: ${missing[*]}"
    echo "Install with:"
    echo "  pip install androguard apkleaks"
    exit 1
  fi
}

# -----------------------------------------------------------------------------
# check_adb_connection
# Verifies ADB is installed and a device is connected
# Returns: 0 if connected, 1 if not
# -----------------------------------------------------------------------------
check_adb_connection() {
  if ! command -v adb &> /dev/null; then
    log_error "ADB not found. Please install Android SDK Platform Tools."
    return 1
  fi
  
  if ! adb devices | grep -q "device$"; then
    log_error "No Android device connected via ADB."
    return 1
  fi
  return 0
}

# -----------------------------------------------------------------------------
# get_device_packages
# Retrieves list of installed packages from connected device
# Args: $1 - filter flag (-3 for third-party, -s for system, empty for all)
# Returns: newline-separated list of package names
# -----------------------------------------------------------------------------
get_device_packages() {
  local pkg_filter="${1:--3}"
  adb shell pm list packages $pkg_filter 2>/dev/null | sed 's/package://' | tr -d '\r'
}

# -----------------------------------------------------------------------------
# pull_apks_from_device
# Downloads all APKs matching filter to local directory
# WARNING: Can consume several GB of disk space
# Args: $1 - output directory path
# -----------------------------------------------------------------------------
pull_apks_from_device() {
  local output_dir="$1"
  
  check_adb_connection || return 1
  
  log_info "Fetching package list from device..."
  mkdir -p "$output_dir"
  
  # Get list of third-party packages (user-installed)
  local packages
  packages=$(get_device_packages -3)
  
  local total=$(echo "$packages" | wc -l)
  local count=0
  
  log_info "Found $total third-party packages"
  
  for pkg in $packages; do
    count=$((count + 1))
    
    # Skip known safe packages
    if should_skip_package "$pkg"; then
      log_info "[$count/$total] Skipping known package: $pkg"
      continue
    fi
    
    log_info "[$count/$total] Pulling: $pkg"
    
    # Get APK path on device
    local apk_path
    apk_path=$(adb shell pm path "$pkg" 2>/dev/null | head -1 | sed 's/package://' | tr -d '\r')
    
    if [ -n "$apk_path" ]; then
      adb pull "$apk_path" "$output_dir/${pkg}.apk" 2>/dev/null || \
        log_warn "Failed to pull $pkg"
    fi
  done
  
  log_success "APK extraction complete"
}

# =============================================================================
# CLEANUP FUNCTIONS
# =============================================================================
# Functions to manage disk space by cleaning up downloaded APKs after analysis

# -----------------------------------------------------------------------------
# prompt_cleanup_apks
# Asks user if they want to delete downloaded APKs after analysis
# Args: $1 - Directory containing APKs
# Returns: 0 on success
# -----------------------------------------------------------------------------
prompt_cleanup_apks() {
  local apk_dir="$1"
  
  # Skip if directory doesn't exist or is empty
  if [ ! -d "$apk_dir" ] || [ -z "$(ls -A "$apk_dir" 2>/dev/null)" ]; then
    return 0
  fi
  
  # Calculate disk usage
  local disk_usage
  disk_usage=$(du -sh "$apk_dir" 2>/dev/null | cut -f1)
  local file_count
  file_count=$(find "$apk_dir" -name "*.apk" 2>/dev/null | wc -l)
  
  echo ""
  echo "=============================================="
  echo "         CLEANUP - DOWNLOADED APKs"
  echo "=============================================="
  echo ""
  echo "Directory: $apk_dir"
  echo "Files:     $file_count APKs"
  echo "Size:      $disk_usage"
  echo ""
  
  case "${CLEANUP_AFTER_ANALYSIS:-ask}" in
    yes|true|1)
      log_info "Auto-cleanup enabled. Removing APKs..."
      rm -rf "$apk_dir"
      log_success "Cleanup complete. Freed $disk_usage"
      ;;
    no|false|0)
      log_info "Cleanup disabled. APKs preserved at: $apk_dir"
      ;;
    *)
      # Interactive prompt
      echo "Options:"
      echo "  [y] Delete all APKs (free $disk_usage)"
      echo "  [n] Keep APKs for future analysis"
      echo "  [s] Keep only suspicious APKs"
      echo ""
      read -rp "Delete downloaded APKs? [y/n/s]: " choice
      
      case "$choice" in
        y|Y)
          log_info "Removing all APKs..."
          rm -rf "$apk_dir"
          log_success "Cleanup complete. Freed $disk_usage"
          ;;
        s|S)
          cleanup_keep_suspicious "$apk_dir"
          ;;
        *)
          log_info "APKs preserved at: $apk_dir"
          ;;
      esac
      ;;
  esac
}

# -----------------------------------------------------------------------------
# cleanup_keep_suspicious
# Removes APKs except those flagged as suspicious (have analysis results)
# Args: $1 - Directory containing APKs
# -----------------------------------------------------------------------------
cleanup_keep_suspicious() {
  local apk_dir="$1"
  local kept=0
  local removed=0
  local freed_bytes=0
  
  log_info "Keeping only suspicious APKs..."
  
  for apk in "$apk_dir"/*.apk; do
    [ -f "$apk" ] || continue
    
    local pkg_name
    pkg_name=$(basename "$apk" .apk)
    local apk_size
    apk_size=$(stat -c%s "$apk" 2>/dev/null || echo 0)
    
    # Check if this package has analysis results (means it was suspicious)
    if [ -f "$PERMISSIONS_DIR/${pkg_name}_permissions.txt" ] || \
       [ -f "$SECRETS_DIR/${pkg_name}_secrets.txt" ] || \
       [ -f "$SECRETS_DIR/${pkg_name}_secrets.json" ]; then
      kept=$((kept + 1))
    else
      rm -f "$apk"
      removed=$((removed + 1))
      freed_bytes=$((freed_bytes + apk_size))
    fi
  done
  
  local freed_mb=$((freed_bytes / 1024 / 1024))
  log_success "Kept $kept suspicious APKs, removed $removed clean APKs (freed ${freed_mb}MB)"
}

# =============================================================================
# STREAMING MODE
# =============================================================================
# Analyzes one APK at a time: download -> analyze -> delete
# This approach minimizes disk usage and avoids I/O bottlenecks
# The APK is deleted from the PC after analysis, NOT from the phone

stream_analyze_device() {
  local pkg_filter="${1:--3}"
  local temp_dir="/tmp/apk_analysis_$$"  # $$ = process ID for uniqueness
  
  check_adb_connection || return 1
  
  mkdir -p "$temp_dir"
  trap "rm -rf '$temp_dir'" EXIT  # Ensure cleanup on script exit
  
  log_info "Fetching package list from device..."
  
  local packages
  packages=$(get_device_packages "$pkg_filter")
  
  local total=$(echo "$packages" | grep -c . || echo 0)
  local count=0
  local analyzed=0
  local suspicious_count=0
  local skipped_count=0
  declare -a suspicious_apps=()
  
  log_info "Found $total packages to analyze"
  log_info "Mode: STREAMING (one APK at a time, minimal disk usage)"
  echo ""
  
  for pkg in $packages; do
    [ -z "$pkg" ] && continue
    count=$((count + 1))
    
    # Skip known safe packages
    if should_skip_package "$pkg"; then
      log_info "[$count/$total] Skipping: $pkg"
      skipped_count=$((skipped_count + 1))
      continue
    fi
    
    echo ""
    log_info "[$count/$total] Processing: $pkg"
    
    # Get APK path on device
    local apk_path
    apk_path=$(adb shell pm path "$pkg" 2>/dev/null | head -1 | sed 's/package://' | tr -d '\r')
    
    if [ -z "$apk_path" ]; then
      log_warn "Could not find APK path for $pkg"
      continue
    fi
    
    # Get APK size before downloading
    local apk_size
    apk_size=$(adb shell stat -c%s "$apk_path" 2>/dev/null | tr -d '\r' || echo "unknown")
    if [ "$apk_size" != "unknown" ]; then
      apk_size_mb=$((apk_size / 1024 / 1024))
      echo "  [Size] ${apk_size_mb}MB"
    fi
    
    # Pull single APK
    local temp_apk="$temp_dir/${pkg}.apk"
    echo -n "  [Download] "
    if adb pull "$apk_path" "$temp_apk" > /dev/null 2>&1; then
      echo -e "${GREEN}[V]${NC}"
    else
      echo -e "${RED}✗ Failed${NC}"
      continue
    fi
    
    analyzed=$((analyzed + 1))
    
    # Analyze permissions
    echo -n "  [Permissions] "
    local perm_pattern
    perm_pattern=$(IFS='|'; echo "${DANGEROUS_PERMISSIONS[*]}")
    local found_perms
    found_perms=$(androguard axml "$temp_apk" 2>/dev/null | grep -oE "$perm_pattern" | sort -u || true)
    
    local is_suspicious=0
    local risk_level="LOW"
    
    if [ -n "$found_perms" ]; then
      echo -e "${RED}[X] DANGEROUS${NC}"
      echo "$found_perms" | sed 's/^/    → /'
      echo "$found_perms" > "$PERMISSIONS_DIR/${pkg}_permissions.txt"
      is_suspicious=1
      
      if echo "$found_perms" | grep -qE "BIND_ACCESSIBILITY|BIND_DEVICE_ADMIN"; then
        risk_level="CRITICAL"
      elif echo "$found_perms" | grep -qE "READ_SMS|SEND_SMS|INSTALL_PACKAGES"; then
        risk_level="HIGH"
      else
        risk_level="MEDIUM"
      fi
    else
      echo -e "${GREEN}[V] OK${NC}"
    fi
    
    # Analyze secrets (optional, slower) - with timeout to prevent hanging
    if [ "${SKIP_SECRETS:-false}" != "true" ]; then
      echo -n "  [Secrets] "
      local json_file="$SECRETS_DIR/${pkg}_secrets.json"
      local secrets_timeout="${SECRETS_TIMEOUT:-120}"  # Default 2 minutes
      timeout "$secrets_timeout" apkleaks -f "$temp_apk" -o "$json_file" > /dev/null 2>&1 || true
      
      if [ -f "$json_file" ]; then
        local secret_pattern
        secret_pattern=$(IFS='|'; echo "${SUSPICIOUS_PATTERNS[*]}")
        local suspicious_content
        suspicious_content=$(grep -iE "$secret_pattern" "$json_file" 2>/dev/null | head -5 || true)
        
        if [ -n "$suspicious_content" ]; then
          echo -e "${YELLOW}[X] FOUND${NC}"
          echo "$suspicious_content" | head -3 | sed 's/^/    → /'
          is_suspicious=1
        else
          echo -e "${GREEN}[V] OK${NC}"
          rm -f "$json_file"  # Remove empty results
        fi
      else
        echo -e "${GREEN}[V] OK${NC}"
      fi
    fi
    
    # Risk assessment and recommended removal tracking
    if [ $is_suspicious -eq 1 ]; then
      case $risk_level in
        "CRITICAL") 
          echo -e "  ${RED}[RISK] ★★★ CRITICAL - Consider removing${NC}"
          echo "$pkg # CRITICAL - $(echo $found_perms | tr '\n' ' ')" >> "$RECOMMENDED_FILE"
          ;;
        "HIGH")
          echo -e "  ${RED}[RISK] ★★☆ HIGH${NC}"
          echo "$pkg # HIGH - $(echo $found_perms | tr '\n' ' ')" >> "$RECOMMENDED_FILE"
          ;;
        "MEDIUM")
          echo -e "  ${YELLOW}[RISK] ★☆☆ MEDIUM${NC}"
          ;;
      esac
      suspicious_count=$((suspicious_count + 1))
      suspicious_apps+=("$pkg")
    fi
    
    # -------------------------------------------------------------------------
    # CLEANUP: Delete temporary APK from PC to free disk space
    # NOTE: This deletes the copy on the computer, NOT the app on the phone
    # -------------------------------------------------------------------------
    rm -f "$temp_apk"
    echo "  [Cleanup] Temporary APK deleted from PC"
  done
  
  # Export variables for report generation
  total_analyzed=$analyzed
  
  # Summary
  echo ""
  echo "=============================================="
  echo "               ANALYSIS COMPLETE"
  echo "=============================================="
  echo ""
  echo "  Total packages:    $total"
  echo "  Analyzed:          $analyzed"
  echo "  Skipped (safe):    $skipped_count"
  echo "  Suspicious:        $suspicious_count"
  echo "  Disk used:         ~0 MB (streaming mode)"
  echo ""
  
  if [ $suspicious_count -gt 0 ]; then
    echo -e "${RED}[X] Suspicious packages found:${NC}"
    for app in "${suspicious_apps[@]}"; do
      echo "    - $app"
    done
    echo ""
    echo "Commands to remove suspicious packages:"
    echo ""
    echo "# Disable (reversible):"
    for app in "${suspicious_apps[@]}"; do
      echo "adb shell pm disable-user --user 0 $app"
    done
    echo ""
    echo "# Uninstall for user (keeps data, reversible with factory reset):"
    for app in "${suspicious_apps[@]}"; do
      echo "adb shell pm uninstall -k --user 0 $app"
    done
  else
    echo -e "${GREEN}[V] No suspicious packages detected${NC}"
  fi
  
  echo ""
  echo "  Results: $RESULTS_DIR/"
  echo "  Recommended removals: $RECOMMENDED_FILE"
  
  # Generate report
  generate_report "${suspicious_apps[@]}"
  
  # Cleanup temp directory
  rm -rf "$temp_dir"
}

# =============================================================================
# PARALLEL ANALYSIS FUNCTIONS
# =============================================================================
# These functions enable parallel processing for --pull and local directory modes
# Parallelism is NOT available for streaming mode due to ADB limitations

# -----------------------------------------------------------------------------
# analyze_single_apk_parallel
# Analyze a single APK file (designed to be called in parallel)
# Args: $1 - APK file path
# Outputs results to files, returns risk level via exit code
# -----------------------------------------------------------------------------
analyze_single_apk_parallel() {
  local apk="$1"
  local filename
  filename=$(basename "$apk")
  local pkg_name="${filename%.apk}"
  
  # Skip if in skip list
  if should_skip_package "$filename"; then
    echo "SKIP:$pkg_name"
    return 0
  fi
  
  local is_suspicious=0
  local risk_level="LOW"
  local found_perms=""
  
  # Analyze permissions
  local perm_pattern
  perm_pattern=$(IFS='|'; echo "${DANGEROUS_PERMISSIONS[*]}")
  found_perms=$(androguard axml "$apk" 2>/dev/null | grep -oE "$perm_pattern" | sort -u || true)
  
  if [ -n "$found_perms" ]; then
    echo "$found_perms" > "$PERMISSIONS_DIR/${pkg_name}_permissions.txt"
    is_suspicious=1
    
    if echo "$found_perms" | grep -qE "BIND_ACCESSIBILITY|BIND_DEVICE_ADMIN"; then
      risk_level="CRITICAL"
    elif echo "$found_perms" | grep -qE "READ_SMS|SEND_SMS|INSTALL_PACKAGES"; then
      risk_level="HIGH"
    else
      risk_level="MEDIUM"
    fi
  fi
  
  # Analyze secrets if not skipped
  if [ "${SKIP_SECRETS:-false}" != "true" ]; then
    local json_file="$SECRETS_DIR/${pkg_name}_secrets.json"
    local secrets_timeout="${SECRETS_TIMEOUT:-120}"
    timeout "$secrets_timeout" apkleaks -f "$apk" -o "$json_file" > /dev/null 2>&1 || true
    
    if [ -f "$json_file" ]; then
      local secret_pattern
      secret_pattern=$(IFS='|'; echo "${SUSPICIOUS_PATTERNS[*]}")
      if grep -qiE "$secret_pattern" "$json_file" 2>/dev/null; then
        is_suspicious=1
      else
        rm -f "$json_file"
      fi
    fi
  fi
  
  # Output result for collection
  if [ $is_suspicious -eq 1 ]; then
    echo "SUSPICIOUS:$pkg_name:$risk_level:$(echo $found_perms | tr '\n' ' ')"
    
    # Add to recommended removal if CRITICAL or HIGH
    if [ "$risk_level" = "CRITICAL" ] || [ "$risk_level" = "HIGH" ]; then
      echo "$pkg_name # $risk_level" >> "$RECOMMENDED_FILE"
    fi
  else
    echo "OK:$pkg_name"
  fi
}

# Export function and variables for parallel execution
export -f analyze_single_apk_parallel should_skip_package 2>/dev/null || true
export PERMISSIONS_DIR SECRETS_DIR RECOMMENDED_FILE SKIP_SECRETS SECRETS_TIMEOUT 2>/dev/null || true
export DANGEROUS_PERMISSIONS SUSPICIOUS_PATTERNS SKIP_PACKAGES 2>/dev/null || true

# -----------------------------------------------------------------------------
# run_parallel_analysis
# Orchestrate parallel analysis of multiple APK files
# Args: $1 - directory containing APK files
# -----------------------------------------------------------------------------
run_parallel_analysis() {
  local apks_dir="$1"
  
  # Determine number of parallel jobs
  local jobs
  if [ "$PARALLEL_JOBS" = "0" ]; then
    jobs=$(( $(nproc 2>/dev/null || echo 2) / 2 ))
    [ "$jobs" -lt 1 ] && jobs=1
  else
    jobs="$PARALLEL_JOBS"
  fi
  
  log_info "Parallel analysis enabled with $jobs concurrent jobs"
  
  # Check if GNU parallel is available (preferred)
  if command -v parallel &> /dev/null && [ "$ENABLE_PARALLEL" = "true" ]; then
    log_info "Using GNU parallel for maximum efficiency"
    
    find "$apks_dir" -maxdepth 1 -name "*.apk" -print0 | \
      parallel -0 -j "$jobs" --bar analyze_single_apk_parallel {} 2>/dev/null | \
      tee "$RESULTS_DIR/parallel_results.txt"
  else
    # Fallback to xargs (more portable)
    log_info "Using xargs for parallel execution"
    
    find "$apks_dir" -maxdepth 1 -name "*.apk" -print0 | \
      xargs -0 -P "$jobs" -I {} bash -c 'analyze_single_apk_parallel "$@"' _ {} | \
      tee "$RESULTS_DIR/parallel_results.txt"
  fi
  
  # Parse results
  local suspicious_count=0
  local analyzed_count=0
  local skipped_count=0
  declare -a suspicious_apps=()
  
  while IFS= read -r line; do
    case "$line" in
      SKIP:*)
        skipped_count=$((skipped_count + 1))
        ;;
      OK:*)
        analyzed_count=$((analyzed_count + 1))
        ;;
      SUSPICIOUS:*)
        analyzed_count=$((analyzed_count + 1))
        suspicious_count=$((suspicious_count + 1))
        local pkg=$(echo "$line" | cut -d: -f2)
        suspicious_apps+=("$pkg")
        ;;
    esac
  done < "$RESULTS_DIR/parallel_results.txt"
  
  # Export for report generation
  total_analyzed=$analyzed_count
  
  # Summary
  echo ""
  echo "=============================================="
  echo "          PARALLEL ANALYSIS COMPLETE"
  echo "=============================================="
  echo ""
  echo "  Analyzed:          $analyzed_count"
  echo "  Skipped (safe):    $skipped_count"
  echo "  Suspicious:        $suspicious_count"
  echo "  Parallel jobs:     $jobs"
  echo ""
  
  if [ $suspicious_count -gt 0 ]; then
    echo -e "${RED}Suspicious packages found:${NC}"
    for app in "${suspicious_apps[@]}"; do
      echo "    - $app"
    done
  else
    echo -e "${GREEN}No suspicious packages detected${NC}"
  fi
  
  echo ""
  echo "  Results: $RESULTS_DIR/"
  echo "  Recommended removals: $RECOMMENDED_FILE"
  
  generate_report "${suspicious_apps[@]}"
  
  rm -f "$RESULTS_DIR/parallel_results.txt"
}

analyze_permissions() {
  local apk="$1"
  local filename="$2"
  local result_file="$PERMISSIONS_DIR/${filename%.apk}_permissions.txt"
  
  # Build grep pattern from dangerous permissions
  local pattern
  pattern=$(IFS='|'; echo "${DANGEROUS_PERMISSIONS[*]}")
  
  local found_perms
  found_perms=$(androguard axml "$apk" 2>/dev/null | grep -oE "$pattern" | sort -u)
  
  if [ -n "$found_perms" ]; then
    echo "$found_perms" > "$result_file"
    echo "$found_perms"
    return 1  # Dangerous permissions found
  fi
  return 0  # No dangerous permissions
}

analyze_secrets() {
  local apk="$1"
  local filename="$2"
  local json_file="$SECRETS_DIR/${filename%.apk}_secrets.json"
  local txt_file="$SECRETS_DIR/${filename%.apk}_secrets.txt"
  
  # Run apkleaks
  apkleaks -f "$apk" -o "$json_file" > /dev/null 2>&1 || true
  
  if [ ! -f "$json_file" ]; then
    return 0
  fi
  
  # Build suspicious patterns regex
  local pattern
  pattern=$(IFS='|'; echo "${SUSPICIOUS_PATTERNS[*]}")
  
  # Check for suspicious content
  local suspicious
  suspicious=$(grep -iE "$pattern" "$json_file" 2>/dev/null | head -10)
  
  # Also check for hardcoded HTTP (non-HTTPS) URLs
  local insecure_urls
  insecure_urls=$(grep -oE 'http://[^"]+' "$json_file" 2>/dev/null | grep -v "schemas.android.com" | head -5)
  
  if [ -n "$suspicious" ] || [ -n "$insecure_urls" ]; then
    {
      echo "=== Suspicious Patterns ==="
      echo "$suspicious"
      echo ""
      echo "=== Insecure URLs ==="
      echo "$insecure_urls"
    } > "$txt_file"
    
    [ -n "$suspicious" ] && echo "$suspicious" | head -3
    [ -n "$insecure_urls" ] && echo "Insecure HTTP URLs found"
    return 1  # Suspicious content found
  fi
  
  # Clean up empty json files
  if [ ! -s "$json_file" ]; then
    rm -f "$json_file"
  fi
  
  return 0
}

analyze_apk() {
  local apk="$1"
  local filename
  filename=$(basename "$apk")
  
  local is_suspicious=0
  local risk_level="LOW"
  local findings=()
  
  echo ""
  log_info "Analyzing: $filename"
  
  # Permission analysis
  echo -n "  [Permissions] "
  local perm_output
  if perm_output=$(analyze_permissions "$apk" "$filename"); then
    echo -e "${GREEN}[V] OK${NC}"
  else
    echo -e "${RED}[X] DANGEROUS${NC}"
    echo "$perm_output" | sed 's/^/    → /'
    is_suspicious=1
    findings+=("dangerous_permissions")
    
    # Check for particularly nasty combinations
    if echo "$perm_output" | grep -qE "BIND_ACCESSIBILITY|BIND_DEVICE_ADMIN"; then
      risk_level="CRITICAL"
    elif echo "$perm_output" | grep -qE "READ_SMS|SEND_SMS|INSTALL_PACKAGES"; then
      risk_level="HIGH"
    else
      risk_level="MEDIUM"
    fi
  fi
  
  # Secrets/leaks analysis
  echo -n "  [Secrets] "
  local secrets_output
  if secrets_output=$(analyze_secrets "$apk" "$filename"); then
    echo -e "${GREEN}[V] OK${NC}"
  else
    echo -e "${YELLOW}[X] FOUND${NC}"
    echo "$secrets_output" | head -3 | sed 's/^/    → /'
    is_suspicious=1
    findings+=("secrets_leaked")
  fi
  
  # Show risk assessment
  if [ $is_suspicious -eq 1 ]; then
    case $risk_level in
      "CRITICAL") echo -e "  ${RED}[RISK] ★★★ CRITICAL - Consider removing${NC}" ;;
      "HIGH")     echo -e "  ${RED}[RISK] ★★☆ HIGH${NC}" ;;
      "MEDIUM")   echo -e "  ${YELLOW}[RISK] ★☆☆ MEDIUM${NC}" ;;
    esac
  fi
  
  return $is_suspicious
}

generate_report() {
  local suspicious_list=("$@")
  local report_file="$RESULTS_DIR/SUMMARY_REPORT.md"
  
  {
    echo "# APK Analysis Report"
    echo "Generated: $(date)"
    echo ""
    echo "## Summary"
    echo "- Total APKs analyzed: $total_analyzed"
    echo "- Suspicious APKs: ${#suspicious_list[@]}"
    echo "- Skipped (known safe): $skipped_count"
    echo ""
    
    if [ ${#suspicious_list[@]} -gt 0 ]; then
      echo "## Suspicious Packages"
      echo ""
      echo "| Package | Recommendation |"
      echo "|---------|----------------|"
      for pkg in "${suspicious_list[@]}"; do
        echo "| $pkg | Review/Remove |"
      done
      echo ""
      echo "## Removal Commands"
      echo "\`\`\`bash"
      echo "# To disable (safer, reversible):"
      for pkg in "${suspicious_list[@]}"; do
        local pkg_name="${pkg%.apk}"
        echo "adb shell pm disable-user --user 0 $pkg_name"
      done
      echo ""
      echo "# To uninstall (permanent for user):"
      for pkg in "${suspicious_list[@]}"; do
        local pkg_name="${pkg%.apk}"
        echo "adb shell pm uninstall -k --user 0 $pkg_name"
      done
      echo "\`\`\`"
    else
      echo "## Result"
      echo "No suspicious packages found! [V]"
    fi
  } > "$report_file"
  
  log_success "Report generated: $report_file"
}

usage() {
  cat << EOF
Usage: $0 [MODE] [OPTIONS]

MODES:
  --stream              Analyze device packages ONE AT A TIME (recommended)
                        Downloads, analyzes, then DELETES each APK
                        Minimal disk usage (~100MB), sequential processing
                        
  --stream-all          Same as --stream but includes system packages
  
  --stream-system       Same as --stream but ONLY system packages
  
  --pull [dir]          Download ALL APKs first, then analyze
                        Default directory: ./device_apks (if [dir] omitted)
                        Warning: Can use several GB of disk space
                        Supports parallel analysis with ENABLE_PARALLEL=true
                        
  <directory>           Analyze APKs already in a local directory
                        Supports parallel analysis with ENABLE_PARALLEL=true

OPTIONS:
  --fast                Skip secrets analysis (faster, permissions only)
  --help                Show this help message

ENVIRONMENT VARIABLES:
  SKIP_SECRETS=true        Skip apkleaks analysis (much faster)
  SECRETS_TIMEOUT=120      Timeout in seconds for apkleaks (default: 120)
  ENABLE_PARALLEL=true     Enable parallel processing (--pull mode only)
  PARALLEL_JOBS=4          Number of parallel jobs (default: auto = nproc/2)
  CLEANUP_AFTER_ANALYSIS   Control APK cleanup: ask (default), yes, or no
  
  * Streaming mode cannot use parallelism because ADB only allows one transfer at a time
EOF
}

# ========================== MAIN =============================================

main() {
  local mode=""
  local pkg_filter="-3"  # Default: third-party only
  
  # Parse arguments
  case "${1:-}" in
    --help|-h)
      usage
      exit 0
      ;;
    --stream)
      mode="stream"
      pkg_filter="-3"  # Third-party only
      ;;
    --stream-all)
      mode="stream"
      pkg_filter=""    # All packages
      ;;
    --stream-system)
      mode="stream"
      pkg_filter="-s"  # System only
      ;;
    --pull)
      mode="pull"
      APKS_DIR="${2:-./device_apks}"
      ;;
    --fast)
      export SKIP_SECRETS=true
      shift
      main "$@"
      return
      ;;
    "")
      usage
      exit 1
      ;;
    *)
      mode="local"
      APKS_DIR="$1"
      ;;
  esac
  
  # Setup - create directory structure
  mkdir -p "$RESULTS_DIR" "$PERMISSIONS_DIR" "$SECRETS_DIR"
  touch "$LOG_FILE"
  
  # Initialize recommended removal file
  echo "# Recommended packages for removal" > "$RECOMMENDED_FILE"
  echo "# Generated: $(date)" >> "$RECOMMENDED_FILE"
  echo "# Criteria: CRITICAL or HIGH risk level" >> "$RECOMMENDED_FILE"
  echo "" >> "$RECOMMENDED_FILE"
  
  echo "=============================================="
  echo "       APK Batch Security Analysis"
  echo "=============================================="
  echo ""
  
  # Check dependencies
  check_dependencies
  
  # Execute based on mode
  case "$mode" in
    stream)
      stream_analyze_device "$pkg_filter"
      return
      ;;
    pull)
      pull_apks_from_device "$APKS_DIR"
      ;;
    local)
      # Just use existing directory
      ;;
  esac
  
  # For pull/local modes: analyze local directory
  if [ ! -d "$APKS_DIR" ]; then
    log_error "Directory '$APKS_DIR' does not exist"
    exit 1
  fi
  
  # Count APKs
  shopt -s nullglob
  local apk_files=("$APKS_DIR"/*.apk)
  local total_apks=${#apk_files[@]}
  
  if [ $total_apks -eq 0 ]; then
    log_error "No APK files found in '$APKS_DIR'"
    exit 1
  fi
  
  log_info "Found $total_apks APK files to analyze"
  echo ""
  
  # Check if parallel processing is enabled
  if [ "${ENABLE_PARALLEL:-false}" = "true" ]; then
    run_parallel_analysis "$APKS_DIR"
    
    # Prompt for cleanup after parallel analysis
    prompt_cleanup_apks "$APKS_DIR"
    return
  fi
  
  # Sequential analysis (default)
  log_info "Running sequential analysis (set ENABLE_PARALLEL=true for faster processing)"
  
  # Analysis counters
  local suspicious_count=0
  local skipped_count=0
  local total_analyzed=0
  local suspicious_apps=()
  
  # Main analysis loop
  for apk in "${apk_files[@]}"; do
    local filename
    filename=$(basename "$apk")
    
    # Skip known safe packages
    if should_skip_package "$filename"; then
      log_info "Skipping known safe: $filename"
      skipped_count=$((skipped_count + 1))
      continue
    fi
    
    total_analyzed=$((total_analyzed + 1))
    
    if ! analyze_apk "$apk"; then
      suspicious_count=$((suspicious_count + 1))
      suspicious_apps+=("$filename")
      
      # Add high-risk packages to recommended removal
      local pkg_name="${filename%.apk}"
      # Re-check risk level from permissions file
      local perm_file="$PERMISSIONS_DIR/${pkg_name}_permissions.txt"
      if [ -f "$perm_file" ]; then
        if grep -qE "BIND_ACCESSIBILITY|BIND_DEVICE_ADMIN" "$perm_file" 2>/dev/null; then
          echo "$pkg_name # CRITICAL" >> "$RECOMMENDED_FILE"
        elif grep -qE "READ_SMS|SEND_SMS|INSTALL_PACKAGES" "$perm_file" 2>/dev/null; then
          echo "$pkg_name # HIGH" >> "$RECOMMENDED_FILE"
        fi
      fi
    fi
  done
  
  # Generate summary report
  echo ""
  echo "=============================================="
  echo "               ANALYSIS COMPLETE"
  echo "=============================================="
  echo ""
  echo "  Total APKs:        $total_apks"
  echo "  Analyzed:          $total_analyzed"
  echo "  Skipped (safe):    $skipped_count"
  echo "  Suspicious:        $suspicious_count"
  echo ""
  
  if [ $suspicious_count -gt 0 ]; then
    echo -e "${RED}[X] Suspicious packages found:${NC}"
    for app in "${suspicious_apps[@]}"; do
      echo "    - $app"
    done
  else
    echo -e "${GREEN}[V] No suspicious packages detected${NC}"
  fi
  
  echo ""
  echo "  Results directory: $RESULTS_DIR/"
  echo "  Log file:          $LOG_FILE"
  
  # Generate markdown report
  generate_report "${suspicious_apps[@]}"
  
  # Prompt for cleanup of downloaded APKs
  prompt_cleanup_apks "$APKS_DIR"
}

# Run main function
main "$@"
