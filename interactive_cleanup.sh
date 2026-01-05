#!/bin/bash
# =============================================================================
# Interactive APK Cleanup Script
# =============================================================================
#
# DESCRIPTION:
#   Interactive tool to review analysis results and take action on suspicious
#   packages. Allows disabling, uninstalling, or skipping each package with
#   detailed information display.
#
# USAGE:
#   ./interactive_cleanup.sh              # Review all suspicious packages
#   ./interactive_cleanup.sh list         # List without interaction
#   ./interactive_cleanup.sh package X    # Review specific package
#   ./interactive_cleanup.sh restore      # Undo all changes
#
# PREREQUISITES:
#   - Run batch_analysis.sh first to generate SUMMARY_REPORT.md
#   - Device connected via ADB
#
# OUTPUT:
#   - UNDO_COMMANDS.sh: Script to reverse all changes made during session
#
# ACTIONS:
#   [d] Disable   - Hide app, keep data (reversible via 'pm enable')
#   [u] Uninstall - Remove for user, keep data (reversible via restore)
#   [f] Force     - Complete removal (may break system apps)
#   [s] Skip      - Take no action
#   [i] Info      - Show detailed package information
#   [q] Quit      - Exit and show summary
#
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

RESULTS_DIR="./analysis_results"
PERMISSIONS_DIR="$RESULTS_DIR/permissions"
SECRETS_DIR="$RESULTS_DIR/secrets"
RECOMMENDED_FILE="$RESULTS_DIR/recommended_removal.txt"

# Terminal formatting codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'  # Reset

# -----------------------------------------------------------------------------
# Session tracking arrays
# Track actions taken for summary and undo script generation
# -----------------------------------------------------------------------------
declare -a disabled_apps=()
declare -a uninstalled_apps=()
declare -a skipped_apps=()

# =============================================================================
# FUNCTIONS
# =============================================================================

# -----------------------------------------------------------------------------
# check_adb
# Verify ADB is installed and device is connected
# -----------------------------------------------------------------------------
check_adb() {
  if ! command -v adb &> /dev/null; then
    echo -e "${RED}Error: ADB not found${NC}"
    exit 1
  fi
  
  if ! adb devices | grep -q "device$"; then
    echo -e "${RED}Error: No Android device connected${NC}"
    exit 1
  fi
}

# -----------------------------------------------------------------------------
# show_package_info
# Display analysis results for a package including permissions and secrets
# Args: $1 - package name
# -----------------------------------------------------------------------------
show_package_info() {
  local pkg="$1"
  
  echo ""
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${CYAN}Package: ${BOLD}$pkg${NC}"
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  
  # Show permissions if file exists (check both old and new locations)
  local perm_file="$PERMISSIONS_DIR/${pkg}_permissions.txt"
  [ ! -f "$perm_file" ] && perm_file="$RESULTS_DIR/${pkg}_permissions.txt"
  if [ -f "$perm_file" ]; then
    echo ""
    echo -e "${RED}Dangerous Permissions:${NC}"
    cat "$perm_file" | while read perm; do
      echo -e "   ${YELLOW}->${NC} $perm"
    done
  fi
  
  # Show secrets if file exists (check both old and new locations)
  local secrets_file="$SECRETS_DIR/${pkg}_secrets.txt"
  [ ! -f "$secrets_file" ] && secrets_file="$RESULTS_DIR/${pkg}_secrets.txt"
  if [ -f "$secrets_file" ]; then
    echo ""
    echo -e "${YELLOW}Leaked Secrets/URLs:${NC}"
    head -20 "$secrets_file" | while read line; do
      echo -e "   ${BLUE}->${NC} $line"
    done
    local total_lines=$(wc -l < "$secrets_file")
    if [ "$total_lines" -gt 20 ]; then
      echo -e "   ${BLUE}... and $((total_lines - 20)) more lines${NC}"
    fi
  fi
  
  # Try to get app name from device
  local app_name
  app_name=$(adb shell dumpsys package "$pkg" 2>/dev/null | grep -m1 "applicationInfo" | sed 's/.*label=//' | cut -d' ' -f1 || echo "Unknown")
  
  # Get install location to determine if system or user app
  local install_loc
  install_loc=$(adb shell pm path "$pkg" 2>/dev/null | head -1 | sed 's/package://' || echo "Unknown")
  
  echo ""
  echo -e "${BLUE}App Info:${NC}"
  echo -e "   Location: $install_loc"
  
  # Check if it's a system app (important for removal decisions)
  if [[ "$install_loc" == *"/system/"* ]] || [[ "$install_loc" == *"/product/"* ]]; then
    echo -e "   Type: ${YELLOW}System/Pre-installed${NC}"
  else
    echo -e "   Type: ${GREEN}User-installed${NC}"
  fi
}

# -----------------------------------------------------------------------------
# show_menu
# Display action menu for current package
# -----------------------------------------------------------------------------
show_menu() {
  echo ""
  echo -e "${BOLD}What do you want to do?${NC}"
  echo ""
  echo -e "  ${GREEN}[d]${NC} Disable    - Reversible, app hidden but data kept"
  echo -e "  ${YELLOW}[u]${NC} Uninstall  - Remove for user, data kept, reversible via factory reset"
  echo -e "  ${RED}[f]${NC} Force      - Remove completely (may cause issues with system apps)"
  echo -e "  ${BLUE}[s]${NC} Skip       - Leave this app alone"
  echo -e "  ${CYAN}[i]${NC} Info       - Show more details about this package"
  echo -e "  ${NC}[q]${NC} Quit       - Exit without processing remaining apps"
  echo ""
  echo -n "Choice [d/u/f/s/i/q]: "
}

# -----------------------------------------------------------------------------
# disable_app
# Disable package using pm disable-user (reversible via pm enable)
# Args: $1 - package name
# Returns: 0 on success, 1 on failure
# -----------------------------------------------------------------------------
disable_app() {
  local pkg="$1"
  echo -n "Disabling $pkg... "
  if adb shell pm disable-user --user 0 "$pkg" 2>/dev/null | grep -q "disabled"; then
    echo -e "${GREEN}Done${NC}"
    disabled_apps+=("$pkg")
    return 0
  else
    echo -e "${RED}Failed${NC}"
    return 1
  fi
}

# -----------------------------------------------------------------------------
# uninstall_app
# Uninstall package for current user only, keeping data (-k flag)
# Can be restored via: adb shell cmd package install-existing <pkg>
# Args: $1 - package name
# Returns: 0 on success, 1 on failure
# -----------------------------------------------------------------------------
uninstall_app() {
  local pkg="$1"
  echo -n "Uninstalling $pkg for user... "
  if adb shell pm uninstall -k --user 0 "$pkg" 2>/dev/null | grep -q "Success"; then
    echo -e "${GREEN}Done${NC}"
    uninstalled_apps+=("$pkg")
    return 0
  else
    echo -e "${RED}Failed (may be system app)${NC}"
    return 1
  fi
}

# -----------------------------------------------------------------------------
# force_uninstall_app
# Force complete removal of package (WARNING: may break system apps)
# Requires user confirmation before proceeding
# Args: $1 - package name
# Returns: 0 on success, 1 on failure or cancellation
# -----------------------------------------------------------------------------
force_uninstall_app() {
  local pkg="$1"
  echo -e "${RED}WARNING: Force uninstall may cause system instability!${NC}"
  echo -n "Are you sure? [y/N]: "
  read -r confirm
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    echo -n "Force uninstalling $pkg... "
    if adb shell pm uninstall --user 0 "$pkg" 2>/dev/null | grep -q "Success"; then
      echo -e "${GREEN}Done${NC}"
      uninstalled_apps+=("$pkg")
      return 0
    else
      echo -e "${RED}Failed${NC}"
      return 1
    fi
  else
    echo "Cancelled"
    return 1
  fi
}

# -----------------------------------------------------------------------------
# show_detailed_info
# Query device for extended package information
# Args: $1 - package name
# -----------------------------------------------------------------------------
show_detailed_info() {
  local pkg="$1"
  echo ""
  echo -e "${CYAN}=== Detailed Package Info ===${NC}"
  
  # Version
  local version
  version=$(adb shell dumpsys package "$pkg" 2>/dev/null | grep -m1 "versionName" | sed 's/.*versionName=//' || echo "Unknown")
  echo "Version: $version"
  
  # First install time
  local first_install
  first_install=$(adb shell dumpsys package "$pkg" 2>/dev/null | grep -m1 "firstInstallTime" | sed 's/.*firstInstallTime=//' || echo "Unknown")
  echo "First installed: $first_install"
  
  # All permissions
  echo ""
  echo "All requested permissions:"
  adb shell dumpsys package "$pkg" 2>/dev/null | grep -A 100 "requested permissions:" | grep "android.permission" | head -20 | while read perm; do
    echo "  $perm"
  done
  
  echo ""
  echo -n "Press Enter to continue..."
  read -r
}

# -----------------------------------------------------------------------------
# show_summary
# Display session summary and generate UNDO_COMMANDS.sh for reverting changes
# Called at end of session or when user quits
# -----------------------------------------------------------------------------
show_summary() {
  echo ""
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}                    CLEANUP SUMMARY${NC}"
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  
  echo -e "${GREEN}Disabled (${#disabled_apps[@]}):${NC}"
  for app in "${disabled_apps[@]:-}"; do
    [ -n "$app" ] && echo "  - $app"
  done
  
  echo ""
  echo -e "${YELLOW}Uninstalled (${#uninstalled_apps[@]}):${NC}"
  for app in "${uninstalled_apps[@]:-}"; do
    [ -n "$app" ] && echo "  - $app"
  done
  
  echo ""
  echo -e "${BLUE}Skipped (${#skipped_apps[@]}):${NC}"
  for app in "${skipped_apps[@]:-}"; do
    [ -n "$app" ] && echo "  - $app"
  done
  
  echo ""
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  
  # Save undo commands
  local undo_file="$RESULTS_DIR/UNDO_COMMANDS.sh"
  {
    echo "#!/bin/bash"
    echo "# Undo commands generated on $(date)"
    echo "# Run this script to restore disabled/uninstalled apps"
    echo ""
    echo "# Re-enable disabled apps:"
    for app in "${disabled_apps[@]:-}"; do
      [ -n "$app" ] && echo "adb shell pm enable $app"
    done
    echo ""
    echo "# Restore uninstalled apps:"
    for app in "${uninstalled_apps[@]:-}"; do
      [ -n "$app" ] && echo "adb shell cmd package install-existing $app"
    done
  } > "$undo_file"
  chmod +x "$undo_file"
  
  echo ""
  echo -e "${GREEN}Undo commands saved to: $undo_file${NC}"
  echo "  Run it to restore all changes"
}

# -----------------------------------------------------------------------------
# process_from_report
# Main review loop: reads SUMMARY_REPORT.md and processes each suspicious pkg
# Extracts package names from markdown table format
# -----------------------------------------------------------------------------
process_from_report() {
  local report="$RESULTS_DIR/SUMMARY_REPORT.md"
  
  if [ ! -f "$report" ]; then
    echo -e "${RED}Error: No analysis report found at $report${NC}"
    echo "Run the analysis first: ./batch_analysis.sh --stream"
    exit 1
  fi
  
  # Extract suspicious packages from report
  local packages
  packages=$(grep -E "^\| com\." "$report" | cut -d'|' -f2 | tr -d ' ' || true)
  
  if [ -z "$packages" ]; then
    echo -e "${GREEN}[V] No suspicious packages found in report!${NC}"
    exit 0
  fi
  
  local total=$(echo "$packages" | wc -l)
  local count=0
  
  echo ""
  echo -e "${BOLD}Found $total suspicious packages to review${NC}"
  
  for pkg in $packages; do
    [ -z "$pkg" ] && continue
    count=$((count + 1))
    
    echo ""
    echo -e "${BLUE}[$count/$total]${NC}"
    
    show_package_info "$pkg"
    
    while true; do
      show_menu
      read -r choice
      
      case "$choice" in
        d|D)
          disable_app "$pkg"
          break
          ;;
        u|U)
          uninstall_app "$pkg"
          break
          ;;
        f|F)
          force_uninstall_app "$pkg"
          break
          ;;
        s|S)
          echo "Skipped"
          skipped_apps+=("$pkg")
          break
          ;;
        i|I)
          show_detailed_info "$pkg"
          ;;
        q|Q)
          echo "Quitting..."
          show_summary
          exit 0
          ;;
        *)
          echo -e "${RED}Invalid choice. Try again.${NC}"
          ;;
      esac
    done
  done
  
  show_summary
}

# -----------------------------------------------------------------------------
# process_single_package
# Review a single package by name (used with 'package' command)
# Args: $1 - package name
# -----------------------------------------------------------------------------
process_single_package() {
  local pkg="$1"
  
  # Verify package exists
  if ! adb shell pm list packages | grep -q "package:$pkg"; then
    echo -e "${RED}Error: Package '$pkg' not found on device${NC}"
    exit 1
  fi
  
  show_package_info "$pkg"
  
  while true; do
    show_menu
    read -r choice
    
    case "$choice" in
      d|D) disable_app "$pkg"; break ;;
      u|U) uninstall_app "$pkg"; break ;;
      f|F) force_uninstall_app "$pkg"; break ;;
      s|S) echo "Skipped"; break ;;
      i|I) show_detailed_info "$pkg" ;;
      q|Q) echo "Quitting..."; exit 0 ;;
      *) echo -e "${RED}Invalid choice${NC}" ;;
    esac
  done
  
  show_summary
}

# -----------------------------------------------------------------------------
# list_suspicious
# Display list of suspicious packages without interactive review
# -----------------------------------------------------------------------------
list_suspicious() {
  local report="$RESULTS_DIR/SUMMARY_REPORT.md"
  
  if [ ! -f "$report" ]; then
    echo -e "${RED}No analysis report found. Run analysis first.${NC}"
    exit 1
  fi
  
  echo ""
  echo -e "${BOLD}Suspicious packages from last analysis:${NC}"
  echo ""
  grep -E "^\| com\." "$report" | while read line; do
    local pkg=$(echo "$line" | cut -d'|' -f2 | tr -d ' ')
    echo "  - $pkg"
  done
}

# -----------------------------------------------------------------------------
# restore_all
# Execute UNDO_COMMANDS.sh to restore all previously modified packages
# Requires user confirmation
# -----------------------------------------------------------------------------
restore_all() {
  local undo_file="$RESULTS_DIR/UNDO_COMMANDS.sh"
  
  if [ ! -f "$undo_file" ]; then
    echo -e "${RED}No undo file found at $undo_file${NC}"
    exit 1
  fi
  
  echo -e "${YELLOW}This will restore all previously disabled/uninstalled apps.${NC}"
  echo -n "Continue? [y/N]: "
  read -r confirm
  
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    echo "Restoring apps..."
    bash "$undo_file"
    echo -e "${GREEN}[V] Restore complete${NC}"
  else
    echo "Cancelled"
  fi
}

# -----------------------------------------------------------------------------
# usage
# Display help text with available commands and examples
# -----------------------------------------------------------------------------
usage() {
  cat << EOF
Usage: $0 [COMMAND] [PACKAGE]

Interactive tool to review and remove suspicious Android packages.

COMMANDS:
  review              Review all suspicious packages from analysis report (default)
  recommended         Review only CRITICAL/HIGH risk packages (priority removal)
  list                List all suspicious packages without taking action
  package <name>      Review a specific package
  restore             Restore all previously removed/disabled packages
  help                Show this help

EXAMPLES:
  $0                          # Review all suspicious packages interactively
  $0 review                   # Same as above
  $0 recommended              # Review only high-priority packages
  $0 list                     # Just list suspicious packages
  $0 package com.example.app  # Review specific package
  $0 restore                  # Undo all changes

FILES:
  $RESULTS_DIR/SUMMARY_REPORT.md       # Full analysis report
  $RECOMMENDED_FILE   # CRITICAL/HIGH risk packages
  $RESULTS_DIR/UNDO_COMMANDS.sh        # Script to reverse changes

EOF
}

# -----------------------------------------------------------------------------
# process_recommended
# Process only CRITICAL/HIGH risk packages from recommended_removal.txt
# These are the highest priority for removal
# -----------------------------------------------------------------------------
process_recommended() {
  if [ ! -f "$RECOMMENDED_FILE" ]; then
    echo -e "${RED}Error: No recommended removal file found at $RECOMMENDED_FILE${NC}"
    echo "Run the analysis first: ./batch_analysis.sh --stream"
    exit 1
  fi
  
  # Extract packages (skip comments and empty lines)
  local packages
  packages=$(grep -v "^#" "$RECOMMENDED_FILE" | grep -v "^$" | cut -d' ' -f1 || true)
  
  if [ -z "$packages" ]; then
    echo -e "${GREEN}[V] No high-risk packages found!${NC}"
    exit 0
  fi
  
  local total=$(echo "$packages" | wc -l)
  local count=0
  
  echo ""
  echo -e "${RED}${BOLD}PRIORITY REVIEW: Found $total CRITICAL/HIGH risk packages${NC}"
  echo -e "These packages have the most dangerous permissions and should be reviewed carefully."
  
  for pkg in $packages; do
    [ -z "$pkg" ] && continue
    count=$((count + 1))
    
    # Get risk level from the file
    local risk_level
    risk_level=$(grep "^$pkg" "$RECOMMENDED_FILE" | grep -oE "CRITICAL|HIGH" | head -1 || echo "HIGH")
    
    echo ""
    if [ "$risk_level" = "CRITICAL" ]; then
      echo -e "${RED}${BOLD}[$count/$total] ★★★ CRITICAL${NC}"
    else
      echo -e "${YELLOW}${BOLD}[$count/$total] ★★☆ HIGH${NC}"
    fi
    
    show_package_info "$pkg"
    
    while true; do
      show_menu
      read -r choice
      
      case "$choice" in
        d|D) disable_app "$pkg"; break ;;
        u|U) uninstall_app "$pkg"; break ;;
        f|F) force_uninstall_app "$pkg"; break ;;
        s|S) skipped_apps+=("$pkg"); echo "Skipped"; break ;;
        i|I) show_detailed_info "$pkg" ;;
        q|Q) show_summary; exit 0 ;;
        *) echo -e "${RED}Invalid choice${NC}" ;;
      esac
    done
  done
  
  show_summary
}

# =============================================================================
# MAIN
# =============================================================================

main() {
  echo ""
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${BOLD}         Interactive APK Cleanup Tool${NC}"
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  
  check_adb
  
  case "${1:-review}" in
    review|"")
      process_from_report
      ;;
    recommended|priority|high-risk)
      process_recommended
      ;;
    list)
      list_suspicious
      ;;
    package)
      if [ -z "${2:-}" ]; then
        echo -e "${RED}Error: Package name required${NC}"
        usage
        exit 1
      fi
      process_single_package "$2"
      ;;
    restore)
      restore_all
      ;;
    help|--help|-h)
      usage
      ;;
    *)
      echo -e "${RED}Unknown command: $1${NC}"
      usage
      exit 1
      ;;
  esac
}

main "$@"
