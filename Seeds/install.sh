#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# FUTILITY'S — Master Installer
# -----------------------------------------------------------------------------
# This script runs all 4 superscripts in sequence to set up a complete
# Futility's Control Plane installation from an empty Ubuntu/Debian server.
#
# USAGE:
#   sudo bash install.sh
#
# DRY RUN (test without making changes):
#   sudo DRY_RUN=1 bash install.sh
#
# RUN INDIVIDUAL SCRIPTS:
#   sudo bash futilitys_superscript_1.sh   # PREP + WIZARD
#   sudo bash futilitys_superscript_2.sh   # CONTROL PLANE BUILD
#   sudo bash futilitys_superscript_3.sh   # WORKER + ORCHESTRATION
#   sudo bash futilitys_superscript_4.sh   # HARDEN + UX POLISH
#
# WHAT THIS INSTALLS:
#   - Caddy reverse proxy with automatic TLS (Let's Encrypt)
#   - FastAPI Control Plane web application
#   - SQLite database with audit logging
#   - GitHub App integration for repo listing and PR creation
#   - DigitalOcean worker orchestration
#   - Slack notifications
#   - TTL sweeper and retention purge (systemd timers)
#   - Security hardening (ZIP-slip protection, path validation)
#   - Optional Tailscale integration
#
# PREREQUISITES:
#   - Ubuntu 20.04+ or Debian 11+
#   - Root access (run with sudo)
#   - DNS A record pointing your domain to this server
#   - DigitalOcean API token
#   - GitHub App (App ID + Private Key)
#   - Slack webhook URL
#   - Tailscale auth key (optional)
#
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_banner() {
  printf "\n"
  printf "  ╔═══════════════════════════════════════════════════════════════╗\n"
  printf "  ║                                                               ║\n"
  printf "  ║   FUTILITY'S — Complete System Installer                      ║\n"
  printf "  ║                                                               ║\n"
  printf "  ║   Takes an empty server to a fully functioning system         ║\n"
  printf "  ║                                                               ║\n"
  printf "  ╚═══════════════════════════════════════════════════════════════╝\n"
  printf "\n"
}

_ok()   { printf "[OK]   %s\n" "$*"; }
_fail() { printf "[FAIL] %s\n" "$*" >&2; exit 1; }
_info() { printf "[INFO] %s\n" "$*"; }
_step() { printf "\n══════════════════════════════════════════════════════════════════\n"; printf "  %s\n" "$*"; printf "══════════════════════════════════════════════════════════════════\n\n"; }

check_root() {
  [ "$(id -u)" = "0" ] || _fail "This installer must be run as root. Use: sudo bash install.sh"
}

check_scripts_exist() {
  local scripts=(
    "futilitys_superscript_1.sh"
    "futilitys_superscript_2.sh"
    "futilitys_superscript_3.sh"
    "futilitys_superscript_4.sh"
  )

  for script in "${scripts[@]}"; do
    if [ ! -f "$SCRIPT_DIR/$script" ]; then
      _fail "Missing script: $SCRIPT_DIR/$script"
    fi
  done

  _ok "All superscripts found"
}

run_superscript() {
  local num="$1"
  local name="$2"
  local script="futilitys_superscript_${num}.sh"

  _step "SUPERSCRIPT $num/4: $name"

  if [ "${DRY_RUN:-0}" = "1" ]; then
    _info "DRY_RUN: Would run $script"
    return 0
  fi

  if ! bash "$SCRIPT_DIR/$script"; then
    _fail "Superscript $num failed. Check logs: /var/log/futilitys/install.log"
  fi

  _ok "Superscript $num complete"
}

main() {
  _banner

  check_root
  check_scripts_exist

  _info "This installer will run 4 scripts in sequence:"
  _info "  1. PREP + WIZARD        - Collect config, install base deps"
  _info "  2. CONTROL PLANE BUILD  - Install Caddy, deploy FastAPI app"
  _info "  3. WORKER ORCHESTRATION - Add job intake, worker management"
  _info "  4. HARDEN + UX POLISH   - Security, UI improvements, verification"
  _info ""

  if [ "${DRY_RUN:-0}" = "1" ]; then
    _info "DRY_RUN mode enabled - no changes will be made"
  fi

  printf "Press Enter to continue (or Ctrl+C to abort)..."
  read -r

  run_superscript 1 "PREP + WIZARD"
  run_superscript 2 "CONTROL PLANE BUILD"
  run_superscript 3 "WORKER + ORCHESTRATION"
  run_superscript 4 "HARDEN + UX POLISH"

  printf "\n"
  printf "  ╔═══════════════════════════════════════════════════════════════╗\n"
  printf "  ║                                                               ║\n"
  printf "  ║   INSTALLATION COMPLETE                                       ║\n"
  printf "  ║                                                               ║\n"
  printf "  ║   Your Futility's Control Plane is ready!                     ║\n"
  printf "  ║                                                               ║\n"
  printf "  ╚═══════════════════════════════════════════════════════════════╝\n"
  printf "\n"

  # Read domain from config if available
  if [ -f "/opt/futilitys/infra/futilitys.env" ]; then
    # shellcheck disable=SC1091
    . /opt/futilitys/infra/futilitys.env
    _info "Access your Control Plane at: https://${DOMAIN:-your-domain}/"
    _info "Health check: https://${DOMAIN:-your-domain}/health"
  fi

  _info ""
  _info "Troubleshooting: /opt/futilitys/TROUBLESHOOTING.md"
  _info "Logs: sudo journalctl -u futilitys-control-plane -f"
}

main "$@"
