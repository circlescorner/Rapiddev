#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# FUTILITY'S — Golden Installer (SYSTEMD) — Superscript 1/4
# -----------------------------------------------------------------------------
# OVERALL 4-SUPERSCRIPT PLAN (run in order):
#
#   1) PREP + WIZARD (this script)
#      - Robust interactive wizard: gather all config, preflight checks,
#        create users/dirs, install base deps, write secured config bundle.
#
#   2) CONTROL PLANE BUILD
#      - Install Caddy, write Caddyfile for TLS, write Control Plane app files,
#        create Python venv, create systemd service for control plane, start it.
#
#   3) WORKER + ORCHESTRATION
#      - DigitalOcean worker orchestration: droplet create/delete wrappers,
#        cloud-init template, job queue, TTL sweeper, retention purge (7 days).
#
#   4) HARDEN + VERIFY + UX POLISH
#      - Tailscale integration (CP + ephemeral workers callback-only),
#        Slack webhook wiring, verification end-to-end, admin UX polish,
#        documentation + troubleshooting commands.
#
# IMPORTANT DEFAULTS (locked in):
# - Git host: GitHub only
# - Base branch: main
# - Push behavior: create branch intake/<job-id>, auto-open PR
# - File placement: incoming/<job-id>/... ONLY (Phase 1 safe default)
# - Region: NYC
# - Retention: 7 days
# - Notifications: Slack webhook
# - Tailscale: callback only (no SSH to workers)
#
# WHAT THIS SCRIPT DOES (1/4):
# - Runs a robust wizard to collect all required inputs
# - Performs preflight checks (OS, root, DNS, ports)
# - Installs baseline packages needed by later steps
# - Creates system user + directories
# - Writes a secure config file used by scripts 2-4
#
# WHAT THIS SCRIPT DOES NOT DO (YET):
# - Does NOT install or start Caddy
# - Does NOT deploy the Control Plane app
# - Does NOT create any DigitalOcean workers
# - Does NOT contact Slack/Tailscale/GitHub APIs (beyond minimal sanity checks)
#
# RUN:
#   sudo bash futilitys_superscript_1.sh
# DRY RUN:
#   sudo DRY_RUN=1 bash futilitys_superscript_1.sh
###############################################################################

# ------------------------------ UX helpers -----------------------------------

DRY_RUN="${DRY_RUN:-0}"
LOG_FILE="/var/log/futilitys/install.log"

_ok()   { printf "[OK]   %s\n" "$*"; }
_fail() { printf "[FAIL] %s\n" "$*" >&2; exit 1; }
_info() { printf "[INFO] %s\n" "$*"; }
_step() { printf "\n[STEP] %s\n" "$*"; }

run() {
  if [ "$DRY_RUN" = "1" ]; then
    printf "DRY_RUN: %s\n" "$*"
  else
    # shellcheck disable=SC2068
    "$@"
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || _fail "Missing required command: $1"
}

as_root() {
  [ "$(id -u)" = "0" ] || _fail "Run as root (use sudo)."
}

log_setup() {
  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN enabled: not touching log file."
    return 0
  fi
  run mkdir -p "$(dirname "$LOG_FILE")"
  run touch "$LOG_FILE"
  run chmod 600 "$LOG_FILE"
  # Redirect stdout+stderr to log while preserving console output
  exec > >(tee -a "$LOG_FILE") 2>&1
  _ok "Logging to $LOG_FILE"
}

prompt() {
  # prompt "VAR" "Question" "default" "secret(0/1)"
  local var="$1"
  local question="$2"
  local def="${3:-}"
  local secret="${4:-0}"
  local val=""

  if [ "$secret" = "1" ]; then
    printf "%s" "$question"
    [ -n "$def" ] && printf " (default hidden)"
    printf ": "
    IFS= read -r -s val
    printf "\n"
  else
    if [ -n "$def" ]; then
      printf "%s [%s]: " "$question" "$def"
    else
      printf "%s: " "$question"
    fi
    IFS= read -r val
  fi

  if [ -z "$val" ] && [ -n "$def" ]; then
    val="$def"
  fi

  # shellcheck disable=SC2163
  export "$var=$val"
}

confirm() {
  # confirm "Question"
  local q="$1"
  local a=""
  while true; do
    printf "%s (y/n): " "$q"
    IFS= read -r a
    case "$a" in
      y|Y) return 0 ;;
      n|N) return 1 ;;
      *) _info "Please answer y or n." ;;
    esac
  done
}

mask() {
  # mask string, show only last 4
  local s="$1"
  local n=${#s}
  if [ "$n" -le 4 ]; then
    printf "****"
  else
    printf "****%s" "${s:$((n-4)):4}"
  fi
}

# ------------------------------ Preflight ------------------------------------

check_os() {
  _step "Preflight: OS + environment"
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    _info "Detected OS: ${PRETTY_NAME:-unknown}"
    case "${ID:-}" in
      ubuntu|debian) ;;
      *) _fail "Unsupported OS. Use Ubuntu or Debian." ;;
    esac
  else
    _fail "Cannot read /etc/os-release."
  fi
  _ok "OS looks supported"
}

check_ports() {
  _step "Preflight: ports 80/443 availability"
  need_cmd ss
  local inuse=""
  if ss -ltn | awk '{print $4}' | grep -qE '(:80|:443)$'; then
    inuse="yes"
  fi

  if [ -n "$inuse" ]; then
    _info "Something is already listening on 80/443. That may block Caddy later."
    _info "This is not fatal for script 1/4, but script 2/4 will fail until resolved."
    _info "To inspect: ss -ltnp | grep -E '(:80|:443)'"
  else
    _ok "Ports 80/443 appear free"
  fi
}

get_public_ip() {
  need_cmd curl
  curl -fsS https://api.ipify.org || return 1
}

check_dns() {
  _step "Preflight: DNS A-record points to this droplet"
  need_cmd getent

  local droplet_ip=""
  droplet_ip="$(get_public_ip || true)"
  if [ -z "$droplet_ip" ]; then
    _info "Could not fetch public IP via api.ipify.org. Skipping DNS verification."
    _info "Script 2/4 will require DNS to be correct for TLS to work."
    return 0
  fi
  _info "Public IP detected: $droplet_ip"

  local resolved=""
  resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1{print $1}' || true)"
  if [ -z "$resolved" ]; then
    _info "DNS for $DOMAIN did not resolve yet."
    _info "Fix: set A-record for $DOMAIN -> $droplet_ip"
    _info "Then re-run this script."
    _fail "DNS not ready"
  fi

  _info "$DOMAIN resolves to: $resolved"
  if [ "$resolved" != "$droplet_ip" ]; then
    _info "Fix: set A-record for $DOMAIN -> $droplet_ip"
    _info "Current mismatch: $resolved != $droplet_ip"
    _fail "DNS mismatch"
  fi

  _ok "DNS is correctly pointed at this droplet"
}

# ------------------------------ Wizard ---------------------------------------

wizard() {
  _step "Wizard: collect configuration"

  _info "You will be asked for secrets. They will be saved to a root-only config file."
  _info "Nothing will be deployed yet (this is script 1/4)."

  prompt DOMAIN "Public domain for Control Plane" "circlescorner.xyz" 0
  prompt TLS_EMAIL "Email for TLS certificate (Caddy/ACME)" "" 0

  prompt ADMIN_USER "Control Plane admin username" "admin" 0
  prompt ADMIN_PASS "Control Plane admin password" "" 1

  prompt DO_TOKEN "DigitalOcean API token (droplet create/delete scope)" "" 1

  _info "GitHub App auth (recommended): App ID + Private Key."
  prompt GH_APP_ID "GitHub App ID (numeric)" "" 0

  _info "Provide the GitHub App private key in ONE of two ways:"
  _info "  (1) Paste it now (recommended), OR"
  _info "  (2) Provide a path to an existing .pem on this server."
  if confirm "Paste GitHub App private key now?"; then
    _info "Paste the PEM contents. End with a line containing only: ENDKEY"
    local key=""
    local line=""
    while true; do
      IFS= read -r line
      if [ "$line" = "ENDKEY" ]; then break; fi
      key="${key}${line}"$'\n'
    done
    export GH_APP_KEY_PEM="$key"
    export GH_APP_KEY_PATH=""
  else
    prompt GH_APP_KEY_PATH "Path to GitHub App private key PEM on server" "" 0
    export GH_APP_KEY_PEM=""
  fi

  prompt SLACK_WEBHOOK "Slack incoming webhook URL" "" 0

  _info "Tailscale (callback-only). Provide an auth key that allows tagged ephemeral nodes."
  prompt TS_AUTHKEY "Tailscale auth key (will be stored root-only)" "" 1

  prompt REGION "DigitalOcean region slug" "nyc3" 0
  prompt WORKER_SIZE "Worker size slug" "default" 0

  _info "Worker TTL: you previously specified 60 seconds. This is configurable."
  _info "If you keep 60, later scripts will enforce strict payload caps or require a prebuilt image."
  prompt WORKER_TTL_SECONDS "Worker TTL seconds" "60" 0

  prompt BASE_BRANCH "Base branch name" "main" 0

  # Fixed decisions (locked):
  export INCOMING_MODE="incoming_only"
  export PR_AUTO_OPEN="1"
  export PUSH_MODE="branch_pr"
  export RETENTION_DAYS="7"
  export TAILSCALE_MODE="callback_only"
  export GIT_HOST="github"

  _ok "Wizard inputs collected"
}

# ------------------------------ Validate inputs ------------------------------

validate_inputs() {
  _step "Validate: basic sanity checks"

  [ -n "${DOMAIN:-}" ] || _fail "DOMAIN is empty."
  [ -n "${TLS_EMAIL:-}" ] || _fail "TLS_EMAIL is empty (required for TLS later)."

  [ -n "${ADMIN_USER:-}" ] || _fail "ADMIN_USER is empty."
  [ -n "${ADMIN_PASS:-}" ] || _fail "ADMIN_PASS is empty."

  [ -n "${DO_TOKEN:-}" ] || _fail "DO_TOKEN is empty."
  [ -n "${GH_APP_ID:-}" ] || _fail "GH_APP_ID is empty."
  [ -n "${SLACK_WEBHOOK:-}" ] || _fail "SLACK_WEBHOOK is empty."
  [ -n "${TS_AUTHKEY:-}" ] || _fail "TS_AUTHKEY is empty."

  # TTL numeric
  case "${WORKER_TTL_SECONDS:-}" in
    ''|*[!0-9]*) _fail "WORKER_TTL_SECONDS must be an integer." ;;
    *) ;;
  esac

  if [ -n "${GH_APP_KEY_PEM:-}" ]; then
    printf "%s" "$GH_APP_KEY_PEM" | grep -q "BEGIN" || _fail "Pasted GitHub key does not look like PEM."
    printf "%s" "$GH_APP_KEY_PEM" | grep -q "PRIVATE KEY" || _fail "Pasted GitHub key missing PRIVATE KEY header."
  else
    [ -n "${GH_APP_KEY_PATH:-}" ] || _fail "You chose not to paste key; GH_APP_KEY_PATH is empty."
    [ -f "$GH_APP_KEY_PATH" ] || _fail "GitHub key file not found at: $GH_APP_KEY_PATH"
  fi

  _ok "Inputs look sane"
}

# ------------------------------ Install baseline deps ------------------------

install_deps() {
  _step "Install: baseline packages (needed for scripts 2-4)"
  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would apt-get update + install packages"
    _ok "Baseline deps (DRY_RUN)"
    return 0
  fi

  run apt-get update -y
  run apt-get install -y \
    ca-certificates \
    curl \
    jq \
    git \
    unzip \
    python3 \
    python3-venv \
    python3-pip \
    sqlite3 \
    openssl \
    uidmap \
    tar

  _ok "Baseline deps installed"
}

# ------------------------------ Create user + dirs ---------------------------

setup_user_dirs() {
  _step "Setup: system user + directories"
  local user="futilitys"
  local app_root="/opt/futilitys"
  local data_root="/var/lib/futilitys"
  local log_root="/var/log/futilitys"

  if id "$user" >/dev/null 2>&1; then
    _info "User $user already exists."
  else
    run useradd --system --home "$app_root" --shell /usr/sbin/nologin "$user"
    _ok "Created system user: $user"
  fi

  run mkdir -p "$app_root" "$data_root" "$log_root"
  run mkdir -p "$data_root/jobs"
  run chown -R "$user:$user" "$app_root" "$data_root"
  run chmod 755 "$app_root" "$data_root"
  run chmod 750 "$log_root"
  _ok "Directories prepared: $app_root, $data_root, $log_root"
}

# ------------------------------ Write secure config --------------------------

write_config_bundle() {
  _step "Write: secure config bundle (used by scripts 2-4)"

  local cfg_dir="/opt/futilitys/infra"
  local cfg_file="/opt/futilitys/infra/futilitys.env"
  local key_file="/opt/futilitys/infra/github_app_private_key.pem"

  run mkdir -p "$cfg_dir"

  # Write key file if pasted
  if [ -n "${GH_APP_KEY_PEM:-}" ]; then
    if [ "$DRY_RUN" = "1" ]; then
      _info "DRY_RUN: would write GitHub private key to $key_file (chmod 600)"
    else
      printf "%s" "$GH_APP_KEY_PEM" > "$key_file"
      chmod 600 "$key_file"
    fi
  else
    # Copy from provided path
    if [ "$DRY_RUN" = "1" ]; then
      _info "DRY_RUN: would copy $GH_APP_KEY_PATH to $key_file (chmod 600)"
    else
      cp -f "$GH_APP_KEY_PATH" "$key_file"
      chmod 600 "$key_file"
    fi
  fi

  # Write env
  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would write config to $cfg_file (chmod 600)"
  else
    cat > "$cfg_file" <<EOF
# FUTILITY'S — Control Plane config (generated by superscript 1/4)
# Root-only. Do not commit. Do not print.

DOMAIN="${DOMAIN}"
TLS_EMAIL="${TLS_EMAIL}"

ADMIN_USER="${ADMIN_USER}"
# ADMIN_PASS is stored hashed later (script 2/4). This raw pass is TEMPORARY.
ADMIN_PASS_RAW="${ADMIN_PASS}"

DIGITALOCEAN_TOKEN="${DO_TOKEN}"
DO_REGION="${REGION}"
WORKER_SIZE="${WORKER_SIZE}"
WORKER_TTL_SECONDS="${WORKER_TTL_SECONDS}"

GIT_HOST="${GIT_HOST}"
BASE_BRANCH="${BASE_BRANCH}"
PUSH_MODE="${PUSH_MODE}"
PR_AUTO_OPEN="${PR_AUTO_OPEN}"
INCOMING_MODE="${INCOMING_MODE}"

GITHUB_APP_ID="${GH_APP_ID}"
GITHUB_APP_KEY_PATH="${key_file}"

SLACK_WEBHOOK_URL="${SLACK_WEBHOOK}"

TAILSCALE_MODE="${TAILSCALE_MODE}"
TAILSCALE_AUTHKEY="${TS_AUTHKEY}"

RETENTION_DAYS="${RETENTION_DAYS}"
EOF
    chmod 600 "$cfg_file"
  fi

  _ok "Config bundle written: $cfg_file"
  _info "GitHub key stored at: /opt/futilitys/infra/github_app_private_key.pem (root-only)"
  _info "NOTE: Script 2/4 will convert ADMIN_PASS_RAW -> bcrypt hash and then wipe the raw password from disk."
}

# ------------------------------ Summary + next steps -------------------------

print_summary() {
  _step "Summary (what you have now + what comes next)"

  _info "Collected configuration for domain: $DOMAIN"
  _info "DigitalOcean region: $REGION"
  _info "Base branch: $BASE_BRANCH"
  _info "Repo placement mode: incoming/<job-id>/ (safe)"
  _info "Worker TTL seconds: $WORKER_TTL_SECONDS"
  _info "Slack webhook: set"
  _info "Tailscale authkey: set"
  _info "GitHub App ID: $GH_APP_ID"
  _info "Config file: /opt/futilitys/infra/futilitys.env"

  _info ""
  _info "NEXT (Superscript 2/4): CONTROL PLANE BUILD (systemd + venv + Caddy)"
  _info "TODOs for script 2/4:"
  _info " - Install and configure Caddy for TLS on $DOMAIN"
  _info " - Write Control Plane app (FastAPI + templates) under /opt/futilitys/app/"
  _info " - Create Python venv and install pinned requirements"
  _info " - Create systemd unit futilitys-control-plane.service"
  _info " - Start service; verify https://$DOMAIN/health"
  _info " - Hash admin password, remove ADMIN_PASS_RAW from config bundle"

  _info ""
  _info "Superscript 3/4 TODOs:"
  _info " - Worker droplet orchestration (create/delete), cloud-init template"
  _info " - Job runner: unzip-safe, git push branch, open PR, callback"
  _info " - TTL sweeper + 7-day retention purge"

  _info ""
  _info "Superscript 4/4 TODOs:"
  _info " - Tailscale CP + ephemeral workers callback-only integration"
  _info " - Slack message formatting + failure alerts"
  _info " - End-to-end verification job, docs, troubleshooting, UX polish"
}

# --------------------------------- Main --------------------------------------

main() {
  as_root
  log_setup

  _step "FUTILITY'S — Superscript 1/4 — PREP + WIZARD"
  _info "DRY_RUN=$DRY_RUN"

  check_os

  # Wizard must happen early because DOMAIN is needed for DNS check
  wizard
  validate_inputs

  check_ports
  check_dns

  install_deps
  setup_user_dirs
  write_config_bundle

  _ok "Superscript 1/4 complete."
  print_summary
}

main "$@"
