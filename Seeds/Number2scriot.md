#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# FUTILITY'S — Golden Installer (SYSTEMD) — Superscript 2/4
# -----------------------------------------------------------------------------
# OVERALL 4-SUPERSCRIPT PLAN (run in order):
#
#   1) PREP + WIZARD
#      - Gather config, preflight checks, create users/dirs, baseline deps,
#        write secure config bundle.   (DONE)
#
#   2) CONTROL PLANE BUILD  (THIS SCRIPT)
#      - Install Caddy (TLS reverse proxy)
#      - Write Control Plane app skeleton (FastAPI + templates)
#      - Create Python venv + pinned requirements
#      - Create systemd unit(s) and start services
#      - Hash admin password (bcrypt) and REMOVE raw password from disk
#      - Verify: https://<domain>/health responds OK
#
#   3) WORKER + ORCHESTRATION
#      - DigitalOcean worker orchestration, cloud-init template, TTL sweeper,
#        retention purge (7 days), job runner that does unzip+git push+PR.
#
#   4) HARDEN + VERIFY + UX POLISH
#      - Tailscale integration (CP + ephemeral workers callback-only),
#        Slack webhook wiring, end-to-end verification job, docs.
#
# IMPORTANT:
# - This script assumes superscript 1/4 already ran and created:
#     /opt/futilitys/infra/futilitys.env
# - This script WILL:
#     - start public HTTPS at your domain via Caddy
#     - start a minimal Control Plane web app (login + health + basic UI shell)
# - This script WILL NOT YET:
#     - populate repo dropdown from GitHub App installations (script 3/4)
#     - accept uploads and spawn workers (script 3/4)
#
# RUN:
#   sudo bash futilitys_superscript_2.sh
# DRY RUN:
#   sudo DRY_RUN=1 bash futilitys_superscript_2.sh
###############################################################################

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

need_cmd() { command -v "$1" >/dev/null 2>&1 || _fail "Missing command: $1"; }
as_root()  { [ "$(id -u)" = "0" ] || _fail "Run as root (use sudo)."; }

log_setup() {
  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN enabled: not touching log file."
    return 0
  fi
  run mkdir -p "$(dirname "$LOG_FILE")"
  run touch "$LOG_FILE"
  run chmod 600 "$LOG_FILE"
  exec > >(tee -a "$LOG_FILE") 2>&1
  _ok "Logging to $LOG_FILE"
}

# ------------------------------ Load config ----------------------------------

CFG_FILE="/opt/futilitys/infra/futilitys.env"
SECRETS_FILE="/opt/futilitys/infra/futilitys.secrets.env"

load_config() {
  _step "Load config bundle"
  [ -f "$CFG_FILE" ] || _fail "Missing config file: $CFG_FILE (run superscript 1/4 first)."
  # shellcheck disable=SC1090
  set -a
  . "$CFG_FILE"
  set +a

  [ -n "${DOMAIN:-}" ] || _fail "DOMAIN missing in config."
  [ -n "${TLS_EMAIL:-}" ] || _fail "TLS_EMAIL missing in config."
  [ -n "${ADMIN_USER:-}" ] || _fail "ADMIN_USER missing in config."
  [ -n "${ADMIN_PASS_RAW:-}" ] || _fail "ADMIN_PASS_RAW missing in config (superscript 1/4 should have set it)."
  [ -n "${RETENTION_DAYS:-}" ] || _fail "RETENTION_DAYS missing in config."

  _ok "Loaded config for domain: $DOMAIN"
}

# ------------------------------ Install Caddy --------------------------------

install_caddy() {
  _step "Install Caddy (reverse proxy + TLS)"
  if command -v caddy >/dev/null 2>&1; then
    _info "Caddy already installed."
    _ok "Caddy present"
    return 0
  fi

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would apt-get install caddy"
    _ok "Caddy install (DRY_RUN)"
    return 0
  fi

  # Try official apt packages first (Ubuntu)
  run apt-get update -y
  if apt-cache policy caddy 2>/dev/null | grep -q "Candidate:"; then
    run apt-get install -y caddy
  else
    # Fallback: add Caddy repo (best effort)
    _info "Caddy not found in default repos; adding official repo."
    run apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl
    run curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | run gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    run curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | run tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    run apt-get update -y
    run apt-get install -y caddy
  fi

  _ok "Caddy installed"
}

# ------------------------------ Write Caddyfile ------------------------------

write_caddyfile() {
  _step "Write Caddyfile (TLS + reverse proxy)"

  local caddyfile="/etc/caddy/Caddyfile"
  local upstream="127.0.0.1:8000"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would write $caddyfile"
    _ok "Caddyfile (DRY_RUN)"
    return 0
  fi

  # Minimal, clean. Caddy will handle ACME using the TLS_EMAIL.
  cat > "$caddyfile" <<EOF
{
  email ${TLS_EMAIL}
}

${DOMAIN} {
  encode gzip
  reverse_proxy ${upstream}
}
EOF

  _ok "Caddyfile written: $caddyfile"
}

enable_start_caddy() {
  _step "Enable + start Caddy"
  run systemctl daemon-reload
  run systemctl enable caddy
  run systemctl restart caddy
  run systemctl --no-pager --full status caddy | sed -n '1,20p' || true
  _ok "Caddy started"
}

# ------------------------------ Control Plane app ----------------------------

APP_ROOT="/opt/futilitys/app/control_plane"
VENV_DIR="/opt/futilitys/venv"
RUN_USER="futilitys"

write_control_plane_files() {
  _step "Write Control Plane app skeleton"

  run mkdir -p "$APP_ROOT/templates" "$APP_ROOT/static"
  run mkdir -p "/opt/futilitys/app/shared"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would write python app + templates into $APP_ROOT"
    _ok "Control Plane files (DRY_RUN)"
    return 0
  fi

  # requirements pinned-ish (keep simple and stable)
  cat > "/opt/futilitys/app/control_plane/requirements.txt" <<'EOF'
fastapi==0.115.6
uvicorn[standard]==0.30.6
jinja2==3.1.4
python-multipart==0.0.9
itsdangerous==2.2.0
passlib[bcrypt]==1.7.4
EOF

  # shared util: redaction + event logger placeholder (full in script 3/4)
  cat > "/opt/futilitys/app/shared/util.py" <<'EOF'
import re
from typing import Any, Dict

REDACT_PATTERNS = [
    re.compile(r'(?i)(token|secret|password|authkey)\s*=\s*["\']?[^"\']+["\']?'),
]

def redact(s: str) -> str:
    if not s:
        return s
    out = s
    for pat in REDACT_PATTERNS:
        out = pat.sub(r"\1=REDACTED", out)
    return out

def safe_details(d: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in d.items():
        if isinstance(v, str):
            out[k] = redact(v)
        else:
            out[k] = v
    return out
EOF

  # main app
  cat > "/opt/futilitys/app/control_plane/app.py" <<'EOF'
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.hash import bcrypt
import os
import time
from itsdangerous import URLSafeSerializer

APP_TITLE = "Futility's Control Plane"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)

DOMAIN = env("DOMAIN")
ADMIN_USER = env("ADMIN_USER")
ADMIN_PASS_HASH = env("ADMIN_PASS_HASH")
RETENTION_DAYS = env("RETENTION_DAYS", "7")

# Session signing
SESSION_SECRET = env("SESSION_SECRET", "")
if not SESSION_SECRET:
    # In production, installer sets this. We still provide a fallback.
    SESSION_SECRET = "dev-" + str(int(time.time()))

serializer = URLSafeSerializer(SESSION_SECRET, salt="futilitys-session")

app = FastAPI(title=APP_TITLE)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

def is_logged_in(request: Request) -> bool:
    cookie = request.cookies.get("futy_session", "")
    if not cookie:
        return False
    try:
        data = serializer.loads(cookie)
        return data.get("u") == ADMIN_USER
    except Exception:
        return False

def require_login(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=303)
    return None

@app.get("/health")
def health():
    return {"ok": True, "service": "futilitys-control-plane", "domain": DOMAIN}

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return TEMPLATES.TemplateResponse("login.html", {"request": request, "domain": DOMAIN})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if username != ADMIN_USER:
        return RedirectResponse("/login?err=1", status_code=303)
    if not ADMIN_PASS_HASH or not bcrypt.verify(password, ADMIN_PASS_HASH):
        return RedirectResponse("/login?err=1", status_code=303)

    cookie = serializer.dumps({"u": ADMIN_USER, "ts": int(time.time())})
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie("futy_session", cookie, httponly=True, secure=True, samesite="strict", max_age=3600*24)
    return resp

@app.post("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("futy_session")
    return resp

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    redir = require_login(request)
    if redir:
        return redir

    # Repo dropdown will be populated in superscript 3/4 (GitHub App installations).
    repos = [
        {"id": "pending", "label": "(Repo dropdown not populated yet — will be wired in superscript 3/4)"}
    ]
    return TEMPLATES.TemplateResponse("home.html", {
        "request": request,
        "domain": DOMAIN,
        "repos": repos,
        "base_branch": env("BASE_BRANCH", "main"),
        "incoming_mode": env("INCOMING_MODE", "incoming_only"),
        "retention_days": RETENTION_DAYS,
    })
EOF

  # templates
  cat > "/opt/futilitys/app/control_plane/templates/login.html" <<'EOF'
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Futility's — Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 32px; }
      .card { max-width: 520px; margin: 0 auto; padding: 18px 20px; border: 1px solid #ddd; border-radius: 10px; }
      label { display:block; margin-top: 12px; font-weight: 600; }
      input { width: 100%; padding: 10px; font-size: 16px; margin-top: 6px; }
      button { margin-top: 16px; padding: 10px 14px; font-size: 16px; cursor: pointer; }
      .err { color: #b00; margin-top: 10px; }
      .muted { color: #666; font-size: 13px; margin-top: 8px; }
    </style>
  </head>
  <body>
    <div class="card">
      <h2>Futility's Control Plane</h2>
      <div class="muted">Domain: {{ domain }}</div>
      {% if request.query_params.get("err") %}
        <div class="err">Login failed.</div>
      {% endif %}
      <form method="post" action="/login">
        <label>Username</label>
        <input name="username" autocomplete="username" required>
        <label>Password</label>
        <input name="password" type="password" autocomplete="current-password" required>
        <button type="submit">Login</button>
      </form>
    </div>
  </body>
</html>
EOF

  cat > "/opt/futilitys/app/control_plane/templates/home.html" <<'EOF'
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Futility's — Wizard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
      .top { display:flex; justify-content:space-between; align-items:center; gap: 12px; flex-wrap: wrap; }
      .pill { padding: 6px 10px; border: 1px solid #ddd; border-radius: 999px; font-size: 13px; color: #444; }
      .card { margin-top: 14px; padding: 14px 16px; border: 1px solid #ddd; border-radius: 10px; max-width: 920px; }
      .row { display:flex; gap: 10px; flex-wrap: wrap; }
      select, input, textarea { width: 100%; padding: 10px; font-size: 16px; margin-top: 6px; }
      textarea { min-height: 170px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
      label { display:block; margin-top: 10px; font-weight: 650; }
      button { margin-top: 12px; padding: 10px 14px; font-size: 16px; cursor: pointer; }
      .muted { color: #666; font-size: 13px; }
      .warn { color: #b00; font-weight: 650; }
      code { background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }
    </style>
  </head>
  <body>
    <div class="top">
      <h2>Futility's Wizard</h2>
      <form method="post" action="/logout">
        <button type="submit">Logout</button>
      </form>
    </div>

    <div class="row">
      <div class="pill">Domain: {{ domain }}</div>
      <div class="pill">Base branch: {{ base_branch }}</div>
      <div class="pill">Mode: incoming/{{ "<job-id>" }}</div>
      <div class="pill">Retention: {{ retention_days }} days</div>
    </div>

    <div class="card">
      <h3>Superscript 2/4 installed</h3>
      <div class="muted">
        This UI is live. Superscript 3/4 will wire repo dropdown, uploads, jobs, workers, PR creation, and audit logs.
      </div>
      <div class="warn" style="margin-top:10px;">
        Current limitation: repo dropdown is not populated yet.
      </div>
    </div>

    <div class="card">
      <h3>Job Intake (preview)</h3>
      <div class="muted">
        This form is a shell. In superscript 3/4 it will create a job and spawn a worker.
        Files will land under <code>incoming/&lt;job-id&gt;/</code> in a PR branch <code>intake/&lt;job-id&gt;</code>.
      </div>

      <label>Target repo (dropdown)</label>
      <select disabled>
        {% for r in repos %}
          <option>{{ r.label }}</option>
        {% endfor %}
      </select>

      <label>Upload ZIP or file</label>
      <input type="file" disabled>
      <div class="muted">Will be enabled in superscript 3/4.</div>

      <label>OR paste Path Blocks</label>
      <textarea disabled>FILE: docs/example.txt
hello world
</textarea>
      <div class="muted">Will be enabled in superscript 3/4.</div>

      <button disabled>Create Job (coming in 3/4)</button>
    </div>

    <div class="card">
      <h3>Health</h3>
      <div class="muted">Check: <code>/health</code></div>
    </div>
  </body>
</html>
EOF

  # Make sure futilitys owns app dir (except secrets in /opt/futilitys/infra are root-only)
  chown -R "$RUN_USER:$RUN_USER" "/opt/futilitys/app"
  chmod -R 755 "/opt/futilitys/app"

  _ok "Control Plane files written"
}

# ------------------------------ Venv + deps ----------------------------------

setup_venv() {
  _step "Create Python venv + install requirements"
  need_cmd python3

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would create venv at $VENV_DIR and pip install requirements"
    _ok "Venv setup (DRY_RUN)"
    return 0
  fi

  if [ ! -d "$VENV_DIR" ]; then
    run python3 -m venv "$VENV_DIR"
  fi

  # shellcheck disable=SC1091
  run "$VENV_DIR/bin/pip" install --upgrade pip
  run "$VENV_DIR/bin/pip" install -r "/opt/futilitys/app/control_plane/requirements.txt"

  _ok "Venv ready: $VENV_DIR"
}

# ------------------------------ Hash admin password --------------------------

hash_admin_password_and_secure_config() {
  _step "Hash admin password (bcrypt) and wipe raw password from disk"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would compute bcrypt hash and write $SECRETS_FILE, then remove ADMIN_PASS_RAW from $CFG_FILE"
    _ok "Admin password hardening (DRY_RUN)"
    return 0
  fi

  local hash=""
  hash="$("$VENV_DIR/bin/python" - <<'PY'
import os
from passlib.hash import bcrypt
pw = os.environ.get("ADMIN_PASS_RAW","")
if not pw:
    raise SystemExit("ADMIN_PASS_RAW missing")
print(bcrypt.hash(pw))
PY
)"

  [ -n "$hash" ] || _fail "Failed to compute bcrypt hash."

  # Generate session secret once
  local session_secret=""
  session_secret="$(openssl rand -hex 32)"

  cat > "$SECRETS_FILE" <<EOF
# FUTILITY'S — secrets (root-only)
ADMIN_PASS_HASH="${hash}"
SESSION_SECRET="${session_secret}"
EOF
  chmod 600 "$SECRETS_FILE"

  # Remove raw password line from CFG_FILE and also remove any prior hashes in CFG_FILE
  # Keep the rest intact.
  local tmp
  tmp="$(mktemp)"
  awk '
    $0 ~ /^ADMIN_PASS_RAW=/ { next }
    $0 ~ /^ADMIN_PASS_HASH=/ { next }
    $0 ~ /^SESSION_SECRET=/ { next }
    { print }
  ' "$CFG_FILE" > "$tmp"
  mv -f "$tmp" "$CFG_FILE"
  chmod 600 "$CFG_FILE"

  _ok "Wrote secrets: $SECRETS_FILE"
  _ok "Removed ADMIN_PASS_RAW from: $CFG_FILE"
  _info "NOTE: future services load $CFG_FILE + $SECRETS_FILE"
}

# ------------------------------ systemd unit ---------------------------------

write_systemd_unit() {
  _step "Write systemd unit for Control Plane"

  local unit="/etc/systemd/system/futilitys-control-plane.service"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would write $unit"
    _ok "systemd unit (DRY_RUN)"
    return 0
  fi

  cat > "$unit" <<EOF
[Unit]
Description=Futility's Control Plane (FastAPI)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_USER}
WorkingDirectory=${APP_ROOT}

# Load config + secrets
EnvironmentFile=${CFG_FILE}
EnvironmentFile=${SECRETS_FILE}

# Runtime env
Environment=PYTHONUNBUFFERED=1
Environment=FUTILITYS_ENV=prod

ExecStart=${VENV_DIR}/bin/uvicorn app:app --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=2

# Hardening (reasonable defaults)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/futilitys /var/log/futilitys /opt/futilitys

[Install]
WantedBy=multi-user.target
EOF

  _ok "Wrote unit: $unit"
}

enable_start_control_plane() {
  _step "Enable + start Control Plane service"
  run systemctl daemon-reload
  run systemctl enable futilitys-control-plane
  run systemctl restart futilitys-control-plane

  # Show status snippet
  if [ "$DRY_RUN" != "1" ]; then
    run systemctl --no-pager --full status futilitys-control-plane | sed -n '1,25p' || true
  fi

  _ok "Control Plane started"
}

# ------------------------------ Verify ---------------------------------------

verify_local_health() {
  _step "Verify: local health endpoint"
  need_cmd curl
  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would curl http://127.0.0.1:8000/health"
    _ok "Local health (DRY_RUN)"
    return 0
  fi
  local out=""
  out="$(curl -fsS "http://127.0.0.1:8000/health" || true)"
  echo "$out" | grep -q '"ok":true' || _fail "Local health check failed. Output: $out"
  _ok "Local health OK"
}

verify_public_https() {
  _step "Verify: public HTTPS health"
  need_cmd curl
  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would curl https://${DOMAIN}/health"
    _ok "Public HTTPS health (DRY_RUN)"
    return 0
  fi

  # Caddy may take a moment to obtain cert; retry a bit.
  local i=0
  local out=""
  while [ "$i" -lt 20 ]; do
    out="$(curl -fsS "https://${DOMAIN}/health" 2>/dev/null || true)"
    if echo "$out" | grep -q '"ok":true'; then
      _ok "Public HTTPS health OK"
      return 0
    fi
    i=$((i+1))
    sleep 2
  done

  _info "Last response (if any): $out"
  _fail "Public HTTPS health failed. Common fixes:
  - Confirm DNS A record for ${DOMAIN} points to this droplet IP
  - Confirm ports 80/443 open (cloud firewall + ufw)
  - Check Caddy logs: journalctl -u caddy --no-pager -n 200"
}

# ------------------------------ Main -----------------------------------------

main() {
  as_root
  log_setup

  _step "FUTILITY'S — Superscript 2/4 — CONTROL PLANE BUILD (systemd)"

  load_config

  _info "This script will:
  - install Caddy + configure TLS for ${DOMAIN}
  - deploy minimal Control Plane service behind Caddy
  - hash admin password and remove raw pass from disk
  - verify /health via HTTPS"

  install_caddy
  write_caddyfile
  enable_start_caddy

  write_control_plane_files
  setup_venv
  hash_admin_password_and_secure_config
  write_systemd_unit
  enable_start_control_plane

  verify_local_health
  verify_public_https

  _ok "Superscript 2/4 complete."
  _info "Open: https://${DOMAIN}/login"
  _info "Health: https://${DOMAIN}/health"
  _info ""
  _info "NEXT (Superscript 3/4) TODOs:"
  _info " - Implement real job intake endpoints (upload + path blocks)"
  _info " - Populate repo dropdown from GitHub App installations"
  _info " - Implement job DB schema (jobs + events append-only) in SQLite"
  _info " - Implement DO worker create/delete + cloud-init template"
  _info " - Implement worker callback + PR creation"
  _info " - Implement TTL sweeper + retention purge (7 days)"
  _info ""
  _info "Note: Current UI shows a disabled intake form. That becomes live in 3/4."
}

main "$@"