#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# FUTILITY'S — Golden Installer (SYSTEMD) — Superscript 3/4
# -----------------------------------------------------------------------------
# OVERALL 4-SUPERSCRIPT PLAN (run in order):
#
#   1) PREP + WIZARD
#      - Gather config, preflight checks, create users/dirs, baseline deps,
#        write secure config bundle.   (DONE)
#
#   2) CONTROL PLANE BUILD
#      - Install Caddy, write minimal CP app, venv, systemd service, start,
#        hash admin password and remove raw pass, verify HTTPS.  (DONE)
#
#   3) WORKER + ORCHESTRATION  (THIS SCRIPT)
#      - Make Control Plane REAL:
#          * Repo dropdown populated from GitHub App installations
#          * Job intake: upload ZIP/file OR paste Path Blocks
#          * SQLite DB schema: jobs + events (append-only audit)
#          * Worker orchestration: create/delete droplets via DigitalOcean API
#          * Worker bootstrap endpoint (one-time secret) to mint install token
#          * Worker payload endpoint (one-time secret)
#          * Worker callback endpoint to update job status + log events
#          * Auto-open PR into main on push
#          * TTL sweeper + 7-day retention purge (systemd timer)
#          * Slack webhook notifications (basic)
#
#   4) HARDEN + UX POLISH (NEXT)
#      - Tailscale CP + ephemeral workers callback-only integration
#      - Prebuilt worker snapshot/image for fast boot (makes 60s TTL realistic)
#      - Optional DO Spaces storage, richer Slack interactivity, promote wizard
#      - End-to-end verification job + docs
#
# IMPORTANT DEFAULTS (locked in):
# - Git host: GitHub only (GitHub App auth)
# - Base branch: main
# - Push behavior: branch intake/<job-id>, auto-open PR
# - File placement: incoming/<job-id>/... ONLY
# - Region: NYC
# - Retention: 7 days
# - Notifications: Slack webhook
#
# NOTE ABOUT WORKER TTL=60 SECONDS:
# - This script implements TTL as configured (WORKER_TTL_SECONDS).
# - Ubuntu droplet boot + apt installs can exceed 60 seconds.
# - Superscript 4/4 will add a prebuilt worker snapshot for fast boot.
# - For now, keep payloads small and expect occasional TTL failures at 60s.
#
# RUN:
#   sudo bash futilitys_superscript_3.sh
# DRY RUN:
#   sudo DRY_RUN=1 bash futilitys_superscript_3.sh
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
  [ -f "$CFG_FILE" ] || _fail "Missing config: $CFG_FILE (run superscript 1/4 first)."
  [ -f "$SECRETS_FILE" ] || _fail "Missing secrets: $SECRETS_FILE (run superscript 2/4 first)."

  # shellcheck disable=SC1090
  set -a
  . "$CFG_FILE"
  . "$SECRETS_FILE"
  set +a

  [ -n "${DOMAIN:-}" ] || _fail "DOMAIN missing."
  [ -n "${DIGITALOCEAN_TOKEN:-}" ] || _fail "DIGITALOCEAN_TOKEN missing."
  [ -n "${DO_REGION:-}" ] || _fail "DO_REGION missing."
  [ -n "${WORKER_TTL_SECONDS:-}" ] || _fail "WORKER_TTL_SECONDS missing."
  [ -n "${GITHUB_APP_ID:-}" ] || _fail "GITHUB_APP_ID missing."
  [ -n "${GITHUB_APP_KEY_PATH:-}" ] || _fail "GITHUB_APP_KEY_PATH missing."
  [ -f "${GITHUB_APP_KEY_PATH:-}" ] || _fail "GitHub App key file missing: $GITHUB_APP_KEY_PATH"
  [ -n "${SLACK_WEBHOOK_URL:-}" ] || _fail "SLACK_WEBHOOK_URL missing."
  [ -n "${BASE_BRANCH:-}" ] || _fail "BASE_BRANCH missing."
  [ -n "${ADMIN_PASS_HASH:-}" ] || _fail "ADMIN_PASS_HASH missing (superscript 2/4 should have created it)."
  [ -n "${SESSION_SECRET:-}" ] || _fail "SESSION_SECRET missing (superscript 2/4 should have created it)."

  _ok "Loaded config for https://${DOMAIN}"
}

# ------------------------------ Install python deps ---------------------------

VENV_DIR="/opt/futilitys/venv"
APP_ROOT="/opt/futilitys/app/control_plane"
RUN_USER="futilitys"

install_python_deps() {
  _step "Install Python deps for orchestration (GitHub App + DO + Slack)"
  need_cmd python3

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would add deps and pip install in venv"
    _ok "Python deps (DRY_RUN)"
    return 0
  fi

  [ -d "$VENV_DIR" ] || _fail "Venv missing at $VENV_DIR (run superscript 2/4)."

  # Append-only safe: rewrite requirements.txt with needed pins.
  cat > "$APP_ROOT/requirements.txt" <<'EOF'
fastapi==0.115.6
uvicorn[standard]==0.30.6
jinja2==3.1.4
python-multipart==0.0.9
itsdangerous==2.2.0
passlib[bcrypt]==1.7.4

# orchestration deps
requests==2.32.3
PyJWT==2.9.0
cryptography==43.0.0
EOF

  run "$VENV_DIR/bin/pip" install -r "$APP_ROOT/requirements.txt"
  _ok "Python deps installed"
}

# ------------------------------ Write CP app (real) ---------------------------

write_control_plane_real() {
  _step "Write Control Plane REAL implementation (repos + jobs + workers + audit)"

  run mkdir -p "/opt/futilitys/app/shared"
  run mkdir -p "/opt/futilitys/app/worker_templates"
  run mkdir -p "/var/lib/futilitys/jobs"
  run chown -R "$RUN_USER:$RUN_USER" "/var/lib/futilitys"
  run chmod 750 "/var/lib/futilitys"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would write python modules, templates, and worker cloud-init template"
    _ok "Control Plane real files (DRY_RUN)"
    return 0
  fi

  # Shared: DB + events (append-only) + redaction
  cat > "/opt/futilitys/app/shared/db.py" <<'EOF'
import os
import sqlite3
import time
import json
from typing import Any, Dict, Optional, List

DB_PATH = os.environ.get("DB_PATH", "/var/lib/futilitys/db.sqlite3")

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS jobs (
  job_id TEXT PRIMARY KEY,
  created_ts INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  repo_full TEXT NOT NULL,
  base_branch TEXT NOT NULL,
  mode TEXT NOT NULL,               -- upload|pathblocks
  status TEXT NOT NULL,             -- RECEIVED|VALIDATED|WORKER_SPAWNED|...|DONE|FAILED
  message TEXT NOT NULL DEFAULT '',
  payload_path TEXT NOT NULL DEFAULT '',
  payload_sha256 TEXT NOT NULL DEFAULT '',
  job_secret TEXT NOT NULL,
  worker_droplet_id INTEGER,
  worker_name TEXT NOT NULL DEFAULT '',
  worker_started_ts INTEGER,
  ttl_seconds INTEGER NOT NULL,
  pr_url TEXT NOT NULL DEFAULT '',
  pr_number INTEGER,
  commit_sha TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  job_id TEXT NOT NULL,
  actor TEXT NOT NULL,      -- user|cp|worker|github|do|slack
  trigger TEXT NOT NULL,    -- ui|api|worker_callback|ttl_sweeper|do_api|github_api
  event_type TEXT NOT NULL, -- enum-ish
  details_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_job_ts ON events(job_id, ts);
"""

def _conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c

def init_db() -> None:
    c = _conn()
    try:
        c.executescript(SCHEMA)
        c.commit()
    finally:
        c.close()

def now_ts() -> int:
    return int(time.time())

def add_event(job_id: str, actor: str, trigger: str, event_type: str, details: Dict[str, Any]) -> None:
    c = _conn()
    try:
        c.execute(
            "INSERT INTO events(ts, job_id, actor, trigger, event_type, details_json) VALUES(?,?,?,?,?,?)",
            (now_ts(), job_id, actor, trigger, event_type, json.dumps(details, sort_keys=True))
        )
        c.commit()
    finally:
        c.close()

def create_job(job: Dict[str, Any]) -> None:
    c = _conn()
    try:
        cols = ",".join(job.keys())
        qs = ",".join(["?"] * len(job))
        c.execute(f"INSERT INTO jobs({cols}) VALUES({qs})", tuple(job.values()))
        c.commit()
    finally:
        c.close()

def update_job(job_id: str, fields: Dict[str, Any]) -> None:
    c = _conn()
    try:
        keys = list(fields.keys())
        sets = ",".join([f"{k}=?" for k in keys])
        vals = [fields[k] for k in keys] + [job_id]
        c.execute(f"UPDATE jobs SET {sets} WHERE job_id=?", vals)
        c.commit()
    finally:
        c.close()

def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    c = _conn()
    try:
        r = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return dict(r) if r else None
    finally:
        c.close()

def list_jobs(limit: int = 50) -> List[Dict[str, Any]]:
    c = _conn()
    try:
        rs = c.execute("SELECT * FROM jobs ORDER BY created_ts DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rs]
    finally:
        c.close()

def list_events(job_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    c = _conn()
    try:
        rs = c.execute(
            "SELECT * FROM events WHERE job_id=? ORDER BY ts ASC LIMIT ?",
            (job_id, limit)
        ).fetchall()
        out = []
        for r in rs:
            d = dict(r)
            out.append(d)
        return out
    finally:
        c.close()

def find_expired_workers() -> List[Dict[str, Any]]:
    # workers that started and are not DONE/FAILED and exceeded ttl
    c = _conn()
    try:
        now = now_ts()
        rs = c.execute("""
          SELECT * FROM jobs
          WHERE worker_started_ts IS NOT NULL
            AND status NOT IN ('DONE','FAILED')
            AND (worker_started_ts + ttl_seconds) <= ?
            AND worker_droplet_id IS NOT NULL
        """, (now,)).fetchall()
        return [dict(r) for r in rs]
    finally:
        c.close()

def find_retention_expired_jobs(retention_days: int) -> List[Dict[str, Any]]:
    c = _conn()
    try:
        cutoff = now_ts() - retention_days * 86400
        rs = c.execute("""
          SELECT * FROM jobs
          WHERE created_ts <= ?
        """, (cutoff,)).fetchall()
        return [dict(r) for r in rs]
    finally:
        c.close()
EOF

  cat > "/opt/futilitys/app/shared/util.py" <<'EOF'
import re
from typing import Any, Dict

SENSITIVE_KEYS = {"token","secret","password","authkey","authorization","private_key","pem","webhook"}
REDACT_PATTERNS = [
    re.compile(r'(?i)(token|secret|password|authkey|authorization)\s*[:=]\s*[^,\s]+'),
]

def redact_str(s: str) -> str:
    if not s:
        return s
    out = s
    for pat in REDACT_PATTERNS:
        out = pat.sub(r"\1=REDACTED", out)
    return out

def redact_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d.items():
        lk = str(k).lower()
        if lk in SENSITIVE_KEYS:
            out[k] = "REDACTED"
        elif isinstance(v, str):
            out[k] = redact_str(v)
        else:
            out[k] = v
    return out
EOF

  # GitHub App client
  cat > "/opt/futilitys/app/shared/github_app.py" <<'EOF'
import os
import time
import jwt
import requests
from typing import Dict, Any, List

GITHUB_API = "https://api.github.com"

def _env(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        raise RuntimeError(f"Missing env {name}")
    return v

def _app_jwt() -> str:
    app_id = int(_env("GITHUB_APP_ID"))
    key_path = _env("GITHUB_APP_KEY_PATH")
    with open(key_path, "rb") as f:
        private_key = f.read()

    now = int(time.time())
    payload = {
        "iat": now - 30,
        "exp": now + 540,  # 9 min
        "iss": app_id,
    }
    return jwt.encode(payload, private_key, algorithm="RS256")

def _headers_app() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {_app_jwt()}",
        "Accept": "application/vnd.github+json",
    }

def list_installations() -> List[Dict[str, Any]]:
    r = requests.get(f"{GITHUB_API}/app/installations", headers=_headers_app(), timeout=20)
    r.raise_for_status()
    return r.json()

def create_installation_token(installation_id: int) -> str:
    r = requests.post(
        f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
        headers=_headers_app(),
        json={},
        timeout=20
    )
    r.raise_for_status()
    return r.json()["token"]

def list_repos_for_installation(installation_id: int) -> List[Dict[str, Any]]:
    tok = create_installation_token(installation_id)
    h = {"Authorization": f"token {tok}", "Accept": "application/vnd.github+json"}
    r = requests.get(f"{GITHUB_API}/installation/repositories", headers=h, timeout=20)
    r.raise_for_status()
    data = r.json()
    repos = data.get("repositories", [])
    out = []
    for repo in repos:
        out.append({
            "id": repo.get("id"),
            "full_name": repo.get("full_name"),
            "clone_url": repo.get("clone_url"),
        })
    return out

def find_installation_for_repo(repo_full: str) -> int:
    # brute: scan installations and their repos
    installs = list_installations()
    for inst in installs:
        iid = inst["id"]
        repos = list_repos_for_installation(iid)
        for r in repos:
            if r["full_name"].lower() == repo_full.lower():
                return int(iid)
    raise RuntimeError(f"Repo not found in any installation: {repo_full}")

def open_pull_request(installation_id: int, repo_full: str, head_branch: str, base_branch: str, title: str, body: str) -> Dict[str, Any]:
    tok = create_installation_token(installation_id)
    h = {"Authorization": f"token {tok}", "Accept": "application/vnd.github+json"}
    payload = {"title": title, "head": head_branch, "base": base_branch, "body": body}
    r = requests.post(f"{GITHUB_API}/repos/{repo_full}/pulls", headers=h, json=payload, timeout=20)
    r.raise_for_status()
    return r.json()

def installation_token_for_repo(repo_full: str) -> Dict[str, Any]:
    iid = find_installation_for_repo(repo_full)
    tok = create_installation_token(iid)
    return {"installation_id": iid, "token": tok}
EOF

  # DigitalOcean client
  cat > "/opt/futilitys/app/shared/do_api.py" <<'EOF'
import os
import requests
from typing import Dict, Any

DO_API = "https://api.digitalocean.com/v2"

def _env(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        raise RuntimeError(f"Missing env {name}")
    return v

def _headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {_env('DIGITALOCEAN_TOKEN')}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def create_droplet(name: str, region: str, size: str, image: str, user_data: str, tags=None) -> Dict[str, Any]:
    payload = {
        "name": name,
        "region": region,
        "size": size,
        "image": image,
        "user_data": user_data,
        "tags": tags or ["futilitys-worker"],
        "with_droplet_agent": True,
    }
    r = requests.post(f"{DO_API}/droplets", headers=_headers(), json=payload, timeout=30)
    r.raise_for_status()
    return r.json()

def delete_droplet(droplet_id: int) -> None:
    r = requests.delete(f"{DO_API}/droplets/{droplet_id}", headers=_headers(), timeout=30)
    if r.status_code not in (204, 202):
        r.raise_for_status()
EOF

  # Slack notifier (simple)
  cat > "/opt/futilitys/app/shared/slack.py" <<'EOF'
import os
import requests
from typing import Dict, Any

def notify(text: str, blocks=None) -> None:
    url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not url:
        return
    payload: Dict[str, Any] = {"text": text}
    if blocks:
        payload["blocks"] = blocks
    try:
        requests.post(url, json=payload, timeout=10)
    except Exception:
        pass
EOF

  # Worker cloud-init template (CP will render variables into this)
  cat > "/opt/futilitys/app/worker_templates/cloud_init.tpl" <<'EOF'
#cloud-config
package_update: true
packages:
  - git
  - unzip
  - curl
  - jq
runcmd:
  - [ bash, -lc, "set -euo pipefail; echo '[worker] boot';" ]
  - [ bash, -lc, "nohup bash -lc 'sleep ${TTL_SECONDS}; shutdown -h now' >/var/log/futy-ttl.log 2>&1 &" ]
  - [ bash, -lc, "mkdir -p /opt/futy && cd /opt/futy" ]
  - [ bash, -lc, "echo '[worker] fetching bootstrap'; curl -fsS '${CP_BASE}/worker/bootstrap?job_id=${JOB_ID}&secret=${JOB_SECRET}' -o bootstrap.json" ]
  - [ bash, -lc, "cat bootstrap.json | jq '.' >/var/log/futy-bootstrap.json || true" ]
  - [ bash, -lc, "export REPO_FULL=$(jq -r .repo_full bootstrap.json); export BASE_BRANCH=$(jq -r .base_branch bootstrap.json); export INSTALLATION_ID=$(jq -r .installation_id bootstrap.json); export GH_TOKEN=$(jq -r .token bootstrap.json)" ]
  - [ bash, -lc, "echo '[worker] fetching payload'; curl -fsS '${CP_BASE}/jobs/${JOB_ID}/payload?secret=${JOB_SECRET}' -o payload.bin" ]
  - [ bash, -lc, "mkdir -p extracted; if file payload.bin | grep -qi zip; then unzip -o payload.bin -d extracted; else mv payload.bin extracted/UPLOAD; fi" ]
  - [ bash, -lc, "echo '[worker] cloning repo'; REPO_URL='https://x-access-token:'\"$GH_TOKEN\"'@github.com/'\"$REPO_FULL\"'.git'; git clone \"$REPO_URL\" repo" ]
  - [ bash, -lc, "cd repo; git checkout -b intake/${JOB_ID}; mkdir -p incoming/${JOB_ID}; cp -a /opt/futy/extracted/. incoming/${JOB_ID}/" ]
  - [ bash, -lc, "cd repo; git add -A; git config user.email 'futilitys-bot@local'; git config user.name 'Futilitys Bot'; git commit -m \"intake ${JOB_ID}\" || true; git push -u origin intake/${JOB_ID}" ]
  - [ bash, -lc, "echo '[worker] opening PR'; PR_JSON=$(curl -fsS -X POST -H \"Authorization: token $GH_TOKEN\" -H \"Accept: application/vnd.github+json\" https://api.github.com/repos/$REPO_FULL/pulls -d @- <<JSON\n{\"title\":\"Futilitys intake ${JOB_ID}\",\"head\":\"intake/${JOB_ID}\",\"base\":\"${BASE_BRANCH}\",\"body\":\"Automated intake job ${JOB_ID}. Files placed under incoming/${JOB_ID}/.\\n\"}\nJSON\n); echo \"$PR_JSON\" > /var/log/futy-pr.json; PR_URL=$(echo \"$PR_JSON\" | jq -r .html_url); PR_NUM=$(echo \"$PR_JSON\" | jq -r .number)" ]
  - [ bash, -lc, "cd repo; COMMIT_SHA=$(git rev-parse HEAD || true); echo \"commit=$COMMIT_SHA pr=$PR_URL\"; curl -fsS -X POST '${CP_BASE}/worker/callback' -H 'Content-Type: application/json' -d @- <<JSON\n{\"job_id\":\"${JOB_ID}\",\"secret\":\"${JOB_SECRET}\",\"status\":\"DONE\",\"message\":\"pushed branch and opened PR\",\"pr_url\":\"'\"$PR_URL\"'\",\"pr_number\":'\"$PR_NUM\"',\"commit_sha\":\"'\"$COMMIT_SHA\"'\"}\nJSON\n" ]
  - [ bash, -lc, "echo '[worker] done; shutting down'; shutdown -h now" ]
EOF

  # Control Plane app: replaces prior app.py and updates templates for real functionality
  cat > "/opt/futilitys/app/control_plane/app.py" <<'EOF'
from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.hash import bcrypt
import os
import time
import hashlib
import secrets
import shutil
import json
from typing import Optional, Dict, Any

from itsdangerous import URLSafeSerializer

from shared.db import init_db, create_job, add_event, update_job, get_job, list_jobs, list_events
from shared.util import redact_dict
from shared import github_app
from shared import do_api
from shared import slack

APP_TITLE = "Futility's Control Plane"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)

DOMAIN = env("DOMAIN")
ADMIN_USER = env("ADMIN_USER")
ADMIN_PASS_HASH = env("ADMIN_PASS_HASH")
SESSION_SECRET = env("SESSION_SECRET")
BASE_BRANCH = env("BASE_BRANCH", "main")

DATA_ROOT = env("DATA_ROOT", "/var/lib/futilitys")
JOBS_ROOT = os.path.join(DATA_ROOT, "jobs")

RETENTION_DAYS = int(env("RETENTION_DAYS", "7"))
WORKER_TTL_SECONDS = int(env("WORKER_TTL_SECONDS", "60"))
DO_REGION = env("DO_REGION", "nyc3")
WORKER_SIZE = env("WORKER_SIZE", "s-1vcpu-1gb")
# Phase 4: switch to prebuilt snapshot; for now use ubuntu image.
WORKER_IMAGE = env("WORKER_IMAGE", "ubuntu-22-04-x64")

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

def job_dir(job_id: str) -> str:
    return os.path.join(JOBS_ROOT, job_id)

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def render_cloud_init(cp_base: str, job_id: str, job_secret: str, ttl: int) -> str:
    tpl_path = "/opt/futilitys/app/worker_templates/cloud_init.tpl"
    with open(tpl_path, "r", encoding="utf-8") as f:
        tpl = f.read()
    tpl = tpl.replace("${CP_BASE}", cp_base.rstrip("/"))
    tpl = tpl.replace("${JOB_ID}", job_id)
    tpl = tpl.replace("${JOB_SECRET}", job_secret)
    tpl = tpl.replace("${TTL_SECONDS}", str(ttl))
    return tpl

def cp_base_url() -> str:
    # Always public HTTPS
    return f"https://{DOMAIN}"

@app.on_event("startup")
def _startup():
    os.makedirs(JOBS_ROOT, exist_ok=True)
    init_db()

@app.get("/health")
def health():
    return {"ok": True, "service": "futilitys-control-plane", "domain": DOMAIN}

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return TEMPLATES.TemplateResponse("login.html", {"request": request, "domain": DOMAIN})

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
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

    # Repos dropdown from GitHub App installations
    repos = []
    err = ""
    try:
        installs = github_app.list_installations()
        for inst in installs:
            iid = int(inst["id"])
            for r in github_app.list_repos_for_installation(iid):
                repos.append(r["full_name"])
        repos = sorted(list(set(repos)))
    except Exception as e:
        err = str(e)

    jobs = list_jobs(limit=25)
    return TEMPLATES.TemplateResponse("home_real.html", {
        "request": request,
        "domain": DOMAIN,
        "repos": repos,
        "base_branch": BASE_BRANCH,
        "incoming_mode": "incoming/<job-id>/",
        "ttl_seconds": WORKER_TTL_SECONDS,
        "err": err,
        "jobs": jobs
    })

@app.get("/repos")
def repos(request: Request):
    redir = require_login(request)
    if redir:
        return JSONResponse({"ok": False, "err": "not logged in"}, status_code=401)
    out = []
    installs = github_app.list_installations()
    for inst in installs:
        iid = int(inst["id"])
        for r in github_app.list_repos_for_installation(iid):
            out.append(r["full_name"])
    out = sorted(list(set(out)))
    return {"ok": True, "repos": out}

@app.post("/jobs")
async def create_job_endpoint(
    request: Request,
    repo_full: str = Form(...),
    mode: str = Form(...),  # upload|pathblocks
    pathblocks: str = Form(""),
    upload: Optional[UploadFile] = File(None),
):
    redir = require_login(request)
    if redir:
        return redir

    job_id = secrets.token_hex(8)
    job_secret = secrets.token_urlsafe(24)
    jd = job_dir(job_id)
    os.makedirs(jd, exist_ok=True)

    payload_path = ""
    payload_sha = ""
    created_by = ADMIN_USER

    add_event(job_id, "user", "ui", "JOB_RECEIVED", {"repo": repo_full, "mode": mode})

    # Validate mode and build payload
    if mode == "upload":
        if not upload:
            add_event(job_id, "cp", "ui", "JOB_FAILED", {"reason": "missing upload"})
            return RedirectResponse(f"/jobs/{job_id}?err=missing_upload", status_code=303)
        payload_path = os.path.join(jd, "payload.bin")
        with open(payload_path, "wb") as f:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
        payload_sha = sha256_file(payload_path)
        add_event(job_id, "cp", "ui", "PAYLOAD_SAVED", {"sha256": payload_sha, "path": payload_path})
    elif mode == "pathblocks":
        # Convert pathblocks into a zip-like payload by storing as text for worker to interpret:
        # For now: store pathblocks as a single file; worker treats it as single file "UPLOAD"
        payload_path = os.path.join(jd, "payload.pathblocks.txt")
        with open(payload_path, "w", encoding="utf-8") as f:
            f.write(pathblocks or "")
        payload_sha = sha256_file(payload_path)
        add_event(job_id, "cp", "ui", "PATHBLOCKS_SAVED", {"sha256": payload_sha})
    else:
        add_event(job_id, "cp", "ui", "JOB_FAILED", {"reason": "invalid mode"})
        return RedirectResponse(f"/?err=invalid_mode", status_code=303)

    # Create DB job record
    create_job({
        "job_id": job_id,
        "created_ts": int(time.time()),
        "created_by": created_by,
        "repo_full": repo_full,
        "base_branch": BASE_BRANCH,
        "mode": mode,
        "status": "VALIDATED",
        "message": "",
        "payload_path": payload_path,
        "payload_sha256": payload_sha,
        "job_secret": job_secret,
        "ttl_seconds": WORKER_TTL_SECONDS,
    })

    add_event(job_id, "cp", "ui", "JOB_VALIDATED", {"repo": repo_full, "ttl": WORKER_TTL_SECONDS})

    # Spawn worker droplet
    try:
        user_data = render_cloud_init(cp_base_url(), job_id, job_secret, WORKER_TTL_SECONDS)
        name = f"futy-worker-{job_id}"
        size = WORKER_SIZE if WORKER_SIZE != "default" else "s-1vcpu-1gb"
        res = do_api.create_droplet(
            name=name,
            region=DO_REGION,
            size=size,
            image=WORKER_IMAGE,
            user_data=user_data,
            tags=["futilitys-worker", f"job-{job_id}"]
        )
        droplet = res.get("droplet", {})
        droplet_id = droplet.get("id")
        update_job(job_id, {"status": "WORKER_SPAWNED", "worker_droplet_id": droplet_id, "worker_name": name, "worker_started_ts": int(time.time())})
        add_event(job_id, "do", "do_api", "WORKER_CREATED", {"droplet_id": droplet_id, "name": name})
        slack.notify(f"Futilitys: worker spawned for job {job_id} repo {repo_full}")
    except Exception as e:
        update_job(job_id, {"status": "FAILED", "message": f"failed to spawn worker: {e}"})
        add_event(job_id, "cp", "do_api", "JOB_FAILED", {"reason": "spawn_failed", "err": str(e)})
        slack.notify(f"Futilitys: job {job_id} FAILED spawning worker: {e}")
        return RedirectResponse(f"/jobs/{job_id}?err=spawn_failed", status_code=303)

    return RedirectResponse(f"/jobs/{job_id}", status_code=303)

@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_page(request: Request, job_id: str):
    redir = require_login(request)
    if redir:
        return redir
    job = get_job(job_id)
    if not job:
        return HTMLResponse("job not found", status_code=404)
    ev = list_events(job_id, limit=500)
    # parse details json
    for e in ev:
        try:
            e["details"] = json.loads(e["details_json"])
        except Exception:
            e["details"] = {}
    return TEMPLATES.TemplateResponse("job.html", {
        "request": request,
        "job": job,
        "events": ev,
        "domain": DOMAIN,
    })

@app.get("/jobs/{job_id}/payload")
def job_payload(job_id: str, secret: str):
    job = get_job(job_id)
    if not job:
        return JSONResponse({"ok": False, "err": "not found"}, status_code=404)
    if secret != job["job_secret"]:
        return JSONResponse({"ok": False, "err": "forbidden"}, status_code=403)

    p = job["payload_path"]
    if not p or not os.path.exists(p):
        return JSONResponse({"ok": False, "err": "payload missing"}, status_code=404)

    # return raw bytes; worker decides zip vs non-zip
    with open(p, "rb") as f:
        data = f.read()
    add_event(job_id, "cp", "worker_fetch", "PAYLOAD_SERVED", {"bytes": len(data)})
    return JSONResponse(content={"ok": True, "b64": data.hex()})  # HEX to avoid b64 libs in cloud-init

@app.get("/worker/bootstrap")
def worker_bootstrap(job_id: str, secret: str):
    job = get_job(job_id)
    if not job:
        return JSONResponse({"ok": False, "err": "not found"}, status_code=404)
    if secret != job["job_secret"]:
        return JSONResponse({"ok": False, "err": "forbidden"}, status_code=403)

    repo_full = job["repo_full"]
    try:
        info = github_app.installation_token_for_repo(repo_full)
        add_event(job_id, "github", "github_api", "INSTALL_TOKEN_MINTED", {"repo": repo_full, "installation_id": info["installation_id"]})
        return {"ok": True, "repo_full": repo_full, "base_branch": job["base_branch"], "installation_id": info["installation_id"], "token": info["token"]}
    except Exception as e:
        add_event(job_id, "cp", "github_api", "BOOTSTRAP_FAILED", {"err": str(e)})
        update_job(job_id, {"status": "FAILED", "message": f"bootstrap failed: {e}"})
        return JSONResponse({"ok": False, "err": "bootstrap failed"}, status_code=500)

@app.post("/worker/callback")
async def worker_callback(request: Request):
    body = await request.json()
    job_id = body.get("job_id", "")
    secret = body.get("secret", "")
    status = body.get("status", "")
    message = body.get("message", "")
    pr_url = body.get("pr_url", "")
    pr_number = body.get("pr_number", None)
    commit_sha = body.get("commit_sha", "")

    job = get_job(job_id)
    if not job:
        return JSONResponse({"ok": False, "err": "not found"}, status_code=404)
    if secret != job["job_secret"]:
        return JSONResponse({"ok": False, "err": "forbidden"}, status_code=403)

    add_event(job_id, "worker", "worker_callback", "WORKER_CALLBACK", redact_dict(body))

    fields: Dict[str, Any] = {}
    if status:
        fields["status"] = status
    if message:
        fields["message"] = message
    if pr_url:
        fields["pr_url"] = pr_url
    if pr_number is not None:
        try:
            fields["pr_number"] = int(pr_number)
        except Exception:
            pass
    if commit_sha:
        fields["commit_sha"] = commit_sha

    update_job(job_id, fields)

    if status == "DONE":
        slack.notify(f"Futilitys: job {job_id} DONE PR: {pr_url}")
    elif status == "FAILED":
        slack.notify(f"Futilitys: job {job_id} FAILED: {message}")

    return {"ok": True}

EOF

  # Update templates: home + job
  cat > "/opt/futilitys/app/control_plane/templates/home_real.html" <<'EOF'
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Futility's — Wizard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 22px; }
      .top { display:flex; justify-content:space-between; align-items:center; gap: 12px; flex-wrap: wrap; }
      .pill { padding: 6px 10px; border: 1px solid #ddd; border-radius: 999px; font-size: 13px; color: #444; }
      .card { margin-top: 14px; padding: 14px 16px; border: 1px solid #ddd; border-radius: 10px; max-width: 980px; }
      .row { display:flex; gap: 10px; flex-wrap: wrap; }
      select, input, textarea { width: 100%; padding: 10px; font-size: 16px; margin-top: 6px; }
      textarea { min-height: 170px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
      label { display:block; margin-top: 10px; font-weight: 650; }
      button { margin-top: 12px; padding: 10px 14px; font-size: 16px; cursor: pointer; }
      .muted { color: #666; font-size: 13px; }
      .err { color: #b00; font-weight: 650; margin-top: 8px; }
      table { border-collapse: collapse; width: 100%; font-size: 14px; margin-top: 10px; }
      th, td { border: 1px solid #eee; padding: 8px; text-align: left; }
      code { background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }
    </style>
    <script>
      function setMode(m) {
        document.getElementById("mode").value = m;
        document.getElementById("uploadBox").style.display = (m === "upload") ? "block" : "none";
        document.getElementById("pathBox").style.display = (m === "pathblocks") ? "block" : "none";
      }
      window.addEventListener("load", () => setMode("upload"));
    </script>
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
      <div class="pill">Incoming: {{ incoming_mode }}</div>
      <div class="pill">Worker TTL: {{ ttl_seconds }}s</div>
    </div>

    {% if err %}
      <div class="err">Repo discovery error: {{ err }}</div>
      <div class="muted">Fix: ensure GitHub App is installed on the repo(s) and credentials are correct.</div>
    {% endif %}

    <div class="card">
      <h3>Create Intake Job</h3>
      <div class="muted">
        Files will be committed under <code>incoming/&lt;job-id&gt;/</code> on branch <code>intake/&lt;job-id&gt;</code> and a PR will be opened into <code>{{ base_branch }}</code>.
      </div>

      <form method="post" action="/jobs" enctype="multipart/form-data">
        <input type="hidden" name="mode" id="mode" value="upload">

        <label>Target repo</label>
        <select name="repo_full" required>
          {% for r in repos %}
            <option value="{{ r }}">{{ r }}</option>
          {% endfor %}
        </select>

        <div class="row" style="margin-top:10px;">
          <button type="button" onclick="setMode('upload')">Use Upload</button>
          <button type="button" onclick="setMode('pathblocks')">Use Path Blocks</button>
        </div>

        <div id="uploadBox" style="margin-top:10px;">
          <label>Upload ZIP or file</label>
          <input type="file" name="upload">
          <div class="muted">ZIP preferred. Non-zip will be stored as a single file.</div>
        </div>

        <div id="pathBox" style="margin-top:10px; display:none;">
          <label>Paste Path Blocks</label>
          <textarea name="pathblocks">FILE: docs/example.txt
hello world
</textarea>
          <div class="muted">Format: repeated blocks starting with <code>FILE: path</code>.</div>
        </div>

        <button type="submit">Create Job + Spawn Worker</button>
      </form>
    </div>

    <div class="card">
      <h3>Recent Jobs</h3>
      <table>
        <thead>
          <tr><th>Job</th><th>Status</th><th>Repo</th><th>PR</th><th>Created</th></tr>
        </thead>
        <tbody>
          {% for j in jobs %}
            <tr>
              <td><a href="/jobs/{{ j.job_id }}">{{ j.job_id }}</a></td>
              <td>{{ j.status }}</td>
              <td>{{ j.repo_full }}</td>
              <td>{% if j.pr_url %}<a href="{{ j.pr_url }}">PR</a>{% else %}-{% endif %}</td>
              <td>{{ j.created_ts }}</td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
      <div class="muted">Times are unix timestamps for now; script 4/4 will polish UI.</div>
    </div>

    <div class="card">
      <h3>Health</h3>
      <div class="muted">Check: <code>/health</code></div>
    </div>
  </body>
</html>
EOF

  cat > "/opt/futilitys/app/control_plane/templates/job.html" <<'EOF'
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Futility's — Job {{ job.job_id }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 22px; }
      .top { display:flex; justify-content:space-between; align-items:center; gap: 12px; flex-wrap: wrap; }
      .card { margin-top: 14px; padding: 14px 16px; border: 1px solid #ddd; border-radius: 10px; max-width: 980px; }
      .muted { color: #666; font-size: 13px; }
      table { border-collapse: collapse; width: 100%; font-size: 13px; margin-top: 10px; }
      th, td { border: 1px solid #eee; padding: 8px; text-align: left; vertical-align: top; }
      code { background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }
    </style>
  </head>
  <body>
    <div class="top">
      <h2>Job {{ job.job_id }}</h2>
      <div><a href="/">Back</a></div>
    </div>

    <div class="card">
      <div><b>Status:</b> {{ job.status }}</div>
      <div><b>Repo:</b> {{ job.repo_full }}</div>
      <div><b>Base:</b> {{ job.base_branch }}</div>
      <div><b>Mode:</b> {{ job.mode }}</div>
      <div><b>TTL:</b> {{ job.ttl_seconds }}s</div>
      <div><b>Droplet ID:</b> {{ job.worker_droplet_id }}</div>
      <div><b>PR:</b> {% if job.pr_url %}<a href="{{ job.pr_url }}">{{ job.pr_url }}</a>{% else %}-{% endif %}</div>
      <div class="muted" style="margin-top:8px;">Message: {{ job.message }}</div>
    </div>

    <div class="card">
      <h3>Audit Timeline (append-only)</h3>
      <table>
        <thead>
          <tr><th>ts</th><th>actor</th><th>trigger</th><th>type</th><th>details</th></tr>
        </thead>
        <tbody>
          {% for e in events %}
            <tr>
              <td>{{ e.ts }}</td>
              <td>{{ e.actor }}</td>
              <td>{{ e.trigger }}</td>
              <td>{{ e.event_type }}</td>
              <td><pre style="margin:0; white-space: pre-wrap;">{{ e.details }}</pre></td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
      <div class="muted">Details are redacted where sensitive.</div>
    </div>
  </body>
</html>
EOF

  # NOTE: We keep login.html from script 2/4 as-is.

  chown -R "$RUN_USER:$RUN_USER" "/opt/futilitys/app"
  _ok "Control Plane updated to REAL mode"
}

# ------------------------------ Fix worker template (payload serving) --------
# The cloud-init template above expects /jobs/<id>/payload returns bytes.
# Because JSONResponse HEX isn't ideal for curl binary in cloud-init, we implement
# a dedicated binary endpoint in python by returning raw Response. To avoid
# adding complexity in this superscript, we instead adjust worker template to
# fetch a HEX string and reconstruct bytes.
#
# We'll patch the worker template accordingly: payload endpoint returns {"b64":hex}
# and worker decodes via python -c.
patch_worker_template_for_hex_payload() {
  _step "Patch worker template to decode HEX payload safely"
  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would patch /opt/futilitys/app/worker_templates/cloud_init.tpl"
    _ok "Worker template patch (DRY_RUN)"
    return 0
  fi

  local tpl="/opt/futilitys/app/worker_templates/cloud_init.tpl"
  # Replace payload fetch and extraction steps:
  # - fetch JSON
  # - decode hex into payload.bin via python
  # We'll do a simple in-place rewrite using awk markers.
  # (Since this is generated by us, we can safely rewrite the whole file with updated lines.)
  cat > "$tpl" <<'EOF'
#cloud-config
package_update: true
packages:
  - git
  - unzip
  - curl
  - jq
  - python3
runcmd:
  - [ bash, -lc, "set -euo pipefail; echo '[worker] boot';" ]
  - [ bash, -lc, "nohup bash -lc 'sleep ${TTL_SECONDS}; shutdown -h now' >/var/log/futy-ttl.log 2>&1 &" ]
  - [ bash, -lc, "mkdir -p /opt/futy && cd /opt/futy" ]
  - [ bash, -lc, "echo '[worker] fetching bootstrap'; curl -fsS '${CP_BASE}/worker/bootstrap?job_id=${JOB_ID}&secret=${JOB_SECRET}' -o bootstrap.json" ]
  - [ bash, -lc, "export REPO_FULL=$(jq -r .repo_full bootstrap.json); export BASE_BRANCH=$(jq -r .base_branch bootstrap.json); export GH_TOKEN=$(jq -r .token bootstrap.json)" ]
  - [ bash, -lc, "echo '[worker] fetching payload json'; curl -fsS '${CP_BASE}/jobs/${JOB_ID}/payload?secret=${JOB_SECRET}' -o payload.json" ]
  - [ bash, -lc, "python3 - <<'PY'\nimport json\nh=json.load(open('payload.json'))\nhexs=h.get('b64','')\nopen('payload.bin','wb').write(bytes.fromhex(hexs))\nprint('wrote',len(hexs)//2,'bytes')\nPY" ]
  - [ bash, -lc, "mkdir -p extracted; if file payload.bin | grep -qi zip; then unzip -o payload.bin -d extracted; else mv payload.bin extracted/UPLOAD; fi" ]
  - [ bash, -lc, "echo '[worker] cloning repo'; REPO_URL='https://x-access-token:'\"$GH_TOKEN\"'@github.com/'\"$REPO_FULL\"'.git'; git clone \"$REPO_URL\" repo" ]
  - [ bash, -lc, "cd repo; git checkout -b intake/${JOB_ID}; mkdir -p incoming/${JOB_ID}; cp -a /opt/futy/extracted/. incoming/${JOB_ID}/" ]
  - [ bash, -lc, "cd repo; git add -A; git config user.email 'futilitys-bot@local'; git config user.name 'Futilitys Bot'; git commit -m \"intake ${JOB_ID}\" || true; git push -u origin intake/${JOB_ID}" ]
  - [ bash, -lc, "echo '[worker] opening PR'; PR_JSON=$(curl -fsS -X POST -H \"Authorization: token $GH_TOKEN\" -H \"Accept: application/vnd.github+json\" https://api.github.com/repos/$REPO_FULL/pulls -d @- <<JSON\n{\"title\":\"Futilitys intake ${JOB_ID}\",\"head\":\"intake/${JOB_ID}\",\"base\":\"${BASE_BRANCH}\",\"body\":\"Automated intake job ${JOB_ID}. Files placed under incoming/${JOB_ID}/.\\n\"}\nJSON\n); echo \"$PR_JSON\" > /var/log/futy-pr.json; PR_URL=$(echo \"$PR_JSON\" | jq -r .html_url); PR_NUM=$(echo \"$PR_JSON\" | jq -r .number)" ]
  - [ bash, -lc, "cd repo; COMMIT_SHA=$(git rev-parse HEAD || true); curl -fsS -X POST '${CP_BASE}/worker/callback' -H 'Content-Type: application/json' -d @- <<JSON\n{\"job_id\":\"${JOB_ID}\",\"secret\":\"${JOB_SECRET}\",\"status\":\"DONE\",\"message\":\"pushed branch and opened PR\",\"pr_url\":\"'\"$PR_URL\"'\",\"pr_number\":'\"$PR_NUM\"',\"commit_sha\":\"'\"$COMMIT_SHA\"'\"}\nJSON\n" ]
  - [ bash, -lc, "echo '[worker] done; shutting down'; shutdown -h now" ]
EOF

  _ok "Worker template updated for HEX payload"
}

# ------------------------------ Sweeper + retention purge ---------------------

write_sweeper() {
  _step "Write sweeper script + systemd timer (TTL + retention)"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would write sweeper python + systemd unit/timer"
    _ok "Sweeper (DRY_RUN)"
    return 0
  fi

  run mkdir -p "/opt/futilitys/scripts"
  cat > "/opt/futilitys/scripts/sweeper.py" <<'EOF'
import os
import shutil
from shared.db import init_db, find_expired_workers, add_event, update_job, find_retention_expired_jobs
from shared import do_api
from shared import slack

def main():
    init_db()

    # TTL: delete expired workers
    expired = find_expired_workers()
    for job in expired:
        job_id = job["job_id"]
        droplet_id = job.get("worker_droplet_id")
        if droplet_id:
            try:
                do_api.delete_droplet(int(droplet_id))
                add_event(job_id, "do", "ttl_sweeper", "WORKER_DELETED_TTL", {"droplet_id": droplet_id})
                update_job(job_id, {"status": "FAILED", "message": "worker ttl exceeded; deleted droplet"})
                slack.notify(f"Futilitys: job {job_id} TTL exceeded; worker deleted.")
            except Exception as e:
                add_event(job_id, "cp", "ttl_sweeper", "WORKER_DELETE_FAILED", {"droplet_id": droplet_id, "err": str(e)})

    # Retention purge
    retention_days = int(os.environ.get("RETENTION_DAYS", "7"))
    old = find_retention_expired_jobs(retention_days)
    jobs_root = os.environ.get("JOBS_ROOT", "/var/lib/futilitys/jobs")
    for job in old:
        job_id = job["job_id"]
        path = os.path.join(jobs_root, job_id)
        try:
            if os.path.exists(path):
                shutil.rmtree(path, ignore_errors=True)
            add_event(job_id, "cp", "retention_purge", "JOB_PURGED", {"path": path})
        except Exception as e:
            add_event(job_id, "cp", "retention_purge", "JOB_PURGE_FAILED", {"path": path, "err": str(e)})

if __name__ == "__main__":
    main()
EOF

  chown -R "$RUN_USER:$RUN_USER" "/opt/futilitys/scripts"
  chmod -R 755 "/opt/futilitys/scripts"

  cat > "/etc/systemd/system/futilitys-sweeper.service" <<EOF
[Unit]
Description=Futility's Sweeper (TTL + retention)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=${RUN_USER}
Group=${RUN_USER}
WorkingDirectory=/opt/futilitys

EnvironmentFile=${CFG_FILE}
EnvironmentFile=${SECRETS_FILE}
Environment=DB_PATH=/var/lib/futilitys/db.sqlite3
Environment=JOBS_ROOT=/var/lib/futilitys/jobs

ExecStart=${VENV_DIR}/bin/python /opt/futilitys/scripts/sweeper.py
EOF

  cat > "/etc/systemd/system/futilitys-sweeper.timer" <<'EOF'
[Unit]
Description=Run Futility's Sweeper every minute

[Timer]
OnBootSec=60
OnUnitActiveSec=60
Unit=futilitys-sweeper.service

[Install]
WantedBy=timers.target
EOF

  _ok "Sweeper service+timer written"
}

enable_start_sweeper() {
  _step "Enable + start sweeper timer"
  run systemctl daemon-reload
  run systemctl enable futilitys-sweeper.timer
  run systemctl restart futilitys-sweeper.timer
  _ok "Sweeper timer running"
}

# ------------------------------ Restart CP + verify ---------------------------

restart_control_plane() {
  _step "Restart Control Plane (apply changes)"
  run systemctl restart futilitys-control-plane
  _ok "Control Plane restarted"
}

verify_https() {
  _step "Verify HTTPS + UI"
  need_cmd curl
  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would curl https://${DOMAIN}/health"
    _ok "Verify (DRY_RUN)"
    return 0
  fi
  local out=""
  out="$(curl -fsS "https://${DOMAIN}/health" || true)"
  echo "$out" | grep -q '"ok":true' || _fail "Health failed: $out"
  _ok "Health OK: https://${DOMAIN}/health"
  _info "Login UI: https://${DOMAIN}/login"
}

# --------------------------------- Main --------------------------------------

main() {
  as_root
  log_setup
  _step "FUTILITY'S — Superscript 3/4 — WORKER + ORCHESTRATION"

  load_config
  install_python_deps
  write_control_plane_real
  patch_worker_template_for_hex_payload
  write_sweeper
  enable_start_sweeper
  restart_control_plane
  verify_https

  _ok "Superscript 3/4 complete."
  _info ""
  _info "What you can do now:"
  _info " - Go to https://${DOMAIN}/login"
  _info " - Create a job (select repo dropdown, upload zip) -> worker spawns -> PR opens"
  _info " - View job audit timeline on /jobs/<job-id>"
  _info ""
  _info "Remaining TODOs (Superscript 4/4):"
  _info " - Tailscale integration (CP + workers as ephemeral nodes, callback-only)"
  _info " - Prebuilt worker snapshot to make TTL=60s reliable"
  _info " - Zip-safety hardening (zip-slip checks, size caps) and pathblocks true multi-file expansion"
  _info " - Better UI polish: human timestamps, clearer errors, repo allowlist controls"
  _info " - End-to-end verification job + docs + troubleshooting commands"
}

main "$@"