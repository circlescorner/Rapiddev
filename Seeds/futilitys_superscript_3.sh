#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# FUTILITY'S — Golden Installer (SYSTEMD) — Superscript 3/4
# -----------------------------------------------------------------------------
# OVERALL 4-SUPERSCRIPT PLAN (run in order):
#
#   1) PREP + WIZARD                    (DONE)
#   2) CONTROL PLANE BUILD              (DONE)
#   3) WORKER + ORCHESTRATION           (THIS SCRIPT)
#      - Implement real job intake (POST /jobs with upload or path blocks)
#      - Populate repo dropdown from GitHub App installations
#      - SQLite database schema (jobs + events append-only)
#      - DigitalOcean worker orchestration (create/delete droplets)
#      - Cloud-init template for fast worker bootstrap
#      - Worker callback endpoints for job updates
#      - TTL sweeper (kill workers exceeding TTL)
#      - 7-day retention purge (systemd timer)
#      - Slack notifications for job events
#
#   4) HARDEN + VERIFY + UX POLISH
#      - Tailscale integration, binary payload handling, ZIP-slip protection,
#        Path Blocks expansion, UI improvements, repo allowlisting.
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
  exec > >(tee -a "$LOG_FILE") 2>&1
  _ok "Logging to $LOG_FILE"
}

# ------------------------------ Load config ----------------------------------

CFG_FILE="/opt/futilitys/infra/futilitys.env"
SECRETS_FILE="/opt/futilitys/infra/futilitys.secrets.env"
APP_ROOT="/opt/futilitys/app/control_plane"
VENV_DIR="/opt/futilitys/venv"
RUN_USER="futilitys"
DATA_DIR="/var/lib/futilitys"
DB_FILE="/var/lib/futilitys/futilitys.db"

load_config() {
  _step "Load config bundle"
  [ -f "$CFG_FILE" ] || _fail "Missing config file: $CFG_FILE"
  [ -f "$SECRETS_FILE" ] || _fail "Missing secrets file: $SECRETS_FILE (run superscript 2/4 first)."
  set -a
  # shellcheck disable=SC1090
  . "$CFG_FILE"
  # shellcheck disable=SC1090
  . "$SECRETS_FILE"
  set +a

  [ -n "${DOMAIN:-}" ] || _fail "DOMAIN missing."
  [ -n "${DIGITALOCEAN_TOKEN:-}" ] || _fail "DIGITALOCEAN_TOKEN missing."
  [ -n "${GITHUB_APP_ID:-}" ] || _fail "GITHUB_APP_ID missing."
  [ -n "${GITHUB_APP_KEY_PATH:-}" ] || _fail "GITHUB_APP_KEY_PATH missing."

  _ok "Loaded config for domain: $DOMAIN"
}

# ------------------------------ SQLite schema --------------------------------

setup_database() {
  _step "Setup SQLite database schema"
  need_cmd sqlite3

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would create $DB_FILE with schema"
    _ok "Database (DRY_RUN)"
    return 0
  fi

  run mkdir -p "$DATA_DIR/jobs"

  sqlite3 "$DB_FILE" <<'SQL'
-- Jobs table: tracks each intake submission
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    status TEXT DEFAULT 'pending',   -- pending, running, success, failed, cancelled
    repo_full_name TEXT NOT NULL,
    branch_name TEXT,
    pr_url TEXT,
    worker_droplet_id TEXT,
    worker_ip TEXT,
    payload_type TEXT,               -- 'zip', 'pathblocks', 'file'
    payload_size_bytes INTEGER,
    error_message TEXT
);

-- Events table: append-only audit log
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT DEFAULT (datetime('now')),
    job_id TEXT,
    event_type TEXT NOT NULL,        -- job_created, worker_started, push_complete, pr_opened, job_failed, etc.
    details TEXT,                    -- JSON blob with event-specific data
    FOREIGN KEY (job_id) REFERENCES jobs(id)
);

-- Index for faster queries
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at);
CREATE INDEX IF NOT EXISTS idx_events_job ON events(job_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
SQL

  chown "$RUN_USER:$RUN_USER" "$DB_FILE"
  chmod 640 "$DB_FILE"

  _ok "Database ready: $DB_FILE"
}

# ------------------------------ GitHub App integration -----------------------

write_github_integration() {
  _step "Write GitHub App integration module"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would write github_integration.py"
    _ok "GitHub integration (DRY_RUN)"
    return 0
  fi

  cat > "/opt/futilitys/app/control_plane/github_integration.py" <<'PYEOF'
"""
GitHub App integration: JWT generation, installation tokens, repo listing, PR creation.
"""
import os
import time
import json
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional
import jwt  # PyJWT

GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "")
GITHUB_APP_KEY_PATH = os.environ.get("GITHUB_APP_KEY_PATH", "")

def _load_private_key() -> str:
    with open(GITHUB_APP_KEY_PATH, "r") as f:
        return f.read()

def generate_jwt() -> str:
    """Generate a JWT for GitHub App authentication (valid 10 min)."""
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + (10 * 60),
        "iss": GITHUB_APP_ID,
    }
    private_key = _load_private_key()
    return jwt.encode(payload, private_key, algorithm="RS256")

def _api_request(url: str, token: str, method: str = "GET", data: Optional[Dict] = None) -> Dict:
    """Make a GitHub API request."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    body = None
    if data:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8") if e.fp else ""
        raise RuntimeError(f"GitHub API error {e.code}: {err_body}")

def get_installations() -> List[Dict]:
    """Get all installations of the GitHub App."""
    jwt_token = generate_jwt()
    url = "https://api.github.com/app/installations"
    return _api_request(url, jwt_token)

def get_installation_token(installation_id: int) -> str:
    """Get an installation access token for a specific installation."""
    jwt_token = generate_jwt()
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    resp = _api_request(url, jwt_token, method="POST")
    return resp["token"]

def list_repos_for_installation(installation_id: int) -> List[Dict]:
    """List repositories accessible to an installation."""
    token = get_installation_token(installation_id)
    url = "https://api.github.com/installation/repositories?per_page=100"
    resp = _api_request(url, token)
    return resp.get("repositories", [])

def get_all_accessible_repos() -> List[Dict[str, Any]]:
    """Get all repos from all installations."""
    repos = []
    for inst in get_installations():
        inst_id = inst["id"]
        inst_repos = list_repos_for_installation(inst_id)
        for r in inst_repos:
            repos.append({
                "id": r["id"],
                "full_name": r["full_name"],
                "private": r["private"],
                "installation_id": inst_id,
            })
    return repos

def create_branch(installation_id: int, repo_full_name: str, branch_name: str, base_branch: str = "main") -> str:
    """Create a new branch from base_branch. Returns the new branch SHA."""
    token = get_installation_token(installation_id)

    # Get base branch SHA
    url = f"https://api.github.com/repos/{repo_full_name}/git/ref/heads/{base_branch}"
    ref_data = _api_request(url, token)
    base_sha = ref_data["object"]["sha"]

    # Create new branch
    url = f"https://api.github.com/repos/{repo_full_name}/git/refs"
    data = {"ref": f"refs/heads/{branch_name}", "sha": base_sha}
    _api_request(url, token, method="POST", data=data)
    return base_sha

def create_or_update_file(installation_id: int, repo_full_name: str, branch: str,
                          path: str, content_b64: str, message: str) -> Dict:
    """Create or update a file in the repo on the given branch."""
    token = get_installation_token(installation_id)

    # Check if file exists to get its SHA
    url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}?ref={branch}"
    sha = None
    try:
        existing = _api_request(url, token)
        sha = existing.get("sha")
    except RuntimeError:
        pass  # File doesn't exist

    url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}"
    data = {
        "message": message,
        "content": content_b64,
        "branch": branch,
    }
    if sha:
        data["sha"] = sha

    return _api_request(url, token, method="PUT", data=data)

def create_pull_request(installation_id: int, repo_full_name: str,
                        head_branch: str, base_branch: str,
                        title: str, body: str) -> Dict:
    """Create a pull request."""
    token = get_installation_token(installation_id)
    url = f"https://api.github.com/repos/{repo_full_name}/pulls"
    data = {
        "title": title,
        "head": head_branch,
        "base": base_branch,
        "body": body,
    }
    return _api_request(url, token, method="POST", data=data)
PYEOF

  _ok "GitHub integration written"
}

# ------------------------------ DigitalOcean worker orchestration ------------

write_worker_orchestration() {
  _step "Write DigitalOcean worker orchestration module"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would write worker_orchestration.py"
    _ok "Worker orchestration (DRY_RUN)"
    return 0
  fi

  cat > "/opt/futilitys/app/control_plane/worker_orchestration.py" <<'PYEOF'
"""
DigitalOcean worker orchestration: create ephemeral droplets, delete on completion/TTL.
"""
import os
import json
import time
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

DO_TOKEN = os.environ.get("DIGITALOCEAN_TOKEN", "")
DO_REGION = os.environ.get("DO_REGION", "nyc3")
WORKER_SIZE = os.environ.get("WORKER_SIZE", "s-1vcpu-1gb")
WORKER_TTL_SECONDS = int(os.environ.get("WORKER_TTL_SECONDS", "300"))
DOMAIN = os.environ.get("DOMAIN", "")

# Worker image: use a prebuilt snapshot ID or a base Ubuntu image
# For production, create a snapshot with deps pre-installed for faster boot
WORKER_IMAGE = os.environ.get("WORKER_IMAGE", "ubuntu-22-04-x64")

def _do_request(endpoint: str, method: str = "GET", data: Optional[Dict] = None) -> Dict:
    """Make a DigitalOcean API request."""
    url = f"https://api.digitalocean.com/v2{endpoint}"
    headers = {
        "Authorization": f"Bearer {DO_TOKEN}",
        "Content-Type": "application/json",
    }
    body = json.dumps(data).encode("utf-8") if data else None

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            if resp.status == 204:
                return {}
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8") if e.fp else ""
        raise RuntimeError(f"DO API error {e.code}: {err_body}")

def generate_cloud_init(job_id: str, callback_url: str, payload_url: str,
                        repo_full_name: str, branch_name: str) -> str:
    """Generate cloud-init script for worker bootstrap."""
    return f'''#!/bin/bash
set -euo pipefail

export JOB_ID="{job_id}"
export CALLBACK_URL="{callback_url}"
export PAYLOAD_URL="{payload_url}"
export REPO_FULL_NAME="{repo_full_name}"
export BRANCH_NAME="{branch_name}"

LOG="/var/log/futilitys-worker.log"
exec > >(tee -a "$LOG") 2>&1

echo "[worker] Starting job $JOB_ID at $(date)"

# Notify control plane: worker started
curl -fsS -X POST "$CALLBACK_URL/callback/started" \\
  -H "Content-Type: application/json" \\
  -d '{{"job_id": "'"$JOB_ID"'", "status": "running"}}' || true

# Download payload
mkdir -p /tmp/payload
cd /tmp/payload
curl -fsS -o payload.zip "$PAYLOAD_URL" || {{
  curl -fsS -X POST "$CALLBACK_URL/callback/failed" \\
    -H "Content-Type: application/json" \\
    -d '{{"job_id": "'"$JOB_ID"'", "error": "payload download failed"}}'
  exit 1
}}

# Extract payload
unzip -o payload.zip || {{
  curl -fsS -X POST "$CALLBACK_URL/callback/failed" \\
    -H "Content-Type: application/json" \\
    -d '{{"job_id": "'"$JOB_ID"'", "error": "payload extraction failed"}}'
  exit 1
}}

echo "[worker] Payload extracted, files:"
ls -la

# Notify completion (actual git push happens via control plane in this simple model)
curl -fsS -X POST "$CALLBACK_URL/callback/completed" \\
  -H "Content-Type: application/json" \\
  -d '{{"job_id": "'"$JOB_ID"'", "status": "completed"}}'

echo "[worker] Job $JOB_ID completed at $(date)"
'''

def create_worker(job_id: str, callback_base_url: str, payload_url: str,
                  repo_full_name: str, branch_name: str) -> Dict[str, Any]:
    """Create an ephemeral worker droplet for a job."""
    name = f"futilitys-worker-{job_id[:8]}"
    cloud_init = generate_cloud_init(
        job_id=job_id,
        callback_url=callback_base_url,
        payload_url=payload_url,
        repo_full_name=repo_full_name,
        branch_name=branch_name,
    )

    data = {
        "name": name,
        "region": DO_REGION,
        "size": WORKER_SIZE,
        "image": WORKER_IMAGE,
        "user_data": cloud_init,
        "tags": ["futilitys-worker", f"job-{job_id}"],
    }

    resp = _do_request("/droplets", method="POST", data=data)
    droplet = resp.get("droplet", {})
    return {
        "droplet_id": droplet.get("id"),
        "name": name,
        "status": droplet.get("status"),
    }

def delete_worker(droplet_id: int) -> bool:
    """Delete a worker droplet."""
    try:
        _do_request(f"/droplets/{droplet_id}", method="DELETE")
        return True
    except Exception:
        return False

def get_droplet_info(droplet_id: int) -> Optional[Dict]:
    """Get droplet info."""
    try:
        resp = _do_request(f"/droplets/{droplet_id}")
        return resp.get("droplet")
    except Exception:
        return None

def list_worker_droplets() -> list:
    """List all futilitys worker droplets."""
    resp = _do_request("/droplets?tag_name=futilitys-worker")
    return resp.get("droplets", [])
PYEOF

  _ok "Worker orchestration written"
}

# ------------------------------ Job intake endpoints -------------------------

write_job_intake() {
  _step "Update Control Plane with job intake endpoints"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would update app.py with job endpoints"
    _ok "Job intake (DRY_RUN)"
    return 0
  fi

  # Add PyJWT to requirements
  if ! grep -q "PyJWT" "/opt/futilitys/app/control_plane/requirements.txt"; then
    echo "PyJWT==2.8.0" >> "/opt/futilitys/app/control_plane/requirements.txt"
    echo "cryptography>=3.4.0" >> "/opt/futilitys/app/control_plane/requirements.txt"
  fi

  # Write updated app with job intake
  cat > "/opt/futilitys/app/control_plane/app.py" <<'PYEOF'
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.hash import bcrypt
import os
import time
import uuid
import sqlite3
import json
import base64
from pathlib import Path
from typing import Optional
from itsdangerous import URLSafeSerializer

# Local modules
from github_integration import get_all_accessible_repos, create_branch, create_or_update_file, create_pull_request
from worker_orchestration import create_worker, delete_worker, list_worker_droplets, WORKER_TTL_SECONDS

APP_TITLE = "Futility's Control Plane"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)

DOMAIN = env("DOMAIN")
ADMIN_USER = env("ADMIN_USER")
ADMIN_PASS_HASH = env("ADMIN_PASS_HASH")
RETENTION_DAYS = int(env("RETENTION_DAYS", "7"))
BASE_BRANCH = env("BASE_BRANCH", "main")
INCOMING_MODE = env("INCOMING_MODE", "incoming_only")
SLACK_WEBHOOK_URL = env("SLACK_WEBHOOK_URL", "")

DB_FILE = "/var/lib/futilitys/futilitys.db"
JOBS_DIR = "/var/lib/futilitys/jobs"

SESSION_SECRET = env("SESSION_SECRET", "dev-fallback")
serializer = URLSafeSerializer(SESSION_SECRET, salt="futilitys-session")

app = FastAPI(title=APP_TITLE)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

# ----------------------- Database helpers -----------------------

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def log_event(job_id: Optional[str], event_type: str, details: dict = None):
    conn = get_db()
    conn.execute(
        "INSERT INTO events (job_id, event_type, details) VALUES (?, ?, ?)",
        (job_id, event_type, json.dumps(details or {}))
    )
    conn.commit()
    conn.close()

def update_job(job_id: str, **kwargs):
    conn = get_db()
    sets = ", ".join(f"{k} = ?" for k in kwargs.keys())
    values = list(kwargs.values()) + [job_id]
    conn.execute(f"UPDATE jobs SET {sets}, updated_at = datetime('now') WHERE id = ?", values)
    conn.commit()
    conn.close()

def get_job(job_id: str) -> Optional[dict]:
    conn = get_db()
    row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

# ----------------------- Auth helpers -----------------------

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

# ----------------------- Slack notification -----------------------

def notify_slack(message: str):
    if not SLACK_WEBHOOK_URL:
        return
    import urllib.request
    data = json.dumps({"text": message}).encode("utf-8")
    req = urllib.request.Request(SLACK_WEBHOOK_URL, data=data,
                                  headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass

# ----------------------- Routes -----------------------

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
    log_event(None, "admin_login", {"user": ADMIN_USER})
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

    # Fetch repos from GitHub App
    try:
        repos = get_all_accessible_repos()
    except Exception as e:
        repos = [{"id": "error", "full_name": f"(Error fetching repos: {e})"}]

    # Fetch recent jobs
    conn = get_db()
    jobs = conn.execute(
        "SELECT * FROM jobs ORDER BY created_at DESC LIMIT 20"
    ).fetchall()
    conn.close()

    return TEMPLATES.TemplateResponse("home.html", {
        "request": request,
        "domain": DOMAIN,
        "repos": repos,
        "jobs": [dict(j) for j in jobs],
        "base_branch": BASE_BRANCH,
        "incoming_mode": INCOMING_MODE,
        "retention_days": RETENTION_DAYS,
    })

@app.get("/api/repos")
def api_repos(request: Request):
    redir = require_login(request)
    if redir:
        raise HTTPException(status_code=401)
    try:
        repos = get_all_accessible_repos()
        return {"repos": repos}
    except Exception as e:
        return {"error": str(e), "repos": []}

@app.post("/api/jobs")
async def create_job(
    request: Request,
    background_tasks: BackgroundTasks,
    repo_full_name: str = Form(...),
    installation_id: int = Form(...),
    path_blocks: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    redir = require_login(request)
    if redir:
        raise HTTPException(status_code=401)

    job_id = str(uuid.uuid4())
    branch_name = f"intake/{job_id[:8]}"

    # Determine payload type
    payload_type = "pathblocks" if path_blocks and path_blocks.strip() else "zip"
    payload_size = 0

    # Save payload
    job_dir = Path(JOBS_DIR) / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    if file and file.filename:
        payload_type = "zip"
        payload_path = job_dir / "payload.zip"
        content = await file.read()
        payload_size = len(content)
        payload_path.write_bytes(content)
    elif path_blocks and path_blocks.strip():
        payload_type = "pathblocks"
        payload_path = job_dir / "pathblocks.txt"
        payload_path.write_text(path_blocks)
        payload_size = len(path_blocks.encode())
    else:
        raise HTTPException(status_code=400, detail="No payload provided (upload file or path blocks)")

    # Insert job record
    conn = get_db()
    conn.execute(
        """INSERT INTO jobs (id, repo_full_name, branch_name, payload_type, payload_size_bytes, status)
           VALUES (?, ?, ?, ?, ?, 'pending')""",
        (job_id, repo_full_name, branch_name, payload_type, payload_size)
    )
    conn.commit()
    conn.close()

    log_event(job_id, "job_created", {
        "repo": repo_full_name,
        "branch": branch_name,
        "payload_type": payload_type,
        "size": payload_size,
    })

    notify_slack(f"New job created: {job_id[:8]} for {repo_full_name}")

    # Process job in background
    background_tasks.add_task(process_job, job_id, repo_full_name, installation_id, branch_name, payload_type, job_dir)

    return {"job_id": job_id, "status": "pending", "branch": branch_name}

def process_job(job_id: str, repo_full_name: str, installation_id: int,
                branch_name: str, payload_type: str, job_dir: Path):
    """Process a job: create branch, push files, open PR."""
    try:
        update_job(job_id, status="running")
        log_event(job_id, "job_started", {})

        # Create branch
        create_branch(installation_id, repo_full_name, branch_name, BASE_BRANCH)
        log_event(job_id, "branch_created", {"branch": branch_name})

        # Parse and push files
        if payload_type == "pathblocks":
            pathblocks_file = job_dir / "pathblocks.txt"
            files = parse_path_blocks(pathblocks_file.read_text())
        else:
            # For ZIP, extract and enumerate files
            import zipfile
            zip_path = job_dir / "payload.zip"
            extract_dir = job_dir / "extracted"
            extract_dir.mkdir(exist_ok=True)
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(extract_dir)
            files = {}
            for f in extract_dir.rglob("*"):
                if f.is_file():
                    rel_path = f.relative_to(extract_dir)
                    files[str(rel_path)] = f.read_bytes()

        # Push each file under incoming/<job-id>/
        for rel_path, content in files.items():
            full_path = f"incoming/{job_id[:8]}/{rel_path}"
            if isinstance(content, bytes):
                content_b64 = base64.b64encode(content).decode()
            else:
                content_b64 = base64.b64encode(content.encode()).decode()

            create_or_update_file(
                installation_id, repo_full_name, branch_name,
                full_path, content_b64,
                f"Add {rel_path} via Futility's job {job_id[:8]}"
            )

        log_event(job_id, "files_pushed", {"count": len(files)})

        # Create PR
        pr_title = f"[Futility's] Intake {job_id[:8]}"
        pr_body = f"Automated intake from Futility's Control Plane.\n\nJob ID: `{job_id}`\nFiles: {len(files)}"
        pr_resp = create_pull_request(
            installation_id, repo_full_name,
            branch_name, BASE_BRANCH,
            pr_title, pr_body
        )
        pr_url = pr_resp.get("html_url", "")

        update_job(job_id, status="success", pr_url=pr_url)
        log_event(job_id, "pr_opened", {"url": pr_url})
        notify_slack(f"Job {job_id[:8]} completed: {pr_url}")

    except Exception as e:
        update_job(job_id, status="failed", error_message=str(e))
        log_event(job_id, "job_failed", {"error": str(e)})
        notify_slack(f"Job {job_id[:8]} failed: {e}")

def parse_path_blocks(text: str) -> dict:
    """Parse FILE: path blocks into {path: content} dict."""
    files = {}
    current_path = None
    current_lines = []

    for line in text.split("\n"):
        if line.startswith("FILE:"):
            if current_path:
                files[current_path] = "\n".join(current_lines)
            current_path = line[5:].strip()
            current_lines = []
        else:
            if current_path is not None:
                current_lines.append(line)

    if current_path:
        files[current_path] = "\n".join(current_lines)

    return files

@app.get("/api/jobs/{job_id}")
def get_job_status(job_id: str, request: Request):
    redir = require_login(request)
    if redir:
        raise HTTPException(status_code=401)
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job

@app.get("/jobs/{job_id}/payload")
def download_payload(job_id: str, request: Request):
    """Download job payload (for worker callback)."""
    job_dir = Path(JOBS_DIR) / job_id
    zip_path = job_dir / "payload.zip"
    if zip_path.exists():
        return FileResponse(zip_path, filename="payload.zip")
    raise HTTPException(status_code=404, detail="Payload not found")

# ----------------------- Worker callbacks -----------------------

@app.post("/callback/started")
async def callback_started(request: Request):
    data = await request.json()
    job_id = data.get("job_id")
    if job_id:
        update_job(job_id, status="running")
        log_event(job_id, "worker_started", data)
    return {"ok": True}

@app.post("/callback/completed")
async def callback_completed(request: Request):
    data = await request.json()
    job_id = data.get("job_id")
    if job_id:
        update_job(job_id, status="success")
        log_event(job_id, "worker_completed", data)
    return {"ok": True}

@app.post("/callback/failed")
async def callback_failed(request: Request):
    data = await request.json()
    job_id = data.get("job_id")
    error = data.get("error", "unknown")
    if job_id:
        update_job(job_id, status="failed", error_message=error)
        log_event(job_id, "worker_failed", data)
    return {"ok": True}
PYEOF

  _ok "Job intake endpoints written"
}

# ------------------------------ Update templates -----------------------------

update_templates() {
  _step "Update home template with functional job intake"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would update home.html template"
    _ok "Templates (DRY_RUN)"
    return 0
  fi

  cat > "/opt/futilitys/app/control_plane/templates/home.html" <<'EOF'
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Futility's — Wizard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; background: #fafafa; }
      .top { display:flex; justify-content:space-between; align-items:center; gap: 12px; flex-wrap: wrap; }
      .pill { padding: 6px 10px; border: 1px solid #ddd; border-radius: 999px; font-size: 13px; color: #444; background: #fff; }
      .card { margin-top: 14px; padding: 14px 16px; border: 1px solid #ddd; border-radius: 10px; max-width: 920px; background: #fff; }
      .row { display:flex; gap: 10px; flex-wrap: wrap; }
      select, input[type="file"], textarea { width: 100%; padding: 10px; font-size: 16px; margin-top: 6px; }
      textarea { min-height: 170px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
      label { display:block; margin-top: 10px; font-weight: 650; }
      button { margin-top: 12px; padding: 10px 14px; font-size: 16px; cursor: pointer; }
      button:disabled { opacity: 0.5; cursor: not-allowed; }
      .muted { color: #666; font-size: 13px; }
      code { background: #f0f0f0; padding: 2px 6px; border-radius: 6px; }
      table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }
      th, td { text-align: left; padding: 8px; border-bottom: 1px solid #eee; }
      th { font-weight: 600; color: #555; }
      .status-pending { color: #888; }
      .status-running { color: #0066cc; }
      .status-success { color: #228b22; }
      .status-failed { color: #cc0000; }
      a { color: #0066cc; }
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
      <div class="pill">Mode: incoming/&lt;job-id&gt;</div>
      <div class="pill">Retention: {{ retention_days }} days</div>
    </div>

    <div class="card">
      <h3>Create Job</h3>
      <form method="post" action="/api/jobs" enctype="multipart/form-data" id="jobForm">
        <label>Target Repository</label>
        <select name="repo_full_name" id="repoSelect" required>
          <option value="">-- Select a repository --</option>
          {% for r in repos %}
            <option value="{{ r.full_name }}" data-installation="{{ r.installation_id }}">
              {{ r.full_name }}{% if r.private %} (private){% endif %}
            </option>
          {% endfor %}
        </select>
        <input type="hidden" name="installation_id" id="installationId">

        <label>Upload ZIP or file</label>
        <input type="file" name="file" accept=".zip,.txt,.json,.md,.py,.js,.ts,.html,.css">
        <div class="muted">Upload a ZIP archive or single file.</div>

        <label>OR paste Path Blocks</label>
        <textarea name="path_blocks" placeholder="FILE: docs/example.txt
hello world

FILE: src/config.json
{&quot;key&quot;: &quot;value&quot;}"></textarea>
        <div class="muted">Use <code>FILE: path/to/file</code> syntax to define multiple files.</div>

        <button type="submit">Create Job</button>
      </form>
    </div>

    <div class="card">
      <h3>Recent Jobs</h3>
      {% if jobs %}
      <table>
        <tr>
          <th>Job ID</th>
          <th>Repository</th>
          <th>Status</th>
          <th>Branch</th>
          <th>PR</th>
          <th>Created</th>
        </tr>
        {% for job in jobs %}
        <tr>
          <td><code>{{ job.id[:8] }}</code></td>
          <td>{{ job.repo_full_name }}</td>
          <td class="status-{{ job.status }}">{{ job.status }}</td>
          <td><code>{{ job.branch_name or '-' }}</code></td>
          <td>{% if job.pr_url %}<a href="{{ job.pr_url }}" target="_blank">View PR</a>{% else %}-{% endif %}</td>
          <td class="muted">{{ job.created_at }}</td>
        </tr>
        {% endfor %}
      </table>
      {% else %}
      <div class="muted">No jobs yet.</div>
      {% endif %}
    </div>

    <script>
      document.getElementById('repoSelect').addEventListener('change', function() {
        var selected = this.options[this.selectedIndex];
        document.getElementById('installationId').value = selected.dataset.installation || '';
      });
    </script>
  </body>
</html>
EOF

  _ok "Templates updated"
}

# ------------------------------ TTL sweeper + retention purge ----------------

write_sweeper_timer() {
  _step "Write TTL sweeper and retention purge systemd timers"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would write sweeper scripts and timers"
    _ok "Sweeper/purge timers (DRY_RUN)"
    return 0
  fi

  # TTL sweeper script
  cat > "/opt/futilitys/bin/ttl-sweeper.sh" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

# Sweeper: delete workers exceeding TTL
# This is a simple implementation; production should use the worker_orchestration module

source /opt/futilitys/infra/futilitys.env

DO_TOKEN="${DIGITALOCEAN_TOKEN:-}"
TTL="${WORKER_TTL_SECONDS:-300}"

if [ -z "$DO_TOKEN" ]; then
  echo "[sweeper] No DO token, skipping"
  exit 0
fi

NOW=$(date +%s)

# List worker droplets
DROPLETS=$(curl -sS -H "Authorization: Bearer $DO_TOKEN" \
  "https://api.digitalocean.com/v2/droplets?tag_name=futilitys-worker" | jq -r '.droplets[] | "\(.id) \(.created_at)"')

while read -r line; do
  [ -z "$line" ] && continue
  ID=$(echo "$line" | awk '{print $1}')
  CREATED=$(echo "$line" | awk '{print $2}')
  CREATED_TS=$(date -d "$CREATED" +%s 2>/dev/null || echo 0)
  AGE=$((NOW - CREATED_TS))

  if [ "$AGE" -gt "$TTL" ]; then
    echo "[sweeper] Deleting droplet $ID (age: ${AGE}s > TTL: ${TTL}s)"
    curl -sS -X DELETE -H "Authorization: Bearer $DO_TOKEN" \
      "https://api.digitalocean.com/v2/droplets/$ID" || true
  fi
done <<< "$DROPLETS"

echo "[sweeper] Done at $(date)"
BASH
  chmod +x "/opt/futilitys/bin/ttl-sweeper.sh"

  # Retention purge script
  cat > "/opt/futilitys/bin/retention-purge.sh" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

# Purge jobs older than RETENTION_DAYS

source /opt/futilitys/infra/futilitys.env

RETENTION="${RETENTION_DAYS:-7}"
DB="/var/lib/futilitys/futilitys.db"
JOBS_DIR="/var/lib/futilitys/jobs"

if [ ! -f "$DB" ]; then
  echo "[purge] No database, skipping"
  exit 0
fi

# Find old jobs
OLD_JOBS=$(sqlite3 "$DB" "SELECT id FROM jobs WHERE created_at < datetime('now', '-${RETENTION} days');")

for JOB_ID in $OLD_JOBS; do
  echo "[purge] Deleting job $JOB_ID"
  rm -rf "${JOBS_DIR}/${JOB_ID}" || true
  sqlite3 "$DB" "DELETE FROM events WHERE job_id = '$JOB_ID';"
  sqlite3 "$DB" "DELETE FROM jobs WHERE id = '$JOB_ID';"
done

echo "[purge] Done at $(date)"
BASH
  chmod +x "/opt/futilitys/bin/retention-purge.sh"

  # systemd timer for sweeper (every minute)
  cat > "/etc/systemd/system/futilitys-sweeper.service" <<EOF
[Unit]
Description=Futility's TTL Sweeper

[Service]
Type=oneshot
ExecStart=/opt/futilitys/bin/ttl-sweeper.sh
EOF

  cat > "/etc/systemd/system/futilitys-sweeper.timer" <<EOF
[Unit]
Description=Run Futility's TTL Sweeper every minute

[Timer]
OnBootSec=60
OnUnitActiveSec=60

[Install]
WantedBy=timers.target
EOF

  # systemd timer for retention purge (daily)
  cat > "/etc/systemd/system/futilitys-purge.service" <<EOF
[Unit]
Description=Futility's Retention Purge

[Service]
Type=oneshot
ExecStart=/opt/futilitys/bin/retention-purge.sh
EOF

  cat > "/etc/systemd/system/futilitys-purge.timer" <<EOF
[Unit]
Description=Run Futility's Retention Purge daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now futilitys-sweeper.timer
  systemctl enable --now futilitys-purge.timer

  _ok "Sweeper and purge timers installed"
}

# ------------------------------ Install additional deps ----------------------

install_additional_deps() {
  _step "Install additional Python dependencies"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would pip install additional deps"
    _ok "Additional deps (DRY_RUN)"
    return 0
  fi

  "$VENV_DIR/bin/pip" install -r "/opt/futilitys/app/control_plane/requirements.txt"
  _ok "Additional deps installed"
}

# ------------------------------ Restart service ------------------------------

restart_control_plane() {
  _step "Restart Control Plane service"
  chown -R "$RUN_USER:$RUN_USER" "/opt/futilitys/app"
  run systemctl restart futilitys-control-plane
  sleep 2
  run systemctl --no-pager --full status futilitys-control-plane | head -20 || true
  _ok "Control Plane restarted"
}

# ------------------------------ Main -----------------------------------------

main() {
  as_root
  log_setup

  _step "FUTILITY'S — Superscript 3/4 — WORKER + ORCHESTRATION"

  load_config
  run mkdir -p "/opt/futilitys/bin"

  setup_database
  write_github_integration
  write_worker_orchestration
  write_job_intake
  update_templates
  install_additional_deps
  write_sweeper_timer
  restart_control_plane

  _ok "Superscript 3/4 complete."
  _info ""
  _info "What's now available:"
  _info " - Job intake: upload ZIP or paste Path Blocks"
  _info " - Repo dropdown populated from GitHub App installations"
  _info " - SQLite database for jobs + events audit log"
  _info " - Worker orchestration (DO droplet create/delete)"
  _info " - TTL sweeper (every minute)"
  _info " - Retention purge (daily, ${RETENTION_DAYS} days)"
  _info " - Slack notifications"
  _info ""
  _info "NEXT (Superscript 4/4) TODOs:"
  _info " - Binary payload handling improvements"
  _info " - ZIP-slip protection"
  _info " - Tailscale integration for secure callbacks"
  _info " - UI polish and repo allowlisting"
  _info " - End-to-end verification"
}

main "$@"
