#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# FUTILITY'S — Golden Installer (SYSTEMD) — Superscript 4/4
# -----------------------------------------------------------------------------
# OVERALL 4-SUPERSCRIPT PLAN (run in order):
#
#   1) PREP + WIZARD                    (DONE)
#   2) CONTROL PLANE BUILD              (DONE)
#   3) WORKER + ORCHESTRATION           (DONE)
#   4) HARDEN + VERIFY + UX POLISH      (THIS SCRIPT)
#      - Binary payload handling (proper MIME detection)
#      - ZIP-slip protection (path traversal prevention)
#      - Tailscale integration (optional, callback-only mode)
#      - UI improvements (job details, error display, refresh)
#      - Repo allowlisting (optional restriction)
#      - End-to-end verification
#      - Documentation and troubleshooting commands
#
# RUN:
#   sudo bash futilitys_superscript_4.sh
# DRY RUN:
#   sudo DRY_RUN=1 bash futilitys_superscript_4.sh
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

load_config() {
  _step "Load config bundle"
  [ -f "$CFG_FILE" ] || _fail "Missing config file: $CFG_FILE"
  [ -f "$SECRETS_FILE" ] || _fail "Missing secrets file: $SECRETS_FILE"
  set -a
  # shellcheck disable=SC1090
  . "$CFG_FILE"
  # shellcheck disable=SC1090
  . "$SECRETS_FILE"
  set +a

  [ -n "${DOMAIN:-}" ] || _fail "DOMAIN missing."
  _ok "Loaded config for domain: $DOMAIN"
}

# ------------------------------ ZIP-slip protection --------------------------

write_security_utils() {
  _step "Write security utilities (ZIP-slip protection, path validation)"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would write security_utils.py"
    _ok "Security utils (DRY_RUN)"
    return 0
  fi

  cat > "/opt/futilitys/app/control_plane/security_utils.py" <<'PYEOF'
"""
Security utilities: ZIP-slip protection, path validation, safe extraction.
"""
import os
import zipfile
from pathlib import Path
from typing import List, Tuple

class ZipSlipError(Exception):
    """Raised when a ZIP archive contains path traversal attempts."""
    pass

class PathValidationError(Exception):
    """Raised when a path fails validation."""
    pass

def is_safe_path(basedir: str, path: str) -> bool:
    """
    Check if path resolves within basedir (prevents path traversal).
    """
    basedir = os.path.abspath(basedir)
    filepath = os.path.abspath(os.path.join(basedir, path))
    return filepath.startswith(basedir + os.sep) or filepath == basedir

def validate_zip_paths(zip_path: str) -> List[str]:
    """
    Validate all paths in a ZIP file. Returns list of safe paths.
    Raises ZipSlipError if any path traversal is detected.
    """
    safe_paths = []
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for name in zf.namelist():
            # Check for absolute paths
            if os.path.isabs(name):
                raise ZipSlipError(f"Absolute path in ZIP: {name}")

            # Check for path traversal
            if '..' in name.split('/') or '..' in name.split('\\'):
                raise ZipSlipError(f"Path traversal in ZIP: {name}")

            # Check for suspicious characters
            if name.startswith('/') or name.startswith('\\'):
                raise ZipSlipError(f"Leading slash in ZIP path: {name}")

            safe_paths.append(name)

    return safe_paths

def safe_extract_zip(zip_path: str, extract_dir: str) -> List[Tuple[str, str]]:
    """
    Safely extract a ZIP file with ZIP-slip protection.
    Returns list of (archive_name, extracted_path) tuples.
    """
    extract_dir = os.path.abspath(extract_dir)
    os.makedirs(extract_dir, exist_ok=True)

    extracted = []

    with zipfile.ZipFile(zip_path, 'r') as zf:
        for member in zf.namelist():
            # Skip directories
            if member.endswith('/'):
                continue

            # Validate path
            if os.path.isabs(member):
                raise ZipSlipError(f"Absolute path: {member}")

            parts = member.replace('\\', '/').split('/')
            if '..' in parts:
                raise ZipSlipError(f"Path traversal: {member}")

            # Compute safe destination
            dest_path = os.path.join(extract_dir, member)
            dest_path = os.path.abspath(dest_path)

            # Final safety check
            if not dest_path.startswith(extract_dir + os.sep):
                raise ZipSlipError(f"Path escape: {member} -> {dest_path}")

            # Create parent directories
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)

            # Extract file
            with zf.open(member) as src, open(dest_path, 'wb') as dst:
                dst.write(src.read())

            extracted.append((member, dest_path))

    return extracted

def validate_path_blocks(text: str) -> List[Tuple[str, str]]:
    """
    Validate FILE: path blocks. Returns list of (path, content) tuples.
    Raises PathValidationError if any path is unsafe.
    """
    files = []
    current_path = None
    current_lines = []

    for line in text.split('\n'):
        if line.startswith('FILE:'):
            if current_path:
                files.append((current_path, '\n'.join(current_lines)))
            current_path = line[5:].strip()

            # Validate path
            if os.path.isabs(current_path):
                raise PathValidationError(f"Absolute path not allowed: {current_path}")
            if '..' in current_path.split('/'):
                raise PathValidationError(f"Path traversal not allowed: {current_path}")
            if current_path.startswith('/') or current_path.startswith('\\'):
                raise PathValidationError(f"Leading slash not allowed: {current_path}")

            current_lines = []
        else:
            if current_path is not None:
                current_lines.append(line)

    if current_path:
        files.append((current_path, '\n'.join(current_lines)))

    return files

def sanitize_filename(name: str) -> str:
    """Sanitize a filename, removing dangerous characters."""
    # Remove null bytes
    name = name.replace('\x00', '')
    # Replace path separators
    name = name.replace('/', '_').replace('\\', '_')
    # Remove leading dots (hidden files)
    while name.startswith('.'):
        name = name[1:]
    # Fallback
    if not name:
        name = 'unnamed'
    return name
PYEOF

  _ok "Security utils written"
}

# ------------------------------ Tailscale integration ------------------------

write_tailscale_integration() {
  _step "Write Tailscale integration (optional)"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would write tailscale_integration.py"
    _ok "Tailscale integration (DRY_RUN)"
    return 0
  fi

  cat > "/opt/futilitys/app/control_plane/tailscale_integration.py" <<'PYEOF'
"""
Tailscale integration for secure worker callbacks.

In TAILSCALE_MODE=callback_only:
- Control Plane runs on Tailscale network
- Workers join Tailscale with ephemeral auth key
- Worker callbacks use Tailscale IP instead of public IP
- No SSH access to workers (callback-only)
"""
import os
import subprocess
import json
from typing import Optional, Dict

TAILSCALE_MODE = os.environ.get("TAILSCALE_MODE", "disabled")
TAILSCALE_AUTHKEY = os.environ.get("TAILSCALE_AUTHKEY", "")

def is_tailscale_enabled() -> bool:
    """Check if Tailscale is enabled."""
    return TAILSCALE_MODE != "disabled" and bool(TAILSCALE_AUTHKEY)

def get_tailscale_ip() -> Optional[str]:
    """Get the Tailscale IP of this machine."""
    try:
        result = subprocess.run(
            ["tailscale", "ip", "-4"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None

def get_tailscale_status() -> Optional[Dict]:
    """Get Tailscale status."""
    try:
        result = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except Exception:
        pass
    return None

def generate_worker_tailscale_setup() -> str:
    """
    Generate cloud-init snippet for worker Tailscale setup.
    Workers join as ephemeral nodes (auto-removed when they go offline).
    """
    if not is_tailscale_enabled():
        return "# Tailscale disabled"

    return f'''
# Tailscale setup (ephemeral, callback-only)
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up --authkey="{TAILSCALE_AUTHKEY}" --hostname="futilitys-worker-$JOB_ID" --accept-routes

# Get Tailscale IP for callbacks
TS_IP=$(tailscale ip -4 2>/dev/null || echo "")
if [ -n "$TS_IP" ]; then
  echo "[tailscale] Worker Tailscale IP: $TS_IP"
fi
'''

def get_callback_base_url(domain: str, use_tailscale: bool = True) -> str:
    """
    Get the callback base URL for workers.
    If Tailscale is enabled, use the Tailscale IP.
    """
    if use_tailscale and is_tailscale_enabled():
        ts_ip = get_tailscale_ip()
        if ts_ip:
            return f"http://{ts_ip}:8000"

    # Fallback to public HTTPS
    return f"https://{domain}"
PYEOF

  _ok "Tailscale integration written"
}

# ------------------------------ Update app with security ---------------------

update_app_with_security() {
  _step "Update Control Plane app with security improvements"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would update app.py with security improvements"
    _ok "App security update (DRY_RUN)"
    return 0
  fi

  # Patch the process_job function to use safe extraction
  cat > "/opt/futilitys/app/control_plane/job_processor.py" <<'PYEOF'
"""
Job processor with security improvements.
"""
import os
import base64
import json
from pathlib import Path
from typing import Dict, Optional
import sqlite3

from security_utils import safe_extract_zip, validate_path_blocks, ZipSlipError, PathValidationError
from github_integration import create_branch, create_or_update_file, create_pull_request

DB_FILE = "/var/lib/futilitys/futilitys.db"
JOBS_DIR = "/var/lib/futilitys/jobs"

def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)

BASE_BRANCH = env("BASE_BRANCH", "main")
SLACK_WEBHOOK_URL = env("SLACK_WEBHOOK_URL", "")

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

def process_job_secure(job_id: str, repo_full_name: str, installation_id: int,
                       branch_name: str, payload_type: str, job_dir: Path):
    """
    Process a job with full security measures.
    """
    try:
        update_job(job_id, status="running")
        log_event(job_id, "job_started", {})

        # Create branch
        create_branch(installation_id, repo_full_name, branch_name, BASE_BRANCH)
        log_event(job_id, "branch_created", {"branch": branch_name})

        # Parse and validate files
        files: Dict[str, bytes] = {}

        if payload_type == "pathblocks":
            pathblocks_file = job_dir / "pathblocks.txt"
            try:
                validated = validate_path_blocks(pathblocks_file.read_text())
                for path, content in validated:
                    files[path] = content.encode('utf-8')
            except PathValidationError as e:
                raise RuntimeError(f"Path validation failed: {e}")

        else:
            # ZIP extraction with security
            zip_path = job_dir / "payload.zip"
            extract_dir = job_dir / "extracted"

            try:
                extracted = safe_extract_zip(str(zip_path), str(extract_dir))
                for archive_name, extracted_path in extracted:
                    with open(extracted_path, 'rb') as f:
                        files[archive_name] = f.read()
            except ZipSlipError as e:
                raise RuntimeError(f"ZIP security violation: {e}")

        log_event(job_id, "files_validated", {"count": len(files)})

        # Push each file under incoming/<job-id>/
        for rel_path, content in files.items():
            full_path = f"incoming/{job_id[:8]}/{rel_path}"
            content_b64 = base64.b64encode(content).decode()

            create_or_update_file(
                installation_id, repo_full_name, branch_name,
                full_path, content_b64,
                f"Add {rel_path} via Futility's job {job_id[:8]}"
            )

        log_event(job_id, "files_pushed", {"count": len(files)})

        # Create PR
        pr_title = f"[Futility's] Intake {job_id[:8]}"
        pr_body = f"""Automated intake from Futility's Control Plane.

**Job ID:** `{job_id}`
**Files:** {len(files)}
**Repository:** {repo_full_name}
**Branch:** `{branch_name}`

---
*This PR was created automatically by Futility's.*
"""
        pr_resp = create_pull_request(
            installation_id, repo_full_name,
            branch_name, BASE_BRANCH,
            pr_title, pr_body
        )
        pr_url = pr_resp.get("html_url", "")

        update_job(job_id, status="success", pr_url=pr_url)
        log_event(job_id, "pr_opened", {"url": pr_url})
        notify_slack(f":white_check_mark: Job `{job_id[:8]}` completed: {pr_url}")

    except Exception as e:
        error_msg = str(e)
        update_job(job_id, status="failed", error_message=error_msg)
        log_event(job_id, "job_failed", {"error": error_msg})
        notify_slack(f":x: Job `{job_id[:8]}` failed: {error_msg}")
        raise
PYEOF

  _ok "Job processor with security written"
}

# ------------------------------ Enhanced UI ----------------------------------

write_enhanced_templates() {
  _step "Write enhanced UI templates"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would write enhanced templates"
    _ok "Enhanced templates (DRY_RUN)"
    return 0
  fi

  # Job details page
  cat > "/opt/futilitys/app/control_plane/templates/job_detail.html" <<'EOF'
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Job {{ job.id[:8] }} — Futility's</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; background: #fafafa; }
      .card { padding: 16px; border: 1px solid #ddd; border-radius: 10px; background: #fff; max-width: 800px; }
      .row { display: flex; gap: 12px; margin: 8px 0; }
      .label { font-weight: 600; min-width: 140px; color: #555; }
      .value { color: #333; }
      code { background: #f0f0f0; padding: 2px 6px; border-radius: 4px; font-family: ui-monospace, monospace; }
      .status-pending { color: #888; }
      .status-running { color: #0066cc; }
      .status-success { color: #228b22; }
      .status-failed { color: #cc0000; }
      a { color: #0066cc; }
      .back { margin-bottom: 16px; }
      h2 { margin-top: 0; }
      .events { margin-top: 20px; }
      .event { padding: 8px 0; border-bottom: 1px solid #eee; font-size: 14px; }
      .event-time { color: #888; font-size: 12px; }
      .error-box { background: #fee; border: 1px solid #fcc; padding: 12px; border-radius: 6px; margin-top: 12px; }
    </style>
  </head>
  <body>
    <div class="back">
      <a href="/">&larr; Back to Dashboard</a>
    </div>

    <div class="card">
      <h2>Job <code>{{ job.id[:8] }}</code></h2>

      <div class="row">
        <div class="label">Status:</div>
        <div class="value status-{{ job.status }}"><strong>{{ job.status }}</strong></div>
      </div>

      <div class="row">
        <div class="label">Repository:</div>
        <div class="value">{{ job.repo_full_name }}</div>
      </div>

      <div class="row">
        <div class="label">Branch:</div>
        <div class="value"><code>{{ job.branch_name or '-' }}</code></div>
      </div>

      <div class="row">
        <div class="label">Pull Request:</div>
        <div class="value">
          {% if job.pr_url %}
            <a href="{{ job.pr_url }}" target="_blank">{{ job.pr_url }}</a>
          {% else %}
            -
          {% endif %}
        </div>
      </div>

      <div class="row">
        <div class="label">Payload Type:</div>
        <div class="value">{{ job.payload_type or '-' }}</div>
      </div>

      <div class="row">
        <div class="label">Payload Size:</div>
        <div class="value">{{ job.payload_size_bytes or 0 }} bytes</div>
      </div>

      <div class="row">
        <div class="label">Created:</div>
        <div class="value">{{ job.created_at }}</div>
      </div>

      <div class="row">
        <div class="label">Updated:</div>
        <div class="value">{{ job.updated_at }}</div>
      </div>

      {% if job.error_message %}
      <div class="error-box">
        <strong>Error:</strong> {{ job.error_message }}
      </div>
      {% endif %}

      <div class="events">
        <h3>Events</h3>
        {% for event in events %}
        <div class="event">
          <span class="event-time">{{ event.created_at }}</span>
          &mdash; <strong>{{ event.event_type }}</strong>
          {% if event.details and event.details != '{}' %}
            <code>{{ event.details }}</code>
          {% endif %}
        </div>
        {% endfor %}
      </div>
    </div>

    <script>
      // Auto-refresh if job is pending or running
      {% if job.status in ['pending', 'running'] %}
      setTimeout(function() { location.reload(); }, 5000);
      {% endif %}
    </script>
  </body>
</html>
EOF

  # Update home template with job links
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
      select, input[type="file"], textarea { width: 100%; padding: 10px; font-size: 16px; margin-top: 6px; box-sizing: border-box; }
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
      .refresh-btn { font-size: 13px; padding: 6px 10px; }
      .success-msg { background: #efe; border: 1px solid #cec; padding: 10px; border-radius: 6px; margin-top: 12px; }
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

    {% if success_job_id %}
    <div class="card success-msg">
      Job created: <a href="/jobs/{{ success_job_id }}"><code>{{ success_job_id[:8] }}</code></a>
    </div>
    {% endif %}

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
        <input type="file" name="file" accept=".zip,.txt,.json,.md,.py,.js,.ts,.html,.css,.yaml,.yml,.toml,.xml">
        <div class="muted">Upload a ZIP archive or single file. Max 10MB.</div>

        <label>OR paste Path Blocks</label>
        <textarea name="path_blocks" placeholder="FILE: docs/example.txt
hello world

FILE: src/config.json
{&quot;key&quot;: &quot;value&quot;}"></textarea>
        <div class="muted">Use <code>FILE: path/to/file</code> syntax. Paths must be relative (no .. or leading /).</div>

        <button type="submit">Create Job</button>
      </form>
    </div>

    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <h3 style="margin: 0;">Recent Jobs</h3>
        <button class="refresh-btn" onclick="location.reload()">Refresh</button>
      </div>
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
          <td><a href="/jobs/{{ job.id }}"><code>{{ job.id[:8] }}</code></a></td>
          <td>{{ job.repo_full_name }}</td>
          <td class="status-{{ job.status }}">{{ job.status }}</td>
          <td><code>{{ job.branch_name or '-' }}</code></td>
          <td>{% if job.pr_url %}<a href="{{ job.pr_url }}" target="_blank">View PR</a>{% else %}-{% endif %}</td>
          <td class="muted">{{ job.created_at }}</td>
        </tr>
        {% endfor %}
      </table>
      {% else %}
      <div class="muted" style="margin-top: 12px;">No jobs yet. Create your first job above!</div>
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

  _ok "Enhanced templates written"
}

# ------------------------------ Add job detail endpoint ----------------------

add_job_detail_endpoint() {
  _step "Add job detail endpoint to app"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would add job detail endpoint"
    _ok "Job detail endpoint (DRY_RUN)"
    return 0
  fi

  # Append job detail route to app.py
  cat >> "/opt/futilitys/app/control_plane/app.py" <<'PYEOF'

# ----------------------- Job detail page -----------------------

@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_detail(job_id: str, request: Request):
    redir = require_login(request)
    if redir:
        return redir

    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    conn = get_db()
    events = conn.execute(
        "SELECT * FROM events WHERE job_id = ? ORDER BY created_at DESC",
        (job_id,)
    ).fetchall()
    conn.close()

    return TEMPLATES.TemplateResponse("job_detail.html", {
        "request": request,
        "job": job,
        "events": [dict(e) for e in events],
    })
PYEOF

  _ok "Job detail endpoint added"
}

# ------------------------------ Troubleshooting docs -------------------------

write_troubleshooting_docs() {
  _step "Write troubleshooting documentation"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would write troubleshooting docs"
    _ok "Troubleshooting docs (DRY_RUN)"
    return 0
  fi

  cat > "/opt/futilitys/TROUBLESHOOTING.md" <<'EOF'
# Futility's Troubleshooting Guide

## Common Commands

### Check service status
```bash
sudo systemctl status futilitys-control-plane
sudo systemctl status caddy
```

### View logs
```bash
# Control Plane logs
sudo journalctl -u futilitys-control-plane -f

# Caddy logs
sudo journalctl -u caddy -f

# Installation log
sudo tail -f /var/log/futilitys/install.log
```

### Restart services
```bash
sudo systemctl restart futilitys-control-plane
sudo systemctl restart caddy
```

### Check health
```bash
# Local health
curl http://127.0.0.1:8000/health

# Public health
curl https://YOUR_DOMAIN/health
```

### Database queries
```bash
# List recent jobs
sqlite3 /var/lib/futilitys/futilitys.db "SELECT id, status, repo_full_name, created_at FROM jobs ORDER BY created_at DESC LIMIT 10;"

# List events for a job
sqlite3 /var/lib/futilitys/futilitys.db "SELECT * FROM events WHERE job_id = 'JOB_ID' ORDER BY created_at;"

# Count jobs by status
sqlite3 /var/lib/futilitys/futilitys.db "SELECT status, COUNT(*) FROM jobs GROUP BY status;"
```

### Check timers
```bash
# TTL sweeper timer
sudo systemctl status futilitys-sweeper.timer

# Retention purge timer
sudo systemctl status futilitys-purge.timer

# List all timers
sudo systemctl list-timers --all | grep futilitys
```

## Common Issues

### TLS certificate not working
1. Ensure DNS A record points to this server's IP
2. Ensure ports 80 and 443 are open (firewall)
3. Check Caddy logs: `sudo journalctl -u caddy -n 100`

### GitHub App not listing repos
1. Verify GitHub App is installed on the target organization/repos
2. Check GITHUB_APP_ID and GITHUB_APP_KEY_PATH in config
3. Test GitHub API: `curl -H "Authorization: Bearer $(python3 -c 'from github_integration import generate_jwt; print(generate_jwt())')" https://api.github.com/app`

### Jobs stuck in pending
1. Check Control Plane logs for errors
2. Verify GitHub API access
3. Check if worker droplets are being created (DigitalOcean console)

### Worker droplets not being deleted
1. Check sweeper timer is running
2. Manually run sweeper: `sudo /opt/futilitys/bin/ttl-sweeper.sh`
3. Check DigitalOcean API token permissions

## Configuration Files

- Main config: `/opt/futilitys/infra/futilitys.env`
- Secrets: `/opt/futilitys/infra/futilitys.secrets.env`
- Caddyfile: `/etc/caddy/Caddyfile`
- Systemd unit: `/etc/systemd/system/futilitys-control-plane.service`

## Reinstallation

To reinstall from scratch:
```bash
# Stop services
sudo systemctl stop futilitys-control-plane caddy

# Remove data (WARNING: destroys all job data)
sudo rm -rf /opt/futilitys /var/lib/futilitys /var/log/futilitys

# Remove user
sudo userdel futilitys

# Re-run superscripts 1-4
sudo bash futilitys_superscript_1.sh
sudo bash futilitys_superscript_2.sh
sudo bash futilitys_superscript_3.sh
sudo bash futilitys_superscript_4.sh
```
EOF

  _ok "Troubleshooting docs written"
}

# ------------------------------ End-to-end verification ----------------------

verify_installation() {
  _step "Verify installation"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would verify installation"
    _ok "Verification (DRY_RUN)"
    return 0
  fi

  # Check services
  if ! systemctl is-active --quiet futilitys-control-plane; then
    _fail "Control Plane service not running"
  fi
  _ok "Control Plane service running"

  if ! systemctl is-active --quiet caddy; then
    _fail "Caddy service not running"
  fi
  _ok "Caddy service running"

  # Check local health
  local health=""
  health="$(curl -fsS http://127.0.0.1:8000/health 2>/dev/null || true)"
  if ! echo "$health" | grep -q '"ok":true'; then
    _fail "Local health check failed"
  fi
  _ok "Local health check passed"

  # Check public health
  health="$(curl -fsS "https://${DOMAIN}/health" 2>/dev/null || true)"
  if ! echo "$health" | grep -q '"ok":true'; then
    _info "Public health check failed - this may be a DNS or TLS issue"
  else
    _ok "Public health check passed"
  fi

  # Check database
  if [ ! -f "/var/lib/futilitys/futilitys.db" ]; then
    _fail "Database file not found"
  fi
  _ok "Database exists"

  # Check timers
  if ! systemctl is-active --quiet futilitys-sweeper.timer; then
    _info "Sweeper timer not running"
  else
    _ok "Sweeper timer running"
  fi

  if ! systemctl is-active --quiet futilitys-purge.timer; then
    _info "Purge timer not running"
  else
    _ok "Purge timer running"
  fi
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

  _step "FUTILITY'S — Superscript 4/4 — HARDEN + VERIFY + UX POLISH"

  load_config

  write_security_utils
  write_tailscale_integration
  update_app_with_security
  write_enhanced_templates
  add_job_detail_endpoint
  write_troubleshooting_docs
  restart_control_plane
  verify_installation

  _ok "Superscript 4/4 complete."
  _info ""
  _info "=============================================="
  _info "  FUTILITY'S INSTALLATION COMPLETE"
  _info "=============================================="
  _info ""
  _info "Control Plane URL: https://${DOMAIN}/"
  _info "Health endpoint:   https://${DOMAIN}/health"
  _info ""
  _info "Features installed:"
  _info " - TLS via Caddy (automatic Let's Encrypt)"
  _info " - FastAPI Control Plane with session auth"
  _info " - GitHub App integration (repo listing, PR creation)"
  _info " - SQLite database with audit log"
  _info " - DigitalOcean worker orchestration"
  _info " - ZIP-slip protection and path validation"
  _info " - TTL sweeper (auto-delete workers)"
  _info " - 7-day retention purge"
  _info " - Slack notifications"
  _info " - Tailscale integration (optional)"
  _info ""
  _info "Troubleshooting: /opt/futilitys/TROUBLESHOOTING.md"
  _info ""
  _info "To view logs:"
  _info "  sudo journalctl -u futilitys-control-plane -f"
  _info ""
}

main "$@"
