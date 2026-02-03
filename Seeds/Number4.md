#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# FUTILITY'S — Golden Installer (HARDEN + UX POLISH) — Superscript 4/4
# -----------------------------------------------------------------------------
# Goal: make the system "IRL-ready" without making it fragile or overcomplicated.
#
# This script:
#   A) Hardens worker payload handling:
#      - Adds binary payload endpoint (/jobs/<id>/payload.bin)
#      - Updates worker cloud-init to fetch binary payload directly
#      - Adds ZIP-slip protection + size checks before extraction
#      - Implements true Path Blocks expansion into files/dirs
#
#   B) UX polish:
#      - Human-readable timestamps in UI
#      - Clearer job status + error hints
#      - Optional repo allowlist filtering (REPO_ALLOWLIST)
#
#   C) Optional (OFF by default):
#      - Tailscale on Control Plane (ENABLE_TAILSCALE=1)
#      - Worker Tailscale (ENABLE_WORKER_TAILSCALE=1) (requires extra thought)
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

DOMAIN=""
BASE_BRANCH=""
RUN_USER="futilitys"
VENV_DIR="/opt/futilitys/venv"
APP_ROOT="/opt/futilitys/app/control_plane"
DATA_ROOT="/var/lib/futilitys"

load_config() {
  _step "Load config bundle"
  [ -f "$CFG_FILE" ] || _fail "Missing config: $CFG_FILE (run superscript 1/4 first)."
  [ -f "$SECRETS_FILE" ] || _fail "Missing secrets: $SECRETS_FILE (run superscript 2/4 first)."

  # shellcheck disable=SC1090
  set -a
  . "$CFG_FILE"
  . "$SECRETS_FILE"
  set +a

  DOMAIN="${DOMAIN:-}"
  BASE_BRANCH="${BASE_BRANCH:-main}"

  [ -n "${DOMAIN:-}" ] || _fail "DOMAIN missing."
  [ -n "${ADMIN_USER:-}" ] || _fail "ADMIN_USER missing."
  [ -n "${ADMIN_PASS_HASH:-}" ] || _fail "ADMIN_PASS_HASH missing."
  [ -n "${SESSION_SECRET:-}" ] || _fail "SESSION_SECRET missing."
  [ -d "$VENV_DIR" ] || _fail "Missing venv at $VENV_DIR (run superscript 2/4)."
  [ -d "$APP_ROOT" ] || _fail "Missing app at $APP_ROOT (run superscript 2/4)."

  _ok "Loaded config for https://${DOMAIN} (base branch: ${BASE_BRANCH})"
}

# ------------------------------ Ensure python deps ----------------------------

install_python_deps_if_needed() {
  _step "Ensure python deps support binary payload endpoint"
  need_cmd python3

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would ensure requirements include fastapi/starlette Response support (already included)."
    _ok "Deps (DRY_RUN)"
    return 0
  fi

  # Keep it simple: FastAPI already includes Response; no new pip deps required.
  _ok "No new pip deps required"
}

# ------------------------------ Patch Control Plane: binary payload ------------

patch_control_plane_payload_bin() {
  _step "Patch Control Plane to serve binary payload (/jobs/<id>/payload.bin) + tighten validations"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would patch $APP_ROOT/app.py (payload endpoints + size cap)"
    _ok "CP patch (DRY_RUN)"
    return 0
  fi

  local app_py="$APP_ROOT/app.py"
  [ -f "$app_py" ] || _fail "Missing $app_py"

  # Re-write app.py in-place is risky; instead we do a targeted patch:
  # - Add Response import
  # - Add MAX_PAYLOAD_BYTES env + enforce during upload
  # - Add /jobs/{job_id}/payload.bin endpoint
  #
  # We'll use a conservative approach: if markers exist, replace blocks; else append safely.

  # 1) Ensure Response import exists
  if ! grep -q "from fastapi.responses import .*Response" "$app_py"; then
    # Insert Response into fastapi.responses import line.
    run python3 - <<'PY'
import re,sys
p=sys.argv[1]
s=open(p,'r',encoding='utf-8').read().splitlines(True)
out=[]
done=False
for line in s:
    if (not done) and line.startswith("from fastapi.responses import "):
        if "Response" not in line:
            line=line.rstrip("\n").rstrip()
            if line.endswith(")"):
                # uncommon
                pass
            # naive: add Response just before end
            line=line + ", Response\n"
        done=True
    out.append(line)
open(p,'w',encoding='utf-8').write(''.join(out))
PY "$app_py"
  fi

  # 2) Add MAX_PAYLOAD_BYTES env and upload enforcement
  # Insert after WORKER_IMAGE env line if possible.
  if ! grep -q "MAX_PAYLOAD_BYTES" "$app_py"; then
    run python3 - <<'PY'
import sys
p=sys.argv[1]
lines=open(p,'r',encoding='utf-8').read().splitlines(True)
out=[]
inserted=False
for i,line in enumerate(lines):
    out.append(line)
    if (not inserted) and "WORKER_IMAGE" in line and "=" in line:
        out.append("\nMAX_PAYLOAD_BYTES = int(env(\"MAX_PAYLOAD_BYTES\", \"10485760\"))  # 10MB default\n")
        inserted=True
open(p,'w',encoding='utf-8').write(''.join(out))
PY "$app_py"
  fi

  # Enforce size in upload loop: add a counter and abort if > MAX
  if ! grep -q "MAX_PAYLOAD_BYTES enforcement" "$app_py"; then
    run python3 - <<'PY'
import sys,re
p=sys.argv[1]
s=open(p,'r',encoding='utf-8').read().splitlines(True)
out=[]
in_upload=False
added=False

for line in s:
    if "if mode == \"upload\"" in line:
        in_upload=True
    if in_upload and (not added) and "with open(payload_path, \"wb\") as f:" in line:
        out.append(line)
        out.append("            total = 0  # MAX_PAYLOAD_BYTES enforcement\n")
        added=True
        continue
    if in_upload and "chunk = await upload.read" in line:
        out.append(line)
        continue
    if in_upload and added and ("if not chunk:" in line):
        out.append(line)
        continue
    if in_upload and added and ("f.write(chunk)" in line):
        # insert counter before write
        indent=line.split("f.write")[0]
        out.append(f"{indent}total += len(chunk)\n")
        out.append(f"{indent}if total > MAX_PAYLOAD_BYTES:\n")
        out.append(f"{indent}    add_event(job_id, \"cp\", \"ui\", \"JOB_FAILED\", {{\"reason\": \"payload_too_large\", \"max\": MAX_PAYLOAD_BYTES}})\n")
        out.append(f"{indent}    return RedirectResponse(f\"/jobs/{{job_id}}?err=payload_too_large\", status_code=303)\n")
        out.append(line)
        continue
    # end upload section heuristics
    if in_upload and ("elif mode == \"pathblocks\"" in line):
        in_upload=False
    out.append(line)

open(p,'w',encoding='utf-8').write(''.join(out))
PY "$app_py"
  fi

  # 3) Add payload.bin endpoint (binary response)
  if ! grep -q 'def job_payload_bin' "$app_py"; then
    # Append endpoint right after existing /jobs/{job_id}/payload endpoint definition if possible.
    run python3 - <<'PY'
import sys
p=sys.argv[1]
txt=open(p,'r',encoding='utf-8').read()
needle='@app.get("/jobs/{job_id}/payload")'
idx=txt.find(needle)
if idx==-1:
    # Fallback: append near end
    insert_at=len(txt)
else:
    # insert after that endpoint block (best-effort): find next "@app." after it
    next_idx=txt.find("\n@app.", idx+1)
    if next_idx==-1: insert_at=len(txt)
    else: insert_at=next_idx

snippet = r'''
@app.get("/jobs/{job_id}/payload.bin")
def job_payload_bin(job_id: str, secret: str):
    """
    Binary payload endpoint for workers.
    - Avoids JSON/hex bloat
    - Simple curl -o payload.bin
    """
    job = get_job(job_id)
    if not job:
        return JSONResponse({"ok": False, "err": "not found"}, status_code=404)
    if secret != job["job_secret"]:
        return JSONResponse({"ok": False, "err": "forbidden"}, status_code=403)

    p = job.get("payload_path", "")
    if not p or (not os.path.exists(p)):
        return JSONResponse({"ok": False, "err": "payload missing"}, status_code=404)

    # Stream small payload in memory (size-capped at upload time)
    with open(p, "rb") as f:
        data = f.read()

    add_event(job_id, "cp", "worker_fetch", "PAYLOAD_SERVED_BIN", {"bytes": len(data)})
    # FastAPI Response (raw bytes)
    return Response(content=data, media_type="application/octet-stream")
'''
new_txt = txt[:insert_at] + snippet + "\n" + txt[insert_at:]
open(p,'w',encoding='utf-8').write(new_txt)
PY "$app_py"
  fi

  run chown "$RUN_USER:$RUN_USER" "$app_py"
  _ok "Control Plane patched for binary payload + size caps"
}

# ------------------------------ Worker template: binary + zip safety + pathblocks

patch_worker_template_binary_and_safe() {
  _step "Patch worker cloud-init to fetch binary payload + enforce zip-slip safety + expand Path Blocks"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would rewrite /opt/futilitys/app/worker_templates/cloud_init.tpl"
    _ok "Worker template patch (DRY_RUN)"
    return 0
  fi

  local tpl="/opt/futilitys/app/worker_templates/cloud_init.tpl"
  run mkdir -p "$(dirname "$tpl")"

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

  # TTL safety net: kill even if stuck
  - [ bash, -lc, "nohup bash -lc 'sleep ${TTL_SECONDS}; echo ttl exceeded >>/var/log/futy-ttl.log; shutdown -h now' >/var/log/futy-ttl.log 2>&1 &" ]

  - [ bash, -lc, "mkdir -p /opt/futy && cd /opt/futy" ]

  # Bootstrap: mint GH installation token
  - [ bash, -lc, "echo '[worker] fetching bootstrap'; curl -fsS '${CP_BASE}/worker/bootstrap?job_id=${JOB_ID}&secret=${JOB_SECRET}' -o bootstrap.json" ]
  - [ bash, -lc, "export REPO_FULL=$(jq -r .repo_full bootstrap.json); export BASE_BRANCH=$(jq -r .base_branch bootstrap.json); export GH_TOKEN=$(jq -r .token bootstrap.json)" ]

  # Fetch binary payload (no JSON/hex bloat)
  - [ bash, -lc, "echo '[worker] fetching payload.bin'; curl -fsS '${CP_BASE}/jobs/${JOB_ID}/payload.bin?secret=${JOB_SECRET}' -o payload.bin" ]

  # Prepare extracted/ directory
  - [ bash, -lc, "rm -rf extracted && mkdir -p extracted" ]

  # Decide: zip vs pathblocks vs single file
  - [ bash, -lc, "echo '[worker] detect payload type'; (file payload.bin || true) | tee /var/log/futy-filetype.log" ]

  # If ZIP: zip-slip guard + extract
  - [ bash, -lc, "if file payload.bin | grep -qi zip; then \
        echo '[worker] zip payload detected'; \
        unzip -Z1 payload.bin > ziplist.txt; \
        python3 - <<'PY'\nimport sys\nbad=[]\nfor p in open('ziplist.txt','r',encoding='utf-8',errors='ignore').read().splitlines():\n    if p.startswith('/') or p.startswith('\\\\') or '..' in p.split('/'):\n        bad.append(p)\nif bad:\n    print('ZIP_SLIP_DETECTED')\n    for b in bad[:50]: print('bad:',b)\n    sys.exit(2)\nprint('zip ok')\nPY \
        && unzip -o payload.bin -d extracted; \
      else \
        echo '[worker] not zip'; \
      fi" ]

  # If not ZIP: try Path Blocks (FILE: path ...), else single file
  - [ bash, -lc, "if ! (file payload.bin | grep -qi zip); then \
        python3 - <<'PY'\nimport os,sys\nb=open('payload.bin','rb').read()\n# Try decode as utf-8-ish text for pathblocks\ntry:\n    t=b.decode('utf-8')\nexcept Exception:\n    t=''\nif t.lstrip().startswith('FILE:'):\n    os.makedirs('extracted', exist_ok=True)\n    cur=None\n    buf=[]\n    def flush():\n        global cur,buf\n        if not cur: return\n        path=cur.strip()\n        if path.startswith('/') or path.startswith('\\\\') or '..' in path.split('/'):\n            raise SystemExit(f'bad path: {path}')\n        full=os.path.join('extracted', path)\n        os.makedirs(os.path.dirname(full), exist_ok=True)\n        open(full,'w',encoding='utf-8').write(''.join(buf))\n    for line in t.splitlines(True):\n        if line.startswith('FILE:'):\n            flush()\n            cur=line[len('FILE:'):].strip()\n            buf=[]\n        else:\n            buf.append(line)\n    flush()\n    print('pathblocks expanded')\nelse:\n    os.makedirs('extracted', exist_ok=True)\n    open('extracted/UPLOAD','wb').write(b)\n    print('stored as single file UPLOAD')\nPY \
      fi" ]

  # Clone repo and commit into incoming/<job-id> on intake/<job-id>
  - [ bash, -lc, "echo '[worker] cloning repo'; REPO_URL='https://x-access-token:'\"$GH_TOKEN\"'@github.com/'\"$REPO_FULL\"'.git'; git clone \"$REPO_URL\" repo" ]
  - [ bash, -lc, "cd repo; git checkout -b intake/${JOB_ID}; mkdir -p incoming/${JOB_ID}; cp -a /opt/futy/extracted/. incoming/${JOB_ID}/" ]
  - [ bash, -lc, "cd repo; git add -A; git config user.email 'futilitys-bot@local'; git config user.name 'Futilitys Bot'; git commit -m \"intake ${JOB_ID}\" || true; git push -u origin intake/${JOB_ID}" ]

  # Open PR
  - [ bash, -lc, "echo '[worker] opening PR'; PR_JSON=$(curl -fsS -X POST -H \"Authorization: token $GH_TOKEN\" -H \"Accept: application/vnd.github+json\" https://api.github.com/repos/$REPO_FULL/pulls -d @- <<JSON\n{\"title\":\"Futilitys intake ${JOB_ID}\",\"head\":\"intake/${JOB_ID}\",\"base\":\"${BASE_BRANCH}\",\"body\":\"Automated intake job ${JOB_ID}. Files placed under incoming/${JOB_ID}/.\\n\"}\nJSON\n); echo \"$PR_JSON\" > /var/log/futy-pr.json; PR_URL=$(echo \"$PR_JSON\" | jq -r .html_url); PR_NUM=$(echo \"$PR_JSON\" | jq -r .number)" ]

  # Callback to CP (redacted by CP)
  - [ bash, -lc, "cd repo; COMMIT_SHA=$(git rev-parse HEAD || true); curl -fsS -X POST '${CP_BASE}/worker/callback' -H 'Content-Type: application/json' -d @- <<JSON\n{\"job_id\":\"${JOB_ID}\",\"secret\":\"${JOB_SECRET}\",\"status\":\"DONE\",\"message\":\"pushed branch and opened PR\",\"pr_url\":\"'\"$PR_URL\"'\",\"pr_number\":'\"$PR_NUM\"',\"commit_sha\":\"'\"$COMMIT_SHA\"'\"}\nJSON\n" ]

  - [ bash, -lc, "echo '[worker] done; shutting down'; shutdown -h now" ]
EOF

  _ok "Worker template updated (binary payload + zip safety + Path Blocks expansion)"
}

# ------------------------------ UI polish: human timestamps + better errors ------

patch_templates_ui_polish() {
  _step "Patch UI templates for human-readable timestamps + clearer status"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would rewrite templates home_real.html + job.html"
    _ok "UI patch (DRY_RUN)"
    return 0
  fi

  local tdir="$APP_ROOT/templates"
  run mkdir -p "$tdir"

  cat > "$tdir/home_real.html" <<'EOF'
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
      .tag { display:inline-block; padding:2px 8px; border:1px solid #eee; border-radius:999px; font-size:12px; }
    </style>
    <script>
      function setMode(m) {
        document.getElementById("mode").value = m;
        document.getElementById("uploadBox").style.display = (m === "upload") ? "block" : "none";
        document.getElementById("pathBox").style.display = (m === "pathblocks") ? "block" : "none";
      }
      function fmtUnix(ts) {
        try {
          const d = new Date(parseInt(ts, 10) * 1000);
          return d.toLocaleString();
        } catch (e) { return ts; }
      }
      window.addEventListener("load", () => {
        setMode("upload");
        document.querySelectorAll("[data-unix]").forEach(el => {
          el.textContent = fmtUnix(el.getAttribute("data-unix"));
        });
      });
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
      <div class="muted">
        Fix checklist:
        <ul>
          <li>Confirm GitHub App is installed on the repo</li>
          <li>Confirm App ID + private key are correct on the Control Plane</li>
        </ul>
      </div>
    {% endif %}

    <div class="card">
      <h3>Create Intake Job</h3>
      <div class="muted">
        Files are committed under <code>incoming/&lt;job-id&gt;/</code> on branch <code>intake/&lt;job-id&gt;</code> and a PR is opened into <code>{{ base_branch }}</code>.
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
          <div class="muted">ZIP preferred. ZIP-slip is blocked. Large payloads may be rejected.</div>
        </div>

        <div id="pathBox" style="margin-top:10px; display:none;">
          <label>Paste Path Blocks</label>
          <textarea name="pathblocks">FILE: docs/example.txt
hello world
FILE: src/main.py
print("hi")
</textarea>
          <div class="muted">Format: repeated blocks starting with <code>FILE: relative/path</code>. Absolute paths and .. are rejected.</div>
        </div>

        <button type="submit">Create Job + Spawn Worker</button>
        <div class="muted" style="margin-top:8px;">
          Tip: if TTL=60s is too tight, increase <code>WORKER_TTL_SECONDS</code> until you build a worker snapshot.
        </div>
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
              <td><span class="tag">{{ j.status }}</span></td>
              <td>{{ j.repo_full }}</td>
              <td>{% if j.pr_url %}<a href="{{ j.pr_url }}">PR</a>{% else %}-{% endif %}</td>
              <td data-unix="{{ j.created_ts }}">{{ j.created_ts }}</td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h3>Health</h3>
      <div class="muted">Check: <code>/health</code></div>
    </div>
  </body>
</html>
EOF

  cat > "$tdir/job.html" <<'EOF'
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
      .tag { display:inline-block; padding:2px 8px; border:1px solid #eee; border-radius:999px; font-size:12px; }
    </style>
    <script>
      function fmtUnix(ts) {
        try { return new Date(parseInt(ts,10)*1000).toLocaleString(); }
        catch(e){ return ts; }
      }
      window.addEventListener("load", () => {
        document.querySelectorAll("[data-unix]").forEach(el => {
          el.textContent = fmtUnix(el.getAttribute("data-unix"));
        });
      });
    </script>
  </head>
  <body>
    <div class="top">
      <h2>Job {{ job.job_id }}</h2>
      <div><a href="/">Back</a></div>
    </div>

    <div class="card">
      <div><b>Status:</b> <span class="tag">{{ job.status }}</span></div>
      <div><b>Repo:</b> {{ job.repo_full }}</div>
      <div><b>Base:</b> {{ job.base_branch }}</div>
      <div><b>Mode:</b> {{ job.mode }}</div>
      <div><b>TTL:</b> {{ job.ttl_seconds }}s</div>
      <div><b>Droplet ID:</b> {{ job.worker_droplet_id }}</div>
      <div><b>PR:</b> {% if job.pr_url %}<a href="{{ job.pr_url }}">{{ job.pr_url }}</a>{% else %}-{% endif %}</div>
      <div class="muted" style="margin-top:8px;">Message: {{ job.message }}</div>

      {% if job.status == "FAILED" %}
        <div class="muted" style="margin-top:10px;">
          Common causes:
          <ul>
            <li>TTL too low for first-boot apt installs (increase WORKER_TTL_SECONDS)</li>
            <li>Repo not in GitHub App installation</li>
            <li>Payload too large (MAX_PAYLOAD_BYTES)</li>
            <li>ZIP-slip blocked (paths with .. or absolute paths)</li>
          </ul>
        </div>
      {% endif %}
    </div>

    <div class="card">
      <h3>Audit Timeline (append-only)</h3>
      <table>
        <thead>
          <tr><th>time</th><th>actor</th><th>trigger</th><th>type</th><th>details</th></tr>
        </thead>
        <tbody>
          {% for e in events %}
            <tr>
              <td data-unix="{{ e.ts }}">{{ e.ts }}</td>
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

  run chown -R "$RUN_USER:$RUN_USER" "$tdir"
  _ok "UI templates patched"
}

# ------------------------------ Optional: Repo allowlist ------------------------

patch_repo_allowlist_support() {
  _step "Optional: repo allowlist (REPO_ALLOWLIST) support in CP home()"

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would add REPO_ALLOWLIST filtering to $APP_ROOT/app.py"
    _ok "Allowlist patch (DRY_RUN)"
    return 0
  fi

  local app_py="$APP_ROOT/app.py"
  if ! grep -q "REPO_ALLOWLIST" "$app_py"; then
    run python3 - <<'PY'
import sys
p=sys.argv[1]
txt=open(p,'r',encoding='utf-8').read().splitlines(True)
out=[]
inserted=False
for line in txt:
    out.append(line)
    if (not inserted) and line.strip().startswith("WORKER_IMAGE"):
        out.append("\nREPO_ALLOWLIST = env(\"REPO_ALLOWLIST\", \"\").strip()  # comma-separated full repo names\n")
        inserted=True
open(p,'w',encoding='utf-8').write(''.join(out))
PY "$app_py"
  fi

  # Filter repos in home() where repos are built; inject after repos=sorted...
  if ! grep -q "apply repo allowlist" "$app_py"; then
    run python3 - <<'PY'
import sys,re
p=sys.argv[1]
lines=open(p,'r',encoding='utf-8').read().splitlines(True)
out=[]
for i,line in enumerate(lines):
    out.append(line)
    if "repos = sorted(list(set(repos)))" in line:
        out.append("\n    # apply repo allowlist\n")
        out.append("    if REPO_ALLOWLIST:\n")
        out.append("        allowed = set([x.strip().lower() for x in REPO_ALLOWLIST.split(',') if x.strip()])\n")
        out.append("        repos = [r for r in repos if r.lower() in allowed]\n")
        out.append("        repos = sorted(repos)\n")
open(p,'w',encoding='utf-8').write(''.join(out))
PY "$app_py"
  fi

  run chown "$RUN_USER:$RUN_USER" "$app_py"
  _ok "Repo allowlist support added (set REPO_ALLOWLIST in futilitys.env if desired)"
}

# ------------------------------ Optional: Tailscale (CP only) ------------------

maybe_install_tailscale_cp() {
  _step "Optional: Tailscale on Control Plane (ENABLE_TAILSCALE=1)"

  local enable="${ENABLE_TAILSCALE:-0}"
  local authkey="${TAILSCALE_AUTHKEY:-}"

  if [ "$enable" != "1" ]; then
    _info "Skipping Tailscale (ENABLE_TAILSCALE != 1)."
    return 0
  fi
  [ -n "$authkey" ] || _fail "ENABLE_TAILSCALE=1 but TAILSCALE_AUTHKEY is empty."

  if [ "$DRY_RUN" = "1" ]; then
    _info "DRY_RUN: would install tailscale and bring up with provided authkey"
    _ok "Tailscale (DRY_RUN)"
    return 0
  fi

  need_cmd curl
  if ! command -v tailscale >/dev/null 2>&1; then
    _info "Installing Tailscale..."
    run curl -fsSL https://tailscale.com/install.sh | bash
  fi

  # Bring up; tags/hostname are optional
  local hn="futy-cp-${DOMAIN//./-}"
  run tailscale up --authkey "$authkey" --hostname "$hn" --ssh=false || true
  _ok "Tailscale enabled on Control Plane (CP only)"
  _info "NOTE: workers still use HTTPS callbacks by default; enabling worker tailscale requires more policy decisions."
}

# ------------------------------ Restart services + verify -----------------------

restart_control_plane() {
  _step "Restart Control Plane (apply patches)"
  run systemctl restart futilitys-control-plane
  _ok "Control Plane restarted"
}

verify_end_to_end_basics() {
  _step "Verify HTTPS + endpoints"
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

  # quick smoke: login page exists
  curl -fsS "https://${DOMAIN}/login" >/dev/null
  _ok "Login page OK: https://${DOMAIN}/login"

  _info "Binary payload endpoint will be exercised on first worker job."
}

print_irL_ops_notes() {
  _step "IRL Ops Notes (practical defaults)"

  cat <<EOF
[IRL DEFAULTS YOU SHOULD USE]
- WORKER_TTL_SECONDS: set to 180-300 until you build a worker snapshot image.
- MAX_PAYLOAD_BYTES: default 10MB. Raise only if you trust your users & inputs.
- REPO_ALLOWLIST: strongly recommended in production (comma separated repo full names).

[TROUBLESHOOTING]
- Control Plane logs:
    journalctl -u futilitys-control-plane -n 200 --no-pager
- Sweeper logs:
    journalctl -u futilitys-sweeper.service -n 200 --no-pager
- Caddy logs (if used):
    journalctl -u caddy -n 200 --no-pager

[WHAT'S NOW FIXED]
- Worker payload fetch is binary (no JSON hex bloat).
- ZIP-slip blocked (.. and absolute paths rejected).
- Path Blocks now expand to real files (FILE: path).
- UI shows human timestamps.

EOF
}

# --------------------------------- Main --------------------------------------

main() {
  as_root
  log_setup

  _step "FUTILITY'S — Superscript 4/4 — HARDEN + UX POLISH"
  load_config

  install_python_deps_if_needed
  patch_control_plane_payload_bin
  patch_worker_template_binary_and_safe
  patch_templates_ui_polish
  patch_repo_allowlist_support
  maybe_install_tailscale_cp

  restart_control_plane
  verify_end_to_end_basics
  print_irL_ops_notes

  _ok "Superscript 4/4 complete — system is IRL-ready."
  _info "Go to: https://${DOMAIN}/login  (create a job → worker spawns → PR opens)"
}

main "$@"