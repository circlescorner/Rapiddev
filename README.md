# Futility's Control Plane

A sophisticated infrastructure automation system that orchestrates code submission workflows, job processing, and automated pull request creation. Futility's accepts code uploads through a secure web interface, processes them via ephemeral cloud workers, and automatically creates pull requests to your GitHub repositories.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Installation Guide](#installation-guide)
   - [Quick Start](#quick-start)
   - [Step-by-Step Installation](#step-by-step-installation)
   - [Post-Installation Verification](#post-installation-verification)
5. [Configuration Reference](#configuration-reference)
6. [Operation Manual](#operation-manual)
   - [Daily Operations](#daily-operations)
   - [Creating Jobs](#creating-jobs)
   - [Monitoring Jobs](#monitoring-jobs)
   - [Managing Workers](#managing-workers)
7. [Administration Guide](#administration-guide)
   - [Service Management](#service-management)
   - [Database Operations](#database-operations)
   - [Log Management](#log-management)
   - [Backup and Recovery](#backup-and-recovery)
8. [Security](#security)
9. [Troubleshooting](#troubleshooting)
10. [API Reference](#api-reference)

---

## Overview

Futility's is designed to:

- **Accept code submissions** via ZIP upload or inline "Path Blocks" syntax
- **Create isolated ephemeral workers** on DigitalOcean to process jobs
- **Automatically create pull requests** to target GitHub repositories
- **Manage retention and cleanup** of worker instances and job data
- **Provide admin oversight** through a secure web interface

### Key Features

| Feature | Description |
|---------|-------------|
| Automatic TLS | Caddy handles Let's Encrypt certificates automatically |
| GitHub App Integration | Secure repo access via GitHub App (no PATs) |
| Ephemeral Workers | DigitalOcean droplets created per-job, auto-deleted |
| Audit Logging | SQLite event log for complete job history |
| Slack Notifications | Real-time alerts for job status changes |
| ZIP-Slip Protection | Security hardening against path traversal attacks |
| Session Authentication | Secure bcrypt-hashed admin login |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           FUTILITY'S ARCHITECTURE                        │
└─────────────────────────────────────────────────────────────────────────┘

    ┌──────────────┐         ┌──────────────────────────────────────────┐
    │    Admin     │         │           Control Plane Server            │
    │   Browser    │────────▶│  ┌────────────────────────────────────┐  │
    └──────────────┘  HTTPS  │  │           Caddy (TLS)              │  │
                             │  │         :80, :443                   │  │
                             │  └────────────────┬───────────────────┘  │
                             │                   │                      │
                             │                   ▼                      │
                             │  ┌────────────────────────────────────┐  │
                             │  │      FastAPI Control Plane         │  │
                             │  │         127.0.0.1:8000             │  │
                             │  │                                    │  │
                             │  │  • Job Intake API                  │  │
                             │  │  • GitHub Integration              │  │
                             │  │  • Worker Orchestration            │  │
                             │  │  • Admin Dashboard                 │  │
                             │  └────────────────┬───────────────────┘  │
                             │                   │                      │
                             │                   ▼                      │
                             │  ┌────────────────────────────────────┐  │
                             │  │         SQLite Database            │  │
                             │  │    /var/lib/futilitys/futilitys.db │  │
                             │  └────────────────────────────────────┘  │
                             └──────────────────────────────────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    │                         │                         │
                    ▼                         ▼                         ▼
           ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
           │   GitHub     │          │ DigitalOcean │          │    Slack     │
           │     API      │          │     API      │          │   Webhook    │
           │              │          │              │          │              │
           │ • List repos │          │ • Create     │          │ • Job alerts │
           │ • Create PR  │          │   droplets   │          │ • Failures   │
           │ • Push files │          │ • Delete     │          │              │
           └──────────────┘          │   droplets   │          └──────────────┘
                                     └──────────────┘
                                            │
                                            ▼
                                   ┌──────────────────┐
                                   │ Ephemeral Worker │
                                   │    (Droplet)     │
                                   │                  │
                                   │ • Process job    │
                                   │ • Callback CP    │
                                   │ • Auto-deleted   │
                                   └──────────────────┘
```

### Directory Structure

```
/opt/futilitys/
├── app/
│   └── control_plane/
│       ├── app.py                    # Main FastAPI application
│       ├── github_integration.py     # GitHub App JWT & API
│       ├── worker_orchestration.py   # DigitalOcean droplet management
│       ├── security_utils.py         # ZIP-slip protection
│       ├── job_processor.py          # Secure job processing
│       ├── tailscale_integration.py  # Optional Tailscale support
│       ├── requirements.txt          # Python dependencies
│       ├── templates/
│       │   ├── login.html
│       │   ├── home.html
│       │   └── job_detail.html
│       └── static/
├── infra/
│   ├── futilitys.env                 # Main configuration (root-only)
│   ├── futilitys.secrets.env         # Secrets file (root-only)
│   └── github_app_private_key.pem    # GitHub App key (root-only)
├── bin/
│   ├── ttl-sweeper.sh                # Worker TTL enforcement
│   └── retention-purge.sh            # 7-day data cleanup
├── venv/                             # Python virtual environment
└── TROUBLESHOOTING.md                # Troubleshooting guide

/var/lib/futilitys/
├── futilitys.db                      # SQLite database
└── jobs/
    └── <job-id>/
        ├── payload.zip               # Uploaded payload
        └── extracted/                # Extracted files

/var/log/futilitys/
└── install.log                       # Installation log

/etc/caddy/
└── Caddyfile                         # Caddy TLS configuration

/etc/systemd/system/
├── futilitys-control-plane.service   # Main service
├── futilitys-sweeper.service         # TTL sweeper
├── futilitys-sweeper.timer           # Runs every minute
├── futilitys-purge.service           # Retention purge
└── futilitys-purge.timer             # Runs daily
```

---

## Prerequisites

### Server Requirements

| Requirement | Specification |
|-------------|---------------|
| **Operating System** | Ubuntu 20.04+ or Debian 11+ |
| **CPU** | 1 vCPU minimum (2 recommended) |
| **RAM** | 1 GB minimum (2 GB recommended) |
| **Disk** | 20 GB minimum |
| **Network** | Public IP with ports 80 and 443 open |

### External Services

Before installation, you need:

#### 1. Domain Name with DNS

- A domain (e.g., `control.yourdomain.com`)
- DNS A record pointing to your server's public IP
- Wait for DNS propagation (can take up to 48 hours, usually minutes)

```bash
# Verify DNS is working
dig +short control.yourdomain.com
# Should return your server's IP
```

#### 2. DigitalOcean Account

- Create account at [digitalocean.com](https://www.digitalocean.com)
- Generate API token with read/write scope:
  1. Go to API → Tokens/Keys
  2. Generate New Token
  3. Name it (e.g., "futilitys-control-plane")
  4. Select both Read and Write scopes
  5. Copy and save the token securely

#### 3. GitHub App

Create a GitHub App for secure repository access:

1. Go to GitHub → Settings → Developer settings → GitHub Apps
2. Click "New GitHub App"
3. Configure:
   - **Name:** `Futilitys-YourOrg` (must be unique)
   - **Homepage URL:** `https://control.yourdomain.com`
   - **Webhook:** Uncheck "Active" (not needed)
   - **Permissions:**
     - Repository permissions:
       - Contents: Read and write
       - Pull requests: Read and write
       - Metadata: Read-only
   - **Where can this app be installed:** Only on this account (or Any account)
4. Click "Create GitHub App"
5. Note the **App ID** (numeric)
6. Generate a **Private Key**:
   - Scroll to "Private keys" section
   - Click "Generate a private key"
   - Save the downloaded `.pem` file
7. **Install the App** on your repositories:
   - Go to "Install App" in left sidebar
   - Select your account/organization
   - Choose "All repositories" or select specific ones

#### 4. Slack Webhook (Optional but Recommended)

1. Go to [api.slack.com/apps](https://api.slack.com/apps)
2. Create New App → From scratch
3. Name it and select workspace
4. Go to "Incoming Webhooks"
5. Activate and "Add New Webhook to Workspace"
6. Select channel and authorize
7. Copy the webhook URL

#### 5. Tailscale (Optional)

For secure worker callbacks via private network:

1. Create account at [tailscale.com](https://tailscale.com)
2. Go to Settings → Keys
3. Generate auth key with:
   - Reusable: Yes
   - Ephemeral: Yes
   - Tags: `tag:futilitys-worker`

---

## Installation Guide

### Quick Start

For experienced users, the fastest path:

```bash
# Clone the repository
git clone https://github.com/yourorg/Rapiddev.git
cd Rapiddev/Seeds

# Run the master installer (interactive)
sudo bash install.sh
```

The installer will prompt for all required configuration values.

### Step-by-Step Installation

#### Step 1: Prepare the Server

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Ensure curl is installed
sudo apt install -y curl

# Verify you have a public IP
curl -s https://api.ipify.org
```

#### Step 2: Verify DNS

```bash
# Replace with your actual domain
DOMAIN="control.yourdomain.com"

# Check DNS resolution
dig +short $DOMAIN

# Should return your server's IP
```

#### Step 3: Clone and Run Installer

```bash
# Clone repository
git clone https://github.com/yourorg/Rapiddev.git
cd Rapiddev/Seeds

# Make scripts executable
chmod +x *.sh

# Run master installer
sudo bash install.sh
```

#### Step 4: Complete the Wizard

The installer will prompt for:

| Prompt | Description | Example |
|--------|-------------|---------|
| Domain | Your Control Plane domain | `control.example.com` |
| TLS Email | Email for Let's Encrypt | `admin@example.com` |
| Admin Username | Login username | `admin` |
| Admin Password | Login password (hidden) | `your-secure-password` |
| DigitalOcean Token | API token (hidden) | `dop_v1_xxx...` |
| GitHub App ID | Numeric App ID | `123456` |
| GitHub App Key | Paste PEM or provide path | (paste or `/path/to/key.pem`) |
| Slack Webhook | Webhook URL | `https://hooks.slack.com/...` |
| Tailscale Auth Key | Auth key (hidden, optional) | `tskey-auth-xxx...` |
| Region | DigitalOcean region | `nyc3` |
| Worker TTL | Seconds before worker cleanup | `300` |

#### Step 5: Verify Installation

After installation completes:

```bash
# Check service status
sudo systemctl status futilitys-control-plane

# Check Caddy status
sudo systemctl status caddy

# Test health endpoint
curl https://control.yourdomain.com/health
```

### Post-Installation Verification

Run these checks to ensure everything is working:

```bash
# 1. Services are running
sudo systemctl is-active futilitys-control-plane  # Should print: active
sudo systemctl is-active caddy                     # Should print: active

# 2. Timers are enabled
sudo systemctl is-active futilitys-sweeper.timer   # Should print: active
sudo systemctl is-active futilitys-purge.timer     # Should print: active

# 3. Health check responds
curl -s https://YOUR_DOMAIN/health | jq .
# Should return: {"ok":true,"service":"futilitys-control-plane","domain":"YOUR_DOMAIN"}

# 4. Database exists
ls -la /var/lib/futilitys/futilitys.db

# 5. Login page loads
curl -s -o /dev/null -w "%{http_code}" https://YOUR_DOMAIN/login
# Should return: 200
```

### Running Individual Scripts

If you need to run scripts separately (e.g., for debugging):

```bash
# Script 1: PREP + WIZARD
sudo bash futilitys_superscript_1.sh

# Script 2: CONTROL PLANE BUILD
sudo bash futilitys_superscript_2.sh

# Script 3: WORKER + ORCHESTRATION
sudo bash futilitys_superscript_3.sh

# Script 4: HARDEN + UX POLISH
sudo bash futilitys_superscript_4.sh
```

### Dry Run Mode

Test the installer without making changes:

```bash
sudo DRY_RUN=1 bash install.sh
```

---

## Configuration Reference

### Main Configuration File

Location: `/opt/futilitys/infra/futilitys.env`

```bash
# Domain and TLS
DOMAIN="control.example.com"
TLS_EMAIL="admin@example.com"

# Admin credentials
ADMIN_USER="admin"

# DigitalOcean
DIGITALOCEAN_TOKEN="dop_v1_..."
DO_REGION="nyc3"
WORKER_SIZE="s-1vcpu-1gb"
WORKER_TTL_SECONDS="300"

# GitHub
GIT_HOST="github"
BASE_BRANCH="main"
PUSH_MODE="branch_pr"
PR_AUTO_OPEN="1"
INCOMING_MODE="incoming_only"
GITHUB_APP_ID="123456"
GITHUB_APP_KEY_PATH="/opt/futilitys/infra/github_app_private_key.pem"

# Notifications
SLACK_WEBHOOK_URL="https://hooks.slack.com/..."

# Tailscale (optional)
TAILSCALE_MODE="callback_only"
TAILSCALE_AUTHKEY="tskey-auth-..."

# Data retention
RETENTION_DAYS="7"
```

### Secrets File

Location: `/opt/futilitys/infra/futilitys.secrets.env`

```bash
# Bcrypt-hashed admin password (generated by installer)
ADMIN_PASS_HASH="$2b$12$..."

# Session signing secret
SESSION_SECRET="..."
```

### Modifying Configuration

To change configuration after installation:

```bash
# 1. Edit configuration
sudo nano /opt/futilitys/infra/futilitys.env

# 2. Restart service
sudo systemctl restart futilitys-control-plane

# 3. Verify
sudo systemctl status futilitys-control-plane
```

### Changing Admin Password

```bash
# Generate new bcrypt hash
NEW_HASH=$(/opt/futilitys/venv/bin/python -c "
from passlib.hash import bcrypt
import getpass
pw = getpass.getpass('New password: ')
print(bcrypt.hash(pw))
")

# Update secrets file
sudo sed -i "s|ADMIN_PASS_HASH=.*|ADMIN_PASS_HASH=\"$NEW_HASH\"|" \
  /opt/futilitys/infra/futilitys.secrets.env

# Restart service
sudo systemctl restart futilitys-control-plane
```

---

## Operation Manual

### Daily Operations

#### Logging In

1. Navigate to `https://your-domain.com/login`
2. Enter your admin username and password
3. Click "Login"

Session expires after 24 hours.

#### Dashboard Overview

The home dashboard displays:

- **Configuration pills**: Current domain, base branch, mode, retention
- **Create Job form**: Submit new code intake jobs
- **Recent Jobs table**: Status of last 20 jobs

### Creating Jobs

#### Method 1: ZIP Upload

1. Select target repository from dropdown
2. Click "Upload ZIP or file" and select your archive
3. Click "Create Job"

The ZIP will be:
- Validated for ZIP-slip attacks
- Extracted safely
- Files placed under `incoming/<job-id>/` in a new branch
- A PR automatically opened

#### Method 2: Path Blocks

For small submissions, paste inline content:

```
FILE: docs/README.md
# My Documentation

This is the content of the README file.

FILE: src/config.json
{
  "setting": "value",
  "enabled": true
}

FILE: src/utils/helper.py
def helper_function():
    return "Hello"
```

Syntax rules:
- Each file starts with `FILE: path/to/file`
- Paths must be relative (no `..` or leading `/`)
- Content follows until the next `FILE:` line

#### Job Workflow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   PENDING   │────▶│   RUNNING   │────▶│   SUCCESS   │     │   FAILED    │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
      │                   │                    │                   │
      │                   │                    │                   │
   Job created       Processing:          PR opened           Error logged
                     • Create branch       • Job complete       • Cleanup
                     • Push files                               • Slack alert
                     • Open PR
```

### Monitoring Jobs

#### Job List

The dashboard shows recent jobs with:

| Column | Description |
|--------|-------------|
| Job ID | Click to view details |
| Repository | Target repository |
| Status | pending, running, success, failed |
| Branch | Git branch name (e.g., `intake/abc123`) |
| PR | Link to pull request (if created) |
| Created | Timestamp |

#### Job Details Page

Click any Job ID to see:

- Full job ID
- Current status
- Repository and branch
- PR link
- Payload type and size
- Error message (if failed)
- Event timeline (audit log)

Auto-refreshes every 5 seconds while pending/running.

### Managing Workers

#### Worker Lifecycle

1. **Creation**: When a job starts, a DigitalOcean droplet is created
2. **Processing**: Worker downloads payload and processes job
3. **Callback**: Worker reports status to Control Plane
4. **Cleanup**: TTL sweeper deletes workers after configured timeout

#### View Active Workers

```bash
# List all futilitys workers in DigitalOcean
curl -s -H "Authorization: Bearer $DO_TOKEN" \
  "https://api.digitalocean.com/v2/droplets?tag_name=futilitys-worker" | jq '.droplets[] | {id, name, status, created_at}'
```

#### Manual Worker Cleanup

```bash
# Run TTL sweeper manually
sudo /opt/futilitys/bin/ttl-sweeper.sh

# Delete specific worker
curl -X DELETE -H "Authorization: Bearer $DO_TOKEN" \
  "https://api.digitalocean.com/v2/droplets/DROPLET_ID"
```

---

## Administration Guide

### Service Management

#### Control Plane Service

```bash
# Check status
sudo systemctl status futilitys-control-plane

# Start/stop/restart
sudo systemctl start futilitys-control-plane
sudo systemctl stop futilitys-control-plane
sudo systemctl restart futilitys-control-plane

# View logs
sudo journalctl -u futilitys-control-plane -f

# View recent logs
sudo journalctl -u futilitys-control-plane -n 100 --no-pager
```

#### Caddy (TLS Proxy)

```bash
# Check status
sudo systemctl status caddy

# Restart (e.g., after config change)
sudo systemctl restart caddy

# View logs
sudo journalctl -u caddy -f

# Validate Caddyfile
caddy validate --config /etc/caddy/Caddyfile
```

#### Systemd Timers

```bash
# List all futilitys timers
sudo systemctl list-timers | grep futilitys

# Check sweeper timer (runs every minute)
sudo systemctl status futilitys-sweeper.timer

# Check purge timer (runs daily)
sudo systemctl status futilitys-purge.timer

# Run sweeper manually
sudo systemctl start futilitys-sweeper.service

# Run purge manually
sudo systemctl start futilitys-purge.service
```

### Database Operations

#### Viewing Data

```bash
# Open SQLite shell
sudo sqlite3 /var/lib/futilitys/futilitys.db

# Common queries (run inside sqlite3):

-- List recent jobs
SELECT id, status, repo_full_name, created_at
FROM jobs ORDER BY created_at DESC LIMIT 20;

-- Count jobs by status
SELECT status, COUNT(*) FROM jobs GROUP BY status;

-- View events for a job
SELECT * FROM events WHERE job_id = 'JOB_ID_HERE' ORDER BY created_at;

-- Find failed jobs
SELECT id, repo_full_name, error_message, created_at
FROM jobs WHERE status = 'failed' ORDER BY created_at DESC;

-- Exit sqlite3
.quit
```

#### Database Maintenance

```bash
# Backup database
sudo cp /var/lib/futilitys/futilitys.db /var/lib/futilitys/futilitys.db.backup

# Check database integrity
sudo sqlite3 /var/lib/futilitys/futilitys.db "PRAGMA integrity_check;"

# Vacuum database (reclaim space)
sudo sqlite3 /var/lib/futilitys/futilitys.db "VACUUM;"
```

### Log Management

#### Log Locations

| Log | Location | Description |
|-----|----------|-------------|
| Installation | `/var/log/futilitys/install.log` | Installer output |
| Control Plane | `journalctl -u futilitys-control-plane` | Application logs |
| Caddy | `journalctl -u caddy` | TLS/proxy logs |
| Sweeper | `journalctl -u futilitys-sweeper` | Worker cleanup logs |
| Purge | `journalctl -u futilitys-purge` | Retention cleanup logs |

#### Log Rotation

Logs are managed by journald. To configure retention:

```bash
# Edit journald config
sudo nano /etc/systemd/journald.conf

# Add/modify:
SystemMaxUse=500M
MaxRetentionSec=30day

# Apply changes
sudo systemctl restart systemd-journald
```

### Backup and Recovery

#### Backup Checklist

| Item | Location | Frequency |
|------|----------|-----------|
| Database | `/var/lib/futilitys/futilitys.db` | Daily |
| Configuration | `/opt/futilitys/infra/` | After changes |
| GitHub Key | `/opt/futilitys/infra/github_app_private_key.pem` | Once |

#### Backup Script

```bash
#!/bin/bash
# /opt/futilitys/bin/backup.sh

BACKUP_DIR="/var/backups/futilitys"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup database
cp /var/lib/futilitys/futilitys.db "$BACKUP_DIR/futilitys_$DATE.db"

# Backup config (excluding secrets for security)
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" \
  --exclude='*.pem' \
  /opt/futilitys/infra/

# Keep only last 7 days
find "$BACKUP_DIR" -type f -mtime +7 -delete

echo "Backup completed: $BACKUP_DIR"
```

#### Recovery Procedure

```bash
# 1. Stop service
sudo systemctl stop futilitys-control-plane

# 2. Restore database
sudo cp /var/backups/futilitys/futilitys_YYYYMMDD.db /var/lib/futilitys/futilitys.db
sudo chown futilitys:futilitys /var/lib/futilitys/futilitys.db

# 3. Restore config (if needed)
sudo tar -xzf /var/backups/futilitys/config_YYYYMMDD.tar.gz -C /

# 4. Start service
sudo systemctl start futilitys-control-plane
```

---

## Security

### Security Features

| Feature | Description |
|---------|-------------|
| TLS Encryption | All traffic encrypted via Caddy + Let's Encrypt |
| Bcrypt Passwords | Admin password hashed with bcrypt |
| Session Tokens | Signed with itsdangerous, HttpOnly cookies |
| Root-Only Config | Secrets files readable only by root |
| ZIP-Slip Protection | Path traversal prevention in uploads |
| Systemd Hardening | ProtectSystem, ProtectHome, NoNewPrivileges |
| Input Validation | Path validation for all file operations |

### Security Best Practices

1. **Use strong admin password** (16+ characters, mixed case, numbers, symbols)
2. **Keep system updated**: `sudo apt update && sudo apt upgrade`
3. **Configure firewall**:
   ```bash
   sudo ufw allow 22/tcp   # SSH
   sudo ufw allow 80/tcp   # HTTP (for ACME)
   sudo ufw allow 443/tcp  # HTTPS
   sudo ufw enable
   ```
4. **Rotate credentials periodically**:
   - DigitalOcean API token
   - GitHub App private key
   - Admin password
5. **Monitor logs** for suspicious activity
6. **Enable Tailscale** for private worker callbacks

### File Permissions Reference

```
/opt/futilitys/infra/futilitys.env          root:root  600
/opt/futilitys/infra/futilitys.secrets.env  root:root  600
/opt/futilitys/infra/github_app_private_key.pem  root:root  600
/opt/futilitys/app/                          futilitys:futilitys  755
/var/lib/futilitys/                          futilitys:futilitys  755
/var/lib/futilitys/futilitys.db             futilitys:futilitys  640
```

---

## Troubleshooting

### Common Issues

#### Service Won't Start

```bash
# Check logs for errors
sudo journalctl -u futilitys-control-plane -n 50 --no-pager

# Common causes:
# - Missing config file: Run superscript 1 first
# - Missing secrets file: Run superscript 2 first
# - Port 8000 in use: Check with `ss -tlnp | grep 8000`
# - Python errors: Check requirements installed
```

#### TLS Certificate Issues

```bash
# Check Caddy logs
sudo journalctl -u caddy -n 50 --no-pager

# Common causes:
# - DNS not pointing to server: Check with `dig +short YOUR_DOMAIN`
# - Ports 80/443 blocked: Check firewall
# - Rate limiting: Wait and retry (Let's Encrypt limits)

# Force certificate renewal
sudo caddy reload --config /etc/caddy/Caddyfile
```

#### GitHub API Errors

```bash
# Test GitHub App JWT
/opt/futilitys/venv/bin/python -c "
from github_integration import generate_jwt
print(generate_jwt()[:50] + '...')
"

# Common causes:
# - Invalid App ID: Check GITHUB_APP_ID in config
# - Invalid private key: Check key file exists and is valid PEM
# - App not installed: Install app on target repos
# - Permissions: Ensure app has Contents and Pull Requests access
```

#### Jobs Stuck in Pending/Running

```bash
# Check for errors in recent events
sqlite3 /var/lib/futilitys/futilitys.db "
SELECT j.id, j.status, e.event_type, e.details
FROM jobs j
LEFT JOIN events e ON j.id = e.job_id
WHERE j.status IN ('pending', 'running')
ORDER BY e.created_at DESC LIMIT 20;
"

# Common causes:
# - GitHub API rate limit: Wait 1 hour
# - Invalid repository: Check repo exists and app has access
# - Network issues: Check connectivity to api.github.com
```

#### Workers Not Being Created/Deleted

```bash
# Test DigitalOcean API
curl -s -H "Authorization: Bearer $DO_TOKEN" \
  "https://api.digitalocean.com/v2/account" | jq .account.status

# List orphaned workers
curl -s -H "Authorization: Bearer $DO_TOKEN" \
  "https://api.digitalocean.com/v2/droplets?tag_name=futilitys-worker" | jq '.droplets | length'

# Common causes:
# - Invalid DO token: Regenerate in DigitalOcean console
# - API rate limit: Check response headers
# - Sweeper not running: Check timer status
```

### Debug Mode

Enable verbose logging:

```bash
# Edit systemd unit
sudo systemctl edit futilitys-control-plane

# Add:
[Service]
Environment=FUTILITYS_DEBUG=1

# Restart
sudo systemctl restart futilitys-control-plane
```

### Getting Help

1. Check `/opt/futilitys/TROUBLESHOOTING.md` on the server
2. Review logs: `sudo journalctl -u futilitys-control-plane -f`
3. Check GitHub issues for known problems
4. Include in bug reports:
   - Error messages from logs
   - Steps to reproduce
   - Server OS version (`cat /etc/os-release`)
   - Script versions (git commit hash)

---

## API Reference

### Health Check

```
GET /health

Response:
{
  "ok": true,
  "service": "futilitys-control-plane",
  "domain": "control.example.com"
}
```

### Authentication

```
POST /login
Content-Type: application/x-www-form-urlencoded

username=admin&password=yourpassword

Response: Redirect to / with session cookie
```

### List Repositories

```
GET /api/repos
Cookie: futy_session=...

Response:
{
  "repos": [
    {
      "id": 123456,
      "full_name": "org/repo",
      "private": false,
      "installation_id": 789
    }
  ]
}
```

### Create Job

```
POST /api/jobs
Cookie: futy_session=...
Content-Type: multipart/form-data

repo_full_name=org/repo
installation_id=789
file=@payload.zip (optional)
path_blocks=FILE: test.txt\nhello (optional)

Response:
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "branch": "intake/550e8400"
}
```

### Get Job Status

```
GET /api/jobs/{job_id}
Cookie: futy_session=...

Response:
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "success",
  "repo_full_name": "org/repo",
  "branch_name": "intake/550e8400",
  "pr_url": "https://github.com/org/repo/pull/123",
  "created_at": "2024-01-15 10:30:00",
  "updated_at": "2024-01-15 10:31:00"
}
```

### Worker Callbacks (Internal)

```
POST /callback/started
POST /callback/completed
POST /callback/failed
Content-Type: application/json

{
  "job_id": "...",
  "status": "...",
  "error": "..." (for failed only)
}
```

---

## License

[Your License Here]

---

## Contributing

[Your Contributing Guidelines Here]
