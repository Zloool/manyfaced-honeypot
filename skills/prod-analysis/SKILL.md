---
name: prod-analysis
description: Production honeypot data-pull, investigation, and report workflow — SSH data pull from droplet, log/DB parsing with analyze_production.py, attack pattern detection, data quality audit, and structured report generation.
---

# Production Honeypot Analysis Skill

Use this skill when you need to **pull gathered data from production and investigate what's working vs. not.** This covers SSH data pulls, DB/log analysis via `analyze_production.py`, data quality audits, attack pattern detection, and structured report generation.

## Triggers

**Use this skill when:**
- "analyze production" or "investigate honeypot data"
- "pull latest data from the droplet" / "get fresh honeypot data"
- "generate a production report" / "write an analysis report"
- References to `honeypot.sqlite` analysis, attack patterns, or data quality audits

**Do NOT use this skill for:**
- Quick service health checks — use **prod-healthcheck** instead (fast read-only SSH check)
- Local development debugging (use `python3 mfh.py -c 8888 -s 9999 -v`)
- Writing new faces or handlers (see DEVELOPER.md and **add-service-handler** skill)

## Prerequisites

- SSH access to production droplet (`~/.ssh/dohp`, port from `.deploy_config`)
- `.deploy_config` file with connection details at repo root
- Python 3.10+ with sqlite3 (stdlib)
- `analyze_production.py` script in `deployment-analysis/`

## Loading config

Before running any SSH commands, source the deploy config:

```bash
# Source connection variables from .deploy_config
source .deploy_config
# Variables available: SERVER_IP, SSH_PORT, SSH_USER, SSH_KEY, REMOTE_DB, REMOTE_LOG
```

## Quick Start

```bash
# 1. Load config
source .deploy_config

# 2. Pull fresh data from production
mkdir -p deployment-analysis/latest
cd deployment-analysis/latest

# Pull log file (may not exist — logging may go to journalctl only)
ssh -i "$SSH_KEY" -p "$SSH_PORT" "${SSH_USER}@${SERVER_IP}" "cat $REMOTE_LOG" > honeypot.log 2>/dev/null || echo "No log file found on server"

# Pull database safely via scp (avoids WAL corruption from cat-redirect)
scp -i "$SSH_KEY" -P "$SSH_PORT" "${SSH_USER}@${SERVER_IP}:${REMOTE_DB}" honeypot.db

# 3. Run analysis script
cd deployment-analysis/latest
python3 ../analyze_production.py .

# 4. Generate report (see Report Generation section below)
```

## Data Sources

### 1. Log File (`honeypot.log`)
- JSON lines format, one entry per line
- Fields: `timestamp`, `level`, `logger`/`module`, `processName`/`process`, `message`
- Contains bot interactions, errors, warnings, service health info
- **Note:** May not exist on server if logging was redirected to journalctl only

### 2. SQLite Database (`honeypot.sqlite`)
- Table: `honeypot_bears` — all captured bot records
- Schema: `id`, `bot_ip`, `hostname`, `timestamp`, `request_path`, `request_command`, `request_version`, `request_raw`, `bot_user_agent`, `bot_country`, `bot_continent`, `bot_tracert`, `bot_dns_name`, `detected_id`, `hive_id`, `login`
- **WAL mode caveat:** Query via active Python connection (reads WAL), not raw file copy. Use `scp` to pull the DB file, then open it with a Python sqlite3 connection for accurate reads.

### 3. Journal Logs (`journalctl -u manyfaced`)
- Recent errors, warnings, service status
- Use for real-time health check and error trend analysis

## Analysis Workflow

### Step 1: Service Status (from prod-healthcheck)

Run **prod-healthcheck** first to verify the service is alive. Carry those findings into report section "1. Service Status". Do not repeat health checks here — delegate that to prod-healthcheck.

### Step 2: Pull Data Locally

```bash
source .deploy_config
mkdir -p deployment-analysis/latest
cd deployment-analysis/latest

# Pull log file (may not exist)
ssh -i "$SSH_KEY" -p "$SSH_PORT" "${SSH_USER}@${SERVER_IP}" "cat $REMOTE_LOG" > honeypot.log 2>/dev/null || echo "No log file found on server"

# Pull database via scp (WAL-safe — avoids cat-redirect corruption)
scp -i "$SSH_KEY" -P "$SSH_PORT" "${SSH_USER}@${SERVER_IP}:${REMOTE_DB}" honeypot.db
```

### Step 3: Run Analysis Script

```bash
cd deployment-analysis/latest
python3 ../analyze_production.py .
```

The script outputs:
- Log level distribution (DEBUG/INFO/WARNING/ERROR)
- Process breakdown (client/server/send_report/data_saving)
- Temporal activity patterns
- Top attacking IPs with mention counts
- Detected service flags distribution
- Database schema, row counts, top IPs
- Data quality metrics (empty fields)
- Request path/command distributions

### Step 4: Generate Structured Report

Create a markdown report following this template structure:

```markdown
# Production Honeypot Analysis Report

**Date:** YYYY-MM-DD  
**Server:** ${SERVER_IP} (DigitalOcean Droplet)  
**Analysis Period:** [time range from DB]

---

## 1. Service Status
- Service: active/inactive/crashing
- Processes: N running (expected: 3)
- Listening Ports: N ports
- Disk/Memory usage

### Critical Issues
1. Issue description with evidence

---

## 2. Database Analysis
- Total Records: N
- Unique IPs: N
- Time Range: start → end

### Top Attacking IPs (by request count)
| IP | Requests | Notes |
|---|---|---|

### Detected Services Distribution
| Service | Count | Percentage |
|---|---|---|

### Data Quality Issues
| Field | Empty | Percentage |
|---|---|---|

---

## 3. Log Analysis (if available)
- Total Lines: N
- Parsed: N (success rate)
- Level Distribution
- Top Errors/Warnings

---

## 4. Key Findings

### What's Working
1. ✅ Finding with evidence

### What's Not Working
1. ❌ Issue with severity and impact

### Attack Patterns Observed
1. Pattern description with examples

---

## 5. Recommendations

### High Priority (fix now)
1. Action item with rationale

### Medium Priority
1. ...

### Low Priority
1. ...

---

## 6. Recent Errors (from journalctl)
```
journalctl output here
```
```

### Step 5: Save Report

Save to `deployment-analysis/latest/report-YYYY-MM-DD.md` or similar untracked location. **Never commit analysis reports** — they contain sensitive IP data and are session-specific.

## Data Quality Checklist

When analyzing, check these fields for emptiness:

| Field | Expected Source | Common Issue |
|-------|----------------|--------------|
| `bot_country` | Geolocation lookup (MaxMind) | API not configured / key missing |
| `bot_user_agent` | HTTP header extraction | Parser bug in HTTPRequest |
| `request_raw` | Raw request capture | Truncation or serialization issue |
| `hostname` | Reverse DNS lookup | DNS timeout / no PTR record |
| `bot_dns_name` | Forward DNS lookup | DNS resolution failure |
| `bot_continent` | Derived from country | Cascading empty from bot_country |

**Typical result:** 100% empty for all geolocation fields, ~50-92% empty for request_raw. This is expected until fixes are deployed.

## Common Analysis Findings & Interpretation

<!-- Canonical detected_id values: manyfaced/common/status.py
  UNKNOWN_HTTP = 4294967294   (Generic/Monster Page)
  SSH_CLIENT     = 4294967293  (Unknown SSH Probe)
  UNKNOWN_NON_HTTP = 4294967292 (Unknown Telnet/RDP Probe)
  EMPTY_CONNECTION = 4294967291 (Zero-byte TCP connection, port scan) -->

| Finding | Severity | Meaning |
|---------|----------|---------|
| All `detected_id=4294967294` (UNKNOWN_HTTP) | Medium | Non-HTTP traffic overwhelming HTTP parser — protocol detection layer needed |
| SSH Probe (`detected_id=4294967293`) present | Good | Protocol detection is working for SSH |
| Empty Connection (`detected_id=4294967291`) present | Low | Zero-byte TCP connections (port scan behavior, no data sent) — expected from aggressive scanners |
| Process count > 3 | Critical | Process explosion — child processes crashing and restarting (see LimitNOFILE fix) |
| Empty `bot_country` (100%) | High | Geolocation not implemented/configured |
| Empty `request_raw` (>50%) | Medium | Request capture pipeline has gaps |
| Loopback traffic in DB | Low | Internal iptables redirect probes — filter 127.0.0.1 and self IP |
| Report send failures | Medium | SERVER process not ready or port mismatch |

## Reusable Analysis Script

The `analyze_production.py` script in this folder provides automated analysis:

```python
# Key functions:
parse_log_line(line)     # Parse JSON log line → dict
analyze_logs(log_path)   # Full log analysis → parsed, ip_counter, interaction_ips
analyze_db(db_path)      # Full DB analysis → schema, counts, distributions, quality
```

Run with: `python3 analyze_production.py /path/to/data/dir`

## Tips

1. **Always pull fresh data** — the DB grows continuously; old snapshots become stale quickly
2. **Check journalctl for real-time errors** — logs may not persist to file on newer deployments
3. **Filter loopback traffic** in analysis: `WHERE bot_ip NOT IN ('127.0.0.1', '${SERVER_IP}')`
4. **Compare detected_id distribution** across time periods to see if protocol detection is improving
5. **Track top IPs over time** — new high-volume IPs indicate active bot campaigns
6. **Data quality degrades** as DB grows — check empty field percentages periodically

## File Structure

```
deployment-analysis/
├── analyze_production.py    # Reusable analysis script (tracked)
├── PRODUCTION_ANALYSIS.md   # Example report from 2026-05-01 (reference)
├── latest/                  # Untracked — fresh analysis data goes here
│   ├── honeypot.db          # SQLite database dump
│   ├── honeypot.log         # Log file dump (may be empty)
│   └── report-YYYY-MM-DD.md # Generated report
```

## Security Notes

- **Never commit** `honeypot.db`, `honeypot.log`, or analysis reports — they contain attacker IP addresses and request data
- Add `deployment-analysis/latest/` to `.gitignore` if not already present
- Analysis reports are for internal use only; share sanitized summaries externally

## Cross-Reference

- For quick service health checks (is the honeypot alive?), use **prod-healthcheck** skill — run it first, carry findings into report section "1. Service Status"
- For adding new service handlers/impersonation faces, see **add-service-handler** skill
