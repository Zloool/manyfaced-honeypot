---
name: prod-healthcheck
description: Fast read-only SSH health check for the manyfaced honeypot service — is it alive, are processes running, ports listening, disk healthy? No data pulls, no reports, nothing written to disk.
---

# Production Honeypot Health Check Skill

Use this skill when you need a quick answer: **is the honeypot alive and healthy right now?** This is a fast, read-only SSH session — no files downloaded, no analysis scripts run, nothing written to disk.

## Triggers

**Use this skill when:**
- "is the honeypot running?" / "manyfaced service status" / "check the honeypot" / "quick health check"
- You need a fast yes/no on service liveness before doing deeper analysis

**Do NOT use this skill for:**
- Data pulls, quality audits, or report generation — use **prod-analysis** instead
- Investigating attack patterns or bot behavior over time
- Analyzing production database data quality (it's PostgreSQL on prod, not sqlite) — use **prod-analysis** for that

## Prerequisites

- SSH access to production droplet (`~/.ssh/dohp`, port from `.deploy_config`)
- `.deploy_config` file with connection details at repo root

## Loading config

Before running any SSH commands, source the deploy config:

```bash
# Source connection variables from .deploy_config
source .deploy_config
# Variables available: SERVER_IP, SSH_PORT, SSH_USER, SSH_KEY, REMOTE_DB, REMOTE_LOG
```

## Health Check Procedure

Run all checks in a single SSH session for speed:

```bash
source .deploy_config
ssh -i "$SSH_KEY" -p "$SSH_PORT" "${SSH_USER}@${SERVER_IP}" "
echo '=== Container Status ===' && docker ps --filter name=manyfaced --format '{{.Names}} {{.Status}}' 2>&1
echo '=== Processes ===' && docker exec \$(docker ps -q --filter name=manyfaced) ps aux 2>/dev/null | grep -E 'mfh|python' | grep -v grep
echo '=== Listening Ports ===' && docker exec \$(docker ps -q --filter name=manyfaced) ss -tlnp 2>/dev/null | grep -c LISTEN
echo '=== Disk Space ===' && df -h /opt/manyfaced
"
```

**Expected:** 3 processes (main + client + server), 47 ports, <50% disk usage.

## Transient Error Check

Pull recent errors from journalctl for immediate context — output to stdout only, no file:

```bash
source .deploy_config
ssh -i "$SSH_KEY" -p "$SSH_PORT" "${SSH_USER}@${SERVER_IP}" \
  "journalctl -u manyfaced --no-pager --since '24 hours ago' | grep -E 'error|exception|fail|crash' | tail -30"
```

## Interpreting Results — Health-Diagnosable Findings

Only the following findings from the full analysis are actionable at the health-check level:

| Finding | Severity | Action |
|---------|----------|--------|
| Process count > 3 | Critical | Process explosion — child processes crashing and restarting (see LimitNOFILE fix) |
| Report send failures in journal | Medium | SERVER process not ready or port mismatch — check server-side config |

## Quick Decision Tree

1. **Service inactive/crashing** → Restart the container: `docker restart manyfaced` (or push to master to redeploy; the deploy pipeline restarts it)
2. **Process count > 3** → Investigate child process crashes (check journal for repeated start/stop cycles)
3. **Ports < expected** → Client process may not be listening on all HONEYTOP_PORTS
4. **Disk > 50%** → Clean up old logs or expand volume
5. **All green** → Service is healthy; if deeper analysis needed, use **prod-analysis** skill

## Cross-Reference

- For full data-pull + investigation workflow (DB analysis, log parsing, report generation), see **prod-analysis** skill
- For adding new service handlers/impersonation faces, see **add-service-handler** skill
