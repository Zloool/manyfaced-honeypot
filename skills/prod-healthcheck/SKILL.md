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

- SSH access to production droplet (`~/.ssh/dohp`)
- `$HOME/.deploy_config` with connection details

## Loading config

Before running any SSH commands, source the deployment config:

```bash
# Variables available: SERVER_IP, SSH_PORT, SSH_USER, SSH_KEY, REMOTE_DB, REMOTE_LOG
source "$HOME/.deploy_config"
```

## Health Check Procedure

Run all checks in a single SSH session for speed. The slim production image deliberately does not include `ps`; inspect its process tree from the Docker host with `docker top` instead.

```bash
source "$HOME/.deploy_config"
ssh -i "$SSH_KEY" -p "$SSH_PORT" "${SSH_USER}@${SERVER_IP}" "
echo '=== Container Status ===' && docker inspect --format '{{.State.Status}} restartCount={{.RestartCount}} started={{.State.StartedAt}}' manyfaced
echo '=== Processes ===' && docker top manyfaced -eo pid,ppid,comm,args
echo '=== Listening Ports ===' && docker exec manyfaced sh -c 'ss -tln 2>/dev/null | grep -c LISTEN'
echo '=== Disk Space ===' && df -h /opt/manyfaced
"
```

**Expected:** container `running`, restartCount stable at `0`, a manager plus worker `manyfaced` processes in `docker top`, and the configured honeypot/dashboard sockets listening. Assess disk by remaining free space and trend; do not use a fixed percentage threshold.

## Transient Error Check

Pull recent container errors for immediate context — output to stdout only, no file:

```bash
source "$HOME/.deploy_config"
ssh -i "$SSH_KEY" -p "$SSH_PORT" "${SSH_USER}@${SERVER_IP}" \
  "docker logs --since 24h manyfaced 2>&1 | grep -Ei 'error|exception|fail|crash' | tail -30"
```

## Interpreting Results — Health-Diagnosable Findings

Only the following findings from the full analysis are actionable at the health-check level:

| Finding | Severity | Action |
|---------|----------|--------|
| Container not running or restart count increasing | Critical | Escalate for deployment/recovery; do not restart it from this read-only check |
| Expected worker processes absent | Critical | Inspect container logs and deployment state |
| Report send failures in container logs | Medium | SERVER process may not be ready or port configuration may mismatch |
| Materially falling disk headroom | Medium | Escalate for log/data retention investigation |

## Quick Decision Tree

1. **Container inactive/crashing** → inspect container logs and latest deployment; escalate through the verified deployment/recovery workflow.
2. **Unexpected process tree** → investigate child process crashes and repeated restarts.
3. **Sockets missing** → client process may not be listening on all configured honeypot ports.
4. **Disk headroom declining** → investigate old logs and retention; do not mutate production from this read-only check.
5. **All green** → service is healthy; if deeper analysis is needed, use **prod-analysis**.

## Cross-Reference

- For full data-pull + investigation workflow (DB analysis, log parsing, report generation), see **prod-analysis** skill
- For adding new service handlers/impersonation faces, see **add-service-handler** skill
