# Maintenance Reference

## Production Server
- Server: root@68.183.114.1
- SSH port: 22222
- SSH key: ~/.ssh/dohp
- Service: manyfaced (runs as a Docker container; deploy restarts the container)
- Install path: /opt/manyfaced/ (releases under /opt/manyfaced/releases/<sha>, current symlinked)
- DB: **PostgreSQL** (container runs with `HONEY_DB_BACKEND=postgresql`; no `honeypot.sqlite` on prod)
- Log: /opt/manyfaced/bots/honeypot.log (inside container; see journalctl for the service wrapper)

## Quick Commands
```bash
# SSH to prod
ssh -i ~/.ssh/dohp -p 22222 root@68.183.114.1

# Check service status (prod runs as a Docker container)
ssh -i ~/.ssh/dohp -p 22222 root@68.183.114.1 "docker ps --filter name=manyfaced --format '{{.Names}} {{.Status}}'; systemctl status manyfaced --no-pager 2>&1 | head -5"

# Check logs
ssh -i ~/.ssh/dohp -p 22222 root@68.183.114.1 "journalctl -u manyfaced --no-pager -n 50"

# Check DB (production uses PostgreSQL — read counts via docker exec + psql,
# or connect with psycopg2 using the HONEY_PG_* vars from /tmp/pg_env)
ssh -i ~/.ssh/dohp -p 22222 root@68.183.114.1 "docker exec \$(docker ps -q --filter name=manyfaced) psql -tAc 'SELECT COUNT(*) FROM honeypot_bears'"

# Pull a fresh DB dump locally (PostgreSQL custom/SQL dump, NOT a sqlite file)
mkdir -p deployment-analysis/latest && \
ssh -i ~/.ssh/dohp -p 22222 root@68.183.114.1 "docker exec \$(docker ps -q --filter name=manyfaced) pg_dump -t honeypot_bears honeypot" > deployment-analysis/latest/honeypot_bears.sql

# Analyze production data
cd deployment-analysis/latest && python3 ../analyze_production.py .

# Deploy (push to master triggers auto-deploy)
git push origin master
```

## Architecture
- Client: multi-port listener → HTTPHandler → Router → ServiceHandler → send_report()
- Server: single-port listener → ServerHandler → BearRequests → Insert() → PostgreSQLStorage (prod) / SQLiteStorage (local dev)
- BearStorage: encapsulates bot data for report
- HTTPRequest: wraps BaseHTTPRequestHandler for string parsing
- GenericHandler: catch-all (detected_id=4294967294)
- Report transport: encrypted TCP (AES) client→server

## CI/CD
- Branch: master
- CI: ruff lint/format + pytest + basedpyright (Python 3.14) — all in a single `deploy.yml` workflow
- Deploy: push-to-master trigger (CI passes first, same workflow, no workflow_run latency); manual dispatch from Actions tab for ad-hoc deploys
- Deploy: rsync + pip install + systemctl restart + per-port ss health check
- Concurrency: serialized deploys via `concurrency: deploy-droplet` group
- .deploy_config in .gitignore
