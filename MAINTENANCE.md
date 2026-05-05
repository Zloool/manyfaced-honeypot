# Maintenance Reference

## Production Server
- Server: root@68.183.114.1
- SSH port: 22222
- SSH key: ~/.ssh/dohp
- Service: manyfaced (systemd)
- Install path: /opt/manyfaced/bots/
- DB: /opt/manyfaced/bots/honeypot.sqlite
- Log: /opt/manyfaced/bots/honeypot.log

## Quick Commands
```bash
# SSH to prod
ssh -i ~/.ssh/dohp -p 22222 root@68.183.114.1

# Check service status
ssh -i ~/.ssh/dohp -p 22222 root@68.183.114.1 "systemctl status manyfaced"

# Check logs
ssh -i ~/.ssh/dohp -p 22222 root@68.183.114.1 "journalctl -u manyfaced --no-pager -n 50"

# Check DB
ssh -i ~/.ssh/dohp -p 22222 root@68.183.114.1 "sqlite3 /opt/manyfaced/bots/honeypot.sqlite 'SELECT COUNT(*) FROM honeypot_bears'"

# Backup DB locally
mkdir -p deployment-analysis/latest && \
ssh -i ~/.ssh/dohp -p 22222 root@68.183.114.1 "cp /opt/manyfaced/bots/honeypot.sqlite /tmp/hp-latest.sqlite && cat /tmp/hp-latest.sqlite" > deployment-analysis/latest/honeypot.db

# Analyze production data
cd deployment-analysis/latest && python3 ../analyze_production.py .

# Deploy (push to master triggers auto-deploy)
git push origin master
```

## Architecture
- Client: multi-port listener → HTTPHandler → HandlerRegistry → ServiceHandler → send_report()
- Server: single-port listener → ServerHandler → BearRequests → Insert() → SQLiteStorage
- BearStorage: encapsulates bot data for report
- HTTPRequest: wraps BaseHTTPRequestHandler for string parsing
- GenericHandler: catch-all (detected_id=4294967294)
- Report transport: encrypted TCP (AES) client→server

## CI/CD
- Branch: master
- CI: pytest (3.11, 3.12, 3.13) + ruff lint
- Deploy: workflow_run trigger on CI success
- Deploy: rsync + pip install + systemctl restart
- .deploy_config in .gitignore
