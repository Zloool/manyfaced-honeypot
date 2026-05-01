# DigitalOcean Deployment Plan — Manyfaced Honeypot

## Architecture Options

### Option A: Single Droplet (simplest)
Both CLIENT and SERVER run on the same droplet. CLIENT reports to `127.0.0.1:8888`.
- ✅ Simple, cheap, sufficient for research
- ❌ If the droplet goes down, both sides are lost

### Option B: Two Droplets (production-recommended)
CLIENT on one droplet (public IP, exposed to internet), SERVER on another (private network).
- ✅ Isolation, CLIENT can be replaced without losing data
- ❌ More expensive, more moving parts

This plan covers **Option A** (single droplet) as the default, with notes for Option B.

---

## 1. DigitalOcean Infrastructure

### 1.1 Droplet Provisioning

| Setting | Value | Rationale |
|---------|-------|-----------|
| **Region** | `fra1` (Frankfurt) or `sfo3` (San Francisco) | Low latency to most scanner sources |
| **Plan** | Basic / $6/mo (1 vCPU, 1 GB RAM) | Honeypot is lightweight; Python + SQLite fits easily |
| **OS Image** | Ubuntu 22.04 LTS or 24.04 LTS | Long-term support, well-documented |
| **SSH Key** | Add your public key | No password auth |
| **SSH Port** | `22222` (or any high port you choose) | Obfuscation — moves SSH off the default port |
| **Volume** | 25 GB Standard SSD (default) | Logs + SQLite DB will grow over time |

> **Option B — Second droplet:** Same spec, but attach both droplets to the same VPC / private network so the CLIENT can reach the SERVER via private IP.

### 1.2 Networking & Firewall

Create a DigitalOcean Firewall with these rules:

| Direction | Protocol | Port | Source | Purpose |
|-----------|----------|------|--------|---------|
| Inbound | TCP | `22222` (your chosen SSH port) | Your IP | SSH access (non-standard) |
| Inbound | TCP | 80 | 0.0.0.0/0 | Client honeypot (WordPress, phpMyAdmin, etc.) |
| Inbound | TCP | 443 | 0.0.0.0/0 | Client honeypot (HTTPS impersonation) |
| Inbound | TCP | `8888` (your chosen server port) | 0.0.0.0/0 | Server — receives encrypted reports |
| Inbound | TCP | 21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017, 5672, 15672 | 0.0.0.0/0 | Additional honeypot ports (top-50 mode) |

> **Port choices:**
> - **SSH:** `22222` (or pick any high port, e.g. `44444`, `31337`) — you decide, note it down
> - **SERVER (honeypot reports):** `8888` — non-standard, only needed for CLIENT→SERVER comms on localhost
> - **Honeypot ports:** keep standard (80, 443) and top-50 scanned ports — bots hit these

> **Warning:** Opening all these ports means *any* IP can connect. This is intentional for a honeypot, but be aware that the CLIENT will receive real malicious traffic.

### 1.3 Domain (optional)

Not strictly required — the honeypot responds to raw HTTP requests regardless of `Host` header. But if you want:
- A domain pointing to the droplet IP for more realistic bot interactions
- Use DigitalOcean DNS, create an `A` record

---

## 2. Server Setup (SSH + System)

### 2.1 Connect

```bash
ssh -p 22222 root@<droplet-ip>
```

> Replace `22222` with whatever SSH port you chose in the firewall.

### 2.2 System packages

```bash
apt update && apt upgrade -y
apt install -y python3 python3-pip python3-venv git curl
```

### 2.3 Change SSH port (obfuscation)

Before creating the honeypot user, change SSH to your chosen non-standard port:

```bash
# Edit SSH config
sed -i 's/#Port 22/Port 22222/' /etc/ssh/sshd_config
# Restart SSH
systemctl restart sshd
# Verify it's listening on the new port
ss -tlnp | grep sshd
```

> **Important:** Do this BEFORE closing your current session. Test a new connection in a second terminal first:
> ```bash
> # In a NEW terminal window:
> ssh -p 22222 root@<droplet-ip>
> ```
> If the new connection works, close the old one. If not, stay on the original session and troubleshoot.

### 2.4 Create a dedicated user (security)

```bash
adduser --disabled-password --gecos "" honeypot
usermod -aG sudo honeypot
```

### 2.5 Python virtual environment

```bash
su - honeypot
mkdir -p /opt/manyfaced
cd /opt/manyfaced
python3 -m venv venv
source venv/bin/activate
```

### 2.6 Install the honeypot

```bash
git clone https://github.com/Zloool/manyfaced-honeypot.git .
pip install -e .
```

### 2.7 GeoIP support (optional but recommended for bot attribution)

```bash
# GeoLite2 database — requires free MaxMind account
pip install python-geoip-geolite2
geoip2 download
# Or use the alternative:
pip install geoip2
```

---

## 3. Configuration

### 3.1 Environment variables

Create `/opt/manyfaced/honeypot.env`:

```bash
# Client — port to impersonate services on
HONEY_HONEYPORT=80

# Client — port mode (single, top, all)
HONEY_PORT_MODE=top

# Hive (server) settings
HONEY_HIVEHOST=127.0.0.1
HONEY_HIVEPORT=8888
HONEY_HIVELOGIN=your_unique_bear_id
HONEY_HIVEPASS=your_strong_random_aes_key

# Database
HONEY_DB_BACKEND=sqlite
HONEY_DB_PATH=/opt/manyfaced/bots/honeypot.sqlite

# Logging
HONEY_LOG_FILE=/opt/manyfaced/bots/honeypot.log

# Security
HONEY_AUTHORISEDBEARS=""
```

> **Port mapping:**
> - `HONEY_HIVEPORT=8888` — matches the firewall rule for the SERVER
> - `HONEY_HONEYPORT=80` — client listens on 80 (standard HTTP, bots expect this)
> - If you chose a different server port, update both the firewall rule AND `HONEY_HIVEPORT`

> **Generate strong keys:**
> ```bash
> python3 -c "import secrets; print(secrets.token_hex(32))"
> ```

### 3.2 Create data directories

```bash
mkdir -p /opt/manyfaced/bots
```

---

## 4. Systemd Service

Create `/etc/systemd/system/manyfaced.service`:

```ini
[Unit]
Description=Manyfaced Honeypot
After=network.target

[Service]
Type=simple
User=honeypot
Group=honeypot
WorkingDirectory=/opt/manyfaced
EnvironmentFile=/opt/manyfaced/honeypot.env
ExecStart=/opt/manyfaced/venv/bin/python3 -m manyfaced.mfh
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=manyfaced

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/manyfaced/bots

[Install]
WantedBy=multi-user.target
```

### Enable and start

```bash
systemctl daemon-reload
systemctl enable manyfaced
systemctl start manyfaced
```

### Check status

```bash
systemctl status manyfaced
journalctl -u manyfaced -f   # live logs
```

---

## 5. Verification

### 5.1 Check the honeypot is running

```bash
ss -tlnp | grep -E '80|8888'
# Should show LISTEN on port 80 (client) and 8888 (server)
```

### 5.2 Test with a curl request

```bash
curl -v http://<droplet-ip>/wp-login.php
curl -v http://<droplet-ip>/phpmyadmin/
```

### 5.3 Check logs

```bash
journalctl -u manyfaced --since "5 minutes ago"
cat /opt/manyfaced/bots/honeypot.log
```

### 5.4 Check database

```bash
sqlite3 /opt/manyfaced/bots/honeypot.sqlite "SELECT COUNT(*) FROM honeypot_bears;"
```

---

## 6. Maintenance

### 6.1 Updates

```bash
systemctl stop manyfaced
cd /opt/manyfaced
git pull
pip install -e .
systemctl start manyfaced
```

### 6.2 Log rotation

The app uses `RotatingFileHandler` (10 MB, 5 backups). For production, add a separate `logrotate` config:

```bash
# /etc/logrotate.d/manyfaced
/opt/manyfaced/bots/honeypot.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    copytruncate
}
```

### 6.3 Database backup

```bash
# Cron job — daily backup
0 3 * * * cp /opt/manyfaced/bots/honeypot.sqlite /opt/manyfaced/bots/honeypot.sqlite.$(date +\%Y\%m\%d)
```

### 6.4 Monitoring

- `htop` / `top` for resource usage
- `ss -s` for connection counts
- Monitor disk space: `df -h`
- Consider DigitalOcean monitoring agent for CPU/RAM/disk metrics

---

## 7. Option B: Two-Droplet Architecture

If deploying CLIENT and SERVER on separate droplets:

### CLIENT droplet:
```bash
# HONEY_HIVEHOST = SERVER's PRIVATE IP
# HONEY_HIVEPORT = 8888
# Open all honeypot ports + SSH
```

### SERVER droplet:
```bash
# Only open SSH + 8888 (from CLIENT's private IP only)
# HONEY_DB_PATH = persistent volume mount
# Consider PostgreSQL for scale
```

### VPC setup:
1. Create a VPC in DigitalOcean
2. Attach both droplets to the VPC
3. Use private IPs for CLIENT→SERVER communication

---

## 8. Security Considerations

| Concern | Mitigation |
|---------|-----------|
| SSH brute-force attacks | Moved to non-standard port (e.g. 22222), restrict source IP in firewall |
| Honeypot receives real malicious traffic | Firewall only exposes what's needed; app runs as non-root user |
| SQLite file grows unbounded | Log rotation + periodic DB cleanup / export |
| HIVEPASS key in env file | Restrict file permissions: `chmod 600 /opt/manyfaced/honeypot.env` |
| DigitalOcean account security | Enable 2FA, use SSH keys only, restrict API tokens |
| Bot traffic could be abusive | Rate-limiting at firewall level if needed |
| GeoIP database license | Check MaxMind EULA for honeypot use |

---

## 9. Deployment Checklist

- [ ] Create DigitalOcean account
- [ ] Add SSH key to DO account
- [ ] Create firewall (or use default)
- [ ] Provision droplet (Ubuntu 22.04/24.04)
- [ ] Configure firewall rules:
  - [ ] SSH on your chosen non-standard port (e.g. 22222), restricted to your IP
  - [ ] Ports 80, 443 open to 0.0.0.0/0
  - [ ] SERVER port (e.g. 8888) open to 0.0.0.0/0
  - [ ] Additional honeypot ports (top-50) open to 0.0.0.0/0
- [ ] SSH into droplet on the non-standard port
- [ ] Change SSH port from 22 to your chosen port (test new connection first!)
- [ ] Set up system packages
- [ ] Create honeypot user + venv
- [ ] Clone repo, install package
- [ ] Configure `honeypot.env` with strong keys and matching server port
- [ ] Create systemd service
- [ ] Enable + start service
- [ ] Verify with `curl` tests
- [ ] Check logs and database
- [ ] Set up logrotate + DB backup cron
- [ ] (Optional) Set up monitoring/alerting

---

## 10. Estimated Cost

| Item | Monthly Cost |
|------|-------------|
| Basic droplet ($6/mo) | $6 |
| Additional droplet (Option B) | +$6 |
| Firewall | Free |
| Monitoring agent | Free |
| Domain (optional) | ~$10/yr |
| **Total** | **$6–$12/mo** |
