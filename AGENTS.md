# Many-faced Honeypot — Agent Landing Page

## What is this?

A Python 3.12+ socket-based honeypot that impersonates many web services (WordPress, phpMyAdmin, WebDAV, Jenkins, etc.) to capture bot interactions. Captured data lands in `honeypot.sqlite` on a DigitalOcean droplet and is served via systemd as the `manyfaced` service.

## Repo layout

```
mfh.py                  # Legacy entry point — calls manyfaced.mfh:run
manyfaced/              # Package root
  mfh.py                # CLI entry point (multiprocess manager)
  common/               # Config, args parsing, crypto, utils
  client/               # Honeypot CLIENT — serves fake responses to bots
  server/               # Honeypot SERVER — receives encrypted bot reports
  handlers/             # Request processing (ABC pattern, service-specific handlers)
  db/                   # Data persistence layer (SQLite / PostgreSQL)
deployment-analysis/    # Production analysis scripts and data (untracked output in latest/)
bots/                   # Untracked — honeypot.sqlite lives here on prod
skills/prod-analysis/   # SSH-based production analysis workflow skill
test/                   # pytest suite (~76% coverage target)
systemd/                # manyfaced.service + logrotate config
.github/workflows/      # CI (ruff lint, pytest on 3.12, basedpyright), deploy (SSH rsync to droplet)
```

## Local development

1. **Install deps:** `pip install -e ".[dev]"`
2. **Run tests:** `pytest -v --tb=short` (coverage enforced at 76%, matches CI exactly)
3. **Lint/format:** `ruff check . && ruff format .`
4. **Run a bot locally:** `python3 mfh.py -c 8888 -s 9999 -v`

See `DEVELOPER.md` for architecture deep-dive and how to add new faces.

## Deployment

Production runs on a DigitalOcean droplet (`~/.deploy_config` holds connection details). The service is managed via systemd (`systemctl status manyfaced`). Health check: SSH in and run `systemctl status manyfaced --no-pager`. For the full analysis workflow (SSH data pull, log/DB parsing, report generation), see the **prod-analysis skill**.

## Available skills

- **`skills/prod-analysis`** — Production honeypot analysis via SSH. Use when you need to analyze production bot data, check service health on the droplet, or generate structured reports from `honeypot.sqlite` and `honeypot.log`. Triggers: "analyze production", "check the honeypot", "pull latest data", "manyfaced service status".

## Pointers

- For repo workflow and how to ship a change, see [CONTRIBUTING.md](CONTRIBUTING.md)
- For code style, the linter configs in `pyproject.toml` / `.ruff.toml` are authoritative
- For per-PR checklist, see [.github/pull_request_template.md](.github/pull_request_template.md)

## Guardrails

- **Never push to `master`** — always work on a feature branch and open a PR
- **Never commit analysis output**, DB files (`*.sqlite`, `*.db`), or logs (`*.log`)
- **Never modify `.deploy_config` in the repo** — it's gitignored for a reason
- **Don't run destructive SSH commands** (e.g., `rm -rf /opt/manyfaced`) without explicit confirmation

## Secrets and config

- `.deploy_config` — SSH creds, droplet IP, ports. **Never committed.**
- `~/.ssh/dohp` — private key for the production droplet. Keep it local.
- `honeypot.env` on the server — environment variables for the systemd service.
- Config auto-generates at `~/.config/manyfaced/config.toml` on first run (from `settings.toml.example`).
