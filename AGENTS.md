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
    storage.py          # _resolve_db_path() precedence: env > TOML config > default 'bots/honeypot.sqlite'
deployment-analysis/    # Production analysis scripts and data (untracked output in latest/)
bots/                   # Untracked — honeypot.sqlite lives here on prod
skills/prod-analysis/   # SSH-based production analysis workflow skill
test/                   # pytest suite (~76% coverage target)
systemd/                # manyfaced.service + logrotate config
.github/workflows/      # CI (ruff lint, deploy only — no tests on master push), deploy (SSH rsync to droplet)
```

## Local development

1. **Install deps:** `pip install -e ".[dev]"`
2. **Run tests:** `pytest -v --tb=short` (coverage enforced at 76%, matches CI exactly)
3. **Lint/format:** `ruff check . && ruff format .`
4. **Run a bot locally:** `python3 mfh.py -c 8888 -s 9999 -v`

See `DEVELOPER.md` for architecture deep-dive and how to add new faces.

## Deployment

Production runs on a DigitalOcean droplet (`~/.deploy_config` holds connection details). The service is managed via systemd (`systemctl status manyfaced`). Health check: SSH in and run `systemctl status manyfaced --no-pager`. For the full analysis workflow (SSH data pull, log/DB parsing, report generation), see the **prod-analysis skill**.

The deploy pipeline (GitHub Actions) runs automatically on push to `master` — it skips tests and deploys directly. It syncs all files atomically via rsync into a per-commit staging directory under `/opt/manyfaced/releases/<sha>/`, reinstalls deps, swaps the symlink (`/opt/manyfaced/current → releases/<sha>`), restarts the service, and verifies honeypot ports are listening. If any step fails, it rolls back to the previous backup.

### Config file locations (critical for debugging)

- **Service runs as `honeypot` user** — reads config from `/home/honeypot/.config/manyfaced/config.toml`, NOT root's config
- Root's stale config at `/root/.config/manyfaced/config.toml` is ignored by the service but can cause Python import errors if loaded directly as root
- **Production DB path:** `/opt/manyfaced/bots/honeypot.sqlite` (persistent, outside releases directory)
- The storage backend (`_resolve_db_path()`) resolves DB path with this precedence:
  1. `HONEY_DB_PATH` environment variable (highest priority)
  2. `database.path` from TOML config (`settings.DB_PATH`)
  3. Default `'bots/honeypot.sqlite'` (relative to CWD — **this was the bug that caused data loss**)

### CI/CD monitoring pattern

- Use `gh run watch <run-id>` to wait on GitHub Actions runs — do NOT use `sleep N` loops
- After pushing a branch: `gh pr create ... && gh pr checks <pr-number> --watch` or `gh run watch <run-id>`

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
