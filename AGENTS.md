# Many-faced Honeypot — Agent Landing Page

## What is this?

A Python 3.12+ socket-based honeypot that impersonates many web services (WordPress, phpMyAdmin, WebDAV, Jenkins, etc.) to capture bot interactions. On production the captured data lands in a **PostgreSQL** database (see *Config file locations* below); for local/dev the default backend is SQLite. The service runs as a Docker container on a DigitalOcean droplet.

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
bots/                   # Untracked — local SQLite DB / runtime artifacts land here in dev
skills/prod-healthcheck/  # Fast read-only service health check (SSH)
skills/prod-analysis/     # Data-pull + investigation + report generation workflow
test/                   # pytest suite (~76% coverage target)
systemd/                # manyfaced.service + logrotate config
.github/workflows/      # CI (ruff lint, deploy only — no tests on master push), deploy (SSH rsync to droplet)
```

## Local development

1. **Install deps:** `pip install -e ".[dev]"`
2. **Install pre-commit hooks (one-time):** `pre-commit install` — runs
   ruff + docs-drift + basedpyright + actionlint locally, matching the fast
   CI gates (see [Definition of Done](#definition-of-done-pre-pr-contract)).
3. **Run tests:** `pytest -v --tb=short` (coverage enforced at 76%, matches CI exactly)
4. **Lint/format:** `ruff check . && ruff format .`
5. **Run a bot locally:** `python3 mfh.py -c 8888 -s 9999 -v`

See [`docs/DEVELOPER.md`](docs/DEVELOPER.md) for architecture deep-dive and how to add new faces.

## Definition of Done (pre-PR contract)

Before opening a PR, ALL of the following must be GREEN locally. These are
exactly the gates CI enforces — no drift between this checklist and CI:

- `ruff check .`
- `ruff format --check .`
- `basedpyright manyfaced/`
- `pytest` (coverage gate is enforced at 76% — if local coverage drops, CI fails)
- `python .github/workflows/scripts/check_docs_drift.py` (doc/code drift check)

Additional rules:

- **Behavior change** → add or update a test that fails without the fix.
- **Doc-affecting change** → re-run the docs-drift check (and update `docs/` if a referenced symbol/CLI changed).
- **New CI job or required status check** → add it to branch protection's required
  checks and to `deploy.yml`'s `needs:` so it actually blocks merges.
- Once #146 lands: also verify `docker compose config` for container-buildable changes.

The PR template (`.github/pull_request_template.md`) links here; fill it out on
every PR. Pairs with #152 (these same gates wired as pre-commit hooks for a
tighter agent loop).

## AI commit attribution (co-author convention)

Every commit made by an AI agent MUST carry a `Co-authored-by:` trailer that
identifies **both the agent and the model** that produced the change. This is the
single source of truth for attribution and was adopted to stop silent /
mis-attributed AI commits (see issue #205).

**Format — include one trailer per agent that authored the commit:**

```
Co-authored-by: <Agent>/<Model> <noreply@nousresearch.com>
```

Concrete examples (the model segment is the live model id, e.g. `Hy3`):

```
Co-authored-by: Hermes/Hy3 <noreply@nousresearch.com>
```

When a human is also an author of the commit, keep their trailer too — the
repo owner's canonical handle is **`Zloool`** (double-o), never `Zlooo`:

```
Co-authored-by: Zloool <zloool@users.noreply.github.com>
```

Rules:

- The trailer goes in the commit **message body** (after a blank line, following
  the standard Git trailer convention). A bare `Co-authored-by: Hermes` without
  the `/<Model>` segment is not sufficient.
- A commit authored entirely by an AI still needs the human owner's trailer when
  the human reviewed/approved it; if the human did not, the agent trailer alone
  is fine.
- This is documented rather than hard-enforced in CI: commit trailers are lost
  on squash-merge, so enforcement lives in the agent loop (this doc + the
  commit tooling), not in a post-merge check. The acceptance gate for #205 is
  "no commit in history lacks attribution" — verify before pushing.
- If you ever see `Co-authored-by: Zlooo` (single-o typo), it is wrong and must
  be rewritten to `Zloool` (see #205 for the history-rewrite procedure).

## Deployment

Production runs on a DigitalOcean droplet (`~/.deploy_config` holds connection details). The service runs as a Docker container (the deploy pipeline restarts it on each push to `master`). For a quick health check, use the **prod-healthcheck** skill; for the full analysis workflow (SSH data pull, log/DB parsing, report generation), see the **prod-analysis** skill.

The deploy pipeline (GitHub Actions) runs automatically on push to `master` — it skips tests and deploys directly. It syncs all files atomically via rsync into a per-commit staging directory under `/opt/manyfaced/releases/<sha>/`, reinstalls deps, swaps the symlink (`/opt/manyfaced/current → releases/<sha>`), restarts the service, and verifies honeypot ports are listening. If any step fails, it rolls back to the previous backup.

### Config file locations

- **Service runs as `honeypot` user** inside a Docker container (image built from the repo `Dockerfile`); config is read from `/home/honeypot/.config/manyfaced/config.toml` and backend settings come from `HONEY_*` env vars (see `templates/honeypot.env.example`).
- **Production DB:** **PostgreSQL** — the container runs with `HONEY_DB_BACKEND=postgresql` (see `/tmp/pg_env` on the droplet). There is **no** `honeypot.sqlite` on prod; SQLite is only the local/dev default backend. To query prod, connect via `psycopg2` using the PG env vars (or `docker exec` + `psql` inside the container).

### CI/CD monitoring pattern

- Use `gh run watch <run-id>` to wait on GitHub Actions runs — do NOT use `sleep N` loops
- After pushing a branch: `gh pr create ... && gh pr checks <pr-number> --watch` or `gh run watch <run-id>`

## Available skills

- **`skills/prod-healthcheck`** — Fast read-only SSH health check for the manyfaced service. Use when you need a quick answer: is it alive, are processes running, ports listening? Triggers: "is the honeypot running?", "manyfaced service status", "quick health check".
- **`skills/prod-analysis`** — Production honeypot data-pull + investigation workflow. Use for SSH data pulls from droplet, log/DB parsing with `analyze_production.py`, attack pattern detection, data quality audit, and structured report generation. Triggers: "analyze production", "pull latest data", "generate a production report".

## Pointers

- For repo workflow and how to ship a change, see [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md)
- For code style, the linter configs in `pyproject.toml` / `.ruff.toml` are authoritative
- For per-PR checklist, see [.github/pull_request_template.md](.github/pull_request_template.md)

## Observability / metrics (#166)

The honeypot exposes lightweight, dependency-free live metrics from
`manyfaced/common/metrics.py`. No external services required.

- **Counters:** `bot_connections`, `credential_captures`, `report_send_success`,
  `report_send_failure`, `geo_lookup_failure`, `db_insert_failure`,
  `handler_exception`.
- **Per-domain response counter:** `responses.<domain>` (e.g. `responses.wordpress`).
- **Gauges:** `report_queue_depth` (backpressure signal), `active_connections`.

Two surfaces:
1. **Structured `stats` log line** emitted every 60s by a daemon thread
   (consumable by the prod-analysis skill and the #165 canary checks), e.g.:
   `INFO ... stats metrics bot_connections=12 credential_captures=3 ...`
2. **`metrics.snapshot()`** — a plain `dict` any component can read to fire on a
   signal (this is the feed the #125 credential-capture alerting consumes).

To add a new signal: call `metrics.incr(name)` / `metrics.set_gauge(name, value)`
at the relevant hook point (router dispatch, report send, storage insert,
geo lookup, credential capture). No new dependency is introduced.

## Handler-replay corpus (#163)

Deterministic, offline validation of handler behavior: feed a raw probe, check
what each face returns. No live bots, no network.

- **Corpus:** `test/corpus/*.raw` — one representative raw probe per scenario
  (WordPress login, phpMyAdmin, `.env` disclosure, SSH banner, FTP creds,
  Redis/VNC handshakes, path traversal, empty/malformed, WebDAV/Jenkins/XML-RPC).
- **Harness:** `test/test_handler_replay.py` runs every probe through
  `HTTPHandler.handle_request` and snapshots the normalized response under
  `test/corpus/snapshots/<scenario>.json`. A handler/route change shows up as a
  snapshot diff — the reviewable blast-radius of the change.
- **Regen:** after an intentional behavior change, run
  `REGEN_SNAPSHOTS=1 pytest test/test_handler_replay.py` and commit the updated
  golden files. Volatile content (Date/Server/Set-Cookie headers, the random
  fake OpenSSH version) is normalized out so snapshots reflect handler *logic*,
  not server clock or randomness.

## Container / Docker (#146)

The honeypot has a `Dockerfile`, `.dockerignore`, and `compose.yaml` for
reproducible local dev, CI, and a future containerized deploy (#149).

- Image runs as the non-root `honeypot` user; captures persist in a named
  volume at `/opt/manyfaced/bots` (mirrors the droplet path).
- Config is wired from `HONEY_*` env vars via `compose.yaml`'s `env_file` (an
  `.env` git-ignored file, seeded from `templates/honeypot.env.example`).
- The **Build Image** workflow builds the image and smoke-tests
  `manyfaced --generate-config` + `docker compose config` on every push/PR. It
  is intentionally NOT a required status check, so it never blocks merges.
- When adding a port/handler, update `compose.yaml` ports and the env example in
  lockstep so the container exposes what prod does.

## Guardrails

- **Never push to `master`** — always work on a feature branch and open a PR
- **AI-authored commits must carry a `Co-authored-by: <Agent>/<Model>` trailer**
  (see [AI commit attribution](#ai-commit-attribution-co-author-convention));
  the human owner is `Zloool` (double-o), never `Zlooo`
- **Never commit analysis output**, DB files (`*.sqlite`, `*.db`), or logs (`*.log`)
- **Never modify `.deploy_config` in the repo** — it's gitignored for a reason
- **Don't run destructive SSH commands** (e.g., `rm -rf /opt/manyfaced`) without explicit confirmation

## Secrets and config

- `.deploy_config` — SSH creds, droplet IP, ports. **Never committed.**
- `~/.ssh/dohp` — private key for the production droplet. Keep it local.
- `honeypot.env` on the server — environment variables for the systemd service.
- Config auto-generates at `~/.config/manyfaced/config.toml` on first run via `Config.generate_config_file()`.
