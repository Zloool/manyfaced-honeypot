# Contributing to Many-faced Honeypot

## The shipping loop

1. **Branch off latest `master`.** Use a descriptive name: `feature/add-jenkins-face`, `fix/ua-extraction-bug`.
2. **Commit in small, logically-grouped chunks.** Imperative mood subject line (~72 chars). Add a body when the "why" isn't obvious from the diff. Don't pre-squash locally — let squash-merge handle it.
3. **Open a PR against `master`.** Opening triggers CI (ruff lint + pytest on Python 3.14 + basedpyright type check).
4. **Watch CI.** Fix failures by fixing the underlying problem, not by disabling checks. If a failure is unrelated to your change, say so explicitly in PR comments.
5. **Squash-merge once green.** No regular merges — keep `master` linear.
6. **Verify post-merge deployment.** The deploy workflow runs automatically on push to master (after CI passes). Link the Actions run URL in a final PR comment. If no deploy workflow is configured, document that gap here.
7. **Delete the feature branch.**

## Branching conventions

| Prefix | Use case |
|--------|----------|
| `feature/` | New faces, handlers, capabilities |
| `fix/`     | Bug fixes, corrections |
| `docs/`    | Documentation-only changes |
| `chore/`   | Dependency bumps, CI tweaks, cleanup |

## Commit conventions

- **Subject:** imperative mood, ~72 chars. Examples:
  - `feat: add WebDAV face with basic auth challenge`
  - `fix: handle empty bot_user_agent in DB insert`
  - `chore: bump ruff to 0.15`
- **Body:** explain the "why" when it's not obvious from the code. Reference issue numbers if applicable.

## Code style

Style rules are enforced by tooling, not prose. The authoritative configs are:

- **Lint + format:** `pyproject.toml` → `[tool.ruff]`
- **Editor defaults:** `.editorconfig` (UTF-8, LF, 4-space indent for Python)
- **Pre-commit hook:** `.pre-commit-config.yaml` (runs ruff on staged files)

Run `ruff check . && ruff format .` before committing. The CI job will reject anything that doesn't pass.

## Tests

Tests live in `test/`. Run them with:

```bash
pytest -v --tb=short          # all tests, coverage enforced at 76% (from pyproject.toml addopts)
pytest test/test_foo.py       # single file
```

These commands match CI exactly — running them locally produces the same result as GitHub Actions.

Mock `geoip2` modules before importing anything that uses them. Use `conftest.py` for shared fixtures.

## Adding new faces (fake web services)

See `DEVELOPER.md` section "How to Add New Faces" for the full procedure:

1. Add path mapping in `manyfaced/client/faces.py` or `manyfaced/client/client.py`
2. Create a response file in `manyfaced/client/responses/`
3. Add special routing logic if the response needs custom handling

## Adding database fields

1. Add column to `_CREATE_TABLE_SQL` and `_INSERT_SQL` in `manyfaced/db/storage.py`
2. Add field extraction in both `SQLiteStorage.insert()` and `PostgreSQLStorage.insert()`
3. Add to `BearRequests` dataclass in `manyfaced/db/dbconnect.py`
4. Verify tests pass for both backends

## Pull requests

- Use the PR template (`.github/pull_request_template.md`) — it auto-populates in the GitHub UI.
- Title should follow commit conventions (`feat:`, `fix:`, etc.).
- Link any related issues with `Closes #NNN` or similar.

## Deployment

After squash-merging to `master`, the deploy workflow runs automatically (CI must pass first). The deploy process:

1. Syncs **all** repo files to `/opt/manyfaced/` on the droplet via rsync (atomic directory swap with timestamped backup)
2. Reinstalls Python dependencies in-place (`pip install -e`)
3. Updates and reloads the systemd service file from `systemd/manyfaced.service`
4. Restarts the service and runs a health check — verifies honeypot is listening on all ports listed in `HONEY_TOP_PORTS`

If any step fails, the deploy workflow automatically rolls back to the previous timestamped backup. Check the GitHub Actions tab for deployment status. The `honeypot.env` file (port config) lives only on the droplet and is not version-controlled.

## What not to do

- Don't push directly to `master`.
- Don't commit analysis output (`deployment-analysis/latest/*.md`, `*.sqlite`, `*.db`, `*.log`).
- Don't modify `.deploy_config` — it's gitignored and contains SSH credentials.
- Don't run destructive SSH commands without explicit confirmation.
