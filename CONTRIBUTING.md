# Contributing to Many-faced Honeypot

## The shipping loop

1. **Branch off latest `master`.** Use a descriptive name: `feature/add-jenkins-face`, `fix/ua-extraction-bug`.
2. **Commit in small, logically-grouped chunks.** Imperative mood subject line (~72 chars). Add a body when the "why" isn't obvious from the diff. Don't pre-squash locally — let squash-merge handle it.
3. **Open a PR against `master`.** Opening triggers CI (ruff lint on 3.14 + pytest and basedpyright on Python 3.12, 3.13, 3.14).
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

After squash-merging to `master`, the deploy workflow runs automatically (CI must pass first). The deploy workflow rsyncs the commit to `/opt/manyfaced/releases/<sha>/`, installs deps into the shared venv, atomically flips `/opt/manyfaced/current` via rename(2), and restarts the systemd service. Post-restart, the workflow verifies every port in `HONEY_TOP_PORTS` is in LISTEN state (with a 30-second retry budget for startup). Rollback flips the symlink back to the previous release. Check the GitHub Actions tab for deployment status. The `honeypot.env` file (port config) lives only on the droplet and is not version-controlled.

Ad-hoc deploys of non-master branches are available via the Actions tab: select "Deploy to Droplet", click "Run workflow", and pick a ref. CI still runs first. Use this for feature-branch testing on the live droplet; do not use it as a replacement for the standard PR/merge flow.

## What not to do

- Don't push directly to `master`.
- Don't commit analysis output (`deployment-analysis/latest/*.md`, `*.sqlite`, `*.db`, `*.log`).
- Don't modify `.deploy_config` — it's gitignored and contains SSH credentials.
- Don't run destructive SSH commands without explicit confirmation.
