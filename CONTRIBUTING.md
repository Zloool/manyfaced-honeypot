# Contributing to Many-faced Honeypot

Thank you for your interest in contributing! This guide covers how to get started and the conventions we follow.

## Getting Started

1. Fork and clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Copy settings template: `cp manyfaced/common/settings.py.example manyfaced/common/settings.py`
4. Run a quick test: `python3 mfh.py -c 8888 -s 9999 -v`

## Workflow

### Adding Features

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Implement your changes
3. Add tests for new functionality
4. Update README.md if you change behavior
5. Submit a pull request

### Adding New Faces (Fake Web Services)

See `DEVELOPER.md` section "How to Add New Faces" for the full procedure.

Quick summary:
1. Add path mapping to `manyfaced/client/faces.py` or `manyfaced/client/client.py`
2. Create a response file in `manyfaced/client/responses/`
3. Add special routing logic if the response needs custom handling

### Adding Database Fields

1. Add column to `_CREATE_TABLE_SQL` and `_INSERT_SQL` in `manyfaced/db/storage.py`
2. Add field extraction in both `SQLiteStorage.insert()` and `PostgreSQLStorage.insert()`
3. Add to `BearRequests` dataclass in `manyfaced/db/dbconnect.py`
4. Verify tests pass for both backends

### Code Style

- Follow PEP 8 with reasonable defaults
- No trailing commas required but welcome
- String literals: single quotes unless the string contains single quotes
- Type hints: prefer them on new code (existing code may have partial annotations)
- Docstrings: use docstrings for public functions and classes

## Writing Tests

Tests go in the `test/` directory.

```bash
# Run all tests
cd /home/zlol/manyfaced-honeypot
/usr/bin/python3 -m pytest test/ -v

# Run a specific test
/usr/bin/python3 -m pytest test/test_integration.py -v
```

### Test Conventions

- Use `/usr/bin/python3` for the test executable path
- Run from the project root with `-c pytest.ini`
- Mock `geoip2` modules before importing anything that uses them
- When testing `AUTHORISEDBEARS`, set it via `sys.modules` dict manipulation
- `multiprocessing.Process.start()` returns immediately — poll the DB for async operations
- Use `conftest.py` for shared fixtures and utilities

## Pull Request Guidelines

1. **Title**: Clear and descriptive (e.g., "Add fake Jenkins CI face", "Fix AES decryption on large payloads")
2. **Description**: Explain WHAT changed and WHY
3. **Tests**: Include tests for new functionality
4. **Documentation**: Update README.md or DEVELOPER.md as needed
5. **No breaking changes**: Prefer backwards-compatible changes

## Questions?

Check:
- `README.md` — overview and quick start
- `DEVELOPER.md` — deep dive into code, architecture, and HOW-TOs
- `manyfaced/db/README.md` — database backend specifics
