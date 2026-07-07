"""Structural validation for the container build artifacts (issue #146).

These tests intentionally do NOT require a running Docker daemon — they run in
the normal test matrix (no Docker on the test runners). The real image build +
smoke (`manyfaced --generate-config` + `docker compose config`) is covered by
the `Build Image` CI workflow. Here we guard against trivial drift: a malformed
compose file, a missing Dockerfile, or a port map that doesn't reference the
wired HONEY_* ports.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / 'Dockerfile'
COMPOSE = REPO_ROOT / 'compose.yaml'
ENV_EXAMPLE = REPO_ROOT / 'templates' / 'honeypot.env.example'


def test_dockerfile_exists_and_is_sane():
    assert DOCKERFILE.is_file()
    text = DOCKERFILE.read_text(encoding='utf-8')
    # Must install the package and expose the console script as entrypoint.
    assert 'pip install .' in text
    assert 'manyfaced.mfh' in text
    # Runs as non-root (security requirement from #146).
    assert 'USER honeypot' in text


def test_compose_file_is_valid_yaml_and_has_service():
    assert COMPOSE.is_file()
    data = yaml.safe_load(COMPOSE.read_text(encoding='utf-8'))
    assert isinstance(data, dict)
    services = data.get('services', {})
    assert 'honeypot' in services
    honeypot = services['honeypot']
    # Builds from the Dockerfile in repo root.
    assert honeypot.get('build', {}).get('dockerfile') == 'Dockerfile'
    # Persists captures via a named volume at the droplet path.
    assert any('manyfaced-data:/opt/manyfaced/bots' in v for v in honeypot.get('volumes', []))
    # Wires HONEY_* config from an env file.
    assert '.env' in honeypot.get('env_file', [])


def test_compose_ports_reference_wired_env_ports():
    """The compose port map should expose the ports configured in honeypot.env.example."""
    env_text = ENV_EXAMPLE.read_text(encoding='utf-8')
    # Extract HONEY_HONEYPORT and HONEY_HIVEPORT defaults.
    honeyport = _get_env_default(env_text, 'HONEY_HONEYPORT')
    hiveport = _get_env_default(env_text, 'HONEY_HIVEPORT')
    assert honeyport and hiveport

    data = yaml.safe_load(COMPOSE.read_text(encoding='utf-8'))
    ports = data['services']['honeypot'].get('ports', [])
    mapped = ' '.join(str(p) for p in ports)
    assert f'{honeyport}:{honeyport}' in mapped
    assert f'{hiveport}:{hiveport}' in mapped


def _get_env_default(env_text: str, key: str) -> str | None:
    for line in env_text.splitlines():
        line = line.strip()
        if line.startswith(f'{key}='):
            return line.split('=', 1)[1].strip().strip('"').strip("'")
    return None


def test_dockerignore_excludes_secrets_and_data():
    ignore = (REPO_ROOT / '.dockerignore').read_text(encoding='utf-8')
    for pattern in ('*.db', 'honeypot.env', '.env', 'bots/', '*.sqlite'):
        assert pattern in ignore, f'dockerignore missing {pattern}'
