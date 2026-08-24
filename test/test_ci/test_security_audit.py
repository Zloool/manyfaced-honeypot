"""Regression guard for issue #697.

The CI `pip-audit` step used to run `pip-audit --desc on` with only the scanner
tooling (pip/ pip-audit/ bandit) installed, so the project's locked dependencies
were never audited and a real project CVE could pass CI silently. This test proves
the gate is now wired to audit the locked dependency graph via
`scripts/audit_deps.sh` (which exports uv.lock and runs `pip-audit -r` on it).
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CI_YML = REPO_ROOT / '.github' / 'workflows' / 'ci.yml'
AUDIT_SCRIPT = REPO_ROOT / 'scripts' / 'audit_deps.sh'

FALSE_PASS_CMD = 'pip-audit --desc on'


def _security_scan_steps() -> list[str]:
    with CI_YML.open(encoding='utf-8') as fh:
        workflow = yaml.safe_load(fh)
    jobs = workflow.get('jobs', {})
    assert 'security-scan' in jobs, 'security-scan job missing from ci.yml'
    steps = jobs['security-scan'].get('steps', [])
    return [step.get('run', '') for step in steps if isinstance(step, dict) and step.get('run')]


def test_audit_script_audits_lockfile() -> None:
    """scripts/audit_deps.sh exports the lock and runs pip-audit -r on it."""
    assert AUDIT_SCRIPT.is_file(), 'scripts/audit_deps.sh must exist'
    body = AUDIT_SCRIPT.read_text(encoding='utf-8')
    assert 'uv export --locked' in body, 'script must export the locked graph'
    assert 'pip-audit -r' in body, 'script must audit a requirements file, not the bare env'
    assert '--no-emit-project' in body, 'script must drop the unpublished root package'


def test_security_scan_job_invokes_audit_script() -> None:
    """The security-scan job must audit the lock, never the false-pass bare env."""
    steps = _security_scan_steps()
    assert any('scripts/audit_deps.sh' in step for step in steps), (
        'security-scan job must run scripts/audit_deps.sh (lockfile audit)'
    )
    assert not any(step.strip() == FALSE_PASS_CMD for step in steps), (
        'security-scan job must not use the bare `pip-audit --desc on` false-pass form'
    )


@pytest.mark.parametrize('step', _security_scan_steps())
def test_no_false_pass_audit_in_any_step(step: str) -> None:
    """No step may audit only the scanner env (the #697 regression)."""
    assert FALSE_PASS_CMD not in step, 'found false-pass `pip-audit --desc on` in a CI step'
