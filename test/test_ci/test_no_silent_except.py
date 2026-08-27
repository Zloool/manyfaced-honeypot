"""Regressions guard for issue #657: no error-swallowing empty ``except``.

Silent ``except ...: pass`` blocks hide prod failures (the 2026-07 code-scanning
findings). This test fails the build if any new one is introduced outside the
two intentional ``KeyboardInterrupt`` clean-shutdown handlers.
"""

from __future__ import annotations

import ast
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = REPO_ROOT / 'manyfaced'


def test_no_silent_except_blocks():
    offenders: list[str] = []
    for p in sorted(TARGET.rglob('*.py')):
        try:
            tree = ast.parse(p.read_text(encoding='utf-8', errors='replace'))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            # The only accepted empty handler is a clean Ctrl-C shutdown.
            if node.type is not None and 'KeyboardInterrupt' in ast.unparse(node.type):
                continue
            body = node.body
            if len(body) == 0 or (len(body) == 1 and isinstance(body[0], ast.Pass)):
                offenders.append(f'{p.relative_to(REPO_ROOT)}:{node.lineno}')
    assert not offenders, f'silent empty except blocks remain: {offenders}'
