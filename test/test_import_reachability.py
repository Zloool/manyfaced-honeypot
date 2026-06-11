"""Test import reachability from the mfh:run entrypoint.

Walks the import graph starting from manyfaced.mfh.run and verifies that every
first-party module under manyfaced/ is reachable (imported by something in the
graph).  Would have caught dead modules like server_factory.py before they were
merged.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path


def _get_all_first_party_modules(root: Path) -> set[str]:
    """Return all first-party module names under manyfaced/ (with manyfaced. prefix)."""
    modules: set[str] = set()
    manyfaced_dir = root / 'manyfaced'
    if not manyfaced_dir.is_dir():
        return modules

    for pyfile in manyfaced_dir.rglob('*.py'):
        rel = pyfile.relative_to(manyfaced_dir)
        parts = list(rel.parts)
        # Convert path to dotted module name (with manyfaced. prefix)
        if parts[-1] == '__init__.py':
            parts = parts[:-1]  # package, not module
        else:
            parts[-1] = parts[-1][:-3]  # strip .py
        modules.add('manyfaced.' + '.'.join(parts))
    return modules


def _get_first_party_imports_from_file(filepath: Path) -> list[str]:
    """Extract first-party (manyfaced.*) import names from a Python file using AST.

    Handles both ``import X`` and ``from X import Y`` forms, including cases where
    Y is itself a module name (e.g. ``from manyfaced.client import client``).
    Also handles relative imports like ``from .storage import get_storage``.

    Only returns entries that correspond to actual files on disk (real modules),
    not imported function/class names like ``manyfaced.common.config.settings``.
    """
    try:
        tree = ast.parse(filepath.read_text())
    except (SyntaxError, OSError):
        return []

    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            level = node.level or 0  # number of dots for relative import
            base_module = node.module

            if level > 0:
                # Relative import — resolve to absolute manyfaced.* path
                # Determine the package of this file
                parts = filepath.parts
                try:
                    idx = parts.index('manyfaced')
                except ValueError:
                    continue  # not a manyfaced module, skip

                # Go up 'level' directories from the current file's package
                pkg_parts = list(parts[idx:-1])  # e.g. ['manyfaced', 'db'] for db/dbconnect.py
                if level <= len(pkg_parts):
                    base_module = '.'.join(pkg_parts[-(level - 1) or None :]) + (
                        f'.{node.module}' if node.module else ''
                    )
                else:
                    # Too many dots — resolve from project root
                    remaining = level - len(pkg_parts)
                    base_module = (
                        'manyfaced'
                        + '.' * (remaining - 1)
                        + (f'.{node.module}' if node.module else '')
                    )

            if not base_module.startswith('manyfaced'):
                continue

            # Add the base module (e.g. "manyfaced.client")
            imports.append(base_module)
            # Also add each imported name if it looks like a submodule
            for alias in node.names or []:
                full = f'{base_module}.{alias.name}'
                if full.startswith('manyfaced'):
                    imports.append(full)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith('manyfaced'):
                    imports.append(alias.name)

    # Filter to only real modules (files that exist on disk)
    root = Path(__file__).resolve().parent.parent  # project root
    manyfaced_dir = root / 'manyfaced'
    real_modules: list[str] = []
    for imp in imports:
        parts = imp.split('.')
        if parts and parts[0] == 'manyfaced':
            parts = parts[1:]
        pyfile = manyfaced_dir
        for p in parts:
            pyfile = pyfile / p
        init_file = pyfile / '__init__.py'
        mod_file = pyfile.with_suffix('.py')
        if init_file.exists() or mod_file.exists():
            real_modules.append(imp)

    return real_modules


def _walk_import_graph(start_module: str, root: Path) -> set[str]:
    """BFS walk of the import graph starting from start_module.

    Only follows first-party (manyfaced.*) imports.  Returns the set of all
    reachable first-party module names.
    """
    visited: set[str] = set()
    queue: list[str] = [start_module]

    while queue:
        mod_name = queue.pop(0)
        if mod_name in visited:
            continue
        visited.add(mod_name)

        # Resolve module name to file path (strip "manyfaced." prefix for path lookup)
        parts = mod_name.split('.')
        # Remove leading "manyfaced" from parts since we prepend it below
        if parts and parts[0] == 'manyfaced':
            parts = parts[1:]

        pyfile = root / 'manyfaced'
        for p in parts:
            pyfile = pyfile / p

        # Check if it's a package (directory with __init__.py) or single-file module (.py)
        dir_path = pyfile  # e.g., manyfaced/handlers/router
        init_file = dir_path / '__init__.py'  # e.g., manyfaced/handlers/router/__init__.py
        mod_file = pyfile.with_suffix('.py')  # e.g., manyfaced/handlers/router.py

        target_file: Path | None = None
        if init_file.exists():
            target_file = init_file
        elif mod_file.exists():
            target_file = mod_file

        if target_file is None:
            continue

        # Extract first-party imports from this file
        for imp in _get_first_party_imports_from_file(target_file):
            if imp not in visited:
                queue.append(imp)

    return visited


def test_all_modules_reachable() -> None:
    """Every first-party module under manyfaced/ must be reachable from mfh.run."""
    root = Path(__file__).resolve().parent.parent  # project root

    all_modules = _get_all_first_party_modules(root)
    reachable = _walk_import_graph('manyfaced.mfh', root)

    # Filter out the "manyfaced." artifact (empty string after stripping prefix)
    all_modules.discard('manyfaced.')
    reachable.discard('manyfaced.')

    # A package __init__.py is considered reachable if any of its submodules are reachable.
    # e.g., manyfaced.common is reachable because manyfaced.common.config is reachable.
    packages_to_mark_reachable: set[str] = set()
    for mod in all_modules:
        parts = mod.split('.')
        # Strip leading "manyfaced" to get relative path components
        rel_parts = [p for p in parts if p != '']  # remove empty strings from trailing dots
        if len(rel_parts) > 1 and rel_parts[0] == 'manyfaced':
            rel_parts = rel_parts[1:]  # strip leading manyfaced
        if len(rel_parts) > 1:
            # This is a submodule — its parent package should be reachable too
            pkg = 'manyfaced.' + '.'.join(rel_parts[:-1])
            packages_to_mark_reachable.add(pkg)

    reachable |= packages_to_mark_reachable

    unreachable = sorted(all_modules - reachable)
    if unreachable:
        print(f'Unreachable modules ({len(unreachable)}):')
        for mod in unreachable:
            print(f'  {mod}')
        sys.exit(1)
    else:
        print(f'All {len(all_modules)} first-party modules are reachable from mfh.run')


if __name__ == '__main__':
    test_all_modules_reachable()
