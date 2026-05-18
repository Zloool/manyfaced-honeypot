#!/usr/bin/env python3
"""Check for documentation drift between docs and code."""

import os
import re
import sys

errors = []

# Check 1: README's directory tree matches reality
# This is a simplified check - just verify key files exist
readme_paths = [
    'manyfaced/mfh.py',
    'manyfaced/common/config.py',
    'manyfaced/server/server.py',
    'manyfaced/client/client.py',
    'test/test_http_handler.py',
    'pyproject.toml',
    'README.md',
]

for path in readme_paths:
    if not os.path.exists(path):
        errors.append(f"README references {path} but it doesn't exist")

# Check 2: Config fields documented in CONFIG.md exist in Config dataclass
# This is a simplified check - just verify the main config file exists
config_file = 'manyfaced/common/config.py'
if not os.path.exists(config_file):
    errors.append("CONFIG.md references manyfaced/common/config.py but it doesn't exist")

# Check 3: CLI flags in arguments.py are documented in README
args_file = 'manyfaced/common/arguments.py'
if os.path.exists(args_file):
    with open(args_file, 'r') as f:
        args_content = f.read()

    # Extract --flag patterns, skip --help (auto-generated)
    flags = re.findall(r'--([\w-]+)', args_content)
    flags = [f for f in flags if f != 'help']

    with open('README.md', 'r') as f:
        readme_content = f.read()

    for flag in flags:
        # Check if the full flag is documented
        if f'--{flag}' not in readme_content:
            # Also check if the short form is documented
            short_form = f'-{flag[0]}'
            if short_form not in readme_content:
                errors.append(f'CLI flag --{flag} in arguments.py not documented in README')

# Check 4: File paths mentioned in README exist
# Match paths that look like actual file references
readme_paths_to_check = set()
for match in re.finditer(
    r"(?:^|[\s`'\",;])((?:manyfaced|test|\.github)/[\w./-]+?)(?:[\s`'\",;]|$)",
    readme_content,
):
    path = match.group(1)
    # Clean up trailing punctuation
    path = path.rstrip('`,;\'"')
    readme_paths_to_check.add(path)

for path in readme_paths_to_check:
    if not os.path.exists(path):
        errors.append(f"README references {path} but it doesn't exist")

if errors:
    print('Documentation drift detected:')
    for error in errors:
        print(f'  - {error}')
    sys.exit(1)
else:
    print('No documentation drift detected')
    sys.exit(0)
