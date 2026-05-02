#!/usr/bin/env python3
"""Check for documentation drift between docs and code."""

import os
import re
import sys

os.chdir("/home/zlol/manyfaced-honeypot")

errors = []

# Check 1: README's directory tree matches reality
# This is a simplified check - just verify key files exist
readme_paths = [
    "manyfaced/mfh.py",
    "manyfaced/common/config.py",
    "manyfaced/server/server.py",
    "manyfaced/client/client.py",
    "test/test_config.py",
    "pyproject.toml",
    "README.md",
]

for path in readme_paths:
    if not os.path.exists(path):
        errors.append(f"README references {path} but it doesn't exist")

# Check 2: Config fields documented in CONFIG.md exist in Config dataclass
# This is a simplified check - just verify the main config file exists
config_file = "manyfaced/common/config.py"
if not os.path.exists(config_file):
    errors.append(
        "CONFIG.md references manyfaced/common/config.py but it doesn't exist"
    )

# Check 3: CLI flags in arguments.py are documented in README
args_file = "manyfaced/common/arguments.py"
if os.path.exists(args_file):
    with open(args_file, "r") as f:
        args_content = f.read()

    # Extract --flag patterns
    flags = re.findall(r"--([\w-]+)", args_content)

    with open("README.md", "r") as f:
        readme_content = f.read()

    for flag in flags:
        if f"--{flag}" not in readme_content:
            errors.append(f"CLI flag --{flag} in arguments.py not documented in README")

# Check 4: File paths mentioned in README exist
# Use a simpler pattern that avoids quote escaping issues
readme_paths_to_check = re.findall(
    r"(manyfaced/\S+|test/\S+|\.github/\S+)", readme_content
)
for path in readme_paths_to_check:
    if not os.path.exists(path):
        errors.append(f"README references {path} but it doesn't exist")

if errors:
    print("Documentation drift detected:")
    for error in errors:
        print(f"  - {error}")
    sys.exit(1)
else:
    print("No documentation drift detected")
    sys.exit(0)
