# Security Policy

ManyFaced (mfh) is a honeypot that ingests hostile network input and handles a
shared AES-256 encryption secret between its client and server components. As
such, it is security-sensitive software. This document describes how to report
vulnerabilities and what we support.

## Supported Versions

We only ship from the `master` branch and tag releases. Security fixes are
applied to the latest release and `master`.

| Version | Supported          |
| ------- | ------------------ |
| latest `master` / latest release tag | :white_check_mark: |
| older releases | :x: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use **GitHub Private Vulnerability Reporting**:

1. Go to the repository's **Security** tab → **Report a vulnerability**.
2. Fill in the form. Only the maintainers can see it.

If private reporting is unavailable, email the maintainer (see the repo
description / `CODEOWNERS`) with the subject `SECURITY: <short summary>` and
include:
- a description of the vulnerability and impact,
- steps to reproduce (or a proof-of-concept),
- the affected version/commit.

You will receive an acknowledgement within a few days. We aim to provide a
fix or mitigation timeline within 14 days for confirmed issues, and we will
coordinate public disclosure with you.

## Scope notes

The honeypot parses attacker-controlled bytes (HTTP requests, protocol
detection, credential extraction, AES decrypt of remote input). Crashes,
resource-exhaustion, and secret-handling bugs in those paths are in scope.
Findings from fuzzing the input parsers are especially welcome.

## Automated scanning

This repository runs:
- **CodeQL** (Python) on every PR and on a weekly schedule.
- **`pip-audit`** dependency/CVE scanning in CI (`security-scan` job).
- **`bandit`** SAST focused on the input-parsing modules in CI.

Dependency update PRs are opened automatically by Dependabot.
