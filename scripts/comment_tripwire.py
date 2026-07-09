"""Issue-comment malware-drop tripwire classifier (issue #325).

Pure, network-free classifier used by the CI workflow
(.github/workflows/triage-comment.yml) to flag suspicious issue/PR comments
from untrusted authors — the shape of a malware / fake-patch social-engineering
drop. The workflow inspects only comment *metadata + text*; it never resolves,
downloads, or runs anything from the comment.

The same function is unit-tested in test/test_scripts/test_comment_tripwire.py
so the heuristic can't silently drift.
"""

from __future__ import annotations

import re

# Author associations that are NOT pre-vetted collaborators.
UNTRUSTED_ASSOCIATIONS = frozenset({'NONE', 'FIRST_TIME_CONTRIBUTOR', 'FIRST_TIMER'})

# Hosts we treat as first-party / safe to link (no flag for these).
_ALLOWED_HOST_SUFFIXES = ('github.com', 'githubusercontent.com', 'gist.github.com')

# Archive / executable references — the malware-drop shape. Matched against a
# URL target or a bare filename token in the comment.
_ARCHIVE_EXTS = (
    '.zip',
    '.rar',
    '.7z',
    '.tar',
    '.tar.gz',
    '.tgz',
    '.gz',
    '.exe',
    '.scr',
    '.msi',
    '.iso',
    '.img',
    '.apk',
    '.jar',
    '.bat',
    '.ps1',
    '.sh',
)

# URL shorteners are always treated as high-risk external links.
_URL_SHORTENERS = (
    'bit.ly',
    't.co',
    'goo.gl',
    'tinyurl.com',
    'ow.ly',
    'is.gd',
    'buff.ly',
    'cutt.ly',
    'rebrand.ly',
    'shorturl.at',
)

_URL_RE = re.compile(r'https?://[^\s)>\]]*', re.IGNORECASE)
_MD_LINK_RE = re.compile(r'\[[^\]]*\]\((\s*https?://[^)\s]*)\)', re.IGNORECASE)
_TOKEN_RE = re.compile(r'[A-Za-z0-9_./:?=&%@~+-]+')


def _host_of(url: str) -> str:
    """Return the lowercased host of a URL, or '' if it can't be parsed."""
    m = re.match(r'https?://([^/?:#@]+)', url, re.IGNORECASE)
    if not m:
        return ''
    host = m.group(1)
    if ':' in host:
        host = host.split(':', 1)[0]
    return host.lower()


def _strip_trailing_punct(token: str) -> str:
    return token.rstrip('.,;:"\')]}>')


def _is_archive_ref(body: str) -> bool:
    """True if ``body`` references an archive/executable file."""
    # URL targets (markdown or bare) ending in an archive extension.
    urls: list[str] = []
    for m in _MD_LINK_RE.finditer(body):
        urls.append(m.group(1).strip())
    urls.extend(_URL_RE.findall(body))
    for url in urls:
        target = _strip_trailing_punct(url)
        if any(target.endswith(ext) or target.rstrip('/').endswith(ext) for ext in _ARCHIVE_EXTS):
            return True
    # Bare filename tokens ending in an archive extension (e.g. "run evil.exe").
    for token in _TOKEN_RE.findall(body):
        t = _strip_trailing_punct(token).lower()
        if t.endswith(_ARCHIVE_EXTS):
            return True
    return False


def _external_link_risk(body: str) -> bool:
    """True if ``body`` links to a non-allowlisted (high-risk) host."""
    urls: list[str] = []
    for m in _MD_LINK_RE.finditer(body):
        urls.append(m.group(1).strip())
    urls.extend(_URL_RE.findall(body))
    # Tokens that *begin* with a scheme but may have no trailing host.
    for token in _TOKEN_RE.findall(body):
        if token.lower().startswith(('http://', 'https://')):
            urls.append(token)
    for url in urls:
        url = _strip_trailing_punct(url).rstrip('/')
        host = _host_of(url)
        if not host:
            # Unparseable / hostless URL — treat as suspicious (can't be allowlisted).
            return True
        if any(host == s or host.endswith('.' + s) for s in _URL_SHORTENERS):
            return True
        if any(host == s or host.endswith('.' + s) for s in _ALLOWED_HOST_SUFFIXES):
            continue
        return True  # any other host is external / high-risk
    return False


def classify(author_association: str, body: str) -> tuple[bool, str | None]:
    """Decide whether an issue/PR comment should be flagged as a malware drop.

    Returns ``(flag, reason)``. ``reason`` is a terse human-readable note for
    the triage label/comment when ``flag`` is True, else None.

    Conservative: a comment is flagged only when BOTH the author is untrusted
    (not OWNER/MEMBER/COLLABORATOR/CONTRIBUTOR) AND the body carries a risk
    signal (an archive/executable reference or an external link to a
    non-allowlisted host).

    The workflow never acts on a flagged comment beyond minimizing + labelling;
    it does not quote the suspicious content back.
    """
    if author_association not in UNTRUSTED_ASSOCIATIONS:
        return False, None

    if _is_archive_ref(body):
        return True, 'archive/executable reference from untrusted author'

    if _external_link_risk(body):
        return True, 'external link to non-allowlisted host from untrusted author'

    return False, None


def main() -> int:
    """CLI entry point for the CI workflow.

    Reads the GitHub event payload from $GITHUB_EVENT_PATH and the author
    association from $COMMENT_AUTHOR_ASSOC, prints FLAG/NOFLAG + reason, and
    exits 0 (the workflow decides what to do next). Never fetches any URL.
    """
    import json
    import os

    assoc = os.environ.get('COMMENT_AUTHOR_ASSOC', '').strip()
    event_path = os.environ.get('GITHUB_EVENT_PATH', '')
    body = ''
    if event_path and os.path.exists(event_path):
        try:
            with open(event_path, encoding='utf-8') as fh:
                event = json.load(fh)
            body = (event.get('comment') or {}).get('body', '') or ''
        except (OSError, ValueError):
            body = ''

    flag, reason = classify(assoc, body)
    if flag:
        print(f'FLAG: {reason}')
        return 0
    print('NOFLAG')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
