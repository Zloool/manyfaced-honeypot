"""Tests for manyfaced.common.classification (issue #271).

Covers the pure classify() against known-benign signals, the spoof-resistance
rule (UA claiming a benign name but non-matching reverse DNS must NOT classify),
and the allowlist loader's rejection of UA-only entries.
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from manyfaced.common.classification import (  # noqa: E402
    UNKNOWN,
    BENIGN,
    ClassificationError,
    classify,
    load_allowlist,
)


# ---------------------------------------------------------------------------
# Known-benign inputs → correct benign_source
# ---------------------------------------------------------------------------


def test_shodan_reverse_dns():
    cls, src = classify(reverse_dns='census.shodan.io')
    assert cls == BENIGN
    assert src == 'shodan'


def test_shodan_wildcard_reverse_dns():
    cls, src = classify(reverse_dns='node-1.scan.shodan.io')
    assert cls == BENIGN
    assert src == 'shodan'


def test_censys_asn():
    cls, src = classify(asn='AS398324')
    assert cls == BENIGN
    assert src == 'censys'


def test_censys_reverse_dns():
    cls, src = classify(reverse_dns='scan-42.censys-scanner.com')
    assert cls == BENIGN
    assert src == 'censys'


def test_cloudflare_org():
    cls, src = classify(org='Cloudflare, Inc.')
    assert cls == BENIGN
    assert src == 'cloudflare-cdn'


def test_cloudflare_asn():
    cls, src = classify(asn='AS13335')
    assert cls == BENIGN
    assert src == 'cloudflare-cdn'


def test_googlebot_reverse_dns():
    cls, src = classify(reverse_dns='crawl-123.googlebot.com')
    assert cls == BENIGN
    assert src == 'google'


def test_shodan_user_agent():
    # UA matches but every entry carrying a UA also carries a network signal;
    # Shodan's entry has reverse_dns + asn, so UA alone is NOT sufficient here.
    cls, src = classify(user_agent='Shodan')
    assert cls == UNKNOWN
    assert src == ''


# ---------------------------------------------------------------------------
# Adversarial spoof attempts → NOT benign
# ---------------------------------------------------------------------------


def test_spoofed_shodan_ua_no_matching_rdns():
    """An attacker UA claiming 'Shodan' but with non-Shodan reverse DNS + ASN
    must NOT be classified benign. Reverse-DNS/ASN are network-verifiable; UA
    is not."""
    cls, src = classify(
        reverse_dns='evil-attacker.example.net',
        asn='AS64500',
        user_agent='Mozilla/5.0 (compatible; Shodan)',
    )
    assert cls == UNKNOWN
    assert src == ''


def test_unknown_source():
    cls, src = classify(reverse_dns='my-home-router.isp.net', asn='AS12345', org='My ISP')
    assert cls == UNKNOWN
    assert src == ''


# ---------------------------------------------------------------------------
# Precedence: reverse_dns beats org beats ua
# ---------------------------------------------------------------------------


def test_allowlist_loaded():
    sources = load_allowlist()
    names = {s.name for s in sources}
    assert 'shodan' in names
    assert 'cloudflare-cdn' in names
    assert 'google' in names


def test_loader_rejects_ua_only_entry(tmp_path):
    """A UA-only allowlist entry must be rejected (spoofable sole basis)."""
    bad = tmp_path / 'bad.toml'
    bad.write_text('[[source]]\nname = "fake"\ncategory = "scanner"\nuser_agent = ["Evil"]\n')
    import pytest

    from manyfaced.common.classification import _load_sources

    with pytest.raises(ClassificationError):
        _load_sources(str(bad))
