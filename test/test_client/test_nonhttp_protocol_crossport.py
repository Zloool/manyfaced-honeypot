"""Regression tests for issue #639: Redis/ZooKeeper/AMQP/Memcached/EPMD probes
arriving on NON-canonical ports (e.g. a Redis RESP frame on the NFS port 2049,
or an AMQP header on the EPMD port 4369) must be attributed to the matching
UNKNOWN_<protocol> sentinel instead of collapsing into the generic
UNKNOWN_NON_HTTP bucket, so per-protocol analysis/credential capture is possible.

This mirrors the HTTP-on-non-HTTP re-sniff (issues #596 / #638): a recognizable
payload signature on a non-canonical port yields a distinct detected_id.
"""

from manyfaced.client.client import _protocol_mismatch_detected_id, _sniff_nonhttp_protocol
from manyfaced.common.status import (
    UNKNOWN_AMQP,
    UNKNOWN_EPMD,
    UNKNOWN_MEMCACHED,
    UNKNOWN_NON_HTTP,
    UNKNOWN_REDIS,
    UNKNOWN_ZOOKEEPER,
)

_CRLF = bytes([13, 10])


def _redis_resp() -> bytes:
    # RESP array header: *1\r\n$4\r\ninfo
    return b'*1' + _CRLF + b'$4' + _CRLF + b'info'


def _amqp_header() -> bytes:
    # AMQP 0-9-1 protocol header: AMQP\x00\x00\x09\x01
    return b'AMQP' + bytes([0, 0, 9, 1])


def _epmd_frame() -> bytes:
    # EPMD PORT_PLEASE2 request: 2-byte len + tag 0x7a
    return bytes([0, 2, 0x7A])


class TestNonHttpProtocolCrossPort:
    def test_redis_resp_on_nfs_port_attributed_to_redis(self):
        assert _protocol_mismatch_detected_id(_redis_resp(), 'nfs') == UNKNOWN_REDIS

    def test_redis_resp_on_memcached_port_attributed_to_redis(self):
        # Cross-protocol: a Redis frame on 11211 (memcached) is still a Redis probe.
        assert _protocol_mismatch_detected_id(_redis_resp(), 'memcached') == UNKNOWN_REDIS

    def test_redis_ping_verb_attributed_to_redis(self):
        assert _protocol_mismatch_detected_id(b'PING' + _CRLF, 'nfs') == UNKNOWN_REDIS

    def test_zookeeper_4lw_on_nfs_port_attributed_to_zookeeper(self):
        assert _protocol_mismatch_detected_id(b'ruok' + _CRLF, 'nfs') == UNKNOWN_ZOOKEEPER

    def test_zookeeper_mntr_attributed_to_zookeeper(self):
        assert _protocol_mismatch_detected_id(b'mntr' + _CRLF, 'nfs') == UNKNOWN_ZOOKEEPER

    def test_amqp_header_on_epmd_port_attributed_to_amqp(self):
        assert _protocol_mismatch_detected_id(_amqp_header(), 'epmd') == UNKNOWN_AMQP

    def test_memcached_version_on_nfs_port_attributed_to_memcached(self):
        assert _protocol_mismatch_detected_id(b'version' + _CRLF, 'nfs') == UNKNOWN_MEMCACHED

    def test_memcached_get_on_nfs_port_attributed_to_memcached(self):
        assert _protocol_mismatch_detected_id(b'get mykey' + _CRLF, 'nfs') == UNKNOWN_MEMCACHED

    def test_epmd_frame_on_nfs_port_attributed_to_epmd(self):
        assert _protocol_mismatch_detected_id(_epmd_frame(), 'nfs') == UNKNOWN_EPMD

    def test_canonical_port_keeps_canonical_attribution(self):
        # A Redis frame on the Redis port (6379, spec.name 'redis') must NOT be
        # re-labelled — it keeps its canonical REDIS attribution (returns None here,
        # meaning "no override").
        assert _protocol_mismatch_detected_id(_redis_resp(), 'redis') is None
        assert _protocol_mismatch_detected_id(b'ruok' + _CRLF, 'zookeeper') is None
        assert _protocol_mismatch_detected_id(_amqp_header(), 'amqp') is None

    def test_unknown_binary_not_mislabeled(self):
        # Random binary that matches no known protocol signature stays generic.
        assert _protocol_mismatch_detected_id(bytes([0, 1, 2, 3]) + b'somegarbage', 'nfs') is None

    def test_http_frame_not_mislabeled_as_protocol(self):
        # HTTP frames are handled by the HTTP re-sniff (separate code path), not here.
        assert _protocol_mismatch_detected_id(b'GET / HTTP/1.1' + _CRLF, 'nfs') is None

    def test_sniff_returns_expected_tuple(self):
        assert _sniff_nonhttp_protocol(_redis_resp()) == ('redis', UNKNOWN_REDIS)
        assert _sniff_nonhttp_protocol(_amqp_header()) == ('amqp', UNKNOWN_AMQP)
        assert _sniff_nonhttp_protocol(b'ruok' + _CRLF) == ('zookeeper', UNKNOWN_ZOOKEEPER)
        # Empty frame is never a protocol probe.
        assert _sniff_nonhttp_protocol(b'') is None
