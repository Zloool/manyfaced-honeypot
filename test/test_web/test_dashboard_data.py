"""Tests for the dashboard's pure data-shaping helpers (issue #326 redesign)."""

from manyfaced.common import status as status_mod
from manyfaced.web import dashboard_data as dd


class TestPortServiceName:
    def test_known_port(self):
        assert dd.port_service_name(22) == 'SSH'
        assert dd.port_service_name(3306) == 'MySQL'

    def test_unknown_port_falls_back(self):
        assert dd.port_service_name(54321) == 'TCP'

    def test_zero_or_none_is_unknown(self):
        assert dd.port_service_name(0) == '?'
        assert dd.port_service_name(None) == '?'


class TestRedirectedPortServiceName:
    """iptables-redirected high ports must resolve to the real service (issue #312)."""

    def test_redirected_ports_resolve_to_privileged_service(self):
        # (high bind port, expected label) — mirrors setup-iptables-privileged-ports.sh
        expected = {
            10021: 'FTP',
            10022: 'SSH',
            10023: 'Telnet',
            10025: 'SMTP',
            10053: 'DNS',
            10110: 'POP3',
            10135: 'MSRPC',
            10139: 'NetBIOS',
            10143: 'IMAP',
            10445: 'SMB',
            10993: 'IMAPS',
            10995: 'POP3S',
        }
        for high, label in expected.items():
            assert dd.port_service_name(high) == label, high

    def test_non_redirected_high_port_still_falls_back(self):
        # 8080/8443 are the HTTP/HTTPS redirects but their privileged names are
        # harmless here; a truly unknown high port must still fall back to 'TCP'.
        assert dd.port_service_name(12345) == 'TCP'


class TestDisplayPortExternalResolution:
    """Dashboard must show the EXTERNAL (attacker-visible) port, not the
    container bind port the honeypot records (issue #320)."""

    def test_redirected_high_port_resolves_to_external(self):
        # Bound high port 10022 (SSH redirect target) -> external 22.
        assert dd.display_port(10022) == 22
        assert dd.display_port(10021) == 21  # FTP
        assert dd.display_port(10445) == 445  # SMB

    def test_non_redirected_port_passes_through(self):
        # Directly-bound, non-redirected ports are shown as-is.
        assert dd.display_port(3306) == 3306
        # 8080/8443 are redirect TARGETS (80->8080, 443->8443), so they resolve
        # to their external privileged identity — which is exactly the
        # attacker-visible port we want to show.
        assert dd.display_port(8080) == 80
        assert dd.display_port(8443) == 443

    def test_zero_and_none(self):
        assert dd.display_port(0) == 0
        assert dd.display_port(None) == 0

    def test_annotate_exposes_display_port(self):
        rec = _rec('1.2.3.4', '2024-01-01 00:00:00.000', 10022)
        annotated = dd.annotate(rec)
        assert annotated['display_port'] == 22
        assert annotated['svc'] == 'SSH'


class TestRedirectMapSingleSource:
    """The redirect mapping must have exactly ONE definition (issue #320):
    manyfaced/common/ports.py. dashboard_data re-exports it; the iptables
    script derives from it. Guard against silent drift."""

    def test_dashboard_data_uses_canonical_map(self):
        from manyfaced.common import ports as ports_mod

        # dashboard_data._PORT_REDIRECT_PRIV_TO_HIGH must be the canonical map.
        assert dd._PORT_REDIRECT_PRIV_TO_HIGH is ports_mod.PRIVILEGED_PORT_REDIRECTS

    def test_canonical_map_invertible_and_complete(self):
        from manyfaced.common import ports as ports_mod

        # Every privileged port maps to a distinct high port.
        highs = list(ports_mod.PRIVILEGED_PORT_REDIRECTS.values())
        assert len(highs) == len(set(highs)), 'duplicate high-port targets'
        # Inverse resolves back exactly.
        for priv, high in ports_mod.PRIVILEGED_PORT_REDIRECTS.items():
            assert ports_mod.external_port(high) == priv
        # Non-redirect ports pass through.
        assert ports_mod.external_port(3306) == 3306

    def test_no_activity_falls_back_to_configured(self):
        # Fresh honeypot: no non-benign captures yet -> show configured listening ports.
        ports = dd.resolve_display_ports([], [22, 80, 443])
        assert ports == [22, 80, 443]

    def test_all_historically_active_ports_shown_and_sorted(self):
        # Every port with >=1 non-benign capture must appear, resolved to its
        # EXTERNAL port and sorted by number (issue #321/#409). Bound 10022
        # (SSH) and 8080 (HTTP) map to external 22 / 80 — caller resolves
        # before calling, so we pass the external ports here.
        configured = list(range(1, 65536))  # "all" mode (fallback only)
        active = [22, 80, 3306, 443]  # external ports that took a non-benign hit
        ports = dd.resolve_display_ports(active, configured)
        # All four active ports present, in numeric order.
        assert ports == [22, 80, 443, 3306]
        # No configured-only padding leaking in (e.g. 21/23 should be absent).
        assert 21 not in ports
        assert 23 not in ports

    def test_weighted_active_ports_not_capped(self):
        # With real activity, the _MAX_HERO_PORTS cap does not drop active ports.
        configured = list(range(1, 65536))
        active = list(range(100, 200))  # 100 ports with a non-benign hit
        ports = dd.resolve_display_ports(active, configured)
        assert len(ports) == 100
        assert ports == sorted(ports)  # sorted by number


class TestSeverityFor:
    def test_login_captured_is_critical(self):
        rec = {'login': 'admin:admin', 'detected_id': status_mod.SSH_CLIENT}
        assert dd.severity_for(rec) == 'crit'

    def test_config_disclosure_is_critical(self):
        rec = {'detected_id': status_mod.CONFIG_DISCLOSURE_HTTP, 'login': ''}
        assert dd.severity_for(rec) == 'crit'

    def test_sensitive_path_marker_is_critical(self):
        rec = {'detected_id': status_mod.WORDPRESS_HTTP, 'request_path': '/.env', 'login': ''}
        assert dd.severity_for(rec) == 'crit'

    def test_http_service_post_is_critical_get_is_warn(self):
        base = {
            'detected_id': status_mod.WORDPRESS_HTTP,
            'request_path': '/wp-login.php',
            'login': '',
        }
        assert dd.severity_for({**base, 'request_command': 'POST'}) == 'crit'
        assert dd.severity_for({**base, 'request_command': 'GET'}) == 'warn'

    def test_telnet_is_critical(self):
        rec = {'detected_id': status_mod.UNKNOWN_TELNET, 'login': ''}
        assert dd.severity_for(rec) == 'crit'

    def test_rdp_is_warn(self):
        rec = {'detected_id': status_mod.UNKNOWN_RDP, 'login': ''}
        assert dd.severity_for(rec) == 'warn'

    def test_default_is_info(self):
        rec = {'detected_id': status_mod.SSH_CLIENT, 'login': ''}
        assert dd.severity_for(rec) == 'info'


def _rec(ip, ts, port, path='/', command='GET', detected=status_mod.UNKNOWN_HTTP):
    return {
        'bot_ip': ip,
        'timestamp': ts,
        'listen_port': port,
        'request_path': path,
        'request_command': command,
        'request_raw': f'{command} {path} HTTP/1.1',
        'detected_id': detected,
        'bot_country': 'US',
        'bot_user_agent': 'curl/8',
        'hostname': 'hive-01',
        'hive_id': None,
        'login': '',
    }


class TestGroupLogRows:
    def test_single_event_stays_single(self):
        rows = dd.group_log_rows([_rec('1.2.3.4', '2024-01-01 00:00:00.000', 80)])
        assert len(rows) == 1
        assert rows[0]['kind'] == 'single'

    def test_port_scan_collapses_to_scan_badge(self):
        records = [
            _rec('1.2.3.4', '2024-01-01 00:00:0' + str(i), port)
            for i, port in enumerate([21, 22, 23, 80, 443])
        ]
        rows = dd.group_log_rows(records)
        assert len(rows) == 1
        assert rows[0]['kind'] == 'group'
        assert rows[0]['badge'] == 'SCAN'
        assert len(rows[0]['members']) == 5

    def test_repeated_same_path_collapses_to_repeat_badge(self):
        records = [
            _rec('1.2.3.4', f'2024-01-01 00:00:0{i}.000', 80, path='/wp-login.php', command='POST')
            for i in range(4)
        ]
        rows = dd.group_log_rows(records)
        assert len(rows) == 1
        assert rows[0]['badge'] == 'REPEAT'

    def test_mixed_paths_same_port_collapses_to_burst_badge(self):
        records = [
            _rec('1.2.3.4', '2024-01-01 00:00:00.000', 80, path='/a'),
            _rec('1.2.3.4', '2024-01-01 00:00:01.000', 80, path='/b'),
            _rec('1.2.3.4', '2024-01-01 00:00:02.000', 80, path='/c'),
        ]
        rows = dd.group_log_rows(records)
        assert len(rows) == 1
        assert rows[0]['badge'] == 'BURST'

    def test_different_ips_do_not_group(self):
        records = [
            _rec('1.2.3.4', '2024-01-01 00:00:00.000', 80),
            _rec('5.6.7.8', '2024-01-01 00:00:01.000', 80),
        ]
        rows = dd.group_log_rows(records)
        assert len(rows) == 2
        assert all(r['kind'] == 'single' for r in rows)

    def test_same_ip_always_groups_regardless_of_time_gap(self):
        records = [
            _rec('1.2.3.4', '2024-01-01 00:00:00.000', 80),
            _rec('1.2.3.4', '2024-01-01 00:01:00.000', 80),  # 60s later — still consecutive
        ]
        rows = dd.group_log_rows(records)
        assert len(rows) == 1
        assert rows[0]['kind'] == 'group'
        assert len(rows[0]['members']) == 2

    def test_interleaved_other_ip_breaks_the_run(self):
        records = [
            _rec('1.2.3.4', '2024-01-01 00:00:00.000', 80),
            _rec('5.6.7.8', '2024-01-01 00:00:01.000', 80),
            _rec('1.2.3.4', '2024-01-01 00:00:02.000', 80),
        ]
        rows = dd.group_log_rows(records)
        assert len(rows) == 3
        assert all(r['kind'] == 'single' for r in rows)

    def test_annotate_prefers_hostname_over_hive_id_for_sensor(self):
        rec = _rec('1.2.3.4', '2024-01-01 00:00:00.000', 80)
        rec['hostname'] = 'hive-eu1'
        rec['hive_id'] = 7
        annotated = dd.annotate(rec)
        assert annotated['sensor'] == 'hive-eu1'

    def test_annotate_falls_back_to_hive_id_when_hostname_missing(self):
        rec = _rec('1.2.3.4', '2024-01-01 00:00:00.000', 80)
        rec['hostname'] = ''
        rec['hive_id'] = 7
        annotated = dd.annotate(rec)
        assert annotated['sensor'] == 7
