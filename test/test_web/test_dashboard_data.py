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


class TestResolveDisplayPorts:
    def test_small_set_returned_as_is(self):
        ports = dd.resolve_display_ports([22, 80, 443], by_port=[])
        assert ports == [22, 80, 443]

    def test_all_mode_caps_and_prefers_active_ports(self):
        configured = list(range(1, 65536))
        by_port = [{'key': 22, 'count': 500}, {'key': 8080, 'count': 10}]
        ports = dd.resolve_display_ports(configured, by_port)
        assert len(ports) <= dd._MAX_HERO_PORTS
        assert 22 in ports
        assert 8080 in ports


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

    def test_events_outside_window_do_not_group(self):
        records = [
            _rec('1.2.3.4', '2024-01-01 00:00:00.000', 80),
            _rec('1.2.3.4', '2024-01-01 00:01:00.000', 80),  # 60s later, outside 10s window
        ]
        rows = dd.group_log_rows(records)
        assert len(rows) == 2

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
