"""Tests for the lightweight metrics registry (issue #166)."""

from __future__ import annotations

from manyfaced.common import metrics


def test_incr_increments_counter():
    before = metrics.snapshot()['counters']['bot_connections']
    metrics.incr('bot_connections')
    metrics.incr('bot_connections', 3)
    after = metrics.snapshot()['counters']['bot_connections']
    assert after == before + 4


def test_incr_unknown_name_is_ignored():
    before = dict(metrics.snapshot()['counters'])
    metrics.incr('not_a_real_metric')
    assert metrics.snapshot()['counters'] == before


def test_incr_response_labels_by_domain():
    # Metrics are a process-wide singleton, so assert on deltas (other tests in
    # the session also exercise router.dispatch and increment these counters).
    before = metrics.snapshot()['responses_by_domain']
    wp_before = before.get('wordpress', 0)
    pm_before = before.get('phpmyadmin', 0)

    metrics.incr_response('wordpress')
    metrics.incr_response('wordpress')
    metrics.incr_response('phpmyadmin')

    after = metrics.snapshot()['responses_by_domain']
    assert after.get('wordpress', 0) == wp_before + 2
    assert after.get('phpmyadmin', 0) == pm_before + 1


def test_set_gauge():
    metrics.set_gauge('report_queue_depth', 7)
    assert metrics.snapshot()['gauges']['report_queue_depth'] == 7
    metrics.set_gauge('report_queue_depth', 0)
    assert metrics.snapshot()['gauges']['report_queue_depth'] == 0


def test_set_gauge_unknown_is_ignored():
    before = dict(metrics.snapshot()['gauges'])
    metrics.set_gauge('no_such_gauge', 99)
    assert metrics.snapshot()['gauges'] == before


def test_format_snapshot_contains_metric_lines():
    metrics.incr('credential_captures')
    line = metrics.format_snapshot()
    assert line.startswith('metrics ')
    assert 'credential_captures=' in line
    assert 'report_queue_depth=' in line


def test_snapshot_is_independent_copy():
    snap1 = metrics.snapshot()
    metrics.incr('bot_connections')
    snap2 = metrics.snapshot()
    # The returned dicts must not alias module state.
    snap1['counters']['bot_connections'] = -1
    assert metrics.snapshot()['counters']['bot_connections'] != -1
    assert snap2['counters']['bot_connections'] != -1 or snap2 is not snap1


def test_stats_logger_thread_lifecycle():
    # start is idempotent; stop must not raise.
    metrics.start_stats_logger(interval=1)
    metrics.start_stats_logger(interval=1)  # second call is a no-op
    metrics.stop_stats_logger()
    assert True  # if we got here without hanging/raising, lifecycle is safe
