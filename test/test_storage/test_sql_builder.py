"""Regression tests for storage record normalization."""

from manyfaced.db.sql_builder import extract_record_fields


_NUL = chr(0)
_ESCAPED_NUL = ''.join((chr(92), 'x00'))


def test_extract_record_fields_escapes_nul_in_every_text_column():
    """PostgreSQL TEXT bindings must never receive an embedded NUL byte."""
    value = f'before{_NUL}after'
    record = {
        'ip': value,
        'hostname': value,
        'timestamp': value,
        'parsed_request': {
            'path': value,
            'command': value,
            'request_version': value,
            'user_agent': value,
        },
        'raw_request': value,
        'country': value,
        'continent': value,
        'tracert': value,
        'dns_name': value,
        'is_detected': 7,
        'hive_id': 9,
        'login': value,
        'bot_profile_data': value,
        'listen_port': 5432,
        'bot_asn': value,
        'bot_org': value,
        'classification': value,
        'benign_source': value,
    }

    fields = extract_record_fields(record)

    text_indices = (*range(12), 14, 15, *range(17, 21))
    for index in text_indices:
        assert _NUL not in fields[index], f'field {index} still contains a PostgreSQL-invalid NUL'
        assert fields[index] == f'before{_ESCAPED_NUL}after'

    assert fields[12:14] == (7, 9)
    assert fields[16] == 5432
