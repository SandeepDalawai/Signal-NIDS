import pytest
from analyzer import parse_csv_bytes


def test_valid_csv_parses():
    rows = parse_csv_bytes(b'src_ip,dst_ip,protocol\n192.0.2.1,192.0.2.2,TCP\n')
    assert len(rows) == 1
    assert rows[0]['src_ip'] == '192.0.2.1'


def test_missing_required_columns_rejected():
    with pytest.raises(ValueError, match='src_ip and dst_ip'):
        parse_csv_bytes(b'foo,bar\na,b\n')


def test_empty_file_rejected():
    with pytest.raises(ValueError, match='empty'):
        parse_csv_bytes(b'')
