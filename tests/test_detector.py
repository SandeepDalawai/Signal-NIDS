from detector import analyze_records


def test_port_scan_and_syn_pattern_detected():
    rows = []
    for i, port in enumerate([21,22,23,25,53,80,110,139,143,443]):
        rows.append({'timestamp':f'2026-10-11T10:00:{i:02d}+00:00','src_ip':'198.51.100.5','dst_ip':'192.0.2.1','dst_port':port,'protocol':'TCP','flags':'S','bytes':60})
    _, alerts = analyze_records(rows)
    rules = {a['rule'] for a in alerts}
    assert 'Possible port scan' in rules
    assert 'SYN scan pattern' in rules


def test_high_volume_is_reported():
    _, alerts = analyze_records([{'timestamp':'2026-10-11T10:00:00Z','src_ip':'192.0.2.2','dst_ip':'192.0.2.3','protocol':'TCP','bytes':6000000}])
    assert any(a['rule'] == 'High traffic volume' and a['severity'] == 'High' for a in alerts)


def test_benign_single_record_does_not_trigger_scan():
    _, alerts = analyze_records([{'timestamp':'2026-10-11T10:00:00Z','src_ip':'192.0.2.2','dst_ip':'192.0.2.3','dst_port':443,'protocol':'TCP','bytes':1200,'flags':'PA'}])
    assert not any(a['rule'] in {'Possible port scan','SYN scan pattern','Destination sweep','Repeated connection attempts'} for a in alerts)
