from report_generator import make_csv, make_pdf


def test_csv_export_has_header():
    payload = make_csv([{'id':1,'timestamp':'2026-10-11T10:00:00Z','src_ip':'192.0.2.1','dst_ip':'192.0.2.2','rule':'Possible port scan','severity':'High'}])
    assert b'timestamp' in payload and b'Possible port scan' in payload


def test_pdf_export_has_pdf_signature():
    summary = {'records':1,'alerts':0,'high':0,'severities':{},'rules':[],'recent':[],'sources':[],'sessions':1,'latest':None}
    payload = make_pdf([], summary)
    assert payload.startswith(b'%PDF')
