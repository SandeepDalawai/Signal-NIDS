import csv
import io

REQUIRED = {'src_ip', 'dst_ip'}
ALIASES = {'source_ip':'src_ip','src':'src_ip','destination_ip':'dst_ip','dst':'dst_ip','proto':'protocol','source_port':'src_port','destination_port':'dst_port','packet_count':'packets','byte_count':'bytes','bytes_transferred':'bytes','tcp_flags':'flags','connection_state':'status','time':'timestamp','ts':'timestamp'}

def parse_csv_bytes(data):
    if not data:
        raise ValueError('The uploaded CSV is empty.')
    if len(data) > 5 * 1024 * 1024:
        raise ValueError('File exceeds the 5 MB upload limit.')
    try:
        text = data.decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise ValueError('CSV must use UTF-8 text encoding.') from exc
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError('CSV header row is missing.')
    normalized_headers = [ALIASES.get(h.strip().lower(), h.strip().lower()) for h in reader.fieldnames]
    if not REQUIRED.issubset(set(normalized_headers)):
        raise ValueError('CSV must include src_ip and dst_ip columns. See the sample CSV for supported fields.')
    rows = []
    for idx, values in enumerate(reader):
        if idx >= 50000:
            raise ValueError('CSV exceeds the 50,000-row processing limit.')
        row = {}
        for original, value in values.items():
            if original is not None:
                key = ALIASES.get(original.strip().lower(), original.strip().lower())
                row[key] = (value or '').strip()
        if row.get('src_ip') or row.get('dst_ip'):
            rows.append(row)
    if not rows:
        raise ValueError('CSV contains no usable records.')
    return rows
