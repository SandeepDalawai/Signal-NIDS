import os
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response, abort, send_file
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from analyzer import parse_csv_bytes
from database import init_db, save_analysis, list_alerts, get_summary, update_alert_status
from detector import analyze_records, DEFAULTS
from report_generator import make_csv, make_pdf

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('NIDS_SECRET_KEY') or os.urandom(32)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
csrf = CSRFProtect(app)
init_db()


def sample_rows():
    rows = []
    # Clearly synthetic, deterministic sample events; all are processed by the same detector as uploads.
    base = datetime.now(timezone.utc).replace(microsecond=0)
    for i in range(10):
        rows.append({'timestamp': (base.replace(second=0)).isoformat(), 'src_ip':'192.0.2.25', 'dst_ip':'198.51.100.10', 'src_port':52000+i, 'dst_port':80, 'protocol':'TCP', 'packets':2, 'bytes':850, 'flags':'SA'})
    for i, port in enumerate([21,22,23,25,53,80,110,139,143,443,445,8080]):
        rows.append({'timestamp': base.isoformat(), 'src_ip':'198.51.100.77', 'dst_ip':'192.0.2.10', 'src_port':40000+i, 'dst_port':port, 'protocol':'TCP', 'packets':1, 'bytes':60, 'flags':'S'})
    rows.append({'timestamp':base.isoformat(), 'src_ip':'203.0.113.42', 'dst_ip':'192.0.2.10', 'src_port':52300, 'dst_port':443, 'protocol':'TCP', 'packets':12000, 'bytes':6500000, 'flags':'PA'})
    for i in range(15):
        rows.append({'timestamp':base.isoformat(), 'src_ip':'203.0.113.88', 'dst_ip':'192.0.2.50', 'src_port':53000+i, 'dst_port':22, 'protocol':'TCP', 'packets':1, 'bytes':70, 'flags':'S'})
    return rows

@app.after_request
def security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'same-origin')
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    return response

@app.get('/')
def overview():
    return render_template('overview.html', summary=get_summary())

@app.get('/analyze')
def analyze_page():
    return render_template('analyze.html')

@app.post('/analyze/sample')
def analyze_sample():
    rows = sample_rows()
    records, alerts = analyze_records(rows)
    analysis_id = save_analysis('Sample demonstration data (synthetic)', records, alerts)
    flash(f'Sample analysis complete: {len(records)} records analyzed and {len(alerts)} alerts generated.', 'success')
    return redirect(url_for('results', analysis_id=analysis_id))

@app.post('/analyze/upload')
def analyze_upload():
    file = request.files.get('traffic_file')
    if not file or not file.filename:
        flash('Choose a CSV file to analyze.', 'error'); return redirect(url_for('analyze_page'))
    if Path(secure_filename(file.filename)).suffix.lower() != '.csv':
        flash('Only CSV files are supported.', 'error'); return redirect(url_for('analyze_page'))
    try:
        rows = parse_csv_bytes(file.read())
        records, alerts = analyze_records(rows)
        analysis_id = save_analysis('CSV import', records, alerts)
    except ValueError as exc:
        flash(str(exc), 'error'); return redirect(url_for('analyze_page'))
    flash(f'Analysis complete: {len(records)} records analyzed and {len(alerts)} alerts generated.', 'success')
    return redirect(url_for('results', analysis_id=analysis_id))

@app.get('/results')
def results():
    severity = request.args.get('severity','')
    search = request.args.get('q','')
    alerts = list_alerts(severity=severity or None, search=search or None)
    return render_template('results.html', alerts=alerts, severity=severity, search=search)

@app.post('/alerts/<int:alert_id>/status')
def set_status(alert_id):
    status = request.form.get('status','')
    if not update_alert_status(alert_id, status):
        flash('Could not update this alert. Check the selected status.', 'error')
    else:
        flash('Alert status updated.', 'success')
    return redirect(request.referrer if request.referrer and request.referrer.startswith('/') else url_for('results'))

@app.get('/reports')
def reports():
    alerts = list_alerts(limit=1000)
    return render_template('reports.html', alerts=alerts, summary=get_summary())

@app.get('/reports/export.csv')
def export_csv():
    alerts = list_alerts(limit=1000)
    return Response(make_csv(alerts), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=nids-detection-report.csv'})

@app.get('/reports/export.pdf')
def export_pdf():
    alerts = list_alerts(limit=1000)
    data = make_pdf(alerts, get_summary())
    return Response(data, mimetype='application/pdf', headers={'Content-Disposition':'attachment; filename=nids-detection-report.pdf'})

@app.get('/sample.csv')
def download_sample():
    return send_file(BASE_DIR / 'data' / 'sample_traffic.csv', mimetype='text/csv', as_attachment=True, download_name='sample_traffic.csv')

@app.get('/api/summary')
def api_summary():
    return jsonify(get_summary())

@app.errorhandler(413)
def too_large(_error):
    flash('Upload exceeds the 5 MB limit.', 'error')
    return redirect(url_for('analyze_page')), 303

@app.errorhandler(500)
def internal_error(_error):
    app.logger.exception('Unexpected application error')
    return render_template('error.html'), 500

if __name__ == '__main__':
    # Local development only. For normal local use, keep debug disabled.
    app.run(host='127.0.0.1', port=int(os.environ.get('PORT', 5000)), debug=False)
