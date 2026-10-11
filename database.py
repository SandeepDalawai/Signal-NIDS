import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("NIDS_DB_PATH", BASE_DIR / "nids.sqlite3"))

@contextmanager
def connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with connection() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS analyses (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          created_at TEXT NOT NULL,
          source TEXT NOT NULL,
          records_count INTEGER NOT NULL,
          alerts_count INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          analysis_id INTEGER NOT NULL,
          timestamp TEXT NOT NULL,
          src_ip TEXT NOT NULL,
          dst_ip TEXT NOT NULL,
          src_port INTEGER,
          dst_port INTEGER,
          protocol TEXT NOT NULL,
          rule TEXT NOT NULL,
          severity TEXT NOT NULL,
          reason TEXT NOT NULL,
          observed TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'New',
          FOREIGN KEY(analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        ''')


def save_analysis(source, records, alerts):
    from datetime import datetime, timezone
    with connection() as db:
        cur = db.execute('INSERT INTO analyses(created_at,source,records_count,alerts_count) VALUES(?,?,?,?)',
                          (datetime.now(timezone.utc).isoformat(), source, len(records), len(alerts)))
        analysis_id = cur.lastrowid
        for a in alerts:
            db.execute('''INSERT INTO alerts(analysis_id,timestamp,src_ip,dst_ip,src_port,dst_port,protocol,rule,severity,reason,observed,status)
                          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                       (analysis_id, a['timestamp'], a['src_ip'], a['dst_ip'], a['src_port'], a['dst_port'], a['protocol'],
                        a['rule'], a['severity'], a['reason'], a['observed'], a.get('status', 'New')))
        return analysis_id


def list_alerts(severity=None, search=None, limit=500):
    query = 'SELECT * FROM alerts WHERE 1=1'
    params = []
    if severity and severity in {'Low','Medium','High','Critical'}:
        query += ' AND severity=?'; params.append(severity)
    if search:
        query += ' AND (src_ip LIKE ? OR dst_ip LIKE ? OR rule LIKE ? OR reason LIKE ?)'
        term = f'%{search[:100]}%'; params.extend([term,term,term,term])
    query += ' ORDER BY timestamp DESC, id DESC LIMIT ?'; params.append(max(1, min(int(limit), 1000)))
    with connection() as db:
        return [dict(r) for r in db.execute(query, params).fetchall()]


def get_summary():
    with connection() as db:
        analyses = db.execute('SELECT COALESCE(SUM(records_count),0) n, COUNT(*) sessions FROM analyses').fetchone()
        total = db.execute('SELECT COUNT(*) n FROM alerts').fetchone()['n']
        high = db.execute("SELECT COUNT(*) n FROM alerts WHERE severity IN ('High','Critical')").fetchone()['n']
        severities = {r['severity']: r['n'] for r in db.execute('SELECT severity,COUNT(*) n FROM alerts GROUP BY severity')}
        rules = [dict(r) for r in db.execute('SELECT rule,COUNT(*) n FROM alerts GROUP BY rule ORDER BY n DESC LIMIT 8')]
        recent = [dict(r) for r in db.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 6')]
        sources = [dict(r) for r in db.execute('SELECT src_ip,COUNT(*) n FROM alerts GROUP BY src_ip ORDER BY n DESC LIMIT 5')]
        latest = db.execute('SELECT MAX(created_at) latest FROM analyses').fetchone()['latest']
    return {'records': analyses['n'], 'sessions': analyses['sessions'], 'alerts': total, 'high': high,
            'severities': severities, 'rules': rules, 'recent': recent, 'sources': sources, 'latest': latest}


def update_alert_status(alert_id, status):
    if status not in {'New','Investigating','Resolved'}:
        return False
    with connection() as db:
        cur = db.execute('UPDATE alerts SET status=? WHERE id=?', (status, alert_id))
        return cur.rowcount > 0
