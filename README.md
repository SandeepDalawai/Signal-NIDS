# Signal / NIDS — Network Intrusion Detection Mini Project

A small Flask application that analyzes normalized network connection records using transparent detection rules, stores findings in SQLite, and exports CSV/PDF reports. The interface uses an editorial “Signal / Field Notes” visual direction: warm stone, forest green, and restrained vermilion rather than a generic hacker dashboard.

## Features

- Sample analysis and CSV upload using the same detection engine.
- Rule-based alerts for possible port scans, SYN scan patterns, repeated connection attempts, high traffic volume, and destination sweeps.
- Evidence and observed values attached to each alert.
- Persistent analysis history and findings in SQLite.
- Search, severity filtering, and investigation status updates.
- CSV and PDF report exports based on stored results.
- Upload size and row limits, CSV schema validation, parameterized SQL, template autoescaping, and CSRF protection for POST forms.

**Scope note:** This mini project analyzes connection records; it does not include live packet capture. Live capture is intentionally optional and is not required for the application to work. A record-based SYN pattern is only an indicator; it cannot confirm a completed TCP handshake without adequate packet/flow data.

## Requirements

- Windows 10/11 or another OS with Python 3.11+.
- VS Code (optional but recommended).
- Internet only for first-time package installation and web fonts; the app itself runs locally.

## Windows PowerShell setup

Open PowerShell in this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:NIDS_SECRET_KEY = "replace-this-with-a-long-random-local-secret"
python app.py
```

Open **http://127.0.0.1:5000**. Keep the terminal open while using the app. Debug mode is disabled.

If PowerShell blocks virtual-environment activation, use a terminal policy appropriate for your machine or run `.venv\Scripts\python.exe -m pip install -r requirements.txt` and `.venv\Scripts\python.exe app.py` directly.

## Quick demo

1. Open **Analyze**.
2. Click **Run sample analysis**. The sample is synthetic and explicitly labeled.
3. Open **Findings** to inspect the alerts and observed values.
4. Update an alert's status using its dropdown.
5. Open **Reports** and download CSV or PDF.
6. Try importing `data/sample_traffic.csv` for a second analysis session.

## CSV format

Required fields: `src_ip`, `dst_ip`. Optional fields: `timestamp`, `src_port`, `dst_port`, `protocol`, `packets`, `bytes`, `flags`, and `status`. Common aliases such as `source_ip`, `destination_ip`, `proto`, `source_port`, and `byte_count` are accepted. Maximum upload size is 5 MB and maximum record count is 50,000.

## Detection rules

Default thresholds are defined in `detector.py`:

- Possible port scan: 8 distinct destination ports from one source within 60 seconds.
- SYN scan pattern: 8 distinct destination ports among TCP SYN-only records from one source within 60 seconds.
- Repeated connection attempts: 12 records from one source to one destination within 60 seconds.
- High traffic volume: 5,000,000 bytes in a record.
- Destination sweep: 12 distinct destination addresses from one source within 60 seconds.

These are simple example thresholds for a teaching project, not universal production values. Tune them for your environment. A triggered rule is not proof of malicious activity; validate surrounding context.

## Tests

```powershell
python -m pytest -q
```

The tests cover basic detection rules, CSV validation, and report output generation.

## Security and privacy

- Use only network data you are authorized to analyze.
- Uploaded data is parsed as text; uploaded files are not executed or retained as files.
- The application stores alert metadata in `nids.sqlite3` in this folder by default. Treat this database as potentially sensitive.
- A development fallback secret exists so the app can start locally; set `NIDS_SECRET_KEY` to a long random value for your local run and do not expose this development server to the internet.
- This is an educational mini project, not a hardened production NIDS. It does not provide user accounts, TLS termination, live capture, packet reassembly, or full incident response.

## Troubleshooting

- **Port 5000 busy:** set `$env:PORT = "5001"` before `python app.py` and visit `http://127.0.0.1:5001`.
- **PDF library missing:** run `pip install -r requirements.txt` again.
- **CSV rejected:** ensure it has `src_ip` and `dst_ip` columns and is UTF-8 encoded.
- **Old demo data:** stop the app, back up and delete `nids.sqlite3`, then restart to create a clean database.
