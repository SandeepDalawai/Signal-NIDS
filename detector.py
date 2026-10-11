"""Transparent rule-based detections for normalized network connection records."""
from collections import defaultdict, deque
from datetime import datetime, timezone

DEFAULTS = {
    "port_scan_unique_ports": 8,
    "port_scan_window_seconds": 60,
    "repeat_attempt_count": 12,
    "repeat_attempt_window_seconds": 60,
    "high_bytes_threshold": 5_000_000,
    "destination_diversity_threshold": 12,
    "destination_diversity_window_seconds": 60,
}


def _parse_time(value):
    if isinstance(value, datetime):
        return value
    text = str(value or "").strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def normalize_record(row, index=0):
    """Normalize supported CSV row fields to a predictable schema."""
    def pick(*keys, default=""):
        for key in keys:
            if row.get(key) not in (None, ""):
                return row.get(key)
        return default

    timestamp = _parse_time(pick("timestamp", "time", "ts", default=datetime.now(timezone.utc).isoformat()))
    def int_or_none(value):
        if value in (None, ""):
            return None
        try:
            n = int(float(value))
            return n if 0 <= n <= 65535 else None
        except (ValueError, TypeError):
            return None
    def nonnegative(value):
        try:
            return max(0, int(float(value or 0)))
        except (ValueError, TypeError):
            return 0

    return {
        "timestamp": timestamp.isoformat(),
        "src_ip": str(pick("src_ip", "source_ip", "src", default="unknown"))[:64],
        "dst_ip": str(pick("dst_ip", "destination_ip", "dst", default="unknown"))[:64],
        "src_port": int_or_none(pick("src_port", "source_port")),
        "dst_port": int_or_none(pick("dst_port", "destination_port")),
        "protocol": str(pick("protocol", "proto", default="UNKNOWN")).upper()[:16],
        "packets": nonnegative(pick("packets", "packet_count", default=1)),
        "bytes": nonnegative(pick("bytes", "byte_count", "bytes_transferred", default=0)),
        "flags": str(pick("flags", "tcp_flags", default="")).upper()[:32],
        "status": str(pick("status", "connection_state", default="")).upper()[:32],
        "record_index": index,
    }


def analyze_records(rows, thresholds=None):
    """Return normalized records and evidence-backed alerts based on simple thresholds."""
    cfg = {**DEFAULTS, **(thresholds or {})}
    records = [normalize_record(row, i) for i, row in enumerate(rows)]
    alerts = []

    def add(record, rule, severity, reason, observed):
        alerts.append({
            "timestamp": record["timestamp"], "src_ip": record["src_ip"], "dst_ip": record["dst_ip"],
            "src_port": record["src_port"], "dst_port": record["dst_port"], "protocol": record["protocol"],
            "rule": rule, "severity": severity, "reason": reason, "observed": observed,
            "status": "New", "record_index": record["record_index"],
        })

    # High-volume events are evaluated per record, using the supplied bytes/packets evidence.
    for r in records:
        if r["bytes"] >= cfg["high_bytes_threshold"]:
            add(r, "High traffic volume", "High",
                f"This record reports {r['bytes']:,} bytes, at or above the configured threshold.",
                f"bytes={r['bytes']}; threshold={cfg['high_bytes_threshold']}")
        if r["flags"] and "S" in r["flags"] and "A" not in r["flags"] and r["protocol"] == "TCP":
            # A single SYN is not an alert; scan patterns are evaluated below.
            pass

    by_source = defaultdict(list)
    by_source_dest = defaultdict(list)
    for r in records:
        by_source[r["src_ip"]].append(r)
        by_source_dest[(r["src_ip"], r["dst_ip"])].append(r)

    def within_window(items, seconds):
        ordered = sorted(items, key=lambda x: _parse_time(x["timestamp"]))
        q = deque()
        for r in ordered:
            t = _parse_time(r["timestamp"])
            while q and (t - _parse_time(q[0]["timestamp"])).total_seconds() > seconds:
                q.popleft()
            q.append(r)
            yield r, list(q)

    for src, items in by_source.items():
        for r, window in within_window(items, cfg["port_scan_window_seconds"]):
            ports = {x["dst_port"] for x in window if x["dst_port"] is not None}
            if len(ports) >= cfg["port_scan_unique_ports"] and r is window[-1]:
                add(r, "Possible port scan", "High",
                    f"Source {src} contacted {len(ports)} distinct destination ports within {cfg['port_scan_window_seconds']} seconds.",
                    f"unique_destination_ports={len(ports)}; threshold={cfg['port_scan_unique_ports']}")
                break
        for r, window in within_window(items, cfg["destination_diversity_window_seconds"]):
            destinations = {x["dst_ip"] for x in window if x["dst_ip"] != "unknown"}
            if len(destinations) >= cfg["destination_diversity_threshold"] and r is window[-1]:
                add(r, "Destination sweep", "Medium",
                    f"Source {src} contacted {len(destinations)} distinct destination addresses within {cfg['destination_diversity_window_seconds']} seconds.",
                    f"unique_destinations={len(destinations)}; threshold={cfg['destination_diversity_threshold']}")
                break

    for (src, dst), items in by_source_dest.items():
        for r, window in within_window(items, cfg["repeat_attempt_window_seconds"]):
            if len(window) >= cfg["repeat_attempt_count"] and r is window[-1]:
                add(r, "Repeated connection attempts", "Medium",
                    f"Source {src} produced {len(window)} records toward {dst} within {cfg['repeat_attempt_window_seconds']} seconds.",
                    f"attempts={len(window)}; threshold={cfg['repeat_attempt_count']}")
                break

    # Detect repeated SYN-only records when the source shows enough distinct destination ports.
    syn_records = [r for r in records if r["protocol"] == "TCP" and r["flags"] and "S" in r["flags"] and "A" not in r["flags"]]
    for src, items in _group(syn_records, "src_ip").items():
        for r, window in within_window(items, cfg["port_scan_window_seconds"]):
            ports = {x["dst_port"] for x in window if x["dst_port"] is not None}
            if len(ports) >= cfg["port_scan_unique_ports"] and r is window[-1]:
                add(r, "SYN scan pattern", "High",
                    f"Observed {len(ports)} distinct destination ports with TCP SYN-only records from {src}; handshake completion cannot be confirmed from these records alone.",
                    f"syn_only_records={len(window)}; unique_ports={len(ports)}")
                break

    # Deduplicate repeated alerts for the same rule and source/destination within one analysis.
    unique = {}
    for alert in alerts:
        key = (alert["rule"], alert["src_ip"], alert["dst_ip"], alert["observed"])
        unique[key] = alert
    return records, sorted(unique.values(), key=lambda a: _parse_time(a["timestamp"]), reverse=True)


def _group(items, key):
    grouped = defaultdict(list)
    for item in items:
        grouped[item[key]].append(item)
    return grouped
