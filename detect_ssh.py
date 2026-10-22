"""Detection rules over the ssh_events table. Writes findings to an alerts table."""
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta

# Tune these against your own attack journal
BRUTE_WINDOW = timedelta(minutes=5)
BRUTE_THRESHOLD = 5        # failed attempts from one IP inside the window
SPRAY_WINDOW = timedelta(minutes=10)
SPRAY_USER_THRESHOLD = 4   # distinct usernames tried by one IP inside the window


def _load_failures(con):
    """Failed or invalid-user events grouped by IP, sorted by time.
    'Invalid user' and 'Failed password for invalid user' lines both appear for
    the same attempt, so identical (ts, ip, user) rows are collapsed."""
    rows = con.execute(
        "SELECT DISTINCT ts, ip, user FROM ssh_events "
        "WHERE status IN ('failed', 'invalid_user') ORDER BY ts"
    ).fetchall()
    by_ip = defaultdict(list)
    for ts, ip, user in rows:
        by_ip[ip].append((datetime.fromisoformat(ts), user))
    return by_ip


def detect_brute_force(by_ip):
    alerts = []
    for ip, events in by_ip.items():
        start = 0
        flagged = False
        for end in range(len(events)):
            while events[end][0] - events[start][0] > BRUTE_WINDOW:
                start += 1
            count = end - start + 1
            if count >= BRUTE_THRESHOLD and not flagged:
                alerts.append({
                    "ts": events[start][0].isoformat(),
                    "ip": ip,
                    "rule": "brute_force",
                    "severity": "high",
                    "detail": f"{count}+ failed logins within {BRUTE_WINDOW}",
                })
                flagged = True  # one alert per IP burst; reset when the burst ends
            elif count < BRUTE_THRESHOLD:
                flagged = False
    return alerts


def detect_spraying(by_ip):
    alerts = []
    for ip, events in by_ip.items():
        start = 0
        flagged = False
        for end in range(len(events)):
            while events[end][0] - events[start][0] > SPRAY_WINDOW:
                start += 1
            users = {u for _, u in events[start:end + 1]}
            if len(users) >= SPRAY_USER_THRESHOLD and not flagged:
                alerts.append({
                    "ts": events[start][0].isoformat(),
                    "ip": ip,
                    "rule": "password_spraying",
                    "severity": "high",
                    "detail": f"{len(users)} distinct usernames within {SPRAY_WINDOW}",
                })
                flagged = True
            elif len(users) < SPRAY_USER_THRESHOLD:
                flagged = False
    return alerts


def run(db_path="events.db"):
    con = sqlite3.connect(db_path)
    con.execute("DROP TABLE IF EXISTS alerts")
    con.execute(
        """CREATE TABLE alerts (
            id INTEGER PRIMARY KEY, ts TEXT, ip TEXT,
            rule TEXT, severity TEXT, detail TEXT)"""
    )
    by_ip = _load_failures(con)
    alerts = detect_brute_force(by_ip) + detect_spraying(by_ip)
    for a in alerts:
        con.execute(
            "INSERT INTO alerts (ts, ip, rule, severity, detail) "
            "VALUES (:ts, :ip, :rule, :severity, :detail)", a)
    con.commit()
    con.close()
    return alerts


if __name__ == "__main__":
    for a in run():
        print(a["ts"], a["ip"], a["rule"], "-", a["detail"])