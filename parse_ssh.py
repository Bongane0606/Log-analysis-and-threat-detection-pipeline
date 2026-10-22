"""Parse OpenSSH entries from a Linux auth.log into structured records."""
import re
import sqlite3
from datetime import datetime

# Example lines:
# Oct 22 14:03:11 ubuntu sshd[1234]: Failed password for invalid user admin from 192.168.56.10 port 50422 ssh2
# Oct 22 14:03:15 ubuntu sshd[1234]: Failed password for testuser from 192.168.56.10 port 50430 ssh2
# Oct 22 14:05:02 ubuntu sshd[1240]: Accepted password for testuser from 192.168.56.10 port 50511 ssh2
# Oct 22 14:06:40 ubuntu sshd[1250]: Invalid user oracle from 192.168.56.10 port 50600

LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s(?P<host>\S+)\ssshd\[\d+\]:\s(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")


def parse_line(line, year):
    """Return a dict for a relevant sshd line, or None to skip it."""
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    # auth.log has no year, so it has to be supplied
    ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")
    msg = m["msg"]

    for regex, status in ((FAILED_RE, "failed"), (ACCEPTED_RE, "success")):
        hit = regex.search(msg)
        if hit:
            return {
                "ts": ts.isoformat(),
                "host": m["host"],
                "user": hit["user"],
                "ip": hit["ip"],
                "status": status,
                "invalid_user": "invalid user" in msg,
            }
    hit = INVALID_RE.search(msg)
    if hit:
        return {
            "ts": ts.isoformat(),
            "host": m["host"],
            "user": hit["user"],
            "ip": hit["ip"],
            "status": "invalid_user",
            "invalid_user": True,
        }
    return None


def load(path, db_path="events.db", year=None):
    year = year or datetime.now().year
    con = sqlite3.connect(db_path)
    con.execute(
        """CREATE TABLE IF NOT EXISTS ssh_events (
            id INTEGER PRIMARY KEY,
            ts TEXT, host TEXT, user TEXT, ip TEXT,
            status TEXT, invalid_user INTEGER)"""
    )
    rows = 0
    with open(path, errors="replace") as f:
        for line in f:
            rec = parse_line(line, year)
            if rec:
                con.execute(
                    "INSERT INTO ssh_events (ts, host, user, ip, status, invalid_user) "
                    "VALUES (:ts, :host, :user, :ip, :status, :invalid_user)",
                    rec,
                )
                rows += 1
    con.commit()
    con.close()
    return rows


if __name__ == "__main__":
    import sys

    n = load(sys.argv[1])
    print(f"Loaded {n} SSH events")