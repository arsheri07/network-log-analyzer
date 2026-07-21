"""
parser.py
---------
Turns raw SSH auth log lines into structured Python objects so the
detection rules don't have to deal with regex/string parsing directly.
"""

import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class LoginEvent:
    timestamp: datetime
    ip: str
    user: str
    success: bool


LINE_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<status>Accepted|Failed)\s+password\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+\d+\s+ssh2"
)


def parse_log_file(path, year=2026):
    """Reads a log file and returns a list of LoginEvent objects,
    sorted chronologically."""
    events = []
    with open(path) as f:
        for line in f:
            match = LINE_PATTERN.match(line.strip())
            if not match:
                continue  # skip lines that don't match (e.g. other log types)

            ts_str = f"{match.group('ts')} {year}"
            timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")

            events.append(
                LoginEvent(
                    timestamp=timestamp,
                    ip=match.group("ip"),
                    user=match.group("user"),
                    success=(match.group("status") == "Accepted"),
                )
            )

    events.sort(key=lambda e: e.timestamp)
    return events


if __name__ == "__main__":
    # quick manual test
    events = parse_log_file("sample_auth.log")
    print(f"Parsed {len(events)} events")
    print("First event:", events[0])
    print("Last event:", events[-1])
