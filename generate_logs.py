"""
generate_logs.py
-----------------
Creates a synthetic SSH auth log (similar format to /var/log/auth.log)
with normal traffic + injected attack patterns, so you have realistic
data to test your analyzer against without needing a real server.

Run: python3 generate_logs.py
Output: sample_auth.log
"""

import random
from datetime import datetime, timedelta

random.seed(42)  # reproducible output

USERS = ["akshith", "admin", "root", "deploy", "backup", "test"]
NORMAL_IPS = ["192.168.1.{}".format(i) for i in range(2, 15)]
ATTACKER_IPS = ["203.0.113.{}".format(i) for i in [45, 87, 132]]

start_time = datetime(2026, 7, 20, 0, 0, 0)
lines = []


def log_line(ts, ip, user, success):
    status = "Accepted password" if success else "Failed password"
    return f"{ts.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000,9999)}]: {status} for {user} from {ip} port {random.randint(1024,65000)} ssh2"


# --- 1. Normal daytime traffic (legit logins spread across the day) ---
t = start_time
for _ in range(40):
    t += timedelta(minutes=random.randint(5, 40))
    hour = t.hour
    # keep normal logins mostly in working hours 7am-10pm
    if hour < 7 or hour > 22:
        t = t.replace(hour=random.randint(8, 18))
    ip = random.choice(NORMAL_IPS)
    user = random.choice(USERS[:2])  # normal users mostly log in as themselves
    lines.append(log_line(t, ip, user, success=True))

# --- 2. Brute-force pattern: one IP hammers many failed logins fast ---
attacker = ATTACKER_IPS[0]
t = start_time.replace(hour=3, minute=10)  # suspicious 3am timing
for _ in range(25):
    t += timedelta(seconds=random.randint(2, 8))  # rapid-fire attempts
    user = random.choice(USERS)
    lines.append(log_line(t, attacker, user, success=False))
# attacker eventually gets in (worst case scenario worth flagging hardest)
t += timedelta(seconds=5)
lines.append(log_line(t, attacker, "root", success=True))

# --- 3. Slow/low brute force from a second IP (harder to catch naively) ---
attacker2 = ATTACKER_IPS[1]
t = start_time.replace(hour=14, minute=0)
for _ in range(12):
    t += timedelta(minutes=random.randint(3, 6))
    lines.append(log_line(t, attacker2, "admin", success=False))

# --- 4. Odd-hours single login (legit-looking creds, suspicious time) ---
t = start_time.replace(hour=4, minute=22)
lines.append(log_line(t, ATTACKER_IPS[2], "deploy", success=True))

# sort everything chronologically like a real log file would be
# (real syslog lines don't include a year either - we add one here
# just for sorting purposes, same as we do in parser.py)
lines.sort(key=lambda l: datetime.strptime(f"{l[:15]} 2026", "%b %d %H:%M:%S %Y"))

with open("sample_auth.log", "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"Generated {len(lines)} log lines -> sample_auth.log")
