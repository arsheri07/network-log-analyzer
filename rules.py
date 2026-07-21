"""
rules.py
--------
Each function takes the full list of LoginEvent objects and returns a
list of Finding objects (one detection rule = one function).

Three detection rules:
  1. brute_force_detector      - fast, high-volume failed logins from one IP
  2. odd_hours_detector        - successful logins outside working hours
  3. slow_brute_force_detector - low-and-slow failed logins that evade
                                 rule 1's tighter time window
"""

from dataclasses import dataclass
from collections import defaultdict
from datetime import timedelta


@dataclass
class Finding:
    rule: str
    severity: str       # "LOW" | "MEDIUM" | "HIGH"
    ip: str
    detail: str


# ---------------------------------------------------------------------
# RULE 1 - Fast brute force detection
# ---------------------------------------------------------------------
def brute_force_detector(events, window_seconds=60, threshold=5):
    """
    Flags any IP that racks up `threshold` or more FAILED logins within
    a rolling `window_seconds` window. This is the classic brute-force
    signature: many wrong passwords, fast, from one source.
    """
    findings = []
    failed_by_ip = defaultdict(list)

    for e in events:
        if not e.success:
            failed_by_ip[e.ip].append(e.timestamp)

    for ip, timestamps in failed_by_ip.items():
        timestamps.sort()
        for i, start in enumerate(timestamps):
            window_end = start + timedelta(seconds=window_seconds)
            count_in_window = sum(1 for t in timestamps[i:] if t <= window_end)
            if count_in_window >= threshold:
                severity = "HIGH" if count_in_window >= threshold * 3 else "MEDIUM"
                findings.append(Finding(
                    rule="Brute Force",
                    severity=severity,
                    ip=ip,
                    detail=f"{count_in_window} failed logins within {window_seconds}s "
                           f"(starting {start.strftime('%H:%M:%S')})"
                ))
                break

    return findings


# ---------------------------------------------------------------------
# RULE 2 - Odd-hours login detector
# ---------------------------------------------------------------------
def odd_hours_detector(events, start_hour=6, end_hour=22):
    """
    Flags any SUCCESSFUL login that happens outside normal working
    hours (before start_hour or after end_hour). A successful login
    at 3am from an account that never normally logs in then is a
    classic sign of a compromised credential being used by an
    attacker, even when no failed attempts preceded it. Severity is
    bumped to HIGH for privileged accounts (root/admin).
    """
    findings = []

    for e in events:
        if not e.success:
            continue

        hour = e.timestamp.hour
        if hour < start_hour or hour > end_hour:
            severity = "HIGH" if e.user in ("root", "admin") else "MEDIUM"
            findings.append(Finding(
                rule="Odd Hours Login",
                severity=severity,
                ip=e.ip,
                detail=f"Successful login as '{e.user}' at "
                       f"{e.timestamp.strftime('%H:%M:%S')} (outside {start_hour}:00-{end_hour}:00)"
            ))

    return findings


# ---------------------------------------------------------------------
# RULE 3 - Slow/distributed brute force detector
# ---------------------------------------------------------------------
def slow_brute_force_detector(events, window_minutes=30, threshold=8):
    """
    Catches "low-and-slow" brute force: an attacker who spaces out
    failed logins by minutes instead of seconds to stay under a naive
    rate limit, but still accumulates enough failures over a longer
    window to be suspicious. Same sliding-window approach as Rule 1,
    just with a wider time window and lower per-window threshold.
    """
    findings = []
    failed_by_ip = defaultdict(list)

    for e in events:
        if not e.success:
            failed_by_ip[e.ip].append(e.timestamp)

    for ip, timestamps in failed_by_ip.items():
        timestamps.sort()
        for i, start in enumerate(timestamps):
            window_end = start + timedelta(minutes=window_minutes)
            count_in_window = sum(1 for t in timestamps[i:] if t <= window_end)
            if count_in_window >= threshold:
                findings.append(Finding(
                    rule="Slow Brute Force",
                    severity="MEDIUM",
                    ip=ip,
                    detail=f"{count_in_window} failed logins within {window_minutes} min "
                           f"(starting {start.strftime('%H:%M:%S')})"
                ))
                break

    return findings
