from datetime import datetime
from parser import LoginEvent
from rules import brute_force_detector, odd_hours_detector


def test_brute_force_detects_fast_attack():
    events = [
        LoginEvent(datetime(2026, 7, 20, 3, 10, 0), "1.2.3.4", "root", False),
        LoginEvent(datetime(2026, 7, 20, 3, 10, 5), "1.2.3.4", "root", False),
        LoginEvent(datetime(2026, 7, 20, 3, 10, 10), "1.2.3.4", "root", False),
        LoginEvent(datetime(2026, 7, 20, 3, 10, 15), "1.2.3.4", "root", False),
        LoginEvent(datetime(2026, 7, 20, 3, 10, 20), "1.2.3.4", "root", False),
    ]
    findings = brute_force_detector(events, window_seconds=60, threshold=5)
    assert len(findings) == 1
    assert findings[0].ip == "1.2.3.4"


def test_odd_hours_ignores_failed_logins():
    events = [LoginEvent(datetime(2026, 7, 20, 3, 0, 0), "1.2.3.4", "root", False)]
    findings = odd_hours_detector(events)
    assert len(findings) == 0  # failed logins shouldn't trigger this rule


def test_odd_hours_flags_successful_night_login():
    events = [LoginEvent(datetime(2026, 7, 20, 3, 0, 0), "1.2.3.4", "root", True)]
    findings = odd_hours_detector(events)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
