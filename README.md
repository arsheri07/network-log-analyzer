# Network Log Analyzer

A Python tool that parses SSH authentication logs and flags suspicious
login patterns — fast brute-force attacks, slow/distributed brute-force
attempts, and successful logins at unusual hours.

## Why I built this

During my IT Help Desk internship at Texas Health & Human Services, I
spent a lot of time triaging support tickets — deciding what was urgent
versus what could wait, based on severity and impact. This project
applies that same instinct to security data instead of IT tickets: given
a stream of login events, decide what's normal noise and what actually
deserves attention. It grew out of wanting a hands-on project that
connects my cybersecurity coursework to something I could actually run
and reason about, rather than just reading about attack patterns.

## What it detects

- **Fast brute force** — many failed logins from one IP within a short time window
- **Slow/distributed brute force** — failed logins spaced out to evade naive rate limits
- **Odd-hours logins** — successful logins outside normal working hours (severity is raised further for privileged accounts like `root`/`admin`)

## Requirements

Python 3, [rich](https://github.com/Textualize/rich) for terminal output, `pytest` for testing

## How to run

```bash
pip install -r requirements.txt
python3 generate_logs.py   # creates sample_auth.log with synthetic data
python3 analyze.py         # runs detection rules and prints findings
```

## Testing

Detection logic is covered by `pytest` unit tests that check each rule
against hand-constructed events, independent of the synthetic log
generator:

```bash
python3 -m pytest -v
```

```
============================= test session starts ==============================
collected 3 items

test_rules.py::test_brute_force_detects_fast_attack PASSED               [ 33%]
test_rules.py::test_odd_hours_ignores_failed_logins PASSED               [ 66%]
test_rules.py::test_odd_hours_flags_successful_night_login PASSED        [100%]

============================== 3 passed in 0.02s ===============================
```

The odd-hours tests specifically check an edge case worth calling out:
a failed login at 3am should NOT be flagged (failed logins are normal
around the clock — bots try constantly), but a *successful* login at
the same hour should be, and should carry HIGH severity for a
privileged account like `root`. Testing this distinction directly
guards against accidentally flagging the wrong condition.

## Sample output

```
Network Log Analyzer
Parsing sample_auth.log...

Loaded 79 login events

                               Security Findings
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Rule             ┃ Source IP     ┃ Detail                         ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH     │ Odd Hours Login  │ 203.0.113.45  │ Successful login as 'root' at  │
│          │                  │               │ 03:12:14 (outside 6:00-22:00)  │
├──────────┼──────────────────┼───────────────┼────────────────────────────────┤
│ MEDIUM   │ Brute Force      │ 203.0.113.45  │ 12 failed logins within 60s    │
│          │                  │               │ (starting 03:10:07)            │
├──────────┼──────────────────┼───────────────┼────────────────────────────────┤
│ MEDIUM   │ Odd Hours Login  │ 203.0.113.132 │ Successful login as 'deploy'   │
│          │                  │               │ at 04:22:00 (outside           │
│          │                  │               │ 6:00-22:00)                    │
├──────────┼──────────────────┼───────────────┼────────────────────────────────┤
│ MEDIUM   │ Slow Brute Force │ 203.0.113.45  │ 25 failed logins within 30 min │
│          │                  │               │ (starting 03:10:07)            │
├──────────┼──────────────────┼───────────────┼────────────────────────────────┤
│ MEDIUM   │ Slow Brute Force │ 203.0.113.87  │ 8 failed logins within 30 min  │
│          │                  │               │ (starting 14:04:00)            │
└──────────┴──────────────────┴───────────────┴────────────────────────────────┘

5 finding(s) total
```

<img width="594" height="404" alt="Screenshot 2026-07-22 at 12 31 37 PM" src="https://github.com/user-attachments/assets/961c6f6c-d9cb-4f97-8f34-b41b0f662085" />
*Output from running `analyze.py` against the synthetic `sample_auth.log` dataset*

## Project Structure
- `generate_logs.py` — generates synthetic `sample_auth.log` data with embedded attack patterns for testing
- `parser.py` — parses raw log lines into structured login event objects
- `rules.py` — detection logic for brute force, slow brute force, and odd-hours login rules
- `analyze.py` — main entry point; loads events, runs detection rules, prints findings
- `test_rules.py` — pytest unit tests for detection rules

## Design decisions & threshold tuning

Thresholds were tuned by sweeping a range of values against the
synthetic attack data in `sample_auth.log`:

- **Fast brute force** (`window=60s, threshold=5`): this rule turned out
  to be insensitive to the exact parameter choice in testing — a fast
  attacker firing 12 failed logins in under a minute got caught at every
  threshold from 3 to 10 and every window from 15s to 120s. Fast attacks
  are a loud, unambiguous signal.
- **Slow brute force** (`window=30min, threshold=8`): far more sensitive.
  Testing showed that dropping the window below 30 minutes, or raising
  the threshold to 10+, let the synthetic slow/distributed attacker
  (failures spaced 3-6 minutes apart) go completely undetected. The
  chosen values sit right at the edge of what's needed to catch that
  pattern — not an arbitrary pick.
- These specific numbers are tuned to this synthetic dataset and would
  need re-validation against real traffic before production use — the
  transferable part is the *sensitivity analysis process*, not the exact
  numbers.

## What I'd add next

- Real-time log tailing instead of static file analysis
- Configurable thresholds via a config file instead of hardcoded values
- GeoIP lookup to flag logins from unexpected countries
- Web dashboard instead of terminal output
- Switch the O(k²) sliding-window scan to an O(k) two-pointer approach for large-scale logs

---
*Built by Akshithreddy Sheri — [github.com/arsheri07](https://github.com/arsheri07)*
