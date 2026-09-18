
from collections import defaultdict
from datetime import datetime
import time

from . import state

_ssh_fail_counter = defaultdict(int)
_ssh_last_reset = time.time()

_scan_404_counter = defaultdict(int)
_scan_last_reset = time.time()


def _push_alert(ip, rule, severity, detail, extra=None):
    with state.lock:
        state.alerts.insert(0, {
            "ip": ip,
            "rule": rule,
            "severity": severity,
            "detail": detail,
            "time": datetime.now().strftime("%H:%M:%S"),
            **(extra or {}),
        })
        if len(state.alerts) > 500:
            state.alerts.pop()
        state._second_counter += 1


def process_ssh_event(evt):
    """evt: dict returned by parsers.parse_ssh_line (never None)."""
    global _ssh_last_reset

    ip = evt["ip"]
    with state.lock:
        state.line_count += 1

    if evt["event"] in ("failed_login", "invalid_user"):
        _ssh_fail_counter[ip] += 1
        rate = _ssh_fail_counter[ip]

        key = (ip, "ssh_bruteforce")
        if rate >= state.ssh_fail_threshold and key not in state.alerted_keys:
            with state.lock:
                state.alerted_keys.add(key)
            severity = "critical" if rate >= state.ssh_fail_threshold * 3 else "high"
            _push_alert(
                ip, "SSH Brute Force", severity,
                f"{rate} failed login attempts within {state.ssh_window_seconds}s (user: {evt.get('user')})",
                extra={"user": evt.get("user"), "count": rate},
            )


    now = time.time()
    if now - _ssh_last_reset > state.ssh_window_seconds:
        _ssh_fail_counter.clear()
        with state.lock:
            state.alerted_keys = {k for k in state.alerted_keys if k[1] != "ssh_bruteforce"}
        _ssh_last_reset = now


def process_access_event(evt):
    """evt: dict returned by parsers.parse_access_line (never None)."""
    global _scan_last_reset

    ip = evt["ip"]
    with state.lock:
        state.line_count += 1

  
    for flag in evt.get("flags", []):
        rule_name = {
            "sqli": "SQL Injection Attempt",
            "xss": "XSS Attempt",
            "path_traversal": "Path Traversal Attempt",
        }.get(flag, flag)
        _push_alert(
            ip, rule_name, "high",
            f"{evt['method']} {evt['path'][:120]}",
            extra={"method": evt["method"], "path": evt["path"], "status": evt["status"]},
        )

    
    if evt.get("status") == 404:
        _scan_404_counter[ip] += 1
        rate = _scan_404_counter[ip]
        key = (ip, "dir_scan")
        if rate >= state.scan_404_threshold and key not in state.alerted_keys:
            with state.lock:
                state.alerted_keys.add(key)
            _push_alert(
                ip, "Directory/File Scanning", "medium",
                f"{rate} requests returned 404 within {state.scan_window_seconds}s (indicates automated directory probing)",
                extra={"count": rate},
            )

    now = time.time()
    if now - _scan_last_reset > state.scan_window_seconds:
        _scan_404_counter.clear()
        with state.lock:
            state.alerted_keys = {k for k in state.alerted_keys if k[1] != "dir_scan"}
        _scan_last_reset = now


def tick_event_history():
    """Called every second to record the events/sec count into event_history (for the chart)."""
    with state.lock:
        state.event_history.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "count": state._second_counter,
        })
        if len(state.event_history) > state.MAX_HISTORY:
            state.event_history.pop(0)
        state._second_counter = 0
