
import threading

lock = threading.Lock()

watching = False
watched_path = None
watched_log_type = None

ssh_fail_threshold = 5
ssh_window_seconds = 60
scan_404_threshold = 10
scan_window_seconds = 20

alerts = []
alerted_keys = set()
line_count = 0
event_history = []
MAX_HISTORY = 300
_second_counter = 0


def reset():
    global alerts, alerted_keys, line_count, event_history, _second_counter
    with lock:
        alerts = []
        alerted_keys = set()
        line_count = 0
        event_history = []
        _second_counter = 0
