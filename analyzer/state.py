"""
Trạng thái dùng chung giữa watcher thread (tail -f log) và Flask routes,
tương tự pattern đã dùng trong DoS Detector (threading.Lock để tránh
race condition giữa background thread và request thread).
"""
import threading

lock = threading.Lock()

# --- watch mode (real-time tail -f) ---
watching = False
watched_path = None
watched_log_type = None   # "ssh" hoặc "web"

# --- cấu hình rule detection ---
ssh_fail_threshold = 5        # số lần login fail / 1 IP trong window -> nghi brute force
ssh_window_seconds = 60
scan_404_threshold = 10       # số request 404 liên tiếp / 1 IP trong window -> nghi bị scan
scan_window_seconds = 20

# --- dữ liệu chung ---
alerts = []                # list alert (mới nhất ở đầu)
alerted_keys = set()        # (ip, rule) đã alert trong window hiện tại, tránh spam
line_count = 0              # tổng số dòng log đã xử lý (phiên hiện tại)
event_history = []          # list[{"time": ..., "count": ...}] để vẽ chart events/giây
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
