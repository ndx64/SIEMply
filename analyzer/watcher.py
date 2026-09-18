"""
Hai chế độ đọc log:

1. watch_file()  - chạy nền, đọc log kiểu "tail -f" (giống sniffer.py của
   DoS Detector chạy nền bắt packet), dùng khi muốn theo dõi hệ thống
   real-time (vd tail /var/log/auth.log khi đang test SSH brute force).

2. process_file_batch() - đọc trọn 1 file log có sẵn (vd log cũ tải về từ
   server, hoặc file mẫu để demo), xử lý toàn bộ 1 lần rồi trả kết quả
   ngay - phù hợp khi không có quyền/khả năng theo dõi real-time.
"""
import os
import time

from . import state
from .parsers import parse_ssh_line, parse_access_line
from .detectors import process_ssh_event, process_access_event


def _dispatch_line(line, log_type):
    if log_type == "ssh":
        evt = parse_ssh_line(line)
        if evt:
            process_ssh_event(evt)
    elif log_type == "web":
        evt = parse_access_line(line)
        if evt:
            process_access_event(evt)


def watch_file(path, log_type):
    """
    Chạy trên background thread. Seek tới cuối file, sau đó liên tục
    kiểm tra dòng mới được ghi thêm (tail -f), xử lý qua rule engine.
    Dừng lại khi state.watching bị set False (nút Stop trên UI).
    """
    state.watching = True
    state.watched_path = path
    state.watched_log_type = log_type

    try:
        with open(path, "r", errors="ignore") as f:
            f.seek(0, os.SEEK_END)  # chỉ đọc log MỚI phát sinh từ lúc bắt đầu watch
            while state.watching:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                _dispatch_line(line.rstrip("\n"), log_type)
    except FileNotFoundError:
        state.watching = False
        raise
    finally:
        state.watching = False


def process_file_batch(file_stream, log_type):
    """
    file_stream: file-like object (vd từ Flask request.files['logfile']).
    Đọc và xử lý toàn bộ nội dung ngay lập tức, trả về số dòng đã xử lý.

    Lưu ý (hạn chế đã biết, giống ghi chú trong DoS Detector):
    rule engine dùng cửa sổ thời gian thực (wall-clock) để đếm brute force/
    scan. Khi xử lý batch 1 file log lịch sử rất nhanh, toàn bộ nội dung
    có thể rơi vào cùng 1 "window" thực tế (vài giây xử lý), nên với các
    log trải dài nhiều giờ/ngày, ngưỡng brute force/scan chỉ được tính
    dựa trên tổng số lần xuất hiện, không phản ánh đúng phân bố thời gian
    gốc trong file. Phù hợp để demo/phát hiện nhanh, chưa phù hợp để làm
    forensic timeline chính xác tuyệt đối.
    """
    processed = 0
    raw = file_stream.read()
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="ignore")

    for line in raw.splitlines():
        if not line.strip():
            continue
        _dispatch_line(line, log_type)
        processed += 1

    return processed
