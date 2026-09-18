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
    state.watching = True
    state.watched_path = path
    state.watched_log_type = log_type

    try:
        with open(path, "r", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
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
