import csv
import io
import threading
import time
from datetime import datetime

from flask import Flask, render_template, request, jsonify, Response

from analyzer import state
from analyzer.watcher import watch_file, process_file_batch
from analyzer.detectors import tick_event_history

app = Flask(__name__)


def _history_ticker():
    while True:
        time.sleep(1)
        tick_event_history()


@app.route("/")
def index():
    return render_template("index.html")


# ---------- Chế độ 1: theo dõi real-time (tail -f) ----------
@app.route("/watch/start", methods=["POST"])
def watch_start():
    data = request.get_json(silent=True) or {}
    path = data.get("path")
    log_type = data.get("log_type")

    if not path or log_type not in ("ssh", "web"):
        return jsonify({"error": "Cần 'path' và 'log_type' (ssh|web)"}), 400

    if state.watching:
        return jsonify({"error": "Đang theo dõi 1 file khác, hãy Stop trước"}), 400

    t = threading.Thread(target=_safe_watch, args=(path, log_type), daemon=True)
    t.start()
    # đợi 1 chút để bắt lỗi FileNotFound sớm, không bắt buộc
    time.sleep(0.3)

    return jsonify({"status": "watching", "path": path, "log_type": log_type})


def _safe_watch(path, log_type):
    try:
        watch_file(path, log_type)
    except FileNotFoundError:
        with state.lock:
            state.alerts.insert(0, {
                "ip": "-", "rule": "System", "severity": "high",
                "detail": f"Không tìm thấy file log: {path}",
                "time": datetime.now().strftime("%H:%M:%S"),
            })


@app.route("/watch/stop", methods=["POST"])
def watch_stop():
    state.watching = False
    return jsonify({"status": "stopped"})


# ---------- Chế độ 2: upload file log có sẵn, phân tích batch ----------
@app.route("/analyze", methods=["POST"])
def analyze_upload():
    log_type = request.form.get("log_type")
    if log_type not in ("ssh", "web"):
        return jsonify({"error": "Thiếu hoặc sai 'log_type' (ssh|web)"}), 400

    if "logfile" not in request.files:
        return jsonify({"error": "Thiếu file 'logfile'"}), 400

    f = request.files["logfile"]
    processed = process_file_batch(f.stream, log_type)

    return jsonify({"status": "analyzed", "lines_processed": processed, "log_type": log_type})


@app.route("/clear", methods=["POST"])
def clear():
    state.reset()
    return jsonify({"status": "cleared"})


@app.route("/alerts")
def alerts():
    with state.lock:
        return jsonify(state.alerts)


@app.route("/stats")
def stats():
    with state.lock:
        return jsonify({
            "watching": state.watching,
            "watched_path": state.watched_path,
            "watched_log_type": state.watched_log_type,
            "line_count": state.line_count,
            "history": state.event_history,
            "alert_count": len(state.alerts),
        })


@app.route("/export")
def export_alerts():
    fmt = request.args.get("format", "txt").lower()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    with state.lock:
        alerts_snapshot = list(state.alerts)
        line_count = state.line_count

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ip", "rule", "severity", "detail", "time"])
        for a in alerts_snapshot:
            writer.writerow([a.get("ip"), a.get("rule"), a.get("severity"), a.get("detail"), a.get("time")])
        filename = f"log_alerts_{ts}.csv"
        return Response(buf.getvalue(), mimetype="text/csv",
                         headers={"Content-Disposition": f"attachment; filename={filename}"})

    lines = [
        "=" * 60,
        "Log Analyzer - Alert Export",
        f"Exported at    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Lines processed: {line_count}",
        f"Total alerts   : {len(alerts_snapshot)}",
        "=" * 60,
        "",
    ]
    if not alerts_snapshot:
        lines.append("(Không có cảnh báo nào được ghi nhận trong phiên này)")
    else:
        for i, a in enumerate(alerts_snapshot, 1):
            lines.append(
                f"[{i}] {a.get('time')}  |  IP: {a.get('ip')}  |  Rule: {a.get('rule')}  |  "
                f"Severity: {str(a.get('severity')).upper()}  |  {a.get('detail')}"
            )

    filename = f"log_alerts_{ts}.txt"
    return Response("\n".join(lines), mimetype="text/plain",
                     headers={"Content-Disposition": f"attachment; filename={filename}"})


if __name__ == "__main__":
    ticker = threading.Thread(target=_history_ticker, daemon=True)
    ticker.start()
    app.run(debug=True, port=5001)
