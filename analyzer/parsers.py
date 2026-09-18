"""
Parser cho 2 loại log phổ biến nhất khi làm blue-team/log analysis:

1. SSH auth log (/var/log/auth.log trên Debian/Ubuntu, /var/log/secure trên RHEL/CentOS)
   Ví dụ dòng log:
   Sep 16 20:15:01 host sshd[1234]: Failed password for root from 192.168.1.5 port 51234 ssh2
   Sep 16 20:15:05 host sshd[1234]: Failed password for invalid user admin from 192.168.1.5 port 51235 ssh2
   Sep 16 20:16:01 host sshd[1234]: Accepted password for dung from 192.168.1.10 port 51300 ssh2

2. Web access log (Apache/Nginx, Combined Log Format)
   Ví dụ dòng log:
   192.168.1.20 - - [16/Sep/2026:20:15:01 +0700] "GET /index.php?id=1' OR '1'='1 HTTP/1.1" 200 512 "-" "curl/7.68.0"
"""
import re
from urllib.parse import unquote

# --- SSH auth.log ---
_SSH_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)
_SSH_ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)
_SSH_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_ssh_line(line):
    """
    Trả về dict {"event": "failed_login"|"accepted_login"|"invalid_user", "ip":..., "user":...}
    hoặc None nếu dòng không khớp mẫu nào.
    """
    m = _SSH_FAILED_RE.search(line)
    if m:
        return {"event": "failed_login", "ip": m.group("ip"), "user": m.group("user")}

    m = _SSH_ACCEPTED_RE.search(line)
    if m:
        return {"event": "accepted_login", "ip": m.group("ip"), "user": m.group("user")}

    m = _SSH_INVALID_USER_RE.search(line)
    if m:
        return {"event": "invalid_user", "ip": m.group("ip"), "user": m.group("user")}

    return None


# --- Web access log (Combined Log Format) ---
_ACCESS_LOG_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

# Pattern nghi vấn trong path/query string
_SQLI_PATTERNS = re.compile(
    r"(\bunion\b.{0,20}\bselect\b|\bor\b\s+1\s*=\s*1|'\s*or\s*'|--\s|\bdrop\b\s+\btable\b|\bxp_cmdshell\b)",
    re.IGNORECASE,
)
_XSS_PATTERNS = re.compile(
    r"(<script|onerror\s*=|onload\s*=|javascript:|<img[^>]+onerror)",
    re.IGNORECASE,
)
_TRAVERSAL_PATTERNS = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|/windows/win.ini)", re.IGNORECASE)


def parse_access_line(line):
    """
    Trả về dict {"ip":..., "method":..., "path":..., "status": int, "flags": [...]}
    hoặc None nếu dòng không khớp Combined Log Format.
    'flags' liệt kê các loại payload nghi vấn tìm thấy trong path (có thể rỗng).
    """
    m = _ACCESS_LOG_RE.search(line)
    if not m:
        return None

    path = m.group("path")
    # Decode URL trước khi match pattern, vì payload thật thường bị encode
    # (vd %27 = ', %20 = space) -> nếu không decode sẽ bỏ sót injection.
    decoded_path = unquote(path)
    flags = []
    if _SQLI_PATTERNS.search(decoded_path):
        flags.append("sqli")
    if _XSS_PATTERNS.search(decoded_path):
        flags.append("xss")
    if _TRAVERSAL_PATTERNS.search(decoded_path):
        flags.append("path_traversal")

    try:
        status = int(m.group("status"))
    except ValueError:
        status = 0

    return {
        "ip": m.group("ip"),
        "method": m.group("method"),
        "path": path,
        "status": status,
        "flags": flags,
    }
