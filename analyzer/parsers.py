import re
from urllib.parse import unquote
 

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
    Returns a dict {"event": "failed_login"|"accepted_login"|"invalid_user", "ip":..., "user":...}
    or None if the line doesn't match any known pattern.
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
 
 

_ACCESS_LOG_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)
 

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
    Returns a dict {"ip":..., "method":..., "path":..., "status": int, "flags": [...]}
    or None if the line doesn't match the Combined Log Format.
    'flags' lists the suspicious payload types found in the path (may be empty).
    """
    m = _ACCESS_LOG_RE.search(line)
    if not m:
        return None
 
    path = m.group("path")
  
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
 
