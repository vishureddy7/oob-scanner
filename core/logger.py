import json
import math
import time
from datetime import datetime
from collections import defaultdict

# Parameter names that are commonly associated with command injection
SUSPICIOUS_KEYWORDS = {
    "cmd", "exec", "execute", "command", "shell", "run", "system",
    "ping", "query", "input", "process", "launch", "invoke",
    "call", "eval", "code", "script", "args", "arg", "param",
}


def _shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Higher entropy = more random/complex value.
    Low entropy param names (like 'cmd') are more suspicious.
    """
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _keyword_flag(param_name: str) -> str:
    """Return 'command-like' if name matches suspicious keywords, else 'normal'."""
    name = param_name.lower().strip()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in name:
            return "command-like"
    return "normal"


def _endpoint_depth(url: str) -> int:
    """Count path segments — e.g. /api/v1/run = depth 3."""
    try:
        from urllib.parse import urlparse
        path = urlparse(url).path.strip("/")
        return len([p for p in path.split("/") if p]) if path else 0
    except Exception:
        return 0


def _check_reflection(response_text: str, payload: str) -> dict:
    """Check if the injected payload appears in the HTTP response body."""
    if not response_text or not payload:
        return {"input_reflection": False, "reflection_count": 0, "reflection_position": "none"}

    # Use a safe substring of the payload to check reflection
    probe = payload.strip()[:20]
    count = response_text.count(probe)
    return {
        "input_reflection":    count > 0,
        "reflection_count":    count,
        "reflection_position": "body" if count > 0 else "none",
    }


def _parse_server_info(headers: dict) -> dict:
    """
    Extract server/stack info from HTTP response headers.
    No 3rd party tools — pure header reading.
    """
    server    = headers.get("Server", "unknown")
    powered   = headers.get("X-Powered-By", "unknown")
    ct        = headers.get("Content-Type", "unknown")

    # Guess OS from Server header
    os_guess = "unknown"
    sl = server.lower()
    if "win" in sl or "iis" in sl:
        os_guess = "windows"
    elif "ubuntu" in sl or "debian" in sl or "centos" in sl or "linux" in sl:
        os_guess = "linux"
    elif "nginx" in sl or "apache" in sl or "gunicorn" in sl or "uwsgi" in sl:
        os_guess = "linux (likely)"

    # Guess language from X-Powered-By
    lang = "unknown"
    pl = powered.lower()
    if "php" in pl:   lang = "php"
    elif "asp" in pl: lang = "asp.net"
    elif "python" in pl or "flask" in pl or "django" in pl: lang = "python"
    elif "ruby" in pl or "rails" in pl: lang = "ruby"
    elif "node" in pl or "express" in pl: lang = "node.js"
    elif "java" in pl or "tomcat" in pl: lang = "java"

    return {
        "web_server":    server,
        "x_powered_by":  powered,
        "content_type":  ct,
        "os_guess":      os_guess,
        "language_guess": lang,
        "header_count":  len(headers),
    }


class ScanLogger:
    """
    Builds a structured dataset row-by-row as the scanner runs.
    Each row = one (endpoint, parameter, payload) combination.
    Saves to scan_results.json at the end.
    """

    def __init__(self, target_url: str, lhost: str, baseline: float):
        self.target_url  = target_url
        self.lhost       = lhost
        self.baseline    = baseline
        self.scan_start  = datetime.utcnow().isoformat()
        self.rows        = []
        self._attack_id  = 0
        self._server_info = {}

    def set_server_info(self, headers: dict):
        """Call once after the baseline request to capture server headers."""
        self._server_info = _parse_server_info(dict(headers))

    def log_attempt(
        self,
        *,
        url: str,
        method: str,
        field: str,
        field_type: str,
        param_count: int,
        payload: str,
        payload_type: str,
        canary_id: str,
        attempt_number: int,
        status_code: int,
        response_time: float,
        response_size: int,
        response_headers: dict,
        response_text: str,
        callback_received: bool,
        callback_protocol: str,   # "http" / "dns" / "none"
        callback_path: str,
        callback_timestamp: str,
        request_timestamp: str,
        vulnerable: int,           # 1 = confirmed, 0 = not confirmed
    ):
        self._attack_id += 1

        reflection = _check_reflection(response_text, payload)
        server_info = _parse_server_info(dict(response_headers)) if response_headers else self._server_info

        # Callback delay in seconds
        callback_delay = None
        if callback_received and callback_timestamp and request_timestamp:
            try:
                fmt = "%Y-%m-%dT%H:%M:%S.%f"
                t1  = datetime.strptime(request_timestamp[:26], fmt)
                t2  = datetime.strptime(callback_timestamp[:26], fmt)
                callback_delay = round((t2 - t1).total_seconds(), 3)
            except Exception:
                callback_delay = None

        row = {
            # ── Attack metadata ──────────────────────────────────────
            "attack_id":           self._attack_id,
            "attempt_number":      attempt_number,

            # ── Endpoint info ────────────────────────────────────────
            "url":                 url,
            "method":              method.upper(),
            "endpoint_depth":      _endpoint_depth(url),

            # ── Parameter metadata ───────────────────────────────────
            "parameter_name":      field,
            "parameter_type":      field_type,
            "parameter_length":    len(field),
            "parameter_entropy":   round(_shannon_entropy(field), 4),
            "keyword_flag":        _keyword_flag(field),
            "param_count":         param_count,

            # ── Payload metadata ─────────────────────────────────────
            "payload":             payload.strip(),
            "payload_type":        payload_type,
            "payload_length":      len(payload.strip()),
            "payload_category":    "time_based" if payload_type == "time_based" else "oob",
            "canary_id":           canary_id,

            # ── HTTP response behaviour ──────────────────────────────
            "status_code":         status_code,
            "response_time_ms":    round(response_time * 1000, 2) if response_time else None,
            "response_size_bytes": response_size,
            "redirect_flag":       status_code in (301, 302, 307, 308) if status_code else False,

            # ── Reflection signals ───────────────────────────────────
            **reflection,

            # ── Server/stack info (from headers — no 3rd party) ─────
            **server_info,

            # ── Timing behaviour ─────────────────────────────────────
            "baseline_ms":         round(self.baseline * 1000, 2),
            "request_timestamp":   request_timestamp,
            "callback_timestamp":  callback_timestamp,
            "callback_delay_secs": callback_delay,

            # ── Callback interaction ─────────────────────────────────
            "callback_received":   callback_received,
            "callback_protocol":   callback_protocol,
            "callback_path":       callback_path,

            # ── Ground truth label ───────────────────────────────────
            "vulnerable":          vulnerable,
        }

        self.rows.append(row)

    def save(self, path="scan_results.json"):
        """Save the full dataset to JSON."""
        output = {
            "meta": {
                "target":     self.target_url,
                "lhost":      self.lhost,
                "baseline_ms": round(self.baseline * 1000, 2),
                "scan_start": self.scan_start,
                "scan_end":   datetime.utcnow().isoformat(),
                "total_rows": len(self.rows),
                "vulnerable_count": sum(r["vulnerable"] for r in self.rows),
            },
            "server_info": self._server_info,
            "dataset":     self.rows,
        }
        with open(path, "w") as f:
            json.dump(output, f, indent=2)
        print(f"[*] Dataset saved → {path}  ({len(self.rows)} rows)")