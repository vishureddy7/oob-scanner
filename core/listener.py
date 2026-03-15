import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from queue import Queue


def _make_handler(oob_queue: Queue):
    """Factory so the handler class can reference the shared queue."""

    class OOBHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path

            print("\n" + "=" * 55)
            print(f"[!!!] ALERT: OOB CALLBACK RECEIVED [!!!]")
            print(f"  Source : {self.client_address[0]}")
            print(f"  Path   : {path}")
            print("=" * 55 + "\n")

            # Signal the orchestrator — it reads this from the queue
            oob_queue.put(path)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Logged.")

        def log_message(self, format, *args):
            # Suppress default access-log noise
            return

    return OOBHandler


def start_listener(ip: str, port: int, oob_queue: Queue = None):
    """
    Start the OOB HTTP listener.

    Args:
        ip        : IP address to bind to.
        port      : Port to listen on.
        oob_queue : Optional shared Queue. Callback paths are put() here
                    so the orchestrator can detect OOB hits in real time.
                    If None, a local queue is created (standalone/testing mode).
    """
    if oob_queue is None:
        oob_queue = Queue()

    handler = _make_handler(oob_queue)
    server  = HTTPServer((ip, port), handler)
    print(f"[*] Phase 1: OOB Listener active on http://{ip}:{port}")
    server.serve_forever()


# --- Standalone testing ---
if __name__ == "__main__":
    MY_IP   = "127.0.0.1"
    MY_PORT = 8000

    test_queue = Queue()

    listener_thread = threading.Thread(
        target=start_listener,
        args=(MY_IP, MY_PORT, test_queue),
        daemon=True
    )
    listener_thread.start()

    print(f"[*] Listener is active. Test it with:")
    print(f"    curl http://{MY_IP}:{MY_PORT}/test_ping")
    print(f"[*] Waiting for callbacks (Ctrl+C to stop)...")

    try:
        while True:
            try:
                hit = test_queue.get(timeout=1)
                print(f"[+] Queue received: {hit}")
            except Exception:
                pass
    except KeyboardInterrupt:
        print("\n[*] Shutting down listener.")