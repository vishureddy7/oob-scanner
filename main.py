import threading
import time
import requests
import sys
import json
import socket
from queue import Queue, Empty
from core.listener import start_listener
from core.scraper import extract_forms
from core.engine import generate_payloads

GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RESET  = "\033[0m"

DEFAULT_LPORT = 8000


def get_local_ip():
    """Auto-detect the outbound local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def run_orchestrator(target_url, lhost, lport):
    print(f"\n[*] {CYAN}Initializing OOB Orchestrator...{RESET}")
    print(f"[*] Listener will bind on {lhost}:{lport}")

    # Shared queue — listener puts callback paths here; orchestrator reads them
    oob_queue = Queue()

    # Phase 1: Start background listener
    threading.Thread(
        target=start_listener,
        args=(lhost, lport, oob_queue),
        daemon=True
    ).start()
    time.sleep(1)

    # Phase 2: Scrape target
    forms = extract_forms(target_url)
    if not forms:
        print(f"{RED}[-] No attack surface found on target.{RESET}")
        return

    # Phase 3: Generate tagged payloads  (payload, type, expected_delay_secs)
    payloads = generate_payloads(lhost, lport)

    # Measure baseline response time to reduce false positives
    print(f"\n[*] {CYAN}Measuring baseline response time...{RESET}")
    try:
        baseline = requests.get(target_url, timeout=10).elapsed.total_seconds()
        print(f"[*] Baseline: {baseline:.2f}s")
    except Exception:
        baseline = 0.0

    findings = []

    # Phase 4: Execution loop
    for form in forms:
        action  = form["action"]
        method  = form["method"]

        for inp in form["inputs"]:
            print(f"\n[*] Auditing field: {GREEN}'{inp['name']}'{RESET} at {action}")

            for payload, ptype, expected_delay in payloads:
                data = {inp["name"]: f"test{payload}"}
                print(f"  [>] Firing ({ptype}): {payload.strip()}")

                start_clock = time.time()
                try:
                    timeout = expected_delay + 3 if expected_delay else 12
                    if method == "post":
                        requests.post(action, data=data, timeout=timeout)
                    else:
                        requests.get(action, params=data, timeout=timeout)
                except requests.exceptions.ReadTimeout:
                    pass
                except Exception as e:
                    print(f"  {RED}[!] Network Error: {e}{RESET}")
                    continue

                duration = time.time() - start_clock

                # --- Time-based detection ---
                if ptype == "time_based":
                    # Only flag if delay is significantly above baseline
                    if duration >= (baseline + expected_delay - 1):
                        finding = {
                            "type":    "TIME-BASED",
                            "url":     action,
                            "field":   inp["name"],
                            "payload": payload.strip(),
                            "delay":   round(duration, 2),
                        }
                        findings.append(finding)
                        print(f"\n  {RED}[!!!] VULNERABILITY CONFIRMED: TIME-BASED INJECTION [!!!]{RESET}")
                        print(f"  [+] Field '{inp['name']}' responded in {duration:.2f}s (baseline: {baseline:.2f}s)\n")

                # --- OOB detection: check queue for callback ---
                if ptype == "oob":
                    time.sleep(2)   # Give the server time to make the callback
                    try:
                        hit_path = oob_queue.get(timeout=0.1)
                        finding = {
                            "type":     "OOB-CALLBACK",
                            "url":      action,
                            "field":    inp["name"],
                            "payload":  payload.strip(),
                            "callback": hit_path,
                        }
                        findings.append(finding)
                        print(f"\n  {RED}[!!!] VULNERABILITY CONFIRMED: OOB CALLBACK RECEIVED [!!!]{RESET}")
                        print(f"  [+] Callback path: {hit_path}\n")
                    except Empty:
                        pass   # No callback — not vulnerable to this payload

    # --- Summary ---
    print(f"\n{'='*55}")
    if findings:
        print(f"{RED}[!!!] {len(findings)} VULNERABILITY/IES CONFIRMED{RESET}")
        for i, f in enumerate(findings, 1):
            print(f"\n  [{i}] Type    : {f['type']}")
            print(f"       URL     : {f['url']}")
            print(f"       Field   : {f['field']}")
            print(f"       Payload : {f['payload']}")
            if "delay" in f:
                print(f"       Delay   : {f['delay']}s")
            if "callback" in f:
                print(f"       Callback: {f['callback']}")
    else:
        print(f"{GREEN}[+] No vulnerabilities detected.{RESET}")

    # --- Save report ---
    report = {
        "target":   target_url,
        "lhost":    lhost,
        "lport":    lport,
        "baseline": round(baseline, 2),
        "findings": findings,
    }
    with open("report.json", "w") as fh:
        json.dump(report, fh, indent=2)

    print(f"\n[*] {GREEN}Report saved to report.json{RESET}")
    print(f"[*] {GREEN}Orchestration complete.{RESET}")
    time.sleep(1)


if __name__ == "__main__":
    print(f"{CYAN}{'='*55}")
    print(f"      OOB Command Injection Scanner")
    print(f"{'='*55}{RESET}")

    try:
        target = input("[?] Enter Target URL (e.g. http://127.0.0.1:9000): ").strip()
        if not target:
            print(f"{RED}[!] No URL provided. Exiting.{RESET}")
            sys.exit(1)

        lhost = get_local_ip()
        lport = DEFAULT_LPORT

        run_orchestrator(target, lhost, lport)

    except KeyboardInterrupt:
        print(f"\n{RED}[!] User interrupted. Exiting.{RESET}")