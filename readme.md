# OOB-Orchestrator: Autonomous Command Injection Scanner

A Python-based security tool that detects **Blind Command Injection** vulnerabilities using Out-of-Band (OOB) callbacks and time-based analysis.

> **Legal notice:** Only use this tool against systems you own or have explicit written permission to test.

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

---

## Detection Methods

| Method | How it works |
|---|---|
| **Time-based** | Injects `sleep`/`ping` commands; measures response delay vs. baseline |
| **OOB callback** | Forces the target to `curl`/`wget` back to our listener |
| **Data exfiltration** | Sends `$(whoami)` (plain & Base64) in the callback URL |

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

You will be prompted for:
- **Target URL** — e.g. `http://127.0.0.1:9000`
- **LHOST** — IP the target can reach for OOB callbacks (auto-detected)
- **LPORT** — listener port (default: 8000)

Findings are printed to stdout and saved to `report.json`.

---

## Output

```
[!!!] VULNERABILITY CONFIRMED: TIME-BASED INJECTION [!!!]
      Field 'userid' responded in 10.23s (baseline: 0.04s)

[!!!] VULNERABILITY CONFIRMED: OOB CALLBACK RECEIVED [!!!]
      Callback path: /EXFIL/cm9vdA==
```

A `report.json` file is written after each run with all confirmed findings.

---

## Project Structure

```
oob-scanner/
├── main.py              Orchestrator entry point
├── vulnerable_app.py    Self-contained lab target (Flask)
├── requirements.txt
├── report.json          Generated after each scan
└── core/
    ├── __init__.py
    ├── listener.py      OOB HTTP listener
    ├── scraper.py       Form/input discovery
    └── engine.py        Payload engine
``` 