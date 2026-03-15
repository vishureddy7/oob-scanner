import os
import re
from flask import Flask, request, render_template_string

app = Flask(__name__)

HTML_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Internal System Panel</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: Arial, sans-serif;
            background: #f0f2f5;
            display: flex;
            justify-content: center;
            padding: 40px 16px;
        }
        .wrapper { width: 100%; max-width: 520px; }
        h1 {
            font-size: 20px;
            color: #1a1a2e;
            margin-bottom: 6px;
        }
        .subtitle {
            font-size: 13px;
            color: #666;
            margin-bottom: 24px;
        }
        .card {
            background: #fff;
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 16px;
            box-shadow: 0 1px 4px rgba(0,0,0,0.08);
            border: 1px solid #e5e7eb;
        }
        .card-title {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 4px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .badge {
            font-size: 10px;
            padding: 2px 8px;
            border-radius: 20px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .badge-vuln  { background: #fde8e8; color: #c0392b; }
        .badge-safe  { background: #e8f5e9; color: #27ae60; }
        .card-desc {
            font-size: 12px;
            color: #888;
            margin-bottom: 16px;
        }
        input[type="text"] {
            width: 100%;
            padding: 9px 12px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 14px;
            margin-bottom: 12px;
            outline: none;
            transition: border 0.2s;
        }
        input[type="text"]:focus { border-color: #4f46e5; }
        button {
            padding: 9px 20px;
            background: #4f46e5;
            color: #fff;
            border: none;
            border-radius: 6px;
            font-size: 13px;
            cursor: pointer;
        }
        button:hover { background: #4338ca; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h1>Internal System Panel</h1>
        <p class="subtitle">Security Test Environment — OOB Scanner Lab</p>

        <!-- VULNERABLE FORM -->
        <div class="card">
            <div class="card-title">
                User ID Lookup
                <span class="badge badge-vuln">Vulnerable</span>
            </div>
            <p class="card-desc">Runs user input directly in a shell command. Injection point for testing.</p>
            <form action="/submit-data" method="POST">
                <input type="text" name="userid" placeholder="e.g. 1001">
                <button type="submit">Check Status</button>
            </form>
        </div>

        <!-- SAFE FORM -->
        <div class="card">
            <div class="card-title">
                Hostname Lookup
                <span class="badge badge-safe">Safe</span>
            </div>
            <p class="card-desc">Input is validated and sanitised before use. Not injectable.</p>
            <form action="/safe-lookup" method="POST">
                <input type="text" name="hostname" placeholder="e.g. server-01">
                <button type="submit">Lookup</button>
            </form>
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(HTML_PAGE)


@app.route('/submit-data', methods=['POST'])
def submit():
    user_input = request.form.get('userid', '')
    print(f"[*] Vulnerable endpoint received: {user_input}")

    # --- THE VULNERABILITY ---
    # User input dropped directly into a shell command — no sanitisation.
    # "; sleep 10 #"  →  echo Processing ID ; sleep 10 #...
    try:
        os.system(f"echo Processing ID {user_input}...")
    except Exception as e:
        print(f"Error: {e}")

    return f"Status: Processed ID {user_input}"


@app.route('/safe-lookup', methods=['POST'])
def safe_lookup():
    hostname = request.form.get('hostname', '')
    print(f"[*] Safe endpoint received: {hostname}")

    # --- SAFE: only allow alphanumeric, hyphens, dots ---
    # Anything that doesn't match is rejected entirely.
    if not re.fullmatch(r'[a-zA-Z0-9\-\.]+', hostname):
        return "Error: Invalid hostname. Only letters, numbers, hyphens and dots are allowed.", 400

    return f"Lookup result: {hostname} — OK"


if __name__ == "__main__":
    print("[!] Target Server is UP on http://127.0.0.1:9000")
    print("[!] Use Ctrl+C to shut down.")
    app.run(host='127.0.0.1', port=9000)