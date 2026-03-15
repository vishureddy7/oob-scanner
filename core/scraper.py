import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

# Input types that are not meaningful injection points
SKIP_TYPES = {"submit", "button", "reset", "image", "file", "checkbox", "radio"}


def extract_forms(url):
    """
    Fetches a URL and returns a list of injectable attack surfaces:
      - HTML form fields (POST and GET)
      - URL query parameters (e.g. ?q=test&id=1)

    Each item dict contains:
      - action : resolved target URL
      - method : "get" or "post"
      - inputs : list of {"name": ..., "type": ...}
    """
    print(f"[*] Phase 2: Scanning {url} for inputs...")

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
    except requests.exceptions.HTTPError as e:
        print(f"[-] HTTP error fetching URL: {e}")
        return []
    except requests.exceptions.ConnectionError:
        print(f"[-] Could not connect to {url}. Is the target running?")
        return []
    except Exception as e:
        print(f"[-] Error fetching URL: {e}")
        return []

    found = []

    # ── URL query parameters ──────────────────────────────────────────
    # e.g. http://site.com/search?q=test&id=1  →  scan q and id
    parsed     = urlparse(url)
    url_params = parse_qs(parsed.query)

    if url_params:
        inputs = [{"name": k, "type": "queryparam"} for k in url_params]
        found.append({
            "action": url,
            "method": "get",
            "inputs": inputs,
        })
        print(f"  [+] Found {len(inputs)} URL query param(s) → GET {url}")

    # ── HTML forms ───────────────────────────────────────────────────
    for form in soup.find_all("form"):
        action = form.attrs.get("action", "").strip()
        method = form.attrs.get("method", "get").lower()
        post_url = urljoin(url, action) if action else url

        inputs = []

        for tag in form.find_all("input"):
            input_type = tag.attrs.get("type", "text").lower()
            input_name = tag.attrs.get("name", "").strip()
            if not input_name or input_type in SKIP_TYPES:
                continue
            inputs.append({"name": input_name, "type": input_type})

        # <textarea> elements are commonly missed injection points
        for tag in form.find_all("textarea"):
            name = tag.attrs.get("name", "").strip()
            if name:
                inputs.append({"name": name, "type": "textarea"})

        if inputs:
            found.append({
                "action": post_url,
                "method": method,
                "inputs": inputs,
            })
            print(f"  [+] Found form → {method.upper()} {post_url} ({len(inputs)} field(s))")

    if not found:
        print("  [-] No injectable inputs found.")

    return found


# ── Standalone testing ────────────────────────────────────────────────
if __name__ == "__main__":
    test_url = "http://127.0.0.1:9000/"
    forms = extract_forms(test_url)

    for i, f in enumerate(forms):
        print(f"\n[+] Surface #{i + 1}")
        print(f"    Action : {f['action']}")
        print(f"    Method : {f['method'].upper()}")
        print(f"    Inputs : {f['inputs']}")