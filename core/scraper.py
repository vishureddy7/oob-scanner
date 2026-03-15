import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Input types that are not meaningful injection points
SKIP_TYPES = {"submit", "button", "reset", "image", "file", "checkbox", "radio"}


def extract_forms(url):
    """
    Fetches a URL and returns a list of injectable forms.

    Each form dict contains:
      - action : resolved POST/GET target URL
      - method : "get" or "post"
      - inputs : list of {"name": ..., "type": ...} for injectable fields only
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

    found_forms = []

    for form in soup.find_all("form"):
        action = form.attrs.get("action", "").strip()
        method = form.attrs.get("method", "get").lower()

        # Resolve relative action paths against the base URL
        post_url = urljoin(url, action) if action else url

        inputs = []
        for tag in form.find_all("input"):
            input_type = tag.attrs.get("type", "text").lower()
            input_name = tag.attrs.get("name", "").strip()

            # Skip non-injectable field types and unnamed inputs
            if not input_name or input_type in SKIP_TYPES:
                continue

            inputs.append({"name": input_name, "type": input_type})

        # Also grab <textarea> elements — often overlooked injection points
        for tag in form.find_all("textarea"):
            name = tag.attrs.get("name", "").strip()
            if name:
                inputs.append({"name": name, "type": "textarea"})

        if inputs:
            found_forms.append({
                "action": post_url,
                "method": method,
                "inputs": inputs,
            })
            print(f"  [+] Found form → {method.upper()} {post_url} ({len(inputs)} field(s))")

    if not found_forms:
        print("  [-] No injectable forms found.")

    return found_forms


# --- Standalone testing ---
if __name__ == "__main__":
    test_url = "http://127.0.0.1:9000/"
    forms = extract_forms(test_url)

    for i, f in enumerate(forms):
        print(f"\n[+] Form #{i + 1}")
        print(f"    Action : {f['action']}")
        print(f"    Method : {f['method'].upper()}")
        print(f"    Inputs : {f['inputs']}")