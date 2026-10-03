"""Browser-level XSS validation using selenium + Chrome."""
import subprocess
import sys
import time
import os

# Start the server
print("=== Starting server on port 8000 ===")
proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
    cwd=os.path.dirname(os.path.abspath(".")),
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

# Wait for server to start
started = False
for _ in range(30):
    time.sleep(1)
    try:
        import urllib.request
        urllib.request.urlopen("http://127.0.0.1:8000/api/health", timeout=2)
        started = True
        break
    except Exception:
        pass

if not started:
    print("ERROR: server did not start")
    proc.terminate()
    sys.exit(1)

print("Server is ready")

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

options = Options()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--disable-gpu")
options.add_argument("--window-size=1920,1080")

print("\n=== Launching Chrome headless ===")
service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service, options=options)
driver.implicitly_wait(5)

BASE = "http://127.0.0.1:8000"
payload = "<script>alert('XSS_PROOF')</script>"

try:
    # --- VULNERABLE endpoint ---
    print("\n=== VULNERABLE: GET /xss with payload ===")
    driver.get(f"{BASE}/xss?username={payload}")
    # The payload executes alert() -> handle the unexpected alert as proof of execution
    try:
        alert = driver.switch_to.alert
        alert_text = alert.text
        alert.accept()
        print(f"  [VULNERABLE] Alert executed in browser: '{alert_text}' -> payload script ran!")
    except Exception:
        alert_text = None
    proof = driver.execute_script("return document.getElementById('xss-proof-executed') === true;")
    page_content = driver.page_source
    raw_script = "<script>alert('XSS_PROOF')</script>" in page_content
    escaped_script = "&lt;script&gt;alert('XSS_PROOF')&lt;/script&gt;" in page_content
    print(f"  DOM marker executed (script injected by payload ran): {proof}")
    print(f"  raw <script> present in HTML: {raw_script}")
    print(f"  escaped &lt;script&gt; in HTML: {escaped_script}")
    if (alert_text == "XSS_PROOF" or proof) and raw_script and not escaped_script:
        print("  [VULNERABLE] Confirmed: payload reflected raw and executed in browser")
    else:
        print("  [UNEXPECTED] Vulnerable behavior not as expected")

    # --- SECURE endpoint ---
    print("\n=== SECURE: GET /secure/xss with payload ===")
    driver.get(f"{BASE}/secure/xss?username={payload}")
    # The secure page writes DOM marker 'xss-secure-rendered' regardless, but the
    # USER payload is encoded, so the payload's script does NOT execute.
    payload_executed = driver.execute_script(
        "return !!document.querySelector('script').innerHTML.match(/XSS_PROOF/);"
    ) if driver.execute_script("return document.getElementsByTagName('script').length;") > 0 else False
    page_source = driver.page_source
    raw_script2 = "<script>alert('XSS_PROOF')</script>" in page_source
    escaped_script2 = "&lt;script&gt;alert('XSS_PROOF')&lt;/script&gt;" in page_source
    print(f"  payload script executed in DOM: {payload_executed}")
    print(f"  raw <script> in HTML: {raw_script2}")
    print(f"  escaped &lt;script&gt; in HTML: {escaped_script2}")
    # Note: the page's own <script> tag contains xss-secure-rendered marker, so we check
    # that the USER payload was encoded, not executed.
    if escaped_script2 and not raw_script2:
        print("  [SECURE] Confirmed: payload HTML-encoded, not executed")
    else:
        print("  [UNEXPECTED] Secure behavior not as expected")

    # --- Payload with quotes/apostrophes (script context attempt) ---
    print("\n=== Robustness: apostrophe/quote payload ===")
    payload2 = "\"><script>alert('XSS_PROOF2')</script><\""
    driver.get(f"{BASE}/xss?username={payload2}")
    content2 = driver.page_source
    print(f"  raw script present: {'<script>' in content2}")
    print(f"  raw &lt; present: {'&lt;script&gt;' in content2}")

    print("\n=== Browser validation complete ===")
finally:
    driver.quit()
    proc.terminate()
    proc.wait()
    print("Server stopped")
