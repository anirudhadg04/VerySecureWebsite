"""Browser-level XSS validation using selenium + Chrome."""
import subprocess
import sys
import time
import os
import urllib.parse

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
    driver.get(f"{BASE}/xss?username={urllib.parse.quote(payload)}")
    # The payload executes alert() -> handle the unexpected alert as proof of execution
    try:
        alert = driver.switch_to.alert
        alert_text = alert.text
        alert.accept()
        # Wait for remaining scripts to execute after alert dismissal
        time.sleep(0.5)
        print(f"  [VULNERABLE] Alert executed in browser: '{alert_text}' -> payload script ran!")
    except Exception:
        alert_text = None
    proof = driver.execute_script("return window.xssProofExecuted === true;")
    print(f"  DOM marker executed (window.xssProofExecuted): {proof}")
    print(f"  alert text: {alert_text}")
    if alert_text == "XSS_PROOF" or proof:
        print("  [VULNERABLE] Confirmed: payload executed in browser")
    else:
        print("  [UNEXPECTED] Vulnerable behavior not as expected")

    # --- SECURE endpoint ---
    print("\n=== SECURE: GET /secure/xss with payload ===")
    driver.get(f"{BASE}/secure/xss?username={urllib.parse.quote(payload)}")
    # The secure page sets window.xssSecureRendered regardless of payload,
    # but the USER payload is encoded, so the payload's script does NOT execute.
    time.sleep(0.5)  # Wait for page to fully load
    payload_executed = driver.execute_script("return window.xssProofExecuted === true;")
    secure_rendered = driver.execute_script("return window.xssSecureRendered === true;")
    print(f"  payload script executed in DOM: {payload_executed}")
    print(f"  secure page rendered marker: {secure_rendered}")
    # Note: the page's own <script> tag sets window.xssSecureRendered, but the
    # USER payload is escaped and does not execute.
    if not payload_executed and secure_rendered:
        print("  [SECURE] Confirmed: payload HTML-encoded, not executed")
    else:
        print("  [UNEXPECTED] Secure behavior not as expected")

    # --- Payload with quotes/apostrophes (script context attempt) ---
    print("\n=== Robustness: apostrophe/quote payload ===")
    payload2 = "\"><script>alert('XSS_PROOF2')</script><\""
    driver.get(f"{BASE}/xss?username={urllib.parse.quote(payload2)}")
    # Handle the alert if it appears
    try:
        alert = driver.switch_to.alert
        alert_text = alert.text
        alert.accept()
        time.sleep(0.3)
        print(f"  alert executed: {alert_text}")
    except Exception:
        pass
    content2 = driver.page_source
    print(f"  raw script present: {'<script>' in content2}")
    print(f"  raw &lt; present: {'&lt;script&gt;' in content2}")

    print("\n=== Browser validation complete ===")
finally:
    driver.quit()
    proc.terminate()
    proc.wait()
    print("Server stopped")
