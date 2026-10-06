from pathlib import Path
p=Path('.pytest-browser-e2e.py')
s=p.read_text()
s=s.replace("alice.find_element(By.CSS_SELECTOR,'#view-record-detail button').click()", "alice.find_element(By.XPATH, \"//button[normalize-space()='COMPARE WITH SECURE VAULT']\").click()")
p.write_text(s)
