from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time
opts=Options(); opts.binary_location=r'C:\Program Files\Google\Chrome\Application\chrome.exe'; opts.add_argument('--headless=new'); opts.add_argument('--no-sandbox'); opts.add_argument('--window-size=1366,768'); opts.set_capability('goog:loggingPrefs', {'browser':'ALL','performance':'ALL'})
d=webdriver.Chrome(service=Service(r'C:\Users\aniru\.wdm\drivers\chromedriver\win64\154.0.8037.92\chromedriver-win64\chromedriver.exe'), options=opts)
try:
 d.get('http://127.0.0.1:8082/'); time.sleep(1)
 d.find_element(By.TAG_NAME,'body').send_keys(Keys.ENTER); time.sleep(.2)
 print('boot hidden after Enter:', 'hidden' in d.find_element(By.ID,'bootSequence').get_attribute('class'))
 print('landing horizontal overflow:', d.execute_script('return document.documentElement.scrollWidth > innerWidth'))
 d.get('http://127.0.0.1:8082/register'); time.sleep(.5)
 for id_, val in [('username','reprouser'),('email','repro@example.test'),('password','FakePass123456'),('confirmPassword','FakePass123456')]: d.find_element(By.ID,id_).send_keys(val)
 d.find_element(By.ID,'submitButton').click(); time.sleep(1)
 print('registration form post-click page:', d.current_url.split('?')[0], 'query has credentials:', '?' in d.current_url and 'password=' in d.current_url)
 d.get('http://127.0.0.1:8082/xss_lab.html'); time.sleep(.2)
 print('xss page URL:', d.current_url.split('?')[0])
 print('duplicate element IDs:', d.execute_script("return Array.from(document.querySelectorAll('[id]')).reduce((a,e)=>{a[e.id]=(a[e.id]||0)+1;return a},{})"))
 print('browser errors:', [e['message'] for e in d.get_log('browser') if e['level']=='SEVERE'][:5])
finally: d.quit()
