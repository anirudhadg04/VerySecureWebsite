import os
os.environ['DEBUG']='false'; os.environ['DATABASE_URL']='sqlite:///./.browser-audit.db'
from app.database import SessionLocal
from app.models import User
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
u=SessionLocal().query(User).filter(User.username.like('audit_alice%')).order_by(User.id.desc()).first().username
q=Options(); q.binary_location=r'C:\Program Files\Google\Chrome\Application\chrome.exe'; q.add_argument('--headless=new'); q.add_argument('--no-sandbox'); q.add_argument('--window-size=390,844')
d=webdriver.Chrome(service=Service(r'C:\Users\aniru\.wdm\drivers\chromedriver\win64\154.0.8037.92\chromedriver-win64\chromedriver.exe'),options=q)
try:
 d.get('http://127.0.0.1:8082/login'); d.find_element(By.ID,'username').send_keys(u); d.find_element(By.ID,'password').send_keys('TestPass12345Z'); d.find_element(By.ID,'submitButton').click(); WebDriverWait(d,10).until(lambda x:'/labs' in x.current_url); d.set_window_size(390,844); d.get('http://127.0.0.1:8082/labs'); WebDriverWait(d,10).until(lambda x:len(x.find_elements(By.CSS_SELECTOR,'.mission-card'))==3)
 print('username',u,'size',d.execute_script('return [innerWidth,document.documentElement.scrollWidth]'))
 print(d.execute_script("return [...document.querySelectorAll('body *')].map(e=>({tag:e.tagName,id:e.id,cls:typeof e.className==='string'?e.className:'',left:Math.round(e.getBoundingClientRect().left),right:Math.round(e.getBoundingClientRect().right),width:Math.round(e.getBoundingClientRect().width),text:(e.innerText||'').slice(0,45)})).filter(x=>x.right>innerWidth+1&&x.width>5).sort((a,b)=>b.right-a.right).slice(0,20)"))
 d.save_screenshot('.dashboard-mobile.png')
finally:d.quit()
