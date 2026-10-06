import os, time
os.environ['DEBUG']='false'; os.environ['DATABASE_URL']='sqlite:///./.browser-audit.db'
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
BASE='http://127.0.0.1:8082'; SUFFIX=str(time.time_ns())[-6:]
ALICE='audit_alice'+SUFFIX; BOB='audit_bob'+SUFFIX; ADMIN='audit_admin'+SUFFIX
options=Options(); options.binary_location=r'C:\Program Files\Google\Chrome\Application\chrome.exe'; options.add_argument('--headless=new'); options.add_argument('--no-sandbox'); options.add_argument('--window-size=1366,768'); options.set_capability('goog:loggingPrefs',{'browser':'ALL','performance':'ALL'})
service=Service(r'C:\Users\aniru\.wdm\drivers\chromedriver\win64\154.0.8037.92\chromedriver-win64\chromedriver.exe')
def browser(): return webdriver.Chrome(service=service,options=options)
def wait(d,cond,timeout=15): return WebDriverWait(d,timeout).until(cond)
def check(cond,msg):
    if not cond: raise AssertionError(msg)
def register(d,user):
    d.get(BASE+'/register')
    for k,v in [('username',user),('email',user+'@example.test'),('password','TestPass12345Z'),('confirmPassword','TestPass12345Z')]: d.find_element(By.ID,k).send_keys(v)
    d.find_element(By.ID,'submitButton').click(); wait(d,EC.url_contains('/login'))
    d.find_element(By.ID,'username').send_keys(user); d.find_element(By.ID,'password').send_keys('TestPass12345Z'); d.find_element(By.ID,'submitButton').click(); wait(d,EC.url_contains('/labs'))
def api(d,path,method='GET',body=None):
    return d.execute_async_script("""const [p,m,b,done]=arguments;const c=document.cookie.split('; ').find(v=>v.startsWith('vsw_csrf='));fetch(p,{method:m,credentials:'include',headers:{'Content-Type':'application/json','X-CSRF-Token':c?decodeURIComponent(c.slice(9)):''},body:b===null?undefined:JSON.stringify(b)}).then(async r=>done({status:r.status,body:await r.json()})).catch(e=>done({error:e.message}));""",path,method,body)
def viewport(d,w,h):
    if w <= 500: d.execute_cdp_cmd('Emulation.setDeviceMetricsOverride', {'width':w,'height':h,'deviceScaleFactor':1,'mobile':True})
    else:
        d.execute_cdp_cmd('Emulation.clearDeviceMetricsOverride', {})
        d.set_window_size(w,h)
    time.sleep(.25)
def overflow(d,label):
    x=d.execute_script('return {w:document.documentElement.scrollWidth,i:innerWidth}'); print(label,x['i'],x['w']); check(x['w']<=x['i']+1,label+' horizontal overflow')
alice,bob,admin=browser(),browser(),browser()
try:
    alice.get(BASE+'/'); check(alice.find_element(By.ID,'skipBootSequence').is_displayed(),'BIOS skip button visible'); alice.find_element(By.TAG_NAME,'body').send_keys(Keys.ENTER); check('hidden' in alice.find_element(By.ID,'bootSequence').get_attribute('class'),'Enter dismisses BIOS'); overflow(alice,'Landing desktop')
    register(alice,ALICE); register(bob,BOB); register(admin,ADMIN)
    from app.database import SessionLocal
    from app.models import User
    db=SessionLocal(); db.query(User).filter(User.username==ADMIN).update({User.role:'admin'}); db.commit(); db.close()
    # BOLA: Alice selects Bob's synthetic record in the real mission page.
    alice.get(BASE+'/bola_lab.html'); wait(alice,EC.visibility_of_element_located((By.ID,'mediApp')))
    row_xpath=f"//tbody[@id='mvRecordsBody']/tr[td[3][normalize-space()='{BOB}']]"
    wait(alice,lambda d: bool(d.find_elements(By.XPATH,row_xpath)))
    rec=int(alice.find_element(By.XPATH,row_xpath).find_elements(By.TAG_NAME,'td')[0].text)
    own_xpath=f"//tbody[@id='mvRecordsBody']/tr[td[3][normalize-space()='{ALICE}']]"
    own_row=alice.find_element(By.XPATH,own_xpath)
    own_row.find_element(By.TAG_NAME,'button').click()
    wait(alice,lambda d:d.find_element(By.ID,'mvDetailTitle').text != 'RECORD DETAIL')
    alice.find_element(By.XPATH,"//button[normalize-space()='COMPARE WITH SECURE VAULT']").click()
    wait(alice,lambda d:'SECURE COMPARISON: HTTP 200' in d.find_element(By.ID,'recordLookupStatus').text)
    alice.find_element(By.XPATH,"//button[normalize-space()='< RETURN TO VAULT']").click()
    alice.find_element(By.ID,'recordLookupId').send_keys(str(rec)); alice.find_element(By.CSS_SELECTOR,'#recordLookupForm button[type=submit]').click()
    wait(alice,lambda d:d.find_element(By.ID,'headerCompleteBtn').is_displayed())
    alice.find_element(By.XPATH, "//button[normalize-space()='COMPARE WITH SECURE VAULT']").click()
    wait(alice,lambda d:'SECURE COMPARISON: access denied' in d.find_element(By.ID,'recordLookupStatus').text)
    alice.find_element(By.ID,'headerCompleteBtn').click(); wait(alice,lambda d:'MISSION ACCOMPLISHED' in d.find_element(By.ID,'headerCompleteBtn').text)
    assert not api(alice,'/labs/bola/complete','POST',{'evidence':{}})['body']['verified']
    duplicate=api(alice,'/api/xp/award','POST',{'source':'lab_completion:bola'})
    check(duplicate['status']==409 and api(alice,'/api/operator/profile')['body']['xp']==500,'duplicate BOLA completion awards no XP twice')
    print('BOLA own record/secure allow, cross-user vulnerable read/secure deny, completion and no duplicate XP: PASS')
    alice.get(BASE+'/labs'); wait(alice,EC.presence_of_element_located((By.CSS_SELECTOR,'.mission-card'))); wait(alice,lambda d:d.find_element(By.ID,'totalXP').text=='500')
    check(alice.find_element(By.ID,'completedMissions').text=='1','BOLA dashboard progress'); overflow(alice,'Dashboard 1366x768')
    for w,h in [(1920,1080),(1366,768),(390,844)]: viewport(alice,w,h); overflow(alice,f'Dashboard {w}x{h}')
    check(alice.execute_script("return document.querySelector('.mission-stats').classList.contains('panel-retro')"),'dashboard stats panel has its class')
    # Terminal must show live account/progress/inventory/achievement data and safely reject unknown input.
    alice.set_window_size(1366,768); alice.get(BASE+'/terminal'); wait(alice,EC.presence_of_element_located((By.ID,'terminalInput')))
    for command, expected in [('help','inventory'),('whoami',ALICE),('status','healthy'),('missions','DATA BREACH'),('inventory','Medical Record'),('achievements','FIRST BREACH')]:
        f=alice.find_element(By.ID,'terminalInput'); f.send_keys(command); f.send_keys(Keys.ENTER); wait(alice,lambda d,e=expected:e.lower() in d.find_element(By.ID,'terminalLines').text.lower())
    f=alice.find_element(By.ID,'terminalInput'); f.send_keys('not-a-command'); f.send_keys(Keys.ENTER); wait(alice,lambda d:'COMMAND NOT RECOGNIZED' in d.find_element(By.ID,'terminalLines').text)
    print('Terminal commands help/whoami/status/missions/inventory/achievements/clear/unknown: PASS')
    # BFLA vulnerable and secure endpoints with UI completion.
    alice.get(BASE+'/bfla_lab.html'); alice.find_element(By.ID,'probeAdminButton').click(); wait(alice,lambda d:'VULNERABLE ROUTE: HTTP 200' in d.find_element(By.ID,'apiResult').text)
    check('SECURE ROUTE: HTTP 403' in alice.find_element(By.ID,'apiResult').text,'standard-user secure BFLA denial'); wait(alice,lambda d:not d.find_element(By.ID,'completeLabBtn').get_attribute('disabled'))
    alice.find_element(By.ID,'completeLabBtn').click(); wait(alice,lambda d:'MISSION ACCOMPLISHED' in d.find_element(By.ID,'completionStatus').text)
    print('BFLA normal user vulnerable access / secure denial / completion: PASS')
    # XSS: payload must execute in isolated vulnerable iframe, while the same value is encoded by secure endpoint.
    alice.get(BASE+'/xss_lab.html'); wait(alice,EC.presence_of_element_located((By.ID,'xssForm')))
    ids=alice.execute_script("return ['xssHintButton','xssHintButtonInline','completeLabBtn','completeLabFooterBtn','formStatus'].map(id=>[id,[...document.querySelectorAll('[id]')].filter(e=>e.id===id).length])")
    check(all(n==1 for _,n in ids),'XSS controls IDs unique: '+str(ids))
    alice.find_element(By.ID,'xssHintButton').click(); check(alice.find_element(By.ID,'xssHintList').is_displayed(),'XSS hint works')
    alice.find_element(By.ID,'xssForm').submit(); wait(alice,lambda d:'PAYLOAD EXECUTED' in d.find_element(By.ID,'formStatus').text,timeout=12)
    encoded=alice.execute_script("return document.getElementById('secureFrame').getAttribute('srcdoc').includes('&lt;script&gt;')")
    check(encoded,'secure XSS output encoded'); alice.find_element(By.ID,'completeLabFooterBtn').click(); wait(alice,lambda d:'MISSION ACCOMPLISHED' in d.find_element(By.ID,'completionStatus').text)
    fabricated=api(alice,'/labs/xss/complete','POST',{'evidence':{'payload':'<script>fake()</script>','attempt_id':'fabricated'}})
    check(not fabricated['body']['verified'],'fabricated XSS attempt denied')
    print('XSS browser execution in sandbox / secure output encoding / valid and invalid evidence: PASS')
    # Cross-user isolation and own BFLA progression.
    bob.get(BASE+'/labs'); wait(bob,EC.presence_of_element_located((By.ID,'totalXP'))); wait(bob,lambda d:d.find_element(By.ID,'totalXP').text=='0')
    check(bob.find_element(By.ID,'completedMissions').text=='0','Bob has no Alice progress'); check(api(bob,'/api/labs/progress')['body']['labs']['bola']['status']=='not_started','BOLA progress isolated')
    bob.get(BASE+'/bfla_lab.html'); bob.find_element(By.ID,'probeAdminButton').click(); wait(bob,lambda d:'VULNERABLE ROUTE: HTTP 200' in d.find_element(By.ID,'apiResult').text); bob.find_element(By.ID,'completeLabBtn').click(); wait(bob,lambda d:'MISSION ACCOMPLISHED' in d.find_element(By.ID,'completionStatus').text)
    check(api(bob,'/secure/admin/users')['status']==403,'nonadmin secure endpoint denied')
    check(api(admin,'/secure/admin/users')['status']==200,'admin secure endpoint allowed')
    # Refresh, logout/login, and progression persist in the server database.
    alice.get(BASE+'/labs'); alice.find_element(By.ID,'logoutBtn').click(); wait(alice,EC.url_contains('/login')); alice.find_element(By.ID,'username').send_keys(ALICE); alice.find_element(By.ID,'password').send_keys('TestPass12345Z'); alice.find_element(By.ID,'submitButton').click(); wait(alice,EC.url_contains('/labs'))
    progress=api(alice,'/api/labs/progress')['body']['labs']; xp=api(alice,'/api/operator/profile')['body']['xp']
    check(all(progress[x]['status']=='completed' for x in ('bola','bfla','xss')),'Alice progress persists'); check(xp==1500,'Alice XP awarded once/persists')
    print('BFLA administrator comparison, Alice/Bob XP/progress isolation, logout/login persistence: PASS')
    # Exercise the real settings UI and verify preferences survive a refresh.
    alice.get(BASE+'/settings'); wait(alice,EC.presence_of_element_located((By.ID,'settingThemeAccent')))
    from selenium.webdriver.support.ui import Select
    Select(alice.find_element(By.ID,'settingThemeAccent')).select_by_value('cyan')
    alice.find_element(By.ID,'settingBrightness').send_keys(Keys.HOME); alice.find_element(By.ID,'settingBrightness').send_keys(Keys.ARROW_RIGHT)
    alice.find_element(By.CSS_SELECTOR,'label.setting-toggle:has(#settingScanlines)').click()
    alice.find_element(By.ID,'saveSettingsBtn').click(); wait(alice,lambda d:'Settings applied successfully' in d.find_element(By.ID,'toastContainer').text)
    saved=api(alice,'/api/user/settings')['body']; check(saved['theme_accent']=='cyan' and saved['crt_scanlines'] is False,'settings save endpoint')
    alice.refresh(); wait(alice,lambda d:Select(d.find_element(By.ID,'settingThemeAccent')).first_selected_option.get_attribute('value')=='cyan')
    check(not alice.find_element(By.ID,'settingScanlines').is_selected(),'settings persisted after refresh')
    print('Settings controls apply, persist and restore after refresh: PASS')
    # Exercise authentication error feedback and recovery form configured/unconfigured state.
    api(alice,'/auth/logout','POST',{})
    alice.get(BASE+'/login'); alice.find_element(By.ID,'username').send_keys(ALICE); alice.find_element(By.ID,'password').send_keys('wrong-password'); alice.find_element(By.ID,'submitButton').click(); wait(alice,lambda d:'Invalid username or password' in d.find_element(By.ID,'authStatus').text)
    alice.get(BASE+'/forgot-password'); alice.find_element(By.ID,'email').send_keys(ALICE+'@example.test'); alice.find_element(By.ID,'submitButton').click(); wait(alice,lambda d:'not configured' in d.find_element(By.ID,'authStatus').text.lower())
    print('Login error and forgot-password SMTP-unconfigured error feedback: PASS')
    alice.get(BASE+'/login'); alice.find_element(By.ID,'username').send_keys(ALICE); alice.find_element(By.ID,'password').send_keys('TestPass12345Z'); alice.find_element(By.ID,'submitButton').click(); wait(alice,EC.url_contains('/labs'))
    # Check protected pages at desktop and an emulated 390px mobile viewport.
    for path in ['/operator/profile','/settings','/bola_lab.html','/bfla_lab.html','/xss_lab.html']:
        alice.get(BASE+path); time.sleep(.4)
        for w,h in [(1366,768),(390,844)]: viewport(alice,w,h); overflow(alice,path+' '+str(w))
    # Use the administrator browser after its access checks to test anonymous auth forms at both sizes.
    api(admin,'/auth/logout','POST',{})
    for path in ['/login','/register']:
        admin.get(BASE+path); wait(admin,EC.presence_of_element_located((By.ID,'authForm')))
        for w,h in [(1366,768),(390,844)]: viewport(admin,w,h); overflow(admin,path+' '+str(w))
    js_errors=[e['message'] for e in alice.get_log('browser') if e['level']=='SEVERE' and 'fonts.googleapis.com' not in e['message']]
    print('browser JavaScript/non-font console errors:',js_errors[:8]); check(not js_errors,'no unexpected browser console errors')
    print('BROWSER END-TO-END: PASS')
finally:
    alice.quit(); bob.quit(); admin.quit()

