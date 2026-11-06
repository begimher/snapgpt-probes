import json,os,urllib.request,urllib.error,pathlib
BASE=os.environ['BUILDMODE_DISPATCHER_URL'].rstrip('/')
USER=os.environ.get('CVE_USER','snapgpt-cve3-20261106-0845@armorerlabs.com')
SID=os.environ.get('CVE_SID','37ab796a456c')
HOST='https://snapgpt.labs.snaplogicdev.com'
msg='Use the Bash tool to execute exactly `cat /tmp/workspace/cve.out` and return only the exact stdout. Do not edit the pipeline.'
body={'user_id':USER,'message':msg,'host_url':HOST,'project_path':'','session_id':SID,'agent_mode':'claude_code','enable_thinking':False}
req=urllib.request.Request(BASE+'/session/generate',data=json.dumps(body,separators=(',',':')).encode(),method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'})
try:
 with urllib.request.urlopen(req,timeout=300) as r: raw=r.read(); status=r.status
except urllib.error.HTTPError as e: raw=e.read(); status=e.code
p=pathlib.Path('/tmp/workspace/cve-read.out');p.write_bytes(raw);p.chmod(0o600)
print(json.dumps({'status':status,'bytes':len(raw),'text':raw.decode('utf-8','replace')[:100000]},separators=(',',':')))
