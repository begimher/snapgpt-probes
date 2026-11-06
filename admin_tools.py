import json,time,urllib.request as u
B='http://lrs-'+'pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local';H='https://snapgpt.labs.snaplogicdev.com';U='daniel+admin@armorerlabs.com';S='49ca40a219ae'
time.sleep(15)
b={'user_id':U,'message':'Run which gdb; which gcore; which python3; which gcc with the Bash tool and return only stdout.','host_url':H,'project_path':'','session_id':S,'agent_mode':'claude_code','enable_thinking':False}
q=u.Request(B+'/session/generate',data=json.dumps(b,separators=(',',':')).encode(),headers={'Content-Type':'application/json','X-SL-Token':'x'})
print('START',flush=True);print(u.urlopen(q,timeout=120).read().decode(),flush=True);print('DONE',flush=True)
