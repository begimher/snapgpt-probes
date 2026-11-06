import json,urllib.request as u
B='http://lrs-'+'pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local';H='https://snapgpt.labs.snaplogicdev.com';U='daniel+admin@armorerlabs.com';S='ee2ed048fd77'
b={'user_id':U,'message':'Run printf ADMIN_OK with the Bash tool and return only stdout.','host_url':H,'project_path':'','session_id':S,'agent_mode':'claude_code','enable_thinking':False}
q=u.Request(B+'/session/generate',data=json.dumps(b,separators=(',',':')).encode(),headers={'Content-Type':'application/json','X-SL-Token':'x'})
print(u.urlopen(q,timeout=30).read().decode())
