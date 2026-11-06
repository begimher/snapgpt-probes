import json,urllib.request as u
B='http://lrs-'+'pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local';H='https://snapgpt.labs.snaplogicdev.com';U='daniel+admin@armorerlabs.com'
print('START',flush=True)
q=u.Request(B+'/session/init',data=json.dumps({'user_id':U,'host_url':H,'project_path':'','project_id':'','force':False},separators=(',',':')).encode(),headers={'Content-Type':'application/json','X-SL-Token':'x'})
print(u.urlopen(q,timeout=30).read().decode(),flush=True)
print('DONE',flush=True)
