#!/usr/bin/env python3
import ctypes,os,struct
PID=1
class R(ctypes.Structure):
 _fields_=[(x,ctypes.c_ulonglong) for x in 'r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()]
C=ctypes.CDLL(None,use_errno=True);C.ptrace.restype=ctypes.c_long;C.ptrace.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p];C.waitpid.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_int),ctypes.c_int]
def p(q,a=0,d=0):
 r=C.ptrace(q,PID,ctypes.c_void_p(a),ctypes.c_void_p(d))
 if r==-1:
  e=ctypes.get_errno()
  if e:raise OSError(e,os.strerror(e))
 return r
def peek(a):return p(1,a)&((1<<64)-1)
def poke(a,w):p(5,a,w&((1<<64)-1))
def write(a,b):
 b+=b'\0';b+=b'\0'*((-len(b))%8)
 for i in range(0,len(b),8):poke(a+i,struct.unpack('<Q',b[i:i+8])[0])
def base():
 for l in open('/proc/1/maps'):
  if 'libpython3.12.so.1.0' in l and 'r--p 00000000' in l:return int(l.split('-',1)[0],16)
 raise RuntimeError('base')
def stack():
 for l in open('/proc/1/maps'):
  if '[stack]' in l:
   a,b=l.split()[0].split('-');return int(a,16),int(b,16)
 raise RuntimeError('stack')
def off(n):
 c=ctypes.CDLL(None);f=getattr(c,n);b=ctypes.create_string_buffer(32)
 if not c.dladdr(f,ctypes.byref(b)):raise RuntimeError('dladdr')
 return ctypes.cast(f,ctypes.c_void_p).value-ctypes.c_void_p.from_buffer(b,8).value
b=base();ens=b+off('PyGILState_Ensure');run=b+off('PyRun_SimpleStringFlags');rel=b+off('PyGILState_Release')
lo,hi=stack();code=lo+0x1000;msg=lo+0x11000;result=lo+0x12000;ns=lo+0x8000
text=b"1/0\n"
# ensure; save state; mov rdi,msg; xor esi,esi; call run; store; release
sc=b'\x48\xb8'+struct.pack('<Q',ens)+b'\xff\xd0'+b'\x49\x89\xc4'
sc+=b'\x48\xbf'+struct.pack('<Q',msg)+b'\x31\xf6'+b'\x48\xb8'+struct.pack('<Q',run)+b'\xff\xd0'
sc+=b'\x48\xbb'+struct.pack('<Q',result)+b'\x48\x89\x03'
sc+=b'\x4c\x89\xe7'+b'\x48\xb8'+struct.pack('<Q',rel)+b'\xff\xd0'+b'\xcc'
st=ctypes.c_int();p(16);C.waitpid(PID,ctypes.byref(st),0);r=R();p(12,0,ctypes.addressof(r));o=R.from_buffer_copy(r)
old=[peek(code+i) for i in range(0,((len(sc)+7)//8)*8,8)];oldm=[peek(msg+i) for i in range(0,((len(text)+7)//8)*8,8)]
write(code,sc);write(msg,text);r.rip=code;r.rsp=ns;p(13,0,ctypes.addressof(r));p(7);C.waitpid(PID,ctypes.byref(st),0)
rv=peek(result)
for i,w in enumerate(old):poke(code+i*8,w)
for i,w in enumerate(oldm):poke(msg+i*8,w)
p(13,0,ctypes.addressof(o));p(17)
print('BASE',hex(b),'ENSURE',hex(ens),'RUN',hex(run),'STOP',st.value,'RET',rv)
