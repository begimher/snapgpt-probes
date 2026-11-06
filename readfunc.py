#!/usr/bin/env python3
import ctypes, os, struct
PID=1
C=ctypes.CDLL(None,use_errno=True); C.ptrace.restype=ctypes.c_long; C.ptrace.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]; C.waitpid.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_int),ctypes.c_int]
def p(req,a=0,d=0):
 r=C.ptrace(req,PID,ctypes.c_void_p(a),ctypes.c_void_p(d))
 if r==-1:
  e=ctypes.get_errno()
  if e: raise OSError(e,os.strerror(e))
 return r
def peek(a): return p(1,a)&((1<<64)-1)
def base():
 for l in open('/proc/1/maps'):
  if 'libpython3.12.so.1.0' in l and 'r--p 00000000' in l:return int(l.split('-',1)[0],16)
 raise RuntimeError('base')
def off(name):
 c=ctypes.CDLL(None); f=getattr(c,name); buf=ctypes.create_string_buffer(32)
 if not c.dladdr(f,ctypes.byref(buf)): raise RuntimeError('dladdr')
 return ctypes.cast(f,ctypes.c_void_p).value-ctypes.c_void_p.from_buffer(buf,8).value
b=base(); st=ctypes.c_int(); p(16); C.waitpid(PID,ctypes.byref(st),0)
try:
 out={'base':hex(b),'stop':st.value,'symbols':{}}
 for n in ['PyGILState_Ensure','PyGILState_Release','PyRun_SimpleString','PyRun_SimpleStringFlags']:
  a=b+off(n); out['symbols'][n]={'addr':hex(a),'bytes':b''.join(struct.pack('<Q',peek(a+i)) for i in range(0,32,8)).hex()}
 print(out)
finally:
 p(17)
