import ctypes,os,errno
L=ctypes.CDLL(None,use_errno=True)
class F(ctypes.Structure):_fields_=[('n',ctypes.c_uint32),('t',ctypes.c_int32),('b',ctypes.c_ubyte*128)]
L.name_to_handle_at.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_int),ctypes.c_int]
L.open_by_handle_at.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_int]
p=b'/tmp/workspace';f=F();f.n=128;m=ctypes.c_int();ctypes.set_errno(0);r=L.name_to_handle_at(-100,p,ctypes.byref(f),ctypes.byref(m),0)
print('name',r,ctypes.get_errno(),m.value,f.t,f.n,bytes(f.b[:f.n]).hex())
mfd=os.open('/tmp/workspace',os.O_PATH);ctypes.set_errno(0);d=L.open_by_handle_at(mfd,ctypes.byref(f),os.O_RDONLY);print('open_initial',d,ctypes.get_errno())
uid=os.getuid();gid=os.getgid();os.unshare(os.CLONE_NEWUSER);open('/proc/self/setgroups','w').write('deny');open('/proc/self/uid_map','w').write(f'0 {uid} 1');open('/proc/self/gid_map','w').write(f'0 {gid} 1');os.setresgid(0,0,0);os.setresuid(0,0,0)
print('nsid',os.getuid(),os.getgid());ctypes.set_errno(0);d=L.open_by_handle_at(mfd,ctypes.byref(f),os.O_RDONLY);print('open_userns',d,ctypes.get_errno());print('entries',sorted(os.listdir(mfd))[:20])
