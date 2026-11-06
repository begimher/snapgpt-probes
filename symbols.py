import ctypes
for n in ('PyRun_SimpleString', 'PyRun_SimpleStringFlags', 'PyGILState_Ensure', 'PyGILState_Release'):
    c=ctypes.CDLL(None)
    f=getattr(c,n)
    b=ctypes.create_string_buffer(32)
    c.dladdr(f,ctypes.byref(b))
    addr=ctypes.cast(f,ctypes.c_void_p).value
    base=ctypes.c_void_p.from_buffer(b,8).value
    print(n,hex(addr),hex(base),hex(addr-base),ctypes.string_at(b).decode(errors='replace'))
