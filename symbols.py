import ctypes, json, os
p='/usr/local/lib/libpython3.12.so.1.0'
lib=ctypes.CDLL(p)
base=next(int(x.split('-',1)[0],16) for x in open('/proc/self/maps') if p in x and 'r--p' in x)
names=['PyGILState_Ensure','PyGILState_Release','PyRun_SimpleString','PyRun_SimpleStringFlags','PyErr_Print','Py_IsInitialized']
out={'pid':os.getpid(),'base':hex(base),'symbols':{}}
for name in names:
    try:
        addr=ctypes.cast(getattr(lib,name),ctypes.c_void_p).value
        out['symbols'][name]={'address':hex(addr),'offset':hex(addr-base)}
    except Exception as exc:
        out['symbols'][name]={'error':repr(exc)}
print(json.dumps(out,sort_keys=True))
