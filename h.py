#!/usr/bin/env python3
import ctypes, errno, json, os, pathlib, socket, stat, time

OUT={"utc":time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),"hostname":socket.gethostname(),"uid":os.getuid(),"gid":os.getgid(),"records":{},"userns":{}}
libc=ctypes.CDLL(None,use_errno=True)
libc.name_to_handle_at.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_int),ctypes.c_int]
libc.name_to_handle_at.restype=ctypes.c_int
libc.open_by_handle_at.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_int]
libc.open_by_handle_at.restype=ctypes.c_int
class FH(ctypes.Structure):
    _fields_=[("handle_bytes",ctypes.c_uint32),("handle_type",ctypes.c_int32),("f_handle",ctypes.c_ubyte*128)]
AT_FDCWD=-100

def e():
    n=ctypes.get_errno(); return {"errno":n,"name":errno.errorcode.get(n,str(n)),"text":os.strerror(n)}
def geth(path):
    fh=FH(); fh.handle_bytes=128; mid=ctypes.c_int(-1); ctypes.set_errno(0)
    rc=libc.name_to_handle_at(AT_FDCWD,os.fsencode(path),ctypes.byref(fh),ctypes.byref(mid),0)
    if rc: return {"rc":rc,"error":e(),"path":path}
    b=bytes(fh.f_handle[:fh.handle_bytes])
    return {"rc":rc,"path":path,"mount_id":mid.value,"handle_type":fh.handle_type,"handle_bytes":fh.handle_bytes,"handle_hex":b.hex(),"handle_words_le":[int.from_bytes(b[i:i+4],'little') for i in range(0,len(b),4)]}
def openh(path,h):
    try: mfd=os.open(path,os.O_PATH)
    except Exception as ex: return {"mount_open_error":repr(ex)}
    fh=FH(); fh.handle_bytes=h["handle_bytes"]; fh.handle_type=h["handle_type"]
    raw=bytes.fromhex(h["handle_hex"])
    for i,x in enumerate(raw): fh.f_handle[i]=x
    ctypes.set_errno(0); fd=libc.open_by_handle_at(mfd,ctypes.byref(fh),os.O_RDONLY)
    rec={"mount_fd":mfd,"fd":fd}
    if fd<0: rec["error"]=e()
    else:
        try:
            st=os.fstat(fd); rec["stat"]={"mode":oct(st.st_mode),"uid":st.st_uid,"gid":st.st_gid,"size":st.st_size,"ino":st.st_ino,"dev":st.st_dev}
            if stat.S_ISREG(st.st_mode): rec["data"]=os.read(fd,4096).decode('utf-8','replace')
            elif stat.S_ISDIR(st.st_mode): rec["entries"]=sorted(os.listdir(fd))[:100]
        except Exception as ex: rec["read_error"]=repr(ex)
        os.close(fd)
    os.close(mfd); return rec

pathlib.Path('/tmp/workspace/.handle_probe').write_text('HANDLE_OK\n')
for p in ['/tmp/workspace/.handle_probe','/tmp/workspace','/home/worker','/etc/hosts','/']:
    try:
        st=os.stat(p); rec={"stat":{"dev":st.st_dev,"ino":st.st_ino,"mode":oct(stat.S_IMODE(st.st_mode))}}
    except Exception as ex: rec={"stat_error":repr(ex)}
    h=geth(p); rec["name_to_handle"]=h
    if h.get('rc')==0: rec["open_by_handle_initial"]=openh(p,h)
    OUT["records"][p]=rec

# Enter a user namespace and map namespace root to the original worker UID/GID.
try:
    uid=os.getuid(); gid=os.getgid()
    os.unshare(os.CLONE_NEWUSER)
    pathlib.Path('/proc/self/setgroups').write_text('deny')
    pathlib.Path('/proc/self/uid_map').write_text(f'0 {uid} 1\n')
    pathlib.Path('/proc/self/gid_map').write_text(f'0 {gid} 1\n')
    os.setresgid(0,0,0); os.setresuid(0,0,0)
    OUT["userns"]["identity"]={"uid":os.getuid(),"gid":os.getgid()}
    OUT["userns"]["status"]=pathlib.Path('/proc/self/status').read_text()
    for p in ['/tmp/workspace/.handle_probe','/tmp/workspace','/home/worker','/etc/hosts','/']:
        h=OUT["records"][p]["name_to_handle"]
        if h.get('rc')==0:
            OUT["userns"][p]={"open_by_handle":openh(p,h)}
    # Test mount capability in the child user namespace.
    os.makedirs('/tmp/nsprobe',exist_ok=True)
    try:
        os.unshare(os.CLONE_NEWNS)
        OUT["userns"]["new_mountns"]=True
    except Exception as ex:
        OUT["userns"]["new_mountns_error"]=repr(ex)
    try:
        libc.mount.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_char_p]
        ctypes.set_errno(0)
        rc=libc.mount(b'tmpfs',b'/tmp/nsprobe',b'tmpfs',0,b'size=1m')
        OUT["userns"]["mount_tmpfs"]={"rc":rc,"error":e() if rc else None}
    except Exception as ex: OUT["userns"]["mount_tmpfs"]={"exception":repr(ex)}
except Exception as ex:
    OUT["userns"]["error"]=repr(ex)
print(json.dumps(OUT,sort_keys=True,separators=(',',':')))
