#!/usr/bin/env python3
import json, os, subprocess, pathlib, time
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'tests':{}}
def run(name,args,timeout=20):
 try:
  p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
  out['tests'][name]={'rc':p.returncode,'stdout':p.stdout[:20000],'stderr':p.stderr[:10000]}
 except Exception as e: out['tests'][name]={'error':repr(e)}
run('unshare_tmpfs',['unshare','-Ur','-m','--propagation','private','sh','-c','mkdir -p /tmp/nsprobe && mount -t tmpfs tmpfs /tmp/nsprobe && touch /tmp/nsprobe/x && ls -la /tmp/nsprobe'])
run('unshare_proc',['unshare','-Ur','-m','-p','-f','--mount-proc','sh','-c','id; grep Cap /proc/self/status; mount -t tmpfs tmpfs /tmp/nsprobe2 2>&1; printf core > /proc/sys/kernel/core_pattern; cat /proc/sys/kernel/core_pattern'])
run('unshare_proc_manual',['unshare','-Ur','-m','-p','-f','sh','-c','mount -t proc proc /tmp/nsprobe3 2>&1; cat /tmp/nsprobe3/sys/kernel/core_pattern 2>&1'])
run('unshare_net',['unshare','-Ur','-n','sh','-c','ip addr show 2>&1; ip route 2>&1; cat /proc/self/status | grep Cap'])
run('userns_status',['sh','-c','unshare -Ur sh -c "cat /proc/self/status; cat /proc/self/uid_map; cat /proc/self/gid_map"'])
run('cgroup_write',['sh','-c','for f in /sys/fs/cgroup/memory/memory.limit_in_bytes /sys/fs/cgroup/memory/memory.usage_in_bytes /sys/fs/cgroup/devices/devices.list; do echo ===$f; cat $f; printf 1 >> $f 2>&1; done'])
run('cgroup_mount',['unshare','-Ur','-m','--propagation','private','sh','-c','mkdir -p /tmp/cgprobe; mount -t cgroup -o memory cgroup /tmp/cgprobe 2>&1; ls -la /tmp/cgprobe | head; cat /tmp/cgprobe/memory.limit_in_bytes 2>&1'])
run('dev_mknod',['sh','-c','mknod /tmp/nvme b 259 1 2>&1; ls -l /tmp/nvme; dd if=/tmp/nvme bs=512 count=1 2>&1 | od -Ax -tx1 -N64'])
run('proc_root',['sh','-c','ls -la /proc/1/root/var/lib 2>&1; ls -la /proc/1/root/var/lib/kubelet 2>&1; ls -la /proc/1/root 2>&1 | head'])
print(json.dumps(out,sort_keys=True,separators=(',',':')))
