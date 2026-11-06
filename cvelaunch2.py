#!/usr/bin/env python3
import os, pathlib, subprocess
root = pathlib.Path('/tmp/workspace')
log = root / 'cve.log'
old = root / 'cve.previous.log'
if log.exists():
    try: log.replace(old)
    except Exception: pass
pid = os.fork()
if pid:
    print(pid)
    raise SystemExit(0)
os.setsid()
with open(root / 'cve.runner.pid', 'w') as f:
    f.write(str(os.getpid()))
with open(log, 'wb', buffering=0) as out:
    p = subprocess.Popen(['/tmp/workspace/cve'], cwd=str(root), stdin=subprocess.DEVNULL,
                         stdout=out, stderr=subprocess.STDOUT, close_fds=True)
    rc = p.wait()
with open(root / 'cve.status', 'w') as f:
    f.write(str(rc))
