import json, os, pathlib, re, time
roots=['/app/.venv/lib/python3.12/site-packages/claude_agent_sdk','/app/.venv/lib/python3.12/site-packages/pygen/core/agents/claude_code']
pat=re.compile(r'(?i)(messaging|cc-socks|peerToken|CLAUDE_CODE_MESSAGING|unix|socket)')
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'roots':roots,'files':[],'errors':[]}
for root in roots:
 p=pathlib.Path(root)
 if not p.exists(): out['errors'].append('missing '+root); continue
 for f in p.rglob('*'):
  if not f.is_file(): continue
  try:
   b=f.read_bytes()
   if len(b)>2_000_000 or b'\0' in b: continue
   lines=b.decode('utf-8','replace').splitlines()
   hits=[]
   for i,line in enumerate(lines,1):
    if pat.search(line): hits.append({'line':i,'text':line[:1500]})
   if hits: out['files'].append({'path':str(f),'hits':hits[:100]})
  except Exception as e: out['errors'].append(str(f)+': '+repr(e))
path=pathlib.Path('/tmp/workspace/claude-sdk-scan.json'); path.write_text(json.dumps(out,separators=(',',':'))); print(json.dumps({'files':len(out['files']),'errors':len(out['errors']),'bytes':path.stat().st_size}))
