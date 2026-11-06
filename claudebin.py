import json,os,pathlib,re,time
p=pathlib.Path('/app/.venv/lib/python3.12/site-packages/claude_agent_sdk/_bundled/claude')
pat=re.compile(rb'(?i)(peerToken|peer-send-message|send-message|messaging|cc-socks|CLAUDE_CODE_MESSAGING|task-notification|fromSession|verifiedPeerPid)')
out={'utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'path':str(p),'bytes':0,'strings':[],'error':''}
try:
 b=p.read_bytes(); out['bytes']=len(b)
 for m in pat.finditer(b):
  lo=max(0,m.start()-300); hi=min(len(b),m.end()+500); chunk=b[lo:hi]
  s=''.join(chr(x) if 32<=x<127 else ' ' for x in chunk)
  s=re.sub(r' +',' ',s)
  if s not in out['strings']: out['strings'].append(s)
  if len(out['strings'])>=100: break
except Exception as e:out['error']=repr(e)
pathlib.Path('/tmp/workspace/claude-binary-scan.json').write_text(json.dumps(out,separators=(',',':')))
print(json.dumps({'bytes':out['bytes'],'strings':len(out['strings']),'error':out['error']}))
