import dns.resolver
for s in ['lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local','lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local']:
 for typ in ['A','SRV','TXT','CNAME']:
  try:
   a=dns.resolver.resolve(s,typ,lifetime=3);print(s,typ,[r.to_text() for r in a])
  except Exception as e:print(s,typ,type(e).__name__)
