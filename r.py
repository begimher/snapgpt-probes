import dns.resolver
services=['lrs-metaserve-01.canv2-sl-app-launcher.svc.cluster.local','lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local']
ports=['http','https','grpc','tcp','mongodb','redis','pygen','metrics']
for s in services:
 for p in ports:
  n=f'_{p}._tcp.{s}'
  try:
   ans=dns.resolver.resolve(n,'SRV',lifetime=2)
   print(n,[(r.target.to_text(),r.port,r.weight,r.priority) for r in ans])
  except Exception as e: print(n,type(e).__name__)
