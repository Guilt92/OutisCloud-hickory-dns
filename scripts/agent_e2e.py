#!/usr/bin/env python3
"""End-to-end check of the agent: register -> sync -> follow a change -> push -> tamper.

Needs a running control API (CONTROL_API, default http://127.0.0.1:8080), an admin
account (ADMIN_USER / ADMIN_PASS), the built agent binary (AGENT_BIN) and an existing
zone (ZONE_DOMAIN). Uses only the standard library.
"""
import json, os, subprocess, sys, tempfile, time, urllib.request

API = os.environ.get("CONTROL_API", "http://127.0.0.1:8080")
AGENT_BIN = os.environ.get("AGENT_BIN", "target/debug/agent")
ZONE = os.environ.get("ZONE_DOMAIN", "ui-test.example")

def call(method, path, tok=None, body=None):
    h = {"Content-Type": "application/json"}
    if tok: h["Authorization"] = "Bearer " + tok
    req = urllib.request.Request(API + path, method=method, headers=h, data=json.dumps(body).encode() if body is not None else None)
    try:
        r = urllib.request.urlopen(req, timeout=20); return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")

failed = 0
def check(name, ok, extra=""):
    global failed
    print(("PASS " if ok else "FAIL ") + name + (f"  -- {extra}" if extra else ""))
    failed += 0 if ok else 1

_, lg = call("POST", "/api/v1/auth/login", body={"username": os.environ.get("ADMIN_USER", "admin"), "password": os.environ["ADMIN_PASS"]})
tok = lg["token"]
_, reg = call("POST", "/api/v1/agents/register", tok, {"name": "e2e-agent", "addr": "10.1.1.9:53"})
workdir = tempfile.mkdtemp()
env = dict(os.environ, CONTROL_API=API, AGENT_ID=reg["id"], AGENT_TOKEN=reg["token"], AGENT_SIGNING_KEY=reg["signing_key"],
           AGENT_NAME="e2e-agent", AGENT_ADDR="10.1.1.9:53", AGENT_ZONE_DIR=workdir, HEARTBEAT_SECS="5")
proc = subprocess.Popen([AGENT_BIN], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def agent(): return next(a for a in call("GET", "/api/v1/agents", tok)[1] if a["id"] == reg["id"])
def wait(cond, t=40):
    s = time.time()
    while time.time() - s < t:
        if cond(agent()): return True
        time.sleep(1)
    return False

try:
    check("agent registers credentials and syncs the first bundle", wait(lambda a: a["in_sync"] and a["applied_version"] > 0))
    zid = next(z for z in call("GET", "/api/v1/zones", tok)[1]["data"] if z["domain"] == ZONE)["id"]
    value = "192.0.2.%d" % (int(time.time()) % 200 + 20)
    call("POST", f"/api/v1/zones/{zid}/records", tok, {"name": "e2e-%d" % int(time.time()), "record_type": "A", "value": value, "ttl": 60})
    check("a change on the control plane makes the agent fall behind", not agent()["in_sync"])
    check("the agent converges again", wait(lambda a: a["in_sync"]))
    check("the replica serves the new record", value in open(os.path.join(workdir, "zone." + ZONE)).read())
    call("POST", "/api/v1/config/push", tok, {"agent_id": reg["id"], "zone_id": "", "zone_config": {}})
    check("push is acknowledged", wait(lambda a: not a["sync_requested"]))
    proc.terminate(); proc.wait()
    env2 = dict(env, AGENT_SIGNING_KEY="0" * 64, AGENT_ZONE_DIR=tempfile.mkdtemp())
    p2 = subprocess.Popen([AGENT_BIN], env=env2, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    check("a wrong signing key is refused and reported", wait(lambda a: a["last_error"] and "signature" in a["last_error"]) and not os.path.exists(os.path.join(env2["AGENT_ZONE_DIR"], "named.toml")))
    p2.terminate(); p2.wait()
finally:
    if proc.poll() is None: proc.terminate()
    call("DELETE", f"/api/v1/agents/{reg['id']}", tok)
sys.exit(1 if failed else 0)
