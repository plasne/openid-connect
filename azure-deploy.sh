# Set variables
SUBSCRIPTION="PROD_EMIT_AzureSandbox"
RG="delete-tyler-auth-rg"
LOCATION="eastus"
APP_SERVICE_PLAN="delete-tyler-plan"
APP_SERVICE_PLAN_LINUX="delete-tyler-plan-linux"
AUTH_DISPLAY_NAME="delete-tyler-auth-service"
WFE_DISPLAY_NAME="delete-tyler-my-app"
API_DISPLAY_NAME="delete-tyler-my-api"
APP_CONFIG_NAME="delete-tyler-app-config"
KEYVAULT_NAME="delete-tyler-auth-kv"
AUTH_DOMAIN="map.xom.cloud"
TENANT_ID="d1ee1acd-bc7a-4bc4-a787-938c49a83906"

# Log into Azure (Interactive)
az login
az account set --subscription $SUBSCRIPTION


# ------------------------------------
# Create a resource group
# ------------------------------------
echo "Create resoure group $RG in location $LOCATION"
az group create --location $LOCATION --name $RG

# ------------------------------------
# Registering applications in Azure Active Directory
# ------------------------------------
echo "Creating app registrations in Azure Active Directory"
auth_client_id=$(az ad app create --display-name $AUTH_DISPLAY_NAME --reply-urls http://localhost:5100/api/auth/token https://$AUTH_DOMAIN/api/auth/token --query appId --output tsv)

#userguid=$(cat /proc/sys/kernel/random/uuid)
#adminguid=$(cat /proc/sys/kernel/random/uuid)
echo '[{
    "allowedMemberTypes": [
      "User"
    ],
    "description": "Users can use the app",
    "displayName": "User",
    "isEnabled": "true",
    "value": "user"
},
{
    "allowedMemberTypes": [
      "User"
    ],
    "description": "Admins can edit the app",
    "displayName": "Admin",
    "isEnabled": "true",
    "value": "admin"
}]' > manifest.json
az ad app create --display-name $WFE_DISPLAY_NAME --app-roles @manifest.json

# ------------------------------------
# Grant permissions for auth service to call the Graph API with Directory.Read.All
# ------------------------------------
# Microsoft Graph Info
# ObjectId af1f8235-7bc3-4847-b24b-bb7683edc5e9 
# AppId 00000003-0000-0000-c000-000000000000
# Directory.Read.All scope id 7ab1d382-f21e-4acd-a863-ba3e13f7da61
az ad app permission add --id $auth_client_id --api 00000003-0000-0000-c000-000000000000 --api-permissions 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Scope
az ad app permission grant --id $auth_client_id --api 00000003-0000-0000-c000-000000000000
#az ad app permission admin-consent --id $auth_client_id

# ------------------------------------
# Create web applications
# ------------------------------------
echo "Create app service plan $APP_SERVICE_PLAN and $APP_SERVICE_PLAN_LINUX in $RG"
az appservice plan create --resource-group $RG --name $APP_SERVICE_PLAN --location $LOCATION --sku S1
#az appservice plan create --resource-group $RG --name $APP_SERVICE_PLAN_LINUX --location $LOCATION --sku B1

echo "Create and deploy auth service $AUTH_DISPLAY_NAME"
az webapp create --name $AUTH_DISPLAY_NAME --resource-group $RG --plan $APP_SERVICE_PLAN
zip -r auth/auth.zip auth
az webapp deployment source config-zip --resource-group $RG --name $AUTH_DISPLAY_NAME --src auth/auth.zip

echo "Create and deploy api service $API_DISPLAY_NAME"
az webapp create --name $API_DISPLAY_NAME --resource-group $RG --plan $APP_SERVICE_PLAN
zip -r api/api.zip api
az webapp deployment source config-zip --resource-group $RG --name $API_DISPLAY_NAME --src api/api.zip

echo "Create and deploy web front end (WFE) app $WFE_DISPLAY_NAME"
az webapp create --name $WFE_DISPLAY_NAME --resource-group $RG --plan $APP_SERVICE_PLAN
zip -r wfe/wfe.zip wfe
az webapp deployment source config-zip --resource-group $RG --name $WFE_DISPLAY_NAME --src wfe/wfe.zip


echo "Create a managed identities for web apps"
auth_pid=$(az webapp identity assign --name $AUTH_DISPLAY_NAME --resource-group $RG --query principalId --output tsv)
echo "Web app managed identity principalId $auth_pid"
# TODO: Allow Auth Service to read directory information from Microsoft Graph to see what roles the user is in (See above permissions for app reg)

api_pid=$(az webapp identity assign --name $API_DISPLAY_NAME --resource-group $RG --query principalId --output tsv)
echo "Web app managed identity principalId $api_pid"

# ------------------------------------
# Create Azure App Config Service to store central configs
# ------------------------------------
appconfig_resource_id=$(az appconfig create --name $APP_CONFIG_NAME --location $LOCATION  --resource-group $RG | jq -j '.id')

#connstring=$(az appconfig credential list --name $APP_CONFIG_NAME --query "[?name == 'Primary'].connectionString" -o tsv)
# TODO: Give auth and api managed identities permission to be owner of app config 

# ------------------------------------
# Create Azure Key Vault to securely store passwords and secrets
# ------------------------------------
echo "Create Azure Keyvault to securely store secrets/passwords"
az keyvault create --name $KEYVAULT_NAME --resource-group $RG --location $LOCATION

echo "Set keyvault policy so that the auth service has access to read"
az keyvault set-policy --name $KEYVAULT_NAME --object-id $auth_pid --secret-permissions get list

# ------------------------------------
# Generate a self-signed certificate and private key
# ------------------------------------
country=US
state=""
locality=""
organization=""
organizationalunit=""
commonname=""
email=""

echo "Generate random passwords to use for openssl certs"
certpswd=$(date +%s | sha256sum | base64 | head -c 32)

echo "Generate private key and public certs"
mkdir certs
privatekey=$(openssl genrsa -des3 -passout pass:$certpswd -out certs/privatekey.pem 2048)
#publiccert=$(openssl req -x509 -new -key certs/privatekey.pem -out certs/certificate.pem -passin pass:$certpswd -subj "/C=US")
publiccert=$(openssl req -x509 -newkey rsa:4096 -keyout certs/privatekey.pem -out certs/certificate.pem -passin pass:$certpswd -passout pass:$certpswd -subj "/C=US")
openssl pkcs12 -export -inkey certs/privatekey.pem -in certs/certificate.pem -passin pass:$certpswd -out certs/cert.pfx -password pass:$certpswd
certpfx=$(openssl base64 -in certs/cert.pfx)

echo "Add secrets to keyvault $KEYVAULT_NAME"
az keyvault secret set --vault-name $KEYVAULT_NAME --name PRIVATEKEY --value "$certpfx"
az keyvault secret set --vault-name $KEYVAULT_NAME --name PRIVATEKEYPW --value $certpswd
az keyvault secret set --vault-name $KEYVAULT_NAME --name PUBLIC-CERT-0 --file certs/certificate.pem

# Must grab the secret in order to get its uri with version. The jq statement pulls the uri without quotes. -JIH
pk_kv_uri=$(az keyvault secret show --name PRIVATEKEY --vault-name $KEYVAULT_NAME | jq -j '.id')
echo $pk_kv_uri
pkpswd_kv_uri=$(az keyvault secret show --name PRIVATEKEYPW --vault-name $KEYVAULT_NAME | jq -j '.id')
echo $pkpswd_kv_uri
pc_kv_uri=$(az keyvault show --name $KEYVAULT_NAME | jq -j '.properties.vaultUri')
echo $pc_kv_uri

# ------------------------------------
# Set up local environment configs
# ------------------------------------
echo "HOST_URL=http://localhost:5100" >> auth/.env
echo "LOG_LEVEL=Debug" >> auth/.env
echo "APPCONFIG_RESOURCE_ID=$appconfig_resource_id" >> auth/.env
echo "CONFIG_KEYS=sample:auth:local:*, sample:common:local:*, sample:auth:dev:*, sample:common:dev:*" >> auth/.env

echo "HOST_URL=http://localhost:5200" >> api/.env
echo "LOG_LEVEL=Debug" >> api/.env
echo "APPCONFIG_RESOURCE_ID=$appconfig_resource_id" >> api/.env
echo "CONFIG_KEYS=sample:api:local:*, sample:common:local:*, sample:api:dev:*, sample:common:dev:*" >> api/.env

echo "HOST_URL=http://localhost:5000" >> wfe/.env
echo "CONFIG_URL=http://localhost:5200/api/config/wfe" >> wfe/.env


echo '{
  "sample:api:dev:PRESENT_CONFIG_wfe": "sample:wfe:dev:*",
  "sample:api:dev:REISSUE_URL": "",
  "sample:api:dev:WELL_KNOWN_CONFIG_URL": "",
  "sample:api:local:ALLOW_TOKEN_IN_HEADER": "true",
  "sample:api:local:PRESENT_CONFIG_wfe": "sample:wfe:local:*, sample:wfe:dev:*",
  "sample:api:local:REISSUE_URL": "http://localhost:5100/api/auth/reissue",
  "sample:api:local:VERIFY_XSRF_HEADER": "false",
  "sample:api:local:WELL_KNOWN_CONFIG_URL": "http://localhost:5100/api/auth/.well-known/openid-configuration",
  "sample:auth:dev:AUTHORITY": "",
  "sample:auth:dev:CLIENT_ID": "",
  "sample:auth:dev:DEFAULT_REDIRECT_URL": "",
  "sample:auth:dev:JWT_DURATION": "2",
  "sample:auth:dev:KEYVAULT_COMMAND_PASSWORD_URL": "",
  "sample:auth:dev:KEYVAULT_PRIVATE_KEY_PASSWORD_URL": "",
  "sample:auth:dev:KEYVAULT_PRIVATE_KEY_URL": "",
  "sample:auth:dev:KEYVAULT_PUBLIC_CERT_PREFIX_URL": "",
  "sample:auth:dev:PUBLIC_KEYS_URL": "",
  "sample:auth:dev:REDIRECT_URI": "",
  "sample:auth:dev:REQUIRE_USER_ENABLED_ON_REISSUE": "false",
  "sample:auth:local:DEFAULT_REDIRECT_URL": "http://localhost:5000",
  "sample:auth:local:PUBLIC_KEYS_URL": "http://localhost:5100/api/auth/keys",
  "sample:auth:local:REDIRECT_URI": "http://localhost:5100/api/auth/token",
  "sample:auth:local:REQUIRE_USER_ENABLED_ON_REISSUE": "true",
  "sample:common:dev:ALLOWED_ORIGINS": "",
  "sample:common:dev:AUDIENCE": "",
  "sample:common:dev:BASE_DOMAIN": "",
  "sample:common:dev:ISSUER": "",
  "sample:common:local:ALLOWED_ORIGINS": "http://localhost:5000",
  "sample:common:local:BASE_DOMAIN": "localhost",
  "sample:common:local:REQUIRE_SECURE_FOR_COOKIES": "false",
  "sample:wfe:dev:LOGIN_URL": "",
  "sample:wfe:dev:ME_URL": "",
  "sample:wfe:local:LOGIN_URL": "http://localhost:5100/api/auth/authorize",
  "sample:wfe:local:ME_URL": "http://localhost:5200/api/identity/me"
}' > appconfig.json
# TODO: if someone knows a better way of assinging dynamic variables to a json file via BASH, please fix
jq --arg reissue_url "https://auth.$AUTH_DOMAIN/api/auth/reissue" '.["sample:api:dev:REISSUE_URL"] |= $reissue_url' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg well_known_config_url "https://auth.$AUTH_DOMAIN/api/auth/.well-known/openid-configuration" '.["sample:api:dev:WELL_KNOWN_CONFIG_URL"] |= $well_known_config_url' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg authority "https://login.microsoftonline.com/$TENANT_ID" '.["sample:auth:dev:AUTHORITY"] |= $authority' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg client_id $auth_client_id '.["sample:auth:dev:CLIENT_ID"] |= $client_id' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg default_redirect_url "https://$AUTH_DOMAIN" '.["sample:auth:dev:DEFAULT_REDIRECT_URL"] |= $default_redirect_url' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg keyvault_command_password_url "" '.["sample:auth:dev:KEYVAULT_COMMAND_PASSWORD_URL"] |= $keyvault_command_password_url' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg keyvault_private_key_url $pkpswd_kv_uri '.["sample:auth:dev:KEYVAULT_PRIVATE_KEY_PASSWORD_URL"] |= $keyvault_private_key_url' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg keyvault_private_key_password_url $pk_kv_uri '.["sample:auth:dev:KEYVAULT_PRIVATE_KEY_URL"] |= $keyvault_private_key_password_url' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg keyvault_public_cert_prefix_url "$pc_kv_uri/secrets/PUBLIC-CERT-" '.["sample:auth:dev:KEYVAULT_PUBLIC_CERT_PREFIX_URL"] |= $keyvault_public_cert_prefix_url' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg public_keys_url "https://auth.$AUTH_DOMAIN/api/auth/keys" '.["sample:auth:dev:PUBLIC_KEYS_URL"] |= $public_keys_url' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg redirect_uri "https://auth.$AUTH_DOMAIN/api/auth/token" '.["sample:auth:dev:REDIRECT_URI"] |= $redirect_uri' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg allowed_origins "https://wfe.$AUTH_DOMAIN" '.["sample:common:dev:ALLOWED_ORIGINS"] |= $allowed_origins' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg audience "https://api.$AUTH_DOMAIN" '.["sample:common:dev:AUDIENCE"] |= $audience' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg base_domain "$AUTH_DOMAIN" '.["sample:common:dev:BASE_DOMAIN"] |= $base_domain' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg issuer "https://auth.$AUTH_DOMAIN" '.["sample:common:dev:ISSUER"] |= $issuer' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg login_url "https://auth.$AUTH_DOMAIN/api/auth/authorize" '.["sample:wfe:dev:LOGIN_URL"] |= $login_url' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json
jq --arg me_url "https://api.$AUTH_DOMAIN/api/identity/me" '.["sample:wfe:dev:ME_URL"] |= $me_url' appconfig.json > tmpconfig.json && mv tmpconfig.json appconfig.json

# Import appconfig.json into Azure App Config Resource
az appconfig kv import --name $APP_CONFIG_NAME --source file --path appconfig.json --format json --yes