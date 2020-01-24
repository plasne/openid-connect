# Set variables
SUBSCRIPTION="PROD_EMIT_AzureSandbox"
RG="delete-tyler-auth-rg"
AUTH_DISPLAY_NAME="delete-tyler-auth-service"
WFE_DISPLAY_NAME="delete-tyler-my-app"
API_DISPLAY_NAME="delete-tyler-my-api"


echo "Delete resource group $RG"
az group delete --name $RG --subscription $SUBSCRIPTION --no-wait --yes

echo "Delete app registrations from Azure Active Directory"
auth_app_id=$(az ad app list --filter "displayName eq '$AUTH_DISPLAY_NAME'" --query [0].appId --output tsv)
az ad app delete --id $auth_app_id
wfe_app_id=$(az ad app list --filter "displayName eq '$WFE_DISPLAY_NAME'" --query [0].appId --output tsv)
az ad app delete --id $wfe_app_id