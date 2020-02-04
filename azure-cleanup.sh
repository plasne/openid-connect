# User set variables
SUBSCRIPTION="<your-azure-subscription>"
RG="<your-resource-group>"
AUTH_DISPLAY_NAME="<your-auth-service-name>"
WFE_DISPLAY_NAME="<your-wfe-name>"
API_DISPLAY_NAME="<your-api-name>"


echo "Delete resource group $RG"
az group delete --name $RG --subscription $SUBSCRIPTION --no-wait --yes

echo "Delete app registrations from Azure Active Directory"
auth_app_id=$(az ad app list --filter "displayName eq '$AUTH_DISPLAY_NAME'" --query [0].appId --output tsv)
az ad app delete --id $auth_app_id
wfe_app_id=$(az ad app list --filter "displayName eq '$WFE_DISPLAY_NAME'" --query [0].appId --output tsv)
az ad app delete --id $wfe_app_id