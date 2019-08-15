Rather than use PowerShell @ https://blog.bredvid.no/accessing-apis-using-azure-managed-service-identity-ff7802b887d?gi=f2307752395a, I was trying to get az to work, but creating the role assignment doesn't appear to work.

```bash
graphId=$(az ad sp list --filter "appId eq '00000003-0000-0000-c000-000000000000'" --query "[0].objectId")
roleId=$(az ad sp list --filter "appId eq '00000003-0000-0000-c000-000000000000'" --query "[0].appRoles[?value=='Directory.Read.All' && contains(allowedMemberTypes, 'Application')] | [0].id")
az role assignment create --role $roleId --assignee-object-id fa22d971-c442-41f2-add1-77e636f80d31 --scope $graphId --assignee-principal-type
```

It throws:

The request did not have a subscription or a valid tenant level resource provider.
