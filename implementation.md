# Implementation

This guide walks you through implementing this sample.

## AUTH_TYPE

When using Service-to-Service authentication (including reading configuration from Azure App Configuration and Azure Key Vault) you will need access_tokens issued. You should decide up-front how you will are going to get those access_tokens.

Each service has an AuthChooser which selects the appropriate authentication method based on how you have configured AUTH_TYPE. It can be either "mi" (default) or "app". If set to "mi", the AuthChooser will use a Managed Identity (or failback to use az-cli when running locally) every time it needs an access_token. If set to "app", the AuthChooser will use an application service principal (the application created in the above section).

There are PROs and CONs with each option:

| Type                          | Pros                                                                                                                          | Cons                                                                                                                                                                                |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Managed Identity              | Execution of the code on the server and debugging locally are both easy because MI is used when possible and az-cli when not. | Debugging locally, automated testing on a build agent, and running on a server will all use different security principals making testing and reproduction of issues more difficult. |
| Application Service Principal | The same credentials are used everywhere.                                                                                     | The CLIENT_SECRET must be provided to the auth and API services as an environment variable.                                                                                         |

I am of the opinion that Managed Identity should be used because it is the safest method, but it also makes adequate testing more difficult.

## DNS and SSL

You will always have at least 3 services and they will all need to share a base domain name, for example:

-   WFE - wfe.plasne.com

-   API - api.plasne.com

-   AUTH - auth.plasne.com

All the services share the "plasne.com" base domain name. This is required because cookies will need to be scoped to that base domain so they can be shared. For instance, the auth service will issue a "user" cookie and "authflow" cookie that will need to passed on each call to the API service. The auth service will issue a "XSRF-TOKEN" cookie that will need to be read by the JavaScript in the WFE. The API service may need to reissue a "user" cookie.

If you are using this as a centralized authentication service across multiple applications, all applications must share a common base domain.

## Azure AD Application

This solution supports a centralized authentication service that can be used across multiple applications. If you are configuring for a single application versus multiple applications the configuration is somewhat different; follow the appropriate documentation below.

### Single Application

1. Create an Azure AD Application.

    - The "Supported account type" option can be set as appropriate.

    - The "Redirect URI" should be the /api/auth/token endpoint of the authentication service once you deploy it (ex. https://auth.plasne.com/api/auth/token). This will later be stored as the setting REDIRECT_URI.

2. On the "Authentication" tab, put a check in the "ID tokens" box under "Implicit grant".

3. If you need the AuthCode flow or plan on using AUTH_TYPE=app (both uncommon), you will need to generate a "Client secret" under the "Certificates & secrets" tab. If you generate one now, be sure and keep it somewhere as you won't be able to see it later.

4. If you want to define roles for your application (the APPLICATION_ID setting), you should do so now in the "Manifest" tab under "appRoles".

5. If you have defined roles for your application, you must give the application permission (not delegated permission) of Microsoft Graph Directory.Read.All on the "API permissions" tab. This access right requires administrative consent - the link is provided on the same page.

6. Make note of the "Application (client) ID" on the "Overview" tab, you will need it later for the CLIENT_ID setting (and possibly the APPLICATION_ID setting).

### Multiple Applications

1. Follow steps 1, 2, 3, 5 (if you plan to use roles in any application), and 6 above to create the auth service application.

2. Follow steps 1 and 4 above for each application you will be providing authentication for.

3. If you are defining roles for your applications, make note of each "Application (client) ID" on the "Overview" tab of each. You will need them later for the APPLICATION_ID setting.

## Azure Key Vault

Follow these steps to configure the Azure Key Vault service...

1. Deploy an Azure Key Vault resource. There are no specific SKUs or configuration options needed, anything should be fine.

2. If you generated a "Client secret", store it in the Key Vault as a secret.

3. Generate a self-signed public certificate and private key.

```bash
openssl req -x509 -newkey rsa:4096 -keyout privatekey.pem -out certificate.pem -days 365
openssl pkcs12 -export -inkey privatekey.pem -in certificate.pem -out cert.pfx
```

4. Store the PFX as a Base64-Encoded secret.

```bash
# output the PFX in base64
openssl base64 -in cert.pfx
```

5. Store the password for the PFX as a secret.

6. Store the public certificate as a secret (it is already Base64-Encoded). Include the BEGIN and END certificate sections.

7. Get the URLs for each secret, you will need them for later.

```bash
# examples
https://pelasne-keyvault.vault.azure.net/secrets/CLIENTSECRET (optional)
https://pelasne-keyvault.vault.azure.net/secrets/PRIVATEKEY
https://pelasne-keyvault.vault.azure.net/secrets/PRIVATEKEYPW
https://pelasne-keyvault.vault.azure.net/secrets/PUBLICCERT
```

## Azure App Configuration

It is possible to configure settings using environment variables and/or a .env file and not use Azure App Configuration at all. If you don't specify CONFIG_KEYS, nothing will be pulled from Azure App Configuration. However, it is recommended given the number of settings that have to be coordinated and correct, that you use Azure App Configuration.

Settings are set in the following order:

1. Environment variables, including...

    - App Service Configuration

    - Environment variables passed to a container

2. A ".env" file in the root directory

3. Azure App Configuration (provided CONFIG_KEYS is specified)

    - Environment variables are set for each key (ex. app:common:env:ISSUER would create an ISSUER environment variable)

Follow these steps to configure the Azure App Configuration service...

1. Deploy an Azure App Configuration resource. There are no specific SKUs or configuration options needed, anything should be fine.

2. Add the necessary key/value pairs in the "Configuration explorer" tab.

The setting options are described below with an example. You are encouraged to use "app:svc:env:key" as the format (application : service : environment : key).

### Local

Generally you need to specify local environment variables (this will also work in App Service Configuration) for each service to let the system know what to pull from Azure App Configuration.

-   AUTH_TYPE - This can be either "mi" (default) or "app". If set to "mi", the AuthChooser will use a Managed Identity (or failback to use az CLI when running locally) every time it needs an access_token. If set to "app", the AuthChooser will use an application service principal (the application created in the above section).

-   APPCONFIG_RESOURCE_ID - This is the Resource ID of the App Configuration instance. You can get this from the Properties tab of the App Configuration resource in the Azure portal. (ex. /subscriptions/8e95e0bb-d7cc-4454-9443-75ca862d34c1/resourceGroups/pelasne-auth-sample/providers/Microsoft.AppConfiguration/configurationStores/pelasne-auth-config)

-   CONFIG_KEYS - This is a comma-delimited list of configuration keys to pull for the specific service. All keys matching the pattern will be pulled. A setting that is already set is not replaced (so left-most patterns take precident). For example, the dev environment of the auth service might contain "app:auth:dev:\*, app:common:dev:\*". If you do not specify any CONFIG_KEYS, no variables will be set from App Configuration.

-   LOG_LEVEL (default: Information) - Specify one of Critical, Debug, Error, Information, None, Trace, Warning. This determines the logging level.

-   HOST_URL - You may specify a fully qualified URL (including protocol) to host the application on (ex. https://localhost:5000 if hosting locally).

If you are going to use AUTH_TYPE=mi, the above settings are the only things you need to set. If you are going to use AUTH_TYPE=app, you must supply the following settings:

-   TENANT_ID - This is the tenant ID of the Azure AD directory that contains the CLIENT_ID.

-   CLIENT_ID - This is the Client ID of the application that will be used to authenticate the user (step 5 from the Azure AD Application section above).

-   CLIENT_SECRET - This is the client secret (step 3 from the Azure AD Application section above) for the CLIENT_ID. If you set this setting, you never need to set KEYVAULT_CLIENT_SECRET_URL.

### Required

-   app:common:env:ISSUER - This denotes the identity of the service that is issuing the identity_token. You can put anything here, but I tend to use the URI of the centralized auth service.

-   app:common:env:AUDIENCE - This denotes the identity of the service that the identity_token was generated for. You can put anything here, but I tend to use the URI of the application or a base URL if this is supporting more than one application.

-   app:common:env:BASE_DOMAIN - This should be the common domain shared by the WFE, API, and auth services. It will used when the cookies are created to ensure they can be shared by all services. In my example, wfe.plasne.com, api.plasne.com, and auth.plasne.com share "plasne.com" as the BASE_DOMAIN.

-   app:auth:env:AUTHORITY - This is the Microsoft endpoint that will act as the authentication authority. It should be https://login.microsoftonline.com/your_tenant_id (no trailing slash). You can get them from "Endpoints" in the "Overview" tab of your Azure AD application.

-   app:auth:env:REDIRECT_URI - This is the URL that the Microsoft login process will deliver the id_token and code to. This must match the Redirect URI specified when creating the Azure AD application.

-   app:auth:env:CLIENT_ID - This is the Client ID of the application that will be used to authenticate the user (step 5 from the Azure AD Application section above). You must have a CLIENT_ID, but it could have already been set by using AUTH_TYPE=app, and if that is the case, it does not need to be in the App Configuration settings.

-   app:auth:env:DEFAULT_REDIRECT_URL - When an authentication request is started, the client can pass a "redirecturi" querystring parameter to the auth/authorize endpoint. If it does not, the DEFAULT_REDIRECT_URL is used. When the authentication flow is done, this the URL that the auth/token endpoint will redirect the user back to.

-   app:auth:env:ALLOWED_ORIGINS - This should be a comma-delimited list of URLs that are allowed by CORS policy to access the auth services. You could use app:common:env:ALLOWED_ORIGINS if the origins were the same for the API.

-   app:auth:env:KEYVAULT_PRIVATE_KEY_URL - This is the URL of the PFX file stored in step 4 of the Azure Key Vault section above.

-   app:auth:env:KEYVAULT_PRIVATE_KEY_PASSWORD_URL - This is the URL of the PFX file password stored in step 5 of the Azure Key Vault section above.

-   app:auth:env:KEYVAULT_PUBLIC_CERT_URL - This is the URL of the public certificate stored in step 6 of the Azure Key Vault section above.

-   app:api:env:ALLOWED_ORIGINS - This should be a comma-delimited list of URLs that are allowed by CORS policy to access the API services. You could use app:common:env:ALLOWED_ORIGINS if the origins were the same for the auth service.

-   app:api:env:PUBLIC_CERTIFICATE_URL - This is the URL of the auth/certificate endpoint. The auth service presents that certificate so the API can use it to validate the identity_token's signature.

### Optional

-   app:common:env:REQUIRE_SECURE_FOR_COOKIES (default: true) - This determines whether cookies are marked "secure", meaning they will only be sent to HTTPS endpoints. If you are running the API and/or auth service locally without SSL, you need to set this to "false".

-   app:auth:env:JWT_DURATION (default: 240) - The number of minutes after an identity_token is issued before it expires. This defaults to 4 hours (240 minutes).

-   app:auth:env:JWT_MAX_DURATION (default: 10080) - You can specify a number of minutes that determines the maximum time for an identity_token is allowed to exist (including reissue). It defaults to 7 days (10080 minutes). You may also specify 0 to allow the token to be reissued forever.

-   app:auth:env:DOMAIN_HINT - If you want to provide a domain hint when authenticating, you can specify it.

-   app:auth:env:APPLICATION_ID - You can optionally include a comma-delimited list of application IDs. If you do, the identity_token will contain the roles from those applications. Each will be projected as a claim named as the APPLICATION_ID-roles. For this to work, the application specified by CLIENT_ID must have Directory.Read.All as a Microsoft Graph Application Permission (not Delegated) - this right requires administrative consent.

-   app:auth:env:KEYVAULT_CLIENT_SECRET_URL - If you are going to use AuthCode, then you need to specify this parameter unless you have already specified CLIENT_SECRET. This would be the URL from step 7 under the Azure Key Vault section above.

-   app:api:env:REISSUE_URL - If you are going to allow for tokens to be reissued, then you need to specify the URL of the auth/reissue endpoint.

-   app:api:env:PRESENT_CONFIG_name - You may create one or more PRESENT_CONFIG_name keys that allow you to specify configurations that can be presented by your API at api/config/name. For example, you could create the following variable "PRESENT_CONFIG_wfedev=app:wfe:dev:\*". All keys under that filter would be returned when someone hit the /api/config/webdev endpoint. Primarily this is provided so your WFE can be configured by Azure App Configuration in the same way as the other services.

-   app:srv:env:PROXY - This solution uses REST APIs to communicate with Azure services. If you require a proxy to access HTTPS endpoints, then you should add the URL of the proxy as a setting for the right scope (ex. app:common:env:PROXY for every service).

### Sample

In this sample configuration, my application is named "sample" and this configuration applies to my "dev" environment.

```json
{
    "sample:api:dev:PUBLIC_CERTIFICATE_URL": "https://auth.plasne.com/api/auth/certificate",
    "sample:api:dev:REISSUE_URL": "https://auth.plasne.com/api/auth/reissue",
    "sample:auth:dev:AUTHORITY": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47",
    "sample:auth:dev:CLIENT_ID": "a288039d-7569-4d16-af38-438d35a6e7b7",
    "sample:auth:dev:DEFAULT_REDIRECT_URL": "https://wfe.plasne.com",
    "sample:auth:dev:KEYVAULT_PRIVATE_KEY_PASSWORD_URL": "https://pelasne-keyvault.vault.azure.net/secrets/PRIVATEKEYPW",
    "sample:auth:dev:KEYVAULT_PRIVATE_KEY_URL": "https://pelasne-keyvault.vault.azure.net/secrets/PRIVATEKEY",
    "sample:auth:dev:KEYVAULT_PUBLIC_CERT_URL": "https://pelasne-keyvault.vault.azure.net/secrets/PUBLICCERT",
    "sample:auth:dev:REDIRECT_URI": "https://auth.plasne.com/api/auth/token",
    "sample:common:dev:ALLOWED_ORIGINS": "https://wfe.plasne.com",
    "sample:common:dev:AUDIENCE": "https://api.plasne.com",
    "sample:common:dev:BASE_DOMAIN": "plasne.com",
    "sample:common:dev:ISSUER": "https://auth.plasne.com"
}
```

## Deploy the Services

How to deploy services in Azure is beyond the scope of this article, however, there are some things to consider for each service deployment below.

### Auth Service

Make sure you configure local environment variables for at least APPCONFIG_RESOURCE_ID and CONFIG_KEYS. CONFIG_KEYS for an application named "sample" and a "dev" environment might look like this: "sample:auth:dev:\*, sample:common:dev:\*".

If you intend to use Managed Identity (AUTH_TYPE=mi), make sure you follow these steps:

1. Enable Managed Identity for the platform.

2. Add an access policy to Key Vault for the Managed Identity that allows GET of SECRETs. You can typically search for the identity by the resource name; it should show as APPLICATION.

3. Add an Access Control Role Assignment (IAM) in the Azure portal on the App Configuration resource for the Managed Identity. It must be an OWNER because it needs to read the security keys required to access App Configuration.

If you are deploying on a Windows-based App Service, you must add WEBSITE_LOAD_USER_PROFILE=1 as per https://github.com/projectkudu/kudu/wiki/Configurable-settings#the-system-cannot-find-the-file-specified-issue-with-x509certificate2.

If you deployed prior to applying the above configuation, you might need to restart your service; the configuration is only read when the application starts.

You can test the following (use your URL, this is a sample):

-   https://auth.plasne.com/api/auth/certificate - This should show the public certificate for validating the identity_token. If this is displayed, the AuthChooser is working and the account has access to the Key Vault.

-   https://auth.plasne.com/api/auth/verify?scope=graph - This should return a 200 if the Microsoft Graph can be queried for all users (requires Directory.Read.All).

### API Service

Make sure you configure local environment variables for at least APPCONFIG_RESOURCE_ID and CONFIG_KEYS. CONFIG_KEYS for an application named "sample" and a "dev" environment might look like this: "sample:api:dev:\*, sample:common:dev:\*".

If you intend to use Managed Identity (AUTH_TYPE=mi), make sure you follow these steps:

1. Enable Managed Identity for the platform.

2. Add an access policy to Key Vault for the Managed Identity that allows GET of SECRETs. You can typically search for the identity by the resource name; it should show as APPLICATION.

3. Add an Access Control Role Assignment (IAM) in the Azure portal on the App Configuration resource for the Managed Identity. It must be an OWNER because it needs to read the security keys required to access App Configuration.

If you deployed prior to applying the above configuation, you might need to restart your service; the configuration is only read when the application starts.

You can test the following (use your URL, this is a sample):

-   https://api.plasne.com/api/identity/version - If this is displayed, the AuthChooser is working and the account has access to the Key Vault.

### WFE

You need to define an environment variable of CONFIG_URL pointing to the URL where the configuration will be obtained, for example:

```bash
CONFIG_URL=https://api.plasne.com/api/config/wfe
```

The WFE sample only has 2 parameters:

```json
{
    "sample:wfe:local:LOGIN_URL": "https://auth.plasne.com/api/auth/authorize",
    "sample:wfe:local:ME_URL": "https://api.plasne.com/api/identity/me"
}
```

## Using the Auth Service

To start a login, the browser should navigate to the auth/authorize endpoint (ex. https://auth.plasne.com/api/auth/authorize). If you want to do an automatic login, you can make a REST call to the api/identity/me endpoint (ex. https://api.plasne.com/api/identity/me), if you receive a 401 Unauthorized, you can then redirect the browser to the auth/authorize endpoint.

Whenever you make a call to an endpoint that requires authentication, you must:

-   read the value of the XSRF-TOKEN cookie and send it's contents as a header called X-XSRF-TOKEN

-   instruct XHR to send credentials (this allows the cookies to be sent)

Here is an example using jQuery:

```javascript
var xsrf = Cookies.get('XSRF-TOKEN');
$.ajax({
    method: 'GET',
    url: config.ME_URL,
    headers: {
        'X-XSRF-TOKEN': xsrf
    },
    xhrFields: { withCredentials: true }
});
```

## Tools

TODO

document stuff in API
