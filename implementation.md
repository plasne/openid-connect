# Implementation

The easiest way to deploy these services is to watch these videos.

-   [Getting Started Video - Local Debugging](https://youtu.be/kMpGEP6CKJY)
-   [Getting Started Video - Deploying to AKS](https://youtu.be/3dun4aDWv0U)

The rest of this page will include quick-start guides for deployment followed by details if you need to dig further.

If you already know how to implement this solution and are just looking for samples configs, look [here](./configuration.md).

With regards to authentication, you can also think of this as the "server". It will generate tokens that will verified and used by the APIs or "clients".

## Quick-Start for Local Host

This guide assumes you are using:

-   dotnetcore 3.1 or better
-   Visual Studio Code

This guide does not address developing a web front end, only the server and client for authentication.

1. Perform the following to create the projects for the server and client...

```bash
# create the auth project (server)
mkdir auth
dotnet new webapi
dotnet add package CasAuth

# delete the project parts you won't need, we use Kestrel and env vars
rm appsettings*.json
rm -r Properties

# create the api project (client)
cd ..
mkdir api
dotnet new webapi
dotnet add package CasAuth

# delete the project parts you won't need, we use Kestrel and env vars
rm appsettings*.json
rm -r Properties
```

2. Create an application in Azure AD with the following specifications...

    - Reply URL of "http://localhost:5100/cas/token".
    - Enable implicit grant for "ID tokens" only (not Access tokens).

3. Create an .env file in the root of the auth folder with the following (use the TENANT_ID and CLIENT_ID from step 2)...

```bash
LOG_LEVEL=Debug
USE_INSECURE_DEFAULTS=true
TENANT_ID=00000000-0000-0000-0000-000000000000
CLIENT_ID=00000000-0000-0000-0000-000000000000
```

4. Modify the Program.cs to resemble the following...

```c#
using System;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using dotenv.net;
using CasAuth;

namespace auth
{
    public class Program
    {

        private static string LogLevel
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("LOG_LEVEL");
            }
        }

        private static string HostUrl
        {
            get
            {
                // http://localhost:5100 by default when using USE_INSECURE_DEFAULTS
                return System.Environment.GetEnvironmentVariable("HOST_URL") ?? CasEnv.ServerHostUrl;
            }
        }

        public static void Main(string[] args)
        {
            DotEnv.Config(false, ".env");
            CreateWebHostBuilder(args).Build().Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args)
        {
            var builder = WebHost.CreateDefaultBuilder(args)
                .ConfigureLogging(logging =>
                {
                    logging.AddConsole();
                    if (Enum.TryParse(LogLevel, out Microsoft.Extensions.Logging.LogLevel level))
                    {
                        logging.SetMinimumLevel(level);
                    }
                    else
                    {
                        logging.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Information);
                    }
                })
                .UseStartup<Startup>();
            if (!string.IsNullOrEmpty(HostUrl)) builder.UseUrls(HostUrl);
            return builder;
        }

    }
}
```

5. Modify the Startup.cs to resemble the following...

```c#
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using CasAuth;

namespace auth
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCasServerAuth();
            services.AddControllers();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseCors();
            app.UseCasServerAuth();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
```

6. You can now run the application...

```c#
dotnet run
```

7. From another terminal prompt, you can test that the endpoint is working...

```bash
curl -i http://locahost:5100/cas/keys
```

...it should return something like...

```bash
HTTP/1.1 200 OK
Date: Fri, 07 Feb 2020 15:54:38 GMT
Content-Type: application/json; charset=utf-8
Server: Kestrel
Transfer-Encoding: chunked

{"keys":...}
```

8. You can further test that a login can be succesful by opening a browser, opening the network developer tools, and going to...

```
http://localhost:5100/cas/authorize
```

...you should get a "user" cookie returned from the /cas/token endpoint containing the session_token and another cookie called "XSRF-TOKEN" that contains the xsrf_token. You will need both of those values for later testing.

9. Create an .env file in the root of the api folder with the following...

```bash
LOG_LEVEL=Debug
USE_INSECURE_DEFAULTS=true
```

10. Modify the Program.cs to resemble the following...

```c#
using System;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using dotenv.net;
using CasAuth;

namespace api
{
    public class Program
    {

        private static string LogLevel
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("LOG_LEVEL");
            }
        }

        private static string HostUrl
        {
            get
            {
                // http://localhost:5200 by default when using USE_INSECURE_DEFAULTS
                return System.Environment.GetEnvironmentVariable("HOST_URL") ?? CasEnv.ClientHostUrl;
            }
        }

        public static void Main(string[] args)
        {
            DotEnv.Config(false, ".env");
            CreateWebHostBuilder(args).Build().Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args)
        {
            var builder = WebHost.CreateDefaultBuilder(args)
                .ConfigureLogging(logging =>
                {
                    logging.AddConsole();
                    if (Enum.TryParse(LogLevel, out Microsoft.Extensions.Logging.LogLevel level))
                    {
                        logging.SetMinimumLevel(level);
                    }
                    else
                    {
                        logging.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Information);
                    }
                })
                .UseStartup<Startup>();
            if (!string.IsNullOrEmpty(HostUrl)) builder.UseUrls(HostUrl);
            return builder;
        }

    }
}
```

11. Modify the Startup.cs to resemble the following...

```c#
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using CasAuth;

namespace api
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCasClientAuth();
            services.AddControllers();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseCors(); // <-- note this needs CORS, AuthN, and AuthZ
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseCasClientAuth();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
```

12. You can now run the application...

```c#
dotnet run
```

13. From another terminal prompt, you can test that the endpoint is working using the session_token from step 8 above...

```bash
curl -i -H "Cookie: user=session_token_goes_here" -H "X-XSRF-TOKEN: xsrf_token_goes_here" http://locahost:5200/cas/me
```

...it should return something like...

```bash
HTTP/1.1 200 OK
Date: Fri, 07 Feb 2020 16:10:29 GMT
Content-Type: application/json; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Server: Kestrel

{"email":...}
```

## AUTH_TYPE

When using Service-to-Service authentication (including reading configuration from Azure App Configuration and Azure Key Vault) you will need access_tokens issued. You should decide up-front how you will are going to get those access_tokens.

Each service has an AuthChooser which selects the appropriate authentication method based on how you have configured AUTH_TYPE. It can be either "mi" (default) or "app". If set to "mi", the AuthChooser will use a Managed Identity (or failback to use az-cli when running locally) every time it needs an access_token. If set to "app", the AuthChooser will use an application service principal (the application created in the above section).

There are pros and cons with each option:

| Type                          | Pros                                                                                                                          | Cons                                                                                                                                                                                |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Managed Identity              | Execution of the code on the server and debugging locally are both easy because MI is used when possible and az-cli when not. | Debugging locally, automated testing on a build agent, and running on a server will all use different security principals making testing and reproduction of issues more difficult. |
| Application Service Principal | The same credentials are used everywhere.                                                                                     | The CLIENT_SECRET must be provided to the auth and API services as an environment variable.                                                                                         |

I am of the opinion that Managed Identity should be used because it is the safest method, but it also makes adequate testing more difficult.

## DNS and SSL

Generally there are at least 3 roles for your application (the authentication service, the API, and the static web assets). Commonly you are going to host these on a different sub-domain sharing a base domain, for example:

-   WEB - web.plasne.com

-   API - api.plasne.com

-   AUTH - auth.plasne.com

All the services share the "plasne.com" base domain name. This is required because cookies will need to be scoped to that base domain so they can be shared. For instance, the auth service will issue a "user" cookie and "authflow" cookie that will need to passed on each call to the API service. The auth service will issue a "XSRF-TOKEN" cookie that will need to be read by the JavaScript in the WFE. The API service may need to reissue a "user" cookie.

If you are using this as a centralized authentication service across multiple applications, all applications must share a common base domain.

In the rare event that all of these roles are hosted on the same domain, you can take advantage of DEFAULT_HOST_URL.

## Azure AD Application

This solution supports a centralized authentication service that can be used across multiple applications. If you are configuring for a single application versus multiple applications the configuration is somewhat different; follow the appropriate documentation below.

### Single Application

1. Create an Azure AD Application. Hereafter this will be referred to as the "primary application".

    - The "Supported account type" option can be set as appropriate.

    - The "Redirect URI" should be the /api/auth/token endpoint of the authentication service once you deploy it (ex. https://auth.plasne.com/api/auth/token). This will later be stored as the setting REDIRECT_URI.

2. On the "Authentication" tab, put a check in the "ID tokens" box under "Implicit grant".

3. If you need the AuthCode flow or plan on using AUTH_TYPE=app (both uncommon), you will need to generate a "Client secret" under the "Certificates & secrets" tab. If you generate one now, be sure and keep it somewhere as you won't be able to see it later.

4. If you want to define roles for your application, you should do so now in the "Manifest" tab under "appRoles". https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-add-app-roles-in-azure-ad-apps

5. If you have defined roles for your application and you are using AUTH_TYPE=app, you must give the application permission (not delegated permission) of Microsoft Graph Directory.Read.All on the "API permissions" tab. This access right requires administrative consent - the link is provided on the same page.

6. Make note of the "Application (client) ID" on the "Overview" tab, you will need it later for the CLIENT_ID setting (and possibly the APPLICATION_ID setting).

### Multiple Applications

1. Follow steps 1, 2, 3, 5 (if you plan to use roles in any application), and 6 above to create the primary application.

2. Follow steps 1 and 4 above for each application you will be providing authentication for.

3. If you are defining roles for your applications, make note of each "Application (client) ID" on the "Overview" tab of each. You will need them later for the APPLICATION_ID setting.

## Azure Key Vault

It is possible to configure all settings in environment variables, .env files, or Azure App Configuration, so a Key Vault is not required, however, it is strongly recommended that all secrets be stored in the Key Vault.

Follow these steps to configure the Azure Key Vault service...

1. Deploy an Azure Key Vault resource. There are no specific SKUs or configuration options needed, anything should be fine.

2. If you generated a "Client secret", store it in the Key Vault as a secret.

3. Generate a self-signed public certificate and private key.

```bash
openssl req -x509 -newkey rsa:4096 -keyout privatekey.pem -out certificate.pem -days 365
openssl pkcs12 -export -inkey privatekey.pem -in certificate.pem -out cert.pfx
```

4. Store the PFX as a base64-encoded secret.

```bash
openssl base64 -in cert.pfx
```

5. Store the password for the PFX as a secret.

6. Store the public certificate as a secret (it is already base64-encoded). Include the BEGIN and END certificate sections. The secret should end with a "0". You can have up to 4 certificates available for validation (0, 1, 2, and 3).

7. Get the URLs for each secret, you will need them for later.

```bash
# examples
https://pelasne-keyvault.vault.azure.net/secrets/CLIENTSECRET (optional)
https://pelasne-keyvault.vault.azure.net/secrets/PRIVATEKEY
https://pelasne-keyvault.vault.azure.net/secrets/PRIVATEKEYPW
https://pelasne-keyvault.vault.azure.net/secrets/PUBLIC-CERT-0
```

## Azure App Configuration

It is possible to configure settings using environment variables and/or a .env file and not use Azure App Configuration at all. If you don't specify CONFIG_KEYS, nothing will be pulled from Azure App Configuration. However, it is recommended given the number of settings that have to be coordinated and correct, that you use Azure App Configuration.

You should never store a secret in this implementation of the Azure App Configuration, the values of the keys are written to the logs, displayed on the console, and potentially even made available by PRESENT_CONFIG_X. Instead the configuration should contains URLs that point to secrets in Azure Key Vault.

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

The settings below are commonly set as environment variables and their values determined before the optional Azure App Configuration is called for additional settings.

-   PROXY - This solution uses REST APIs to communicate with Azure services. If you require a proxy to access HTTPS endpoints, then you should set this value. You can also use HTTP_PROXY or HTTPS_PROXY.

-   AUTH_TYPE (default: mi) - This can be either "mi" (default) or "app". If set to "mi", the AuthChooser will use a Managed Identity (or failback to use az CLI when running locally) every time it needs an access_token. If set to "app", the AuthChooser will use an application service principal (the application created in the above section).

-   APPCONFIG - This is the name of the App Configuration instance (ex. plasne-config) that holds your configuration settings. This is optional, you can configure all settings via environment variables.

-   CONFIG_KEYS - This is a comma-delimited list of configuration keys to pull for the specific service. All keys matching the pattern will be pulled. A setting that is already set is not replaced (so left-most patterns take precident). For example, the dev environment of the auth service might contain "app:auth:dev:\*, app:common:dev:\*". If you do not specify any CONFIG_KEYS, no variables will be set from App Configuration.

-   LOG_LEVEL (default: Information) - Specify one of Critical, Debug, Error, Information, None, Trace, Warning. This determines the logging level.

-   HOST_URL - You may specify a fully qualified URL (including protocol) to host the application on (ex. https://localhost:5000 if hosting locally).

-   USE_INSECURE_DEFAULTS (default: false) - When running in localhost debug mode, some additional (though insecure) defaults can be used, most notably, default certificates can be used for signing and verifying the JWT. You will never run with this setting in production.

If you are going to use AUTH_TYPE=mi, the above settings are the only things you will commonly set. If you are going to use AUTH_TYPE=app, you must supply the following settings:

-   TENANT_ID - This is the tenant ID of the Azure AD directory that contains the CLIENT_ID.

-   CLIENT_ID - This is the Client ID of the application that will be used to authenticate the user (step 5 from the Azure AD Application section above).

-   CLIENT_SECRET - This is the client secret (step 3 from the Azure AD Application section above) for the CLIENT_ID.

### Recommended

Generally, you should supply these settings. These are shown in the format that they would be used by Azure App Configuration, but you can always supply these via simple environment variable (ex. SERVER_HOST_URL).

-   app:common:env:SERVER_HOST_URL - This allows you to specify the fully qualified URL of the authentication service (ex. https://auth.plasne.com). Using this setting in conjunction with CLIENT_HOST_URL and WEB_HOST_URL will be able to set many of the default values. When unspecified and USE_INSECURE_DEFAULTS is true, this will default to http://localhost:5100.

-   app:common:env:CLIENT_HOST_URL - This allows you to specify the fully qualified URL of the authentication service (ex. https://api.plasne.com). Using this setting in conjunction with SERVER_HOST_URL and WEB_HOST_URL will be able to set many of the default values. When unspecified and USE_INSECURE_DEFAULTS is true, this will default to http://localhost:5200.

-   app:common:env:WEB_HOST_URL - This allows you to specify the fully qualified URL of the static web assets (ex. https://web.plasne.com). Using this setting in conjunction with SERVER_HOST_URL and CLIENT_HOST_URL will be able to set many of the default values. When unspecified and USE_INSECURE_DEFAULTS is true, this will default to http://localhost:5000.

-   app:auth:env:TENANT_ID - This is the tenant ID of the Azure AD directory that contains the CLIENT_ID. You must have a CLIENT_ID, but it could have already been set by using AUTH_TYPE=app, and if that is the case, it does not need to be in the App Configuration settings.

-   app:auth:env:CLIENT_ID - This is the Client ID of the application that will be used to authenticate the user (step 5 from the Azure AD Application section above). You must have a CLIENT_ID, but it could have already been set by using AUTH_TYPE=app, and if that is the case, it does not need to be in the App Configuration settings.

### Optional

Generally these settings do not need to be modified, but there are many configuration options available to use. These are shown in the format that they would be used by Azure App Configuration, but you can always supply these via simple environment variable (ex. DEFAULT_HOST_URL).

-   app:common:env:DEFAULT_HOST_URL - This allows you to specify the fully qualified URL that will act as the default for SERVER_HOST_URL, CLIENT_HOST_URL, and WEB_HOST_URL. There is generally no need to set this unless you are using the same domain for all three.

-   app:common:env:ISSUER (default: WEB_HOST_URL) - This denotes the identity of the service that is issuing the session_token. You can put anything here, but I tend to use the URI of the centralized auth service.

-   app:common:env:AUDIENCE (default: SERVER_HOST_URL) - This denotes the identity of the service that the session_token was generated for. You can put anything here, but I tend to use the URI of the application or a base URL if this is supporting more than one application.

-   app:common:env:BASE_DOMAIN (default: derived from SERVER_HOST_URL, CLIENT_HOST_URL, and WEB_HOST_URL) - This should be the common domain shared by the WFE, API, and auth services. It will used when the cookies are created to ensure they can be shared by all services. In my example, wfe.plasne.com, api.plasne.com, and auth.plasne.com share "plasne.com" as the BASE_DOMAIN. This can be automatically calculated when SERVER_HOST_URL, CLIENT_HOST_URL, and WEB_HOST_URL or DEFAULT_HOST_URL is supplied. If you are using multiple domains, you can use the variables $RequestDomain or $RequestSubdomain; for more details see the [multiple domain](./multiple-domain) docs.

-   app:auth:env:AUTHORITY (default: derived from TENANT_ID) - This is the Microsoft endpoint that will act as the authentication authority. It should be https://login.microsoftonline.com/your_tenant_id (no trailing slash). You can get them from "Endpoints" in the "Overview" tab of your Azure AD application.

-   app:auth:env:REDIRECT_URI (default: derived from CLIENT_HOST_URL) - This is the URL that the Microsoft login process will deliver the id_token and code to. This must match the Redirect URI specified when creating the Azure AD application. If you are using multiple domains, you can use the variable $RequestDomain; for more details see the [multiple domain](./multiple-domain) docs.

-   app:common:env:ALLOWED_ORIGINS (default: WEB_HOST_URL) - This should be a comma-delimited list of URLs that are allowed by CORS policy to access the auth services.

-   app:auth:env:APPLICATION_ID - You can optionally include a comma-delimited list of application IDs. If you do, the session_token will contain the roles from those applications. Each will be projected as a claim named as the APPLICATION_ID-roles. For this to work, the application specified by CLIENT_ID must have Directory.Read.All as a Microsoft Graph Application Permission (not Delegated) - this right requires administrative consent.

-   app:auth:env:CLIENT_SECRET - This is the Client Secret of the application that will be used to authenticate the user (step 5 from the Azure AD Application section above). You only need this if using AuthCode. This could have already been set if using AUTH_TYPE=app. This commonly will be a URL to a secret in the Key Vault.

-   app:auth:env:DEFAULT_REDIRECT_URL (default: WEB_HOST_URL) - When an authentication request is started, the client can pass a "redirecturi" querystring parameter to the auth/authorize endpoint. If it does not, the DEFAULT_REDIRECT_URL is used. When the authentication flow is done, this the URL that the auth/token endpoint will redirect the user back to.

-   app:common:env:REQUIRE_SECURE_FOR_COOKIES (default: derived from SERVER_HOST_URL, CLIENT_HOST_URL, and WEB_HOST_URL) - This determines whether cookies are marked "secure", meaning they will only be sent to HTTPS endpoints. If your URLs are all HTTPS when this defaults to "true", otherwise "false".

-   app:auth:env:JWT_DURATION (default: 240) - The number of minutes after an session_token is issued before it expires. This defaults to 4 hours (240 minutes).

-   app:auth:env:JWT_SERVICE_DURATION (default: JWT_DURATION) - The number of minutes after an session_token is issued to a service account using the client credential grant before it expires.

-   app:auth:env:JWT_MAX_DURATION (default: 10080) - You can specify a number of minutes that determines the maximum time for an session_token is allowed to exist (including reissue). It defaults to 7 days (10080 minutes). You may also specify 0 to allow the token to be reissued forever.

-   app:auth:env:PRIVATE_KEY - This is the key that will be used to sign the JWTs issued by the auth service. This commonly will be a URL to a secret in the Key Vault.

-   app:auth:env:PRIVATE_KEY_PASSWORD - The private key is in PFX format, which requires a password for export. This allows you to specify the password you used when creating the PFX. This commonly will be a URL to a secret in the Key Vault.

-   app:auth:env:PUBLIC_CERT_index (0, 1, 2, 3) - Rather than store the public certificates in the Key Vault, it is possible to specify PUBLIC_CERT_0, PUBLIC_CERT_1, PUBLIC_CERT_2, and/or PUBLIC_CERT_3 as environment variables instead. These commonly will be URLs to secrets in the Key Vault.

-   app:api:env:WELL_KNOWN_CONFIG_URL (default: derived from SERVER_HOST_URL) - This is the URL of the auth/.well-known/openid-configuration endpoint.

-   app:auth:env:PUBLIC_KEYS_URL (default: derived from SERVER_HOST_URL) - This is the URL of the auth/keys endpoint. The auth service presents an auth/.well-known/openid-configuration that contains this endpoint so that the API can validate the JWT signature using the public keys.

-   app:api:env:REISSUE_URL (default: derived from SERVER_HOST_URL) - This is the URL of the reissue endpoint. You could set this to "false" if you don't want tokens to be reissued.

-   app:auth:env:DOMAIN_HINT - If you want to provide a domain hint when authenticating, you can specify it.

-   app:auth:env:REQUIRE_USER_ENABLED_ON_REISSUE (default: true) - Before a token is reissued, the "accountEnabled" status of the user is checked to ensure it is "true". However, if you set REQUIRE_USER_ENABLED_ON_REISSUE to "false", this check will be ignored. Querying the "accountEnabled" property of a user requires Directory.Read.All or User.Read.All.

-   app:auth:env:COMMAND_PASSWORD (default: secret) - Administrative functions for the authentication service require a command password as proof of authority (this is because the authentication might not be working for the actual authentication service). This commonly will be a URL to a secret in the Key Vault.

-   app:api:env:PRESENT_CONFIG_X - You may create one or more PRESENT_CONFIG_X keys that allow you to specify configurations that can be presented by your API at api/config/x. For example, you could create the following variable "PRESENT_CONFIG_WFEDEV=app:wfe:dev:\*". All keys under that filter would be returned when someone hit the /api/config/webdev endpoint. Primarily this is provided so your WFE can be configured by Azure App Configuration in the same way as the other services. It is required that the entire PRESENT_CONFIG_X key be uppercase, though calling the api/config/x endpoint is not case-sensitive.

-   app:auth:env:USER_COOKIE_NAME (default: user) - The name of the cookie that is used for the session_token.

-   app:auth:env:ROLE_FOR_ADMIN (default: admin) - The name of the role that must be verified in order to perform client administrative functions.

-   app:auth:env:ROLE_FOR_SERVICE (default: service) - The name of the role that indicates this authentication is for a service (for instance, will accept an authentication bearer token).

- app:common:env:IS_HTTPS (default: derived) - You can specifically set whether URLs that are generated by defaults in the configuration are HTTP or HTTPS using this flag. You should generally just let the application decide. If you want more details, look at the [version 3](./version3.md) docs for how this is implemented.

- app:common:env:SAME_SITE (default: lax) - This determines the same-site field for all cookies. You can specifically set this value to "strict" or "none" (though many browsers will no longer respect "none"). Many browsers now require "lax" for Javascript to be able to read the XSRF-TOKEN cookie. Generally you should leave this on "lax", but if you used a single domain for API, auth, and WFE, you might set it to "strict".

### Alternate Service Authentication

In some rare cases, you might need separate methods of authetication to Azure services, if so, you can use these settings.

-   app:common:env:AUTH_TYPE_CONFIG (default: AUTH_TYPE) - Generally, you just need to use AUTH_TYPE which applies to everything, but if you needed a different method for accessing Azure App Configuration, you can specify it specifically.

-   app:auth:env:AUTH_TYPE_VAULT (default: AUTH_TYPE) - Generally, you just need to use AUTH_TYPE which applies to everything, but if you needed a different method for accessing Azure Key Vault, you can specify it specifically.

-   app:auth:env:AUTH_TYPE_GRAPH (default: AUTH_TYPE) - Generally, you just need to use AUTH_TYPE which applies to everything, but if you needed a different method for accessing the Microsoft Graph, you can specify it specifically.

-   app:common:env:TENANT_ID_CONFIG (default: TENANT_ID) - Generally, you just need to use TENANT_ID which specifies the tenant to use for all AUTH_TYPE=app calls, but if you need something different for accessing Azure App Configuration, you can specify it specifically.

-   app:common:env:CLIENT_ID_CONFIG (default: CLIENT_ID) - Generally, you just need to use CLIENT_ID which specifies the application ID to use for all AUTH_TYPE=app calls, but if you need something different for accessing Azure App Configuration, you can specify it specifically.

-   app:common:env:CLIENT_SECRET_CONFIG (default: CLIENT_SECRET) - Generally, you just need to use CLIENT_SECRET which specifies the secret to use for all AUTH_TYPE=app calls, but if you need something different for accessing Azure App Configuration, you can specify it specifically.

-   app:auth:env:TENANT_ID_VAULT (default: TENANT_ID) - Generally, you just need to use TENANT_ID which specifies the tenant to use for all AUTH_TYPE=app calls, but if you need something different for accessing the Azure Key Vault, you can specify it specifically.

-   app:auth:env:CLIENT_ID_VAULT (default: CLIENT_ID) - Generally, you just need to use CLIENT_ID which specifies the application ID to use for all AUTH_TYPE=app calls, but if you need something different for accessing Azure Key Vault, you can specify it specifically.

-   app:auth:env:CLIENT_SECRET_VAULT (default: CLIENT_SECRET) - Generally, you just need to use CLIENT_SECRET which specifies the secret to use for all AUTH_TYPE=app calls, but if you need something different for accessing Azure Key Vault, you can specify it specifically.

-   app:auth:env:TENANT_ID_GRAPH (default: TENANT_ID) - Generally, you just need to use TENANT_ID which specifies the tenant to use for all AUTH_TYPE=app calls, but if you need something different for accessing the Microsoft Graph, you can specify it specifically.

-   app:auth:env:CLIENT_ID_GRAPH (default: CLIENT_ID) - Generally, you just need to use CLIENT_ID which specifies the application ID to use for all AUTH_TYPE=app calls, but if you need something different for accessing the Microsoft Graph, you can specify it specifically.

-   app:auth:env:CLIENT_SECRET_GRAPH (default: CLIENT_SECRET) - Generally, you just need to use CLIENT_SECRET which specifies the secret to use for all AUTH_TYPE=app calls, but if you need something different for accessing the Microsoft Graph, you can specify it specifically. If specified, this commonly will be a URL to a secret in the Key Vault.

### Use Authorization Bearer Mode

For users, the normal behavior is for the session_token to be stored in a user cookie marked HttpOnly and the XSRF code to be stored in a XSRF-TOKEN cookie that is readable by JavaScript. When a request goes to the server, it validates based on the user cookie and the X-XSRF-TOKEN header. This pattern was developed by looking at the common pattern for Angular applications. This configuration is the default, but includes the following settings:

-   app:common:env:REQUIRE_HTTPONLY_ON_USER_COOKIE = true

-   app:auth:env:REQUIRE_HTTPONLY_ON_XSRF_COOKIE = false

-   app:api:env:VERIFY_TOKEN_IN_COOKIE = true

-   app:api:env:VERIFY_TOKEN_IN_HEADER = false

-   app:api:env:VERIFY_XSRF_IN_COOKIE = false

-   app:api:env:VERIFY_XSRF_IN_HEADER = true

You can reverse these settings if you want to send the session_token as an Authorization Bearer token and let the XSRF be validated by reading the cookie directly. That configuration would look like this:

-   app:common:env:REQUIRE_HTTPONLY_ON_USER_COOKIE = false

-   app:auth:env:REQUIRE_HTTPONLY_ON_XSRF_COOKIE = true

-   app:api:env:VERIFY_TOKEN_IN_COOKIE = false

-   app:api:env:VERIFY_TOKEN_IN_HEADER = true

-   app:api:env:VERIFY_XSRF_IN_COOKIE = true

-   app:api:env:VERIFY_XSRF_IN_HEADER = false

It is important that you have one cookie HttpOnly to be validated by cookie and one cookie readable by JavaScript to be validated in the header. This combination is what gives you reasonable XSS and XSRF protection. For a local debug environment that is "permissive" and lets you test any combination, you can do this (don't do this in production):

-   app:common:env:REQUIRE_HTTPONLY_ON_USER_COOKIE = false

-   app:api:env:VERIFY_TOKEN_IN_COOKIE = true

-   app:api:env:VERIFY_TOKEN_IN_HEADER = true

-   app:common:env:VERIFY_XSRF_IN_COOKIE = false

-   app:common:env:VERIFY_XSRF_IN_HEADER = false

If verification allows for both a header and cookie, the header is always checked first. If the token is not allowed to be verified by header or cookie, authentication will always fail. If the XSRF is not allowed to be verified by header or cookie, it allow authentication anyway and will not even generate an XSRF-TOKEN cookie.

Whenever REQUIRE_HTTPONLY_ON_USER_COOKIE is "false", the XSRF code will be converted into a JWT and signed so that we can be sure it has not been tampered with.

### Service Accounts

The validation of service account credentials always supports validation of the session_token via the Authorization Bearer token and validation of XSRF is skipped.

## Deploy the Services

How to deploy services in Azure is beyond the scope of this article, however, there are some things to consider for each service deployment below.

### Auth Service

Follow these steps to configure the Auth service...

1. If you intend to use AUTH_TYPE=mi, enable Managed Identity for the platform.

2. Add an access policy to Key Vault for the Managed Identity or Application Service Principal that allows GET of SECRETs. You can typically search for the identity by the resource name; it should show as APPLICATION.

3. Add an Access Control Role Assignment (IAM) in the Azure portal on the App Configuration resource for the Managed Identity or Application Service Principal. It must have the "App Configuration Data Reader" role.

4. If using APPLICATION_ID or REQUIRE_USER_ENABLED_ON_REISSUE (which is a default), then the Managed Identity or Application Service Principal must be given rights to query all objects in the Microsoft Graph:

    - Managed Identity - Follow these steps to assign grant access:

    ```bash
    # Directory.Read.All scope id 7ab1d382-f21e-4acd-a863-ba3e13f7da61
    az ad app permission add --id $your_app_id --api 00000003-0000-0000-c000-000000000000 --api-permissions 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Scope
    az ad app permission grant --id $your_app_id --api 00000003-0000-0000-c000-000000000000
    ```

    - Application Service Principal - You can give the Application (not Delegated) Microsoft Graph Directory.Read.All rights. This will require consent of an Azure AD Global Administrator.

5. If you are deploying on a Windows-based App Service, you must add WEBSITE_LOAD_USER_PROFILE=1 as per https://github.com/projectkudu/kudu/wiki/Configurable-settings#the-system-cannot-find-the-file-specified-issue-with-x509certificate2.

6. If you deployed prior to applying the above configuation, you might need to restart your service; the configuration is only read when the application starts.

You can test the following (use your URL, this is a sample):

-   https://auth.plasne.com/cas/keys - This should show the public certificate for validating the session_token. If this is displayed, the AuthChooser is working and the account has access to the Key Vault.

-   https://auth.plasne.com/cas/check-requirements - This should return a 200 if the Microsoft Graph can be queried for all users (requires Directory.Read.All).

### API Service

Follow these steps to configure the API service...

1. If you intend to use AUTH_TYPE=mi, enable Managed Identity for the platform.

2. Add an access policy to Key Vault for the Managed Identity or Application Service Principal that allows GET of SECRETs. You can typically search for the identity by the resource name; it should show as APPLICATION.

3. Add an Access Control Role Assignment (IAM) in the Azure portal on the App Configuration resource for the Managed Identity or Application Service Principal. It must have the "App Configuration Data Reader" role.

4. If you deployed prior to applying the above configuation, you might need to restart your service; the configuration is only read when the application starts.

### WFE

Follow these steps to configure the WFE...

1. You need to define an environment variable of HOST_URL and CONFIG_URL. The port from the HOST_URL will determine which port the WFE runs on. The CONFIG_URL should point to the URL where the configuration will be obtained, for example:

```bash
HOST_URL=http://localhost:5000
CONFIG_URL=https://api.plasne.com/api/config/wfe
```

The WFE sample only has 2 parameters:

```json
{
    "sample:wfe:local:LOGIN_URL": "https://auth.plasne.com/api/auth/authorize",
    "sample:wfe:local:ME_URL": "https://api.plasne.com/api/identity/me"
}
```

2. You can start the node server by the following...

```bash
npm install
node index.js
```

### Tools

Generally you need to set the .env file for tools the same as your server configuration.

### Multi-Tenant

It is possible to configure this application to work for multi-tenant. You need to make the following changes:

-   You need to specify an AUTHORITY of "https://login.microsoftonline.com/common".

-   You need to change the main application registration to "multi-tenant". You can find that under "Auth" and then "Supported account types".

You can invite users from other directories as guests into your AAD directory if you want to assign roles to the users in your applications. This is not a requirement if you don't need roles from AAD.

When configured for multi-tenant the following changes can be observed:

-   A "tenant" claim containing the Azure AD Tenant ID will be added to the session_token.

-   The oid that comes in the id_token is the id in the user's home directory, not their B2B id in your application's directory. Since, that is not useful, the claim written to the session_token is fixed so it is the oid in the application's directory.

-   If there would be a "roles" claim for the primary application, it will not be included. This is an unfortunate side effect of the oid claim asserted in the id_token not being the id for the user in the application's directory. However, you can still include that application in the APPLICATION_ID list and it will be included as a separate claim.

## Steps to implement using Visual Studio Online (Linux)

[Clone Repository with Visual Studio Online](https://online.visualstudio.com/environments/new?name=Centralized%20Auth%20Service&repo=plasne/openid-connect)

1. Open the link above.
1. Create a Visual Studio Online plan associated with an active Azure subscription.
1. Connect to the environment.
1. Open a new terminal by `[ctrl]+[backtick]` and run `git checkout -b version1 origin/version1`.
1. Install the package jq by running `sudo apt-get install jq`. It is used by the azure-deploy.sh script to manipulate json files.
1. Copy the .gitignore file from the root into the auth, api, and wfe folders. This is very important because it keeps the .env files from being published.
1. Change the _user set variables_ in the azure-deploy.sh file and save.
1. In the terminal, run `bash azure-deploy.sh`. Note: the script uses the Azure CLI to create the resources; You must log in for it to work.
1. After deployment is complete, run the following commands in three seperate terminals:

```
cd wfe/
npm install
node index.js
```

```
cd api/
dotnet run
```

```
cd auth/
dotnet run
```

### Port forwarding

1. Open the Remote Explorer activity pane
1. In the Environment Details panel, click the Forward Port button that appears when you hover over Forwarded Ports (#)
1. Enter port 5000 in the prompt
1. Accept the default name
1. Repeat for ports 5100 and 5200
1. Click the Copy Port URL button in the localhost:5000 title bar
1. Paste the URL into the browser of your choice.

Note: VS Online has forwarded the environment's port 5000 to a location you can now access
