# Version 4

Version 4 supports a number of new and streamlined features. Breaking changes...

## NetBricks

I developed a new dependency package that takes care of...

-   Configuration Management
-   Access Tokens
-   Console Logging

...called NetBricks. This solution now uses this package instead of the one-off implementation.

## Google ID Support - LIMITED

This version brings limited support for a second identity provider (IDP) -> Google. You can enable support simply by providing the GOOGLE_CLIENT_ID parameter. The following limitations apply:

-   Authentication is limited to OpenID id_tokens only.
-   AuthCode is _not_ supported.
-   Reissue is _not_ supported.
-   Roles of any kind initiated from Google are _not_ supported. You can use custom claims (including roles) via IClaimsBuilder.

It is likely that I will add AuthCode and Reissue support in the near future - there is no technical reason that cannot be added. It is unclear if I will be able to support REQUIRE_USER_ENABLED_ON_REISSUE or querying for roles.

To direct the /cas/authorize endpoint to use the Google IDP, you need to specify the querystring parameter of "idp=google" (ex. http://localhost:5100/cas/authorize?idp=google).

GOOGLE_EMAIL_MUST_BE_VERIFIED is "true" by default and requires the "email_verified" claim must be "true" in the id_token received from Google. You can turn that check off by supplying "false".

GOOGLE_DOMAIN_HINT can be used to provide a domain hint for the login.

**NOTE:** Google support only applies to authentication, this solution is still largely an Azure-first solution. While Google support is optional, Azure support is required. You must create an application in Azure, if you choose to use configuration management or a key vault, those must be in Azure.

## Config

**BREAKING CHANGE:** Previous versions stored in IStorageCollection as "ICasConfig", now it is "IConfig".

If you need to get access to the CasConfig, you will access it slightly differently...

```c#
public class AddClaimsFromUserDb : ICasClaimsBuilder
{

    public AddClaimsFromUserDb(IConfig config)
    {
        this.Config = config as CasConfig;
    }

    private CasConfig Config { get; }

    public async Task AddClaimsAsync(IEnumerable<Claim> inClaims, List<Claim> outClaims)
    {
        int myVar = Config.Get<string>("MY_VARIABLE").AsInt(() => 0);
    }

}
```

Generally everything you need to do could just use the IConfig interface (for example, everything shown above), but you can also cast to CasConfig as I have shown.

## CasEnv - REMOVED

The actual methods and properties for configuration values were previously stored in a class called CasEnv. The CasEnv file no longer exists, instead all those methods and properties are now in NetBricks.Config and CasAuth.CasConfig.

## CasAuthChooser - REPLACED

The CasAuthChooser file no longer exists, instead the functionality has been moved to NetBricks.AccessTokenFetcher. There is still an AUTH_TYPE environment variable that works the same way.

## Azure Prefix

A bunch of environment variables are now prefixed with AZURE\_ to differentiate from GOOGLE\_ or any other IDPs that might be added in the future, including...

-   AZURE_TENANT_ID
-   AZURE_CLIENT_ID
-   AZURE_CLIENT_SECRET
-   AZURE_TENANT_ID_CONFIG
-   AZURE_CLIENT_ID_CONFIG
-   AZURE_CLIENT_SECRET_CONFIG
-   AZURE_TENANT_ID_VAULT
-   AZURE_CLIENT_ID_VAULT
-   AZURE_CLIENT_SECRET_VAULT
-   AZURE_TENANT_ID_GRAPH
-   AZURE_CLIENT_ID_GRAPH
-   AZURE_CLIENT_SECRET_GRAPH
-   AZURE_AUTHORITY
-   AZURE_DOMAIN_HINT
-   AZURE_APPLICATION_ID

The original names still work if you want to use those, but ideally use the new names going forward.

## IDP Claim

Tokens issued will now include a claim (named "idp") showing which IDP was used. It will be "Azure" or "Google".

## SingleLineConsoleLogger

The SingleLineConsoleLogger will now be added via AddCasClientAuth and AddCasServerAuth. This makes the logs easier to read and can improve performance.

You must clear the existing providers (to remove the normal console logger) in order for it to work, but there is no need to configure it separately. Here is an example of clearing the providers and adding the Web App provider...

```c#
class Program
{
    ...

    public static IWebHostBuilder CreateWebHostBuilder(string[] args)
    {
        var builder = WebHost.CreateDefaultBuilder(args)
            .ConfigureLogging(logging =>
            {
                logging.ClearProviders();
                logging.AddAzureWebAppDiagnostics();
            })
            .UseStartup<Startup>();
        builder.UseUrls($"http://*:{Port}");
        return builder;
    }

}
```

## AddCasClientAuthAsync and AddCasServerAuthAsync

AddCasClientAuth and AddCasServerAuth always blocked the primary thread while starting up. This is not much of a concern since you cannot use the solution until it starts up anyway. However, you can now use the async methods with await if desired.

## AUDIENCE fix

For several versions, AUDIENCE didn't actually work, it was instead set to ISSUER - this has been fixed.
