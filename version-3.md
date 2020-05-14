# Version 3

Version 3 supports a number of new and streamlined features. There is one breaking change. UseCasServerAuth() no longer takes any startup options - you must instead create classes based on ICasAuthCodeReceiver or ICasClaimsBuilder to implement the prior functionality.

## Multiple Domain Support

CasAuth now supports APIs on multiple domains authenticating against a single authentication service. You can read more about that [here](./multiple-domain.md).

## IS_HTTPS

There is a new environment variable called IS_HTTPS. This was always used by CasEnv, but it was not previously exposed as a setting that you could control. Generally, you should just leave it with the default behavior:

-   if CLIENT_HOST_URL is not set => true
-   if SERVER_HOST_URL is not set => true
-   if both CLIENT_HOST_URL and SERVER_HOST_URL start with "https://" => true
-   otherwise => false

This was added because of the REDIRECT_URI change (below). Now that REDIRECT_URI supports building a URL based on the RequestDomain, there needs to be a consistent way to apply a protocol. The defaults should work fine, but if they don't, you can now change it manually.

## BASE_DOMAIN

This setting supports 2 variables now: "$RequestDomain" or "$RequestSubdomain". If it set to "$RequestDomain", the domain of the request is used for each cookie's domain field. If it is set to "$RequestSubdomain", the domain of the request is truncated by one subdomain and then used for each cookie's domain field. Generally, you should only set this setting if sharing a single authentication service across multiple domains.

If both your auth service, WFE, and API were all hosted on the exact same domain, you might use "\$RequestDomain". For instance, if everything was on "portal.domain1.com", then the request domain from the browser will be "portal.domain1.com" and the cookies will all use that for the domain field.

However, more commonly, you host on subdomains, and so you might have "auth.domain1.com" for your auth service, "web.domain1.com" for your WFE, and "portal.domain1.com" for your API. If that is your scenario, you want to use "\$RequestSubdomain". When a request comes from your browser to "portal.domain1.com", then the subdomain of "domain1.com" will be used for all cookie domain fields. This allows you to share the cookie across all of those services on the subdomains.

## SAME_SITE

The default for this setting was "strict" in prior versions, as of 3.0.0 it is now "lax". Several browsers now require "lax" for Javascript to be able to read the XSRF-TOKEN cookie from a subdomain.

## REDIRECT_URI

This setting now supports the variable "\$RequestDomain". The job of the REDIRECT_URI is to determine where the auth-code is delivered to. This will always be a "/cas/token" endpoint, but it needs to be on the correct domain for the cookies to be set (if the endpoint provides the browser with a cookie for a domain other than the request domain or subdomains it will be denied). If the request comes in for "auth.domain1.com" then this setting will set the REDIRECT_URI to "http(s)://auth.domain1.com/cas/token". If the request was for "auth.domain2.com" then it would set "http(s)://auth.domain2.com/cas/token". The protocol is determined by IS_HTTPS.

## DEFAULT_REDIRECT_URL

This was always listed as OPTIONAL, but it was in the code as REQUIRED. It is now indeed OPTIONAL, however, if not set, the /cas/token endpoint will simply not redirect if there isn't somewhere to redirect to.

## IsAuthorized()

Previously when you wanted to know if a user was authenticated or not, you generally needed to hit an endpoint and check for 401 vs 200. That is fine for many cases, but in the event that you need an individual endpoint to determine whether the user is authorized or not, there was not a great way to do it. You could check "User?.Identity.IsAuthenticated", but that didn't tell you if the user passed authorization (ie. did they have a valid XSRF token).

You can now find the CasXsrfHandler via the ServiceProvider and call the IsAuthorized() method. This will run the exact same code as would be run during [Authorize].

```c#
[ApiController]
public class ApiController : ControllerBase
{

    public ApiController(IEnumerable<IAuthorizationHandler> authHandlers)
    {
        this.CasXsrfHandler = authHandlers.OfType<CasXsrfHandler>().FirstOrDefault();
    }

    private CasXsrfHandler CasXsrfHandler { get; }

    [HttpGet("/test")]
    public async Task<ActionResult<string>> Test()
    {
        bool isAuth = await CasXsrfHandler.IsAuthorized(User?.Identity)
        if (isAuth)
        {
            return Ok("authorized");
        }
        else
        {
            return Ok("not-authorized");
        }
    }

}
```

## /cas/me shows Roles

Due to a mistake, /cas/me was not showing a user's roles, now it does.

## CasHttpException Redirect

You can now raise a CasHttpException which will cause a redirection. For instance, if you added an ICasClaimsBuilder and due to an exception, the user authentication is going to fail and you want to redirect the user to some controlled error page, you could...

```c#
throw new CasHttpException(new Uri("https://redirect-here"), "you failed auth.");
```

## Func() for CasConfig GetOnce Methods

The GetOnce methods do not require an instance of CasConfig, they do not cache, and they cannot resolve to secrets in Key Vault. They are designed to be called quickly and often. Unfortunately, some of the logic for determining default values can be considerable and it doesn't make sense to calculate that every time. The default can now be a function that isn't resolved unless the default value is needed. You can also await those functions. For example...

```c#
return CasConfig.GetBoolOnce("IS_HTTPS", () =>
{
    if (string.IsNullOrEmpty(ClientHostUrl)) return true;
    if (string.IsNullOrEmpty(ServerHostUrl)) return true;
    return ClientHostUrl.Contains("https://", StringComparison.InvariantCultureIgnoreCase)
        && ServerHostUrl.Contains("https://", StringComparison.InvariantCultureIgnoreCase);
});
```

## UseCasServerAuth

UseCasServerAuth no longer has options. Instead everything is provided via the following 2 interfaces. Often for AuthCode flow or adding claims it was necessary to use objects in the ServiceProvider, and this makes that much easier.

## ICasAuthCodeReceiver

For implementing an AuthCode flow to capture access-tokens and refresh-tokens, you can create a class that inherits from ICasAuthCodeReceiver. You can then implement one of GetScopes() or GetScopesAsync() and one of Receive() or ReceiveAsync(). It is fine to leave the one you aren't using to throw a NotImplementedException. Both sync and async methods are called, so you should not implement both.

You define the extra scopes you want to receive in GetScopes() or GetScopesAsync(). You will then receive the access-tokens and refresh-tokens for those scopes whenever an authentication is successful via the Receive() or ReceiveAsync() method.

```c#
using System.Collections.Generic;
using System.Threading.Tasks;
using CasAuth;

public class MyAuthCodeReceiver : ICasAuthCodeReceiver
{
    public IEnumerable<string> GetScopes()
    {
        return new string[] { "new_scope_1", "new_scope_2" };
    }

    public Task<IEnumerable<string>> GetScopesAsync()
    {
        throw new System.NotImplementedException();
    }

    public void Receive(string scope, string accessToken, string refreshToken)
    {
        throw new System.NotImplementedException();
    }

    public Task ReceiveAsync(string scope, string accessToken, string refreshToken)
    {
        // store in a database
        return Task.CompletedTask;
    }
}
```

Make sure in the startup that you register the receiver...

```c#
public void ConfigureServices(IServiceCollection services)
{
    services.AddSingleton<ICasAuthCodeReceiver, MyAuthCodeReceiver>();
    services.AddCasServerAuth();
    services.AddControllers();
}
```

## ICasClaimsBuilder

Adding custom claims is now done by implementing a class that inherits from ICasClaimsBuilder. You will implement either AddClaims() or AddClaimsAsync() leaving the other throwing a NotImplementedException. For example...

```c#
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using CasAuth;

namespace auth
{

    public class AddClaimsFromUserDb : ICasClaimsBuilder
    {

        public AddClaimsFromUserDb(ICasConfig config)
        {
            this.Config = config;
        }

        private ICasConfig Config { get; set; }

        public async Task AddClaimsAsync(IEnumerable<Claim> inClaims, List<Claim> outClaims)
        {

            // get a secret, potentially even from key vault
            string connstring = await Config.GetString("USER_SQL_CONNSTRING");

            // implement a connection to SQL to read claims

            // add claims
            outClaims.AddShort("role", "admin");

        }

        void ICasClaimsBuilder.AddClaims(IEnumerable<Claim> inClaims, List<Claim> outClaims)
        {
            throw new System.NotImplementedException();
        }
    }

}
```

Make sure in the startup that you register the builder...

```c#
public void ConfigureServices(IServiceCollection services)
{
    services.AddSingleton<ICasClaimsBuilder, AddClaimsFromUserDb>();
    services.AddCasServerAuth();
    services.AddControllers();
}
```
