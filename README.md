# OpenID Connect Authentication Sample

While this repository is named "openid-connect", this sample will actually encompass OpenID Connect (OIDC), AuthCode, and Service-to-Service (S2S) authentication and authorization techniques.

There are many ways to authenticate users. Some of the advantages of this approach include:

-   It is opinionated - there are lots of ways to do authentication, here is a prescriptive way to do it

-   It does not require any session state

- It allows for single-page applications (including renewal) safely

-   It allows for claims to be asserted from multiple sources (id_token, Microsoft Graph, databases, etc.)

-   Multiple applications can use this authentication solution as a centralized service

-   You can control how long the token for access to your app is issued for

-   The reissue process ensures that as roles change or users are deactivated, the access changes appropriately

-   XSS and XSRF protection is provided in an industry-standard way

-   Testing is made easier by allowing you to generate tokens with different roles

-   Supports local debug configurations including proxy

-   Addresses all 3 common auth flows in one sample (OpenID Connect, AuthCode, and Service-to-Service)

-   Supports hosting your application across multiple subdomains (for instance, the WFE and API can be on different domains)

-   Supports multi-tenant authentication

Links:

-   [Implementation Guide](./implementation.md)
-   [Getting Started Video - Local Debugging](https://youtu.be/kMpGEP6CKJY)
    -   NOTE: the video does not show app.UseCors() for the auth service, but this is required
-   [Getting Started Video - Deploying to AKS](https://youtu.be/3dun4aDWv0U)
-   [Getting Started Video - Deploying to App Service](https://youtu.be/TJt56Y9K0f4)
-   [Sample Configurations](./configuration.md)
-   [Authentication Flow](./flow.md)
-   [Reissue Process](./reissue.md)
-   [Debugging Locally](./debugging.md)
-   [Key Rotation](./key-rotation.md)

## Design

This sample is composed of these pieces:

-   An application is composed of an **API** (client) and **WFE** (web front end).

-   A centralized **auth** (server) service provides authentication services for one or more applications.

-   A command line set of **tools** provides helper functions to generate and validate authentication requests.

There are multiple methods of authentication shown in this sample:

-   An OIDC authentication flow produces an id_token which can be validated to confirm the user's identity.

-   An AuthCode authentication flow can optionally be used to obtain an access_token for a single Azure resource.

    -   The access_token must never be exposed to the client.

    -   The access_token will expire. If it is needed for longer, a refresh_token must be kept to extend access.

    -   The refresh_token can also be used to get an access_token for a different resource.

-   S2S authentication flows can be used to get access_tokens under a shared principal.

    -   The access_tokens must never be exposed to the client.

    -   The access_tokens will expire so refresh_tokens must also be kept to extend access to those systems.

After the initial authentication, some session must be established so that the application continues to know who the user is and what rights they have. This is accomplished via an session_token which has the following characteristics:

-   The session_token will be a JWT so that we can verify it has not been tampered with.

-   The session_token may contain user info and roles that were obtained from multiple sources (id_token, Microsoft Graph, databases, etc.).

-   The session_token will be stored as a cookie marked "HttpOnly" and "Secure" to ensure it is delivered with each service call but not accessible via JavaScript.

-   Since this sample demonstrates a centralized auth service, the JWT is signed with an asymmetric key. If it were deployed as a joint service with the API, a symmetric key would be just as good.

## Dependencies

This project has the following dependencies:

-   Azure AD application

-   Azure App Configuration (optional)

-   Azure Key Vault (technically optional, but strongly recommended)

Ideally, you would also host this application on a platform which support Managed Identity, for example:

-   Azure Kubernetes Service

-   Azure App Service

-   Azure Virtual Machines

-   Azure Functions (this would require significant refactoring)

## State

This solution was specifically designed so that it did not require any state. However, if your application does have a solution for state, the following aspects could be changed. There is not a compelling reason why these _need_ to be stored in state system, but they also don't _need_ to be given to the client. Generally if we don't _need_ to give something to the client, we shouldn't.

-   The "authflow" information (state and nonce values) could be stored in the state system.

    -   The "authflow" data is sent in a cookie marked HttpOnly so it is not accessible via JavaScript, however, the information could still be accessible via a compromised browser or device. These values are only used during the authentication flow (between calls to /authorize and /token), which should happen within a few seconds. I cannot think of a specific way this information could be used in a hack.

-   The session_token could be stored in the state system. A standard session cookie could be sent to the client that references the token in the state system.

    -   The session_token is sent in a cookie marked HttpOnly so it is not accessible via JavaScript, however, the information could still be accessible via a compromised browser or device. This should still be OK because any change to the information would invalidate the signature.

-   In the next section about reissuing, the reason the more common refresh_token was not used for the renewal is because semantically it seemed inappropriate to issue a refresh_token without some way of revoking it. If the application did manage state, you could consider adding a revokable refresh_token and using that for reissue.

There is one condition that would require state...

-   If you are using the AuthCode flow to get access_tokens/refresh_tokens on-behalf-of the user and you intend to keep them so that you can do things as the user later in your application, you will NEED to have some state because you need to cache those tokens somewhere server-side. I think this is an uncommon pattern, but it could drive a state requirement.

## Roles Claims

You can define roles for Azure AD applications as defined here: https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-add-app-roles-in-azure-ad-apps.

There are 2 types of roles claims that can be issued in the session_token:

-   If the application used for authentication (CLIENT_ID) contains roles and the user being authenticated is in one or more of those roles, the "roles" claim will be added with the roles the user is in.

-   If one or more APPLICATION_IDs are specified and the id_token contains an "oid" claim, the roles for those applications will be queried and compared against the user's membership in those roles (determined by the oid). An "appId-roles" claim (where appId is the GUID application ID) will be issued for each containing the roles the user is in. If a user doesn't have a role in an application a claim will not be added for that application.

Example:

```json
{
    "email": "pelasne@microsoft.com",
    "displayName": "Peter Lasne",
    "oid": "00000000-0000-0000-0000-000000000000",
    "roles": "user",
    "xsrf": "bYicx4FtS6JdxPIRDylq7g",
    "old": "1566221345",
    "790c50cb-2350-4216-a7ef-4c179dde26db-roles": ["user", "admin"],
    "95ed35ff-c531-4785-83f6-ed7470cf67e4-roles": "superuser",
    "exp": 1565619573,
    "iss": "https://auth.plasne.com",
    "aud": "https://api.plasne.com"
}
```

## Using the Auth Service

To deploy a new auth service, you can do the following...

```bash
dotnet new webapi
dotnet add package CasAuth --version 2.0.0
```

Then in Startup.cs, you can add the following...

```c#
public void ConfigureServices(IServiceCollection services)
{
    services.AddCasServerAuth(); // <-- this
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseRouting();
    app.UseCors();
    app.UseCasServerAuth(); // <-- and this
}
```

To support a .env file, you can add the following to Program.cs...

```c#
public static void Main(string[] args)
{
    DotEnv.Config(throwOnError: false); // <-- this
    CreateWebHostBuilder(args).Build().Run();
}
```

You should look [here](./configuration.md) for sample configurations to get started.

To start a login, the browser should navigate to the auth/authorize endpoint (ex. https://auth.plasne.com/cas/authorize). If you want to do an automatic login, you can make a REST call to the api/identity/me endpoint (ex. https://api.plasne.com/cas/me), if you receive a 401 Unauthorized, you can then redirect the browser to the auth/authorize endpoint.

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

Angular has module which reads the XSRF-TOKEN cookie and creates the X-XSRF-TOKEN header on each request: https://angular.io/api/common/http/HttpClientXsrfModule. Unfortunately it only works when services being called use relative URLs (are hosted on the exact same domain). However, you can implement your own solution like this:

Based on the following: https://stackoverflow.com/questions/46040922/angular4-httpclient-csrf-does-not-send-x-xsrf-token.

In the app.module.ts...

```typescript
import { HttpXsrfInterceptor } from './core/services/authentication/xsrf-injector';

@NgModule({
  providers: [
    { provide: HTTP_INTERCEPTORS, useClass: HttpXsrfInterceptor, multi: true }
  ]
})
```

In a file called xsrf-injector.ts...

```typescript
import { Injectable } from '@angular/core';
import {
    HttpInterceptor,
    HttpHandler,
    HttpRequest,
    HttpXsrfTokenExtractor,
    HttpEvent
} from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable()
export class HttpXsrfInterceptor implements HttpInterceptor {
    constructor(private tokenExtractor: HttpXsrfTokenExtractor) {}

    intercept(
        req: HttpRequest<any>,
        next: HttpHandler
    ): Observable<HttpEvent<any>> {
        const headerName = 'X-XSRF-TOKEN';
        const token = this.tokenExtractor.getToken();
        if (token !== null && !req.headers.has(headerName)) {
            req = req.clone({ headers: req.headers.set(headerName, token) });
        }
        return next.handle(req);
    }
}
```

## Using the API

To deploy a new API service, you can do the following...

```bash
dotnet new webapi
dotnet add package CasAuth --version 2.0.0
```

Then in Startup.cs, you can add the following...

```c#
public void ConfigureServices(IServiceCollection services)
{
    services.AddCasClientAuth(); // <-- this
    services.AddControllers();
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseRouting();
    app.UseCors();
    app.UseAuthentication(); // <-- this
    app.UseAuthorization(); // <-- this
    app.UseCasClientAuth(); // <-- and this
    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllers();
    });
}
```

To support a .env file, you can add the following to Program.cs...

```c#
public static void Main(string[] args)
{
    DotEnv.Config(throwOnError: false); // <-- this
    CreateWebHostBuilder(args).Build().Run();
}
```

You should look [here](./configuration.md) for sample configurations to get started.

The API code included with this project gives you a great starting place if you are using dotnetcore for your API. If you are not, you might look at the "node-api" sample that shows a very simple API written in Node.js. The bulk of the code is in the auth service on purpose, the intent is that the API is very easy to implement. The "node-api" sample is a sample, not production code.

The steps that need to be implemented by the API are:

1. Ensure the "user" cookie (session_token) was provided.
1. Ensure the "X-XSRF-TOKEN" header was provided.
1. See if the session_token is expired, if it is...
    1. Ask the auth service for a new token
    1. Write the new token as a "user" cookie to replace the previous one
1. Get the public certificates from the auth service
1. Use the correct public certificate to verify the session_token signature
1. Make sure the "X-XSRF-TOKEN" header matches the "xsrf" claim in the session_token.
1. Verify that the user has the appropriate roles claims.

## Using the Tools

There is a tools application that allows you do the following:

-   issue-token - This allows you to issue a token. This could be useful for debugging problems, but also for testing. For instance, you might want to generate a token for testing as a user and then as an administrator.

```bash
# generated as a user
dotnet run issue -o 00000000-0000-0000-0000-000000000000 -e pelasne@microsoft.com -n "Peter Lasne" -r user

# generated as an admin and user
dotnet run issue -o 00000000-0000-0000-0000-000000000000 -e pelasne@microsoft.com -n "Peter Lasne" -r admin,user
```

-   validate-token - This allows you to validate a token and see its contents. If there is a problem validating the token, you will be informed why.

```bash
dotnet run validate-token -t ey...Q=
```

-   get-certficates - This will show all validation certifiates and their associated parameters (kid, x5t, n, e, x5c).

```bash
dotnet run get-certificates
```

-   get-user - This allows you to query the Microsoft Graph for a specific user by their oid or email address.

```bash
# get user by oid
dotnet run get-user -o 00000000-0000-0000-0000-000000000000

# get user by email address
dotnet run get-user -e pelasne@microsoft.com
```

## FAQ

### Azure App Services include Easy Auth, why not just use that?

You could use Easy Auth if: (1) you only needed an id_token, and (2) you had a way to store session state. While Easy Auth supports getting an access_token, this uses an implicit grant flow that is no longer recommended.

Per the IETF's OAuth 2.0 Security Best Current Practise, you should no longer use implicit grants: https://tools.ietf.org/html/draft-ietf-oauth-security-topics-09#section-2.1.2.

The id_token issued by Easy Auth will be available to the backend service in a header called "X-MS-TOKEN-AAD-ID-TOKEN".

### Why not use aspnetcore auth?

You absolutely can - this auth service is built on aspnetcore. If you have a simple authentication scenario...

-   all your claims are in Azure AD

-   you are authenticating for a single application

-   you can store session state server-side

...then it probably is easier to aspnetcore. When you have more complex requirements and would need to write a bunch of code, consider that this service already provides a comprehensive solution.

### Why do I keep saying you need session state if you are using the common patterns?

By common patterns, I am talking about Easy Auth, aspnetcore auth, and similar patterns. If you are OK reauthenticating every 1 hour, then you don't need session state.

Your session state must be server-side so the claims cannot be altered and your refresh_tokens are not exposed to the client. Keep in mind that almost all cloud implementations will have multiple instances of your API service running so the session state needs to be a standalone, shared service (like Azure Redis, Cosmos, Azure SQL DB, Azure Blob/Table Storage, or similar).

If you do want to prevent having your users go back through authentication every 1 hour, there are several possible scenarios:

-   You use OIDC to get an id_token. That id_token expires in 1 hour, so you need to extract the claims and store them in your state solution. Then you issue a session cookie that contains a key to get to the claims.

-   You use OAuth2 or OIDC to get an access_token and refresh_token. You store the refresh_token in your state solution. Every hour when your access_token expires, you can use the refresh_token to get a new one.

-   You can use the pattern that this auth service provides, the claims from the id_token are extracted into a self-signed JWT that you now control. You can validate the signature so you know it hasn't been tampered with and you can reissue by validating whatever you need to server-side without storing a refresh_token.

### What is XSS and XSRF protection?

XSS is cross-site-scripting and XSRF is cross-site-request-forgery. You can read more [here](./xss-xsrf.md).

### Can I use this service to authenticate with APIM?

Yes, see the instructions [here](./APIM.md).

### When would I use an AuthCode flow?

Several times in this documentation, I mentioned that used AuthCode is uncommon. Generally the claims you need put into your session_token can be obtained from the id_token, the Microsoft Graph (querying as a service principal), and from one or more databases.

You would need to use the AuthCode flow because you are accessing a resource on-behalf-of the user. The common scenarios would involve Office 365 (email, OneDrive, calendar, etc.).

To use AuthCode, check out the documentation [here](./authcode.md).

### How do I inject custom claims?

See the instructions [here](./custom-claims.md).

### Sending the session_token to microservices in an overlay network is a larger header than needed, is there an alternative?

Yes, this solution supports the safe authentication at the edge using everything described in this project. Then for internal services that are not exposed outside of the application's overlay network, we can simply send identity headers that don't require signature verification.

This pattern is discussed [here](./internal-services.md).

### Do I have to register custom domain names?

Yes, it turns out that Mozilla keeps a list of cloud provider domains that host shared resources at https://publicsuffix.org/list/effective_tld_names.dat. At least Firefox and Chrome block cookies from being stored if the domain matches those listed.

### How long are tokens issued for?

These are the current lifetimes for tokens, but of course that could change.

-   id_token - 1 hour

-   access_token - 1 hour

-   refresh_token - 90 days

-   session_token - user-determined; 4 hours by default

## Limitations

-   Cookies cannot be larger than 4K. If you had a bunch of claims or application roles it is possible you could exceed this limit. Consider implementing a storage system for state (ex. Redis) and keeping the JWT there.

-   This solution sends cookies with each API REST call, if you have a bunch of cookies that are large in size this could significantly increase your payload size.

## TODO

-   Reissue should requery the "role" claim as well.
