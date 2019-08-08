# Authentication

There are many ways to handle authentication and authorization with Azure AD. This repo will discuss a few options and present an opinionated code sample for doing authentication.

## OpenID Connect - ID Token

OpenID Connect with an ID Token is used by Azure App Services. In addition, the sample I have included here uses this method in combination with an AuthCode flow.

You need to enable an implicit flow to get the ID token (which will contain the information about the authenticated user).

You can do that in the manifest...

```json
{
    "oauth2AllowIdTokenImplicitFlow": true
}
```

...or you can do that under Authentication in the GUI...

![idtoken](/images/implicit-idtoken.png)

Once you do that, there will be a "X-MS-TOKEN-AAD-ID-TOKEN" request header available.

## Allow Implicit Flow - Access Token

Per the IETF's OAuth 2.0 Security Best Current Practise, you should no longer use implicit grants: https://tools.ietf.org/html/draft-ietf-oauth-security-topics-09#section-2.1.2.

> While this method is supported by Azure App Services, it should not be used per the warnings regarding implicit flow.

You can enable it in the manifest...

```json
{
    "oauth2AllowImplicitFlow": true
}
```

Once you do that, there will be a "X-MS-TOKEN-AAD-ACCESS-TOKEN" request header available. However, this will only be an access token to your own app, so I am not sure how that is helpful. Instead you might want a token to do something in Azure, for that, see: https://blogs.msdn.microsoft.com/aaddevsup/2018/02/28/configuring-an-app-service-to-get-an-access-token-for-graph-api/.

This method also does not allow getting multiple access tokens, so it is usefulness if further limited.

## User Claims for App Service

There will be a number of headers that will be added by the App Service. It will remove any of the headers if they were passed in, so it is safe to assume they came only from App Service.

https://docs.microsoft.com/en-us/azure/app-service/app-service-authentication-how-to#access-user-claims

Most notably, you can get the user by "X-MS-CLIENT-PRINCIPAL-NAME" (for me, that is pelasne@microsoft.com).

Additionally, there is a bunch more information about the user in "X-MS-TOKEN-AAD-ID-TOKEN" which is a JWT token. You could extract the payload.

## AuthCode Flow

The idea behind the AuthCode flow is that the client-secret and all tokens are kept by a secure server and never exposed to the client.

https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow

## Combining an ID Token and AuthCode

The included sample uses both an ID Token obtained by OpenID Connect and Access Tokens obtained by the AuthCode flow.

![authflow](/images/authflow.png)

-   Orange - OpenID Connect flow
-   Purple - AuthCode flow
-   Green - JWT identity cookie

The idea behind this pattern is:

-   Use OpenID Connect to authenticate the user via Azure AD.

-   Use AuthCode (server obtains and keeps access_tokens without exposing them to the client) to get access to Azure resources.

-   Obtain all necessary information about the user and their application roles from the id_token, Microsoft Graph, other databases, etc. to build a JWT identity cookie.

-   The identity cookie is marked "HttpOnly" and "Secure" to ensure it is delivered with each service call.

-   The identity cookie is a JWT so that we can ensure it has not been tampered with.

-   The identity cookie may contain user info and roles that were obtained by contacting multiple systems.

### Using codes and tokens

The authorization code that is obtained from the sign-in that can be redeemed for access tokens has a very short lifetime (30 min). It should immediately be used to get access tokens. If those access tokens expire (1 hour), they can be reissued using the refresh tokens (which are good until revoked).

## Opinionated vs. Unopinionated

We could simply return the id_token as the identity cookie (opinionated). However, generating our own JWT allows for more flexibility (unopinionated).

1. Authentication
    - **Azure AD**
    - Multiple Azure directories
    - LDAP
    - Username/password
    - Certificate
    - Generating tokens for other uses
1. Discovery
    - **Microsoft Graph**
    - LDAP
    - Databases
    - Custom logic
    - On-premises systems
    - REST calls
1. Build Token
    - **Fixed lifetime**
    - Variable lifetime (based on use-case)

The highlighted option in each section could be implemented by Azure AD. It is an "opinionated" solution. If you want to implement any of the other options, then the implementation we built would accomodate (as an "unopinionated" framework).

## Sample

The sample is 2 separate projects: API and WFE, which could be hosted on 2 different URLs.

## XSRF

XSRF is an attack technique by which the attacker can trick an authenticated user into unknowingly executing actions on your website. A malicious actor posts data to your API and expects that an existing authorization/identity/session cookie will be automatically sent along with the request.

This sample does not address this because the "user" cookie is not set to SameSite=strict. It could be if the web pages and API services were hosted on the same domain and if the browser supports it: https://caniuse.com/#search=samesite).

Some frameworks, like Angular, also include a method to implement XSRF protection: https://docs.angularjs.org/api/ng/service/$http#cross-site-request-forgery-xsrf-protection.

## Stuff

I don't like that the nonce is stored in a cookie https://auth0.com/docs/api-auth/tutorials/nonce
alternatively could write IP address to JWT

https://publicsuffix.org/list/effective_tld_names.dat

# Notes

-   https://github.com/projectkudu/kudu/wiki/Configurable-settings#the-system-cannot-find-the-file-specified-issue-with-x509certificate2

-   https://gist.github.com/crpietschmann/35024f1da2a5beb0466e616ce1d7a876

-   https://blog.bredvid.no/accessing-apis-using-azure-managed-service-identity-ff7802b887d

# Improvements

-   Move JwtCookieToHeader and ReissueToken so they are only called if [Authorize]

-   Key rotation

-   remove Key Vault requirement
