# OpenID Connect Authentication Sample

While this repository is named "openid-connect", this sample will actually encompass OpenID Connect (OIDC), AuthCode, and Service-to-Service (S2S) authentication and authorization techniques.

While there are many other ways to authenticate users, this solution was developed to allow for the following special features:

-   It does not require any session state

-   It allows for claims to be asserted from multiple sources (id_token, Microsoft Graph, databases, etc.)

-   Multiple applications can use this authentication solution as a centralized service

## Design

This sample is composed of these pieces:

-   An application is composed of an **API** and **WFE** (web front end).

-   A centralized **auth** service provides authentication services for one or more applications.

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

After the initial authentication, some session must be established so that the application continues to know who the user is and what rights they have. This is accomplished via an identity_token which has the following characteristics:

-   The identity_token will be a JWT so that we can verify it has not been tampered with.

-   The identity_token may contain user info and roles that were obtained from multiple sources (id_token, Microsoft Graph, databases, etc.).

-   The identity_token will be stored as a cookie marked "HttpOnly" and "Secure" to ensure it is delivered with each service call but not accessible via JavaScript.

-   Since this sample demonstrates a centralized auth service, the JWT is signed with an asymmetric key. If it were deployed as a joint service with the API, a symmetric key would be just as good.

## Flow

![authflow](/images/authflow.png)

Auto-Login (skip to step 3 if doing a manual login):

1. The client attempts to contact a service on the API that requires authentication.

2. The API responds with a 401 Unauthorized.

Open-ID Connect

3. The client navigates to the auth/authorize endpoint (window.location.href).

4. The auth/authorize endpoint responds with a 302 Redirect to the login.microsoftonline.com/authorize endpoint (including all relevant authorization information - ex. the Client ID for the application).

    - The response contains an "authflow" cookie (HttpOnly, Secure) which contains a state and nonce randomly generated string. These will be verified by the auth/token endpoint in step 10 to ensure the flow has not been tampered with.

5. The client redirects to the login.microsoftonline.com/authorize endpoint.

    - The user provides their UserPrincipalName (commonly email address) so Azure AD knows who provides authentication for that domain.

6. The login.microsoftonline.com/authorize endpoint responds with a 302 Redirect to the URL of the customer's authentication provider (ex. ADFS, Okta, Ping, etc.).

7. The client redirects to the appropriate authentication provider URL.

    - The user provides credentials.

    - There may be more than one redirection to multiple services if there is a separate MFA provider.

8. The customer's authentication provider responds with a 302 Redirect to login.microsoftonline.com/login endpoint with an authorization_code.

9. The client redirects to the login.microsoftonline.com/login endpoint.

10. The login.microsoftonline.com/login page POSTs the id_token and authorization_code to the auth/token endpoint.

    - The auth/token endpoint verifies the state from the querystring with the state value in the authflow cookie.

    - The auth/token endpoint verifies the nonce in the id_token with the nonce value in the authflow cookie.

    - The auth/token endpoint validates the id_token signature.

AuthCode (this is optional and commonly not necessary)

11. The auth/token endpoint redeems the authorization_code for an access_token by contacting the login.microsoftonline.com/token endpoint.

    -   The authorization_code can only be redeemed for a single access_token. Each resource type (ex. Microsoft Graph vs Azure Key Vault) in Azure requires a different access_token.

12. The login.microsoftonline.com/token endpoint returns the access_token (and a refresh_token if requested).

    -   The access_token should never be revealed to the client, so it should be used immediately to build the JWT or it should be cached server-side.

    -   If the access_token is going to be used later, the refresh_token should also be cached as the access_token is only good for a short period of time.

    -   You can also use the refresh_token to obtain an access_token for a different resource.

Service-to-Service (this is an example of getting more information from the Microsoft Graph)

13. The auth/token endpoint calls the Microsoft Graph to get more information about the user asserted in the id_token.

    -   The auth/token endpoint uses the AuthChooser to get an access_token to the Microsoft Graph.

        -   You should configure the AuthChooser to use the AzureServiceTokenProvider when deployed on a service that supports a Managed Identity (AUTH_TYPE=mi).

        -   You should configure the AuthChooser to use MSAL when deployed on a service that does not support a Managed Identity (AUTH_TYPE=app).

        -   In either case, access_tokens will be cached for their lifetime, refresh_tokens will be automatically used to get new access_tokens once expired, and new access_tokens can be issued using client credentials when required.

14. The Microsoft Graph responds with details about the user.

    -   The auth/token endpoint generates an identity_token by asserting all required claims from all sources (id_token, Microsoft Graph, etc.)

Identity_Token (self-signed, self-issued JWT)

15. The auth/token responds with a 302 Redirect to the home page of the application.

    -   The response contains a "user" cookie (HttpOnly, Secure) which contains the identity_token (a self-signed JWT containing all claims and roles).

    -   The response contains a "XSRF-TOKEN" cookie (Secure) which contains a random string.

16. The client calls an authenticated service in the API.

    -   The client should read the "XSRF-TOKEN" cookie via JavaScript and create a request header of "X-XSRF-TOKEN" containing the cookie contents.

17. The API POSTs the existing identity_token to the auth/reissue endpoint.

    -   _For the purposes of this flow, let's assume the identity_token has expired and the auth service is configured to allow for reissuing the JWT (otherwise the flow would continue with step 19)._

    -   The service gets the identity_token from the "user" cookie.

18. The auth/reissue endpoint responds with a new identity_token to the API service.

    -   The existing identity_token signature and all claims are validated (the expiration is allowed to be invalid of course).

    -   Provided the maximum age of the identity_token has not been reached, the token is reissued.

19. The service responds to the initial request (step 16) with the appropriate payload.

    -   The service validates the JWT signature and all claims.

    -   The service verifies that there is an "X-XSRF-TOKEN" request header whose contents match a claim of "xsrf" in the identity_token.

    -   If the identity_token was reissued, the service replaces the existing "user" cookie with the new token.

## Dependencies

This project has the following dependencies:

-   Azure AD application

-   Azure App Configuration

-   Azure Key Vault

Ideally, you would also host this application on a platform which support Managed Identity, for example:

-   Azure Kubernetes Service

-   Azure App Service

-   Azure Virtual Machines

-   Azure Functions (this would require significant refactoring)

## State

This solution was specifically designed so that it did not require any state. However, if your application does have a solution for state, the following aspects could be changed. There is not a compelling reason why these _need_ to be stored in state system, but they also don't _need_ to be given to the client. Generally if we don't _need_ to give something to the client, we shouldn't.

-   The "authflow" information (state and nonce values) could be stored in the state system.

    -   The "authflow" data is sent in a cookie marked HttpOnly so it is not accessible via JavaScript, however, the information could still be accessible via a compromised browser or device. These values are only used during the authentication flow (between calls to /authorize and /token), which should happen within a few seconds. I cannot think of a specific way this information could be used in a hack.

-   The identity_token could be stored in the state system. A standard session cookie could be sent to the client that references the token in the state system.

    -   The identity_token is sent in a cookie marked HttpOnly so it is not accessible via JavaScript, however, the information could still be accessible via a compromised browser or device. This should still be OK because any change to the information would invalidate the signature.

-   In the next section about reissuing, the reason the more common refresh_token was not used for the renewal is because semantically it seemed inappropriate to issue a refresh_token without some way of revoking it. If the application did manage state, you could consider adding a revokable refresh_token and using that for reissue.

There is one condition that would require state...

-   If you are using the AuthCode flow to get access_tokens/refresh_tokens on-behalf-of the user and you intend to keep them so that you can do things as the user later in your application, you will NEED to have some state because you need to cache those tokens somewhere server-side. I think this is an uncommon pattern, but it could drive a state requirement.

## When is AuthCode Used?

TODO

## Why Reissue?

The reissue capability was added into this solution after the first implementation because the customer wanted the application authentication to potentially last for days. The identity_token is passed by cookie on every REST call and contains the information needed to validate the authentication.

### Options

We could have addressed the requirement in a number of ways:

-   We could issue the identity_token without an expiration date.

    -   Having no expiration date on a token used for authentication seemed an unnecessary risk.

-   We could issue the identity_token with a long expiration period (ex. 1 week).

    -   Having a long enough expiration period to satisify the requirement but still a constrainted period of time is reasonable, but arbitrary (why 1 week instead of 2 weeks).

-   We could issue a refresh_token (good for a long period of time) along with the identity_token so it could be reissued.

    -   This approach is reasonable and in keeping with the OAuth specification. To implement this, we would need to store the refresh_token somewhere securely and we would need some way to revoke it. Since we do not have any state management in this current solution, that was problematic.

-   We could extend the expiration time if the identity_token if it was still good and the user was still authorized.

    -   This approach could not address changing the user's access if their role changed since the roles claim would remain the same in the extended token.

-   We could reissue the identity_token if it was still good and the user was still authorized.

    -   This approach was adopted, see more information below.

### Procedure

The following procedure is used for the reissuing of an access_token:

1. The API determines that the access_token has expired.

1. The API sends the access_token to the auth/reissue endpoint.

1. The auth service validates the signature and the claims in the access_token (except the expiration).

1. The auth service ensures that the maximum duration of access_token has not been exceeded (the "old" claim).

1. The auth service determines if the user is still enabled in Azure AD.

    - This ensures that if user is disabled the token will not be reissued.

1. The auth service gets new claim values from the required services (at least the roles claim).

1. The auth service signs a new identity_token with new claim values.

1. The auth service sends the new identity_token back to the API.

    - If a role is required for the application and the new identity_token did not contain a role, the API could reject it.

1. The API modifies the Authorization header to include the new identity_token.

1. The API writes the new cookie to the response stream.

### Testing the Reissue Process

You can test the reissue process by POSTing an expired token to the reissue service. If all is working properly, you should get a new token as the body of the response.

```bash
curl -i -X POST -d "token=ey...dQ" https://auth.plasne.com/api/auth/reissue
```

## Roles Claims

You can define roles for Azure AD applications as defined here: https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-add-app-roles-in-azure-ad-apps.

There are 2 types of roles claims that can be issued in the identity_token:

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

## XSS and XSRF Protection

This pattern is designed to address Cross-Site Scripting (XSS) and Cross-Site Request Forgery (XSRF). An example of each attack is below. Keep in mind that there is never perfect security, but the techniques employed here can mitigate the common concerns.

You can protect a cookie containing a token against a malicious actor using an XSS attack effectively by marking it as HttpOnly. However, when you do that, your JavaScript can no longer read the cookie to send the token as an Authorization Bearer token in the header, so the cookie must be automatically delivered with each service call. Sending the cookie on every service call opens your service up to an XSRF attack.

The approach used by this solution is two-fold. Two cookies are issued:

-   identity_token - contained in a cookie marked HttpOnly

-   XSRF-TOKEN - contained in a cookie readable by JavaScript

Authentication is only accepted when the cookie containing the identity_token is passed AND there is an X-XSRF-TOKEN header (obtained by reading the cookie containing the XSRF-TOKEN value via JavaScript). This combination approach ensures that this solution is resilient versus these common attacks.

### Example of an XSS Hack

1. You prompt the user to enter their name in an input field.

1. The hacker instead pastes a malicious JavaScript.

1. You display the "name" but in fact are prompting the browser to run the JavaScript.

1. The JavaScript reads all cookies looking for an access_token or identity_token.

1. The attacker uses the token to do something unintended.

### Example of an XSRF Hack

1. The attacker assumes that you send cookies with authentication on each API REST call.

1. The attacker assumes the user has recently logged into the application so the cookie might still provide authentication.

1. The attacker uses a phishing attack to get the user to click on a link that will initiate an API REST call to your service.

1. The cookie with authentication is sent to your service and an unintended action is performed under the user's authority.

## Token Lifetimes

These are the current lifetimes for tokens, but of course that could change.

-   id_token - 1 hour

-   access_token - 1 hour

-   refresh_token - 90 days

-   identity_token - user-determined; 4 hours by default

## Debugging Locally

You should create a .env file in the folder you will be running "dotnet run" from for each service (API and auth). You should include in that file a setting called HOST_URL that specifies the protocol and port that you want to run that service on. You might also include a more granular LOG_LEVEL and a PROXY if needed. These 3 settings must be set in the .env file (or by some other means to create an environment variable) as they are utilized prior to getting the configuration from Azure App Service. For example:

```bash
HOST_URL=http://localhost:5100
LOG_LEVEL=Debug
PROXY=http://proxy
```

If you are are going to host the WFE sample from this project, you also need to create a .env file where you will be running "node server.js" from. It should contain the HOST_URL (only the port is actually used) and CONFIG_URL:

```bash
HOST_URL=http://localhost:5000
CONFIG_URL=http://localhost:5200/api/config/wfe
```

There will be some settings that are different for a local configuration. You can create additional configuration items in Azure App Configuration specifically for the local environment. You can specify all settings or you can simply override some settings. The environment variables are favored from left-to-right, so where there are local settings they would take precident and the dev settings would fill in the gaps if you did something like this:

```bash
CONFIG_KEYS=sample:auth:local:\*, sample:common:local:\*, sample:auth:dev:\*, sample:common:dev:\*
```

As an example, these were the settings I overwrote for my local environment:

```json
{
    "sample:api:local:PRESENT_CONFIG_wfe": "sample:wfe:local:*, sample:wfe:dev:*",
    "sample:api:local:PUBLIC_CERTIFICATE_URL": "http://localhost:5100/api/auth/certificate",
    "sample:api:local:REISSUE_URL": "http://localhost:5100/api/auth/reissue",
    "sample:auth:local:DEFAULT_REDIRECT_URL": "http://localhost:5000",
    "sample:auth:local:REDIRECT_URI": "http://localhost:5100/api/auth/token",
    "sample:common:local:ALLOWED_ORIGINS": "http://localhost:5000",
    "sample:common:local:BASE_DOMAIN": "localhost",
    "sample:common:local:REQUIRE_SECURE_FOR_COOKIES": "false",
    "sample:wfe:local:LOGIN_URL": "http://localhost:5100/api/auth/authorize",
    "sample:wfe:local:ME_URL": "http://localhost:5200/api/identity/me"
}
```

One warning, at least in Chrome and Firefox, cookies without the Secure flag will not replace cookies with the Secure flag. Therefore, if you run with REQUIRE_SECURE_FOR_COOKIES with the default of "true" and then change it to "false", cookies could have been created that wouldn't get replaced and you will get errors that the state and nonce values don't match. You can manually delete those cookies should that happen.

## Limitations

-   Cookies cannot be larger than 4K. If you had a bunch of claims or application roles it is possible you could exceed this limit. Consider implementing a storage system for state (ex. Redis) and keeping the JWT there.

-   This solution sends cookies with each API REST call, if you have a bunch of cookies that are large in size this could significantly increase your payload size.
