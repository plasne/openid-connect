# OpenID Connect Authentication Sample

While this repository is named "openid-connect", this sample will actually encompass OpenID Connect (OIDC), AuthCode, and Service-to-Service (S2S) authentication and authorization techniques.

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

xsrf xss
