# Flow

This document shows a basic authentication flow.

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

    -   The auth/token endpoint generates an session_token by asserting all required claims from all sources (id_token, Microsoft Graph, etc.)

session_token (self-signed, self-issued JWT)

15. The auth/token responds with a 302 Redirect to the home page of the application.

    -   The response contains a "user" cookie (HttpOnly, Secure) which contains the session_token (a self-signed JWT containing all claims and roles).

    -   The response contains a "XSRF-TOKEN" cookie (Secure) which contains a random string.

16. The client calls an authenticated service in the API.

    -   The client should read the "XSRF-TOKEN" cookie via JavaScript and create a request header of "X-XSRF-TOKEN" containing the cookie contents.

17. The API POSTs the existing session_token to the auth/reissue endpoint.

    -   _For the purposes of this flow, let's assume the session_token has expired and the auth service is configured to allow for reissuing the JWT (otherwise the flow would continue with step 19)._

    -   The service gets the session_token from the "user" cookie.

18. The auth/reissue endpoint responds with a new session_token to the API service.

    -   The existing session_token signature and all claims are validated (the expiration is allowed to be invalid of course).

    -   Provided the maximum age of the session_token has not been reached, the token is reissued.

19. The service responds to the initial request (step 16) with the appropriate payload.

    -   The service validates the JWT signature and all claims.

    -   The service verifies that there is an "X-XSRF-TOKEN" request header whose contents match a claim of "xsrf" in the session_token.

    -   If the session_token was reissued, the service replaces the existing "user" cookie with the new token.
