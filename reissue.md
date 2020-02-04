## Why Reissue?

The reissue capability was added into this solution after the first implementation because the customer wanted the application authentication to potentially last for days. The session_token is passed by cookie on every REST call and contains the information needed to validate the authentication.

### Options

We could have addressed the requirement in a number of ways:

-   We could issue the session_token without an expiration date.

    -   Having no expiration date on a token used for authentication seemed an unnecessary risk.

-   We could issue the session_token with a long expiration period (ex. 1 week).

    -   Having a long enough expiration period to satisify the requirement but still a constrainted period of time is reasonable, but arbitrary (why 1 week instead of 2 weeks).

-   We could issue a refresh_token (good for a long period of time) along with the session_token so it could be reissued.

    -   This approach is reasonable and in keeping with the OAuth specification. To implement this, we would need to store the refresh_token somewhere securely and we would need some way to revoke it. Since we do not have any state management in this current solution, that was problematic.

-   We could extend the expiration time if the session_token if it was still good and the user was still authorized.

    -   This approach could not address changing the user's access if their role changed since the roles claim would remain the same in the extended token.

-   We could reissue the session_token if it was still good and the user was still authorized.

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

1. The auth service signs a new session_token with new claim values.

1. The auth service sends the new session_token back to the API.

    - If a role is required for the application and the new session_token did not contain a role, the API could reject it.

1. The API modifies the Authorization header to include the new session_token.

1. The API writes the new cookie to the response stream.

### Testing the Reissue Process

You can test the reissue process by POSTing an expired token to the reissue service. If all is working properly, you should get a new token as the body of the response.

```bash
curl -i -X POST -d "token=ey...dQ" https://auth.plasne.com/cas/reissue
```
