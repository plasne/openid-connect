# AuthProxy

A company had a product that runs in Pods in Kubernetes but does not directly support authentication - they were using a gateway but it was only supported on a platform they were migrating from. They wanted a sidecar that could run in the Pod and provide authentication before passing on the request to the main container in the Pod. They wanted a solution that could run on any platform.

I built this AuthProxy example as a demonstration on how to meet those requirements. This solution will support any OIDC JWT that can be validated using a /.well-known/openid-configuration endpoint.

## Standard Configurations

The configuration is provided via environment variables. This solution supports dotenv, so you can create a .env file in the same directory as you are running from.

A configuration that supports a "user" cookie and expects a "X-XSRF-TOKEN" header might look something like this...

```env
LOG_LEVEL=Debug
JWT_COOKIE=user
XSRF_HEADER=X-XSRF-TOKEN
XSRF_CLAIM=xsrf
ISSUER=auth.plasne.com
AUDIENCE=web.plasne.com
WELL_KNOWN_CONFIG_URL=https://auth.plasne.com/cas/.well-known/openid-configuration
```

A configuration that supports an authorization bearer token and no XSRF protection might look something like this...

```env
LOG_LEVEL=Debug
JWT_HEADER=Authorization
ISSUER=auth.plasne.com
AUDIENCE=web.plasne.com
WELL_KNOWN_CONFIG_URL=https://auth.plasne.com/cas/.well-known/openid-configuration
```

Make 100% sure if you deploy this as a side-car that you do not expose the API port to any service outside of the Kubernetes overlay network, this will nullify your security.

## Options

-   LOG_LEVEL (default: Information) - Specify one of Critical, Debug, Error, Information, None, Trace, Warning. This determines the logging level.

-   DISABLE_COLORS (default: false) - If "true", the log category will not change color.

-   FROM_PORT (default: 8080) - Specify the port that the proxy will listen on.

-   TO_PORT (default: 8081) - Specify the port that contains the backend service.

-   TO_HOST (default: localhost) - Specify the host name to proxy traffic to. If you are running this as a sidecar, you should leave it as "localhost".

-   ALLOW_ANONYMOUS (default: false) - If "true", the reverse proxy will not check for authentication or authorization. Setting this to "true" invalidates the remaining options.

-   JWT_HEADER (required unless JWT_COOKIE is provided) - Specify the name of the header that contains the JWT token for validation.

-   JWT_COOKIE (required unless JWT_HEADER is provided) - Specify the name of the cookie that contains the JWT token for validation.

-   XSRF_HEADER (required if XSRF_CLAIM is provided) - Specify the name of the header that contains the XSRF token.

-   XSRF_CLAIM (required if XSRF_HEADER is provided) - Specify the name of the claim that contains the XSRF token in the JWT.

-   WELL_KNOWN_CONFIG_URL (required) - Specify the URL of the /.well-known/openid-configuration endpoint that specifies the keys URL to use for validating the signature of the JWT.

-   ISSUER (required) - Specify one or more issuers (comma-separated) of the JWT token. The JWT will be rejected if it contains none of the issuers.

-   AUDIENCE (required) - Specify one or more audiences (comma-separated) of the JWT token. The JWT will be rejected if it contains none of the audiences.

It is possible to support both JWT_HEADER and JWT_COOKIE, both will be checked.

## XSRF Support

If you want to support XSRF, use JWT_COOKIE, XSRF_HEADER, and XSRF_CLAIM.

When your authentication provider issues the JWT cookie, should be marked HTTP-ONLY, marked SECURE, use a trusted DOMAIN, and should contain the XSRF as a claim. By marking the XSRF as HTTP-ONLY, Javascript will not be able to read the JWT to discover the value of the claim. By marking SECURE, you ensure that the cookie will only be passed to an SSL endpoint. By issuing the cookie for a trusted domain, you ensure that it will only be sent to domains you trust.

When your authentication provider issues the JWT_COOKIE, it should also issue a XSRF cookie marked SECURE and use a trusted DOMAIN.

In your client, all AJAX calls should specify "withCredentials: true" to ensure the JWT_COOKIE is sent. In addition, Javascript should be used to read the XSRF cookie and put the contents into the XSRF_HEADER.

## Where to go from here?

-   While this solution authenticates the user, it does nothing for authorization. The JWT is passed to the API, so you could read the claims from the JWT without validating it again. You could modify this code to extract and present certain claims (like roles) as headers.

-   This solution treats everything as requiring authentication. You could change it so only certain routes required or didn't require authentication.

-   This solution only handles HTTP/1.1 traffic, it could be extended to support other protocols, such as HTTP/2 or gRPC.

-   The intent of this solution was that you would use some gateway with SSL offload in front of your exposed endpoints, so this solution would use HTTP only. If that wasn't the case, you could add support for SSL.

-   This solution only supports validating tokens from a single /.well-known/openid-configuration endpoint. This is the recommended pattern, but if you had the desire to support tokens from different authorities, you could modify this solution to support that.
