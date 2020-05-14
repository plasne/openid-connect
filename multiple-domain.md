# Multiple Root Domains

Version 3.1.0 and up includes improved support for multiple root domains. The scenario this is trying to address can be described this way...

-   One or more applications span multiple root domain names (ex. portal.domain1.com, app.domain2.com, and app.domain3.com).
-   You want the user to authenticate and then to be able to access APIs on each seamlessly.
-   You want to implement a single authentication service that supports all APIs (ex. auth.domain1.com).

For reference, prior implementations of CasAuth allowed for multiple applications but they all had to share a common base domain or implement a very complex set of configurations.

In the "multiple-domain" folder of this project, there is a complete sample.

## Authentication Service (server)

When you deploy a single auth service to support multiple domains, you cannot use SERVER_HOST_URL, CLIENT_HOST_URL, or WEB_HOST_URL as those settings would be different for each implementation. Since we cannot use those, the configuration is a little more complex, but this should do it...

```
LOG_LEVEL=Debug
TENANT_ID=a...a
CLIENT_ID=1...e

BASE_DOMAIN=$RequestSubdomain
REDIRECT_URI=$RequestDomain

ISSUER=auth.domain1.com
ALLOWED_ORIGINS=web.domain1.com, web.domain2.com, web.domain3.com
PUBLIC_KEYS_URL=https://auth.domain1.com/cas/keys
PRIVATE_KEY=https://mykeyvault.vault.azure.net/secrets/PRIVATE-KEY
PRIVATE_KEY_PASSWORD=https://mykeyvault.vault.azure.net/secrets/PRIVATE-KEY-PASSWORD
PUBLIC_CERT_0=https://mykeyvault.vault.azure.net/secrets/PUBLIC-CERT-0
```

Note:

-   The single auth service will be hosted under multiple domain names (ex. auth.domain1.com, auth.domain2.com, auth.domain3.com).
-   The application registration (TENANT_ID and CLIENT_ID) is the same for all services.
-   The ISSUER and PUBLIC_KEYS_URL reference a single domain name, but that is fine.
    -   ISSUER can be any string, it is just a way for you to denote who is issuing the token.
    -   PUBLIC_KEYS_URL is never called by a browser, so CORS, cookies, etc. that might be tied to a domain are not relevant.
-   All of your web-front-ends need to be covered by ALLOWED_ORGINS.
-   BASE_DOMAIN and REDIRECT_URI use new values in v3.1.0 explained below.

BASE_DOMAIN can be set to "$RequestDomain" or "$RequestSubdomain". If it set to "$RequestDomain", the domain of the request is used for each cookie's domain field. If it is set to "$RequestSubdomain", the domain of the request is truncated by one subdomain and then used for each cookie's domain field.

If both your auth service, WFE, and API were all hosted on the exact same domain, you might use "\$RequestDomain". For instance, if everything was on "portal.domain1.com", then the request domain from the browser will be "portal.domain1.com" and the cookies will all use that for the domain field.

However, more commonly, you host on subdomains, and so you might have "auth.domain1.com" for your auth service, "web.domain1.com" for your WFE, and "portal.domain1.com" for your API. If that is your scenario, you want to use "\$RequestSubdomain". When a request comes from your browser to "portal.domain1.com", then the subdomain of "domain1.com" will be used for all cookie domain fields. This allows you to share the cookie across all of those services on the subdomains.

Now consider that the auth service is hosted on multiple domains (ex. auth.domain1.com, auth.domain2.com, auth.domain3.com), this setting allows the single service to set cookies for "domain1.com", "domain2.com", and "domain3.com" depending on the request domain.

REDIRECT_URI is similar but it only supports "\$RequestDomain". The job of the REDIRECT_URI is to determine where the auth-code is delivered to. This will always be a "/cas/token" endpoint, but it needs to be on the correct domain for the cookies to be set (if the endpoint provides the browser with a cookie for a domain other than the request domain or subdomains it will be denied). If the request comes in for "auth.domain1.com" then this setting will set the REDIRECT_URI to "http(s)://auth.domain1.com/cas/token". If the request was for "auth.domain2.com" then it would set "http(s)://auth.domain2.com/cas/token". The protocol is determined by IS_HTTPS.

## API Services (client)

As mentioned above, we cannot set SERVER_HOST_URL, CLIENT_HOST_URL, or WEB_HOST_URL, so the configuration for a client might look like this...

```
LOG_LEVEL=Debug
ISSUER=auth.plasne.com
ALLOWED_ORIGINS=web.domain1.com, web.domain2.com, web.domain3.com
WELL_KNOWN_CONFIG_URL=https://auth.plasne.com/cas/.well-known/openid-configuration
BASE_DOMAIN=$RequestSubdomain
```

Note:

-   As always, the ISSUER must be consistent with the auth service.
-   WELL_KNOWN_CONFIG_URL is pointing to a single domain for the auth service, but it is never called by a browser, so it is fine to use any of the endpoints.
-   BASE_DOMAIN works the same way as described above.
