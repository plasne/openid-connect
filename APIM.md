# APIM Authentication

## Default Flow

It is possible for APIM to work with the default authentication flow provided by this auth service (user cookie and X-XSRF-TOKEN header). If you would prefer to use the session_token as an Authorization Bearer token, that is also supported and shown later on this page.

This reads the user cookie and makes it an Authorization Bearer token header. It then validates the signature and the XSRF claim.

```xml
<policies>
    <inbound>
        <base />
        <set-header name="Authorization" exists-action="override">
            <value>@{
                    string raw = context.Request.Headers.GetValueOrDefault("Cookie");
                    if (string.IsNullOrEmpty(raw)) {
                        return string.Empty;
                    }
                    string[] cookies = raw.Split(';');
                    string cookie = cookies.FirstOrDefault(c => c.StartsWith("user="));
                    if (string.IsNullOrEmpty(cookie)) {
                        return string.Empty;
                    }
                    return "Bearer " + cookie.Replace("user=", "");
                }</value>
        </set-header>
        <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized">
            <openid-config url="https://auth2.plasne.com/api/auth/.well-known/openid-configuration" />
            <audiences>
                <audience>https://api2.plasne.com</audience>
            </audiences>
            <issuers>
                <issuer>https://auth2.plasne.com</issuer>
            </issuers>
            <required-claims>
                <claim name="xsrf">
                    <value>@(context.Request.Headers.GetValueOrDefault("X-XSRF-TOKEN"))</value>
                </claim>
            </required-claims>
        </validate-jwt>
    </inbound>
    <backend>
        <base />
    </backend>
    <outbound>
        <base />
    </outbound>
    <on-error>
        <base />
    </on-error>
</policies>
```

## Using an Authorization Bearer Token

If you want Azure API Management to validate the session_token as an Authorization Bearer token, you first need to configure the service to accept the session_token as Authorization Bearer token. Set the following settings:

-   app:common:env:REQUIRE_HTTPONLY_ON_USER_COOKIE = false

-   app:common:env:REQUIRE_HTTPONLY_ON_XSRF_COOKIE = true

-   app:api:env:VERIFY_TOKEN_IN_COOKIE = false

-   app:api:env:VERIFY_TOKEN_IN_HEADER = true

-   app:common:env:VERIFY_XSRF_IN_COOKIE = true

-   app:common:env:VERIFY_XSRF_IN_HEADER = false

Your client can then read the session_token from the user cookie and sent it as an Authorization Bearer token.

You can validate the Bearer token using the validate-jwt policy like so...

```xml
<policies>
    <inbound>
        <base />
        <validate-jwt header-name="Authorization" failed-validation-httpcode="401" failed-validation-error-message="Unauthorized. Access token is missing or invalid.">
            <openid-config url="https://auth2.plasne.com/api/auth/.well-known/openid-configuration" />
            <required-claims>
                <claim name="aud">
                    <value>https://api2.plasne.com</value>
                </claim>
            </required-claims>
        </validate-jwt>
    </inbound>
    <backend>
        <base />
    </backend>
    <outbound>
        <base />
    </outbound>
    <on-error>
        <base />
    </on-error>
</policies>
```

...however, that does not provide any XSS/XSRF protection, instead, it is better to extract the XSRF-TOKEN from the request cookie and extract the session_token from the Authorization header and send those to the auth/verify service. The verify service will validate both tokens and compare the XSRF claim to ensure a match. It will respond with a 200 OK if it is all good or 400 Bad Request if it is not.

The auth/verify method should never be called directly from a client (not to mention the client should not be able to get the XSRF-TOKEN cookie contents anyway), but rather should always be called from a gateway service like APIM.

```xml
<policies>
    <inbound>
        <base />
        <send-request mode="new" response-variable-name="VerifyResponse" timeout="10" ignore-error="true">
            <set-url>https://auth2.plasne.com/api/auth/verify</set-url>
            <set-method>POST</set-method>
            <set-header name="X-XSRF-TOKEN" exists-action="override">
                <value>@{
                    string raw = context.Request.Headers.GetValueOrDefault("Cookie");
                    if (string.IsNullOrEmpty(raw)) {
                        return string.Empty;
                    }
                    string[] cookies = raw.Split(';');
                    string cookie = cookies.FirstOrDefault(c => c.StartsWith("XSRF-TOKEN="));
                    if (string.IsNullOrEmpty(cookie)) {
                        return string.Empty;
                    }
                    return cookie.Replace("XSRF-TOKEN=", "");
                }</value>
            </set-header>
            <set-header name="X-SESSION-TOKEN" exists-action="override">
                <value>@{
                    string raw = context.Request.Headers.GetValueOrDefault("Authorization");
                    if (string.IsNullOrEmpty(raw)) {
                        return string.Empty;
                    }
                    return raw.Split(' ').Last();
                }</value>
            </set-header>
            <set-body />
        </send-request>
        <choose>
            <when condition="@(((IResponse)context.Variables["VerifyResponse"]).StatusCode == 200)">
                <!-- everything is good to continue -->
            </when>
            <otherwise>
                <return-response>
                    <set-status code="401" reason="Unauthorized" />
                </return-response>
            </otherwise>
        </choose>
    </inbound>
    <backend>
        <base />
    </backend>
    <outbound>
        <base />
    </outbound>
    <on-error>
        <base />
    </on-error>
</policies>
```

Unfortuately the "safe" flow requires an additional service call for every call to the API, this will significantly reduce the performance of this application.
