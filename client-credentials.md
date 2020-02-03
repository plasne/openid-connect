# Client Credentials Grant

You may have service accounts that need to connect to services in an application protected by this authNZ service. To do that, you will use an Azure AD client credential grant. When this flow is used, a JWT will be generated like the user authentication process except that it will have a "role" claim in the payload that will be set to "service" (or whatever else is configured for ROLE_FOR_SERVICE).

Tokens generated for service accounts like this should always be passed in the "Authorization" header as a "Bearer" token. Even if VERIFY_TOKEN_IN_HEADER is set to "false", the token will be accepted if it has the "role"="service" claim. In addition, no XSRF code will be required.

## Lifetime

Tokens generated for service accounts will have a lifetime of JWT_SERVICE_DURATION (which defaults to JWT_DURATION if it is not provided), however, they are not eligible for reissue. If the token is expired, a new one should be issued.

## Client Secret

You may obtain a token for a service account using a client secret or a certificate. To create a token from the client secret...

```
URL:
    https://auth.plasne.com/api/auth/service

HEADERS:
    Content-Type:multipart/form-data

BODY:
    clientId:00000000-0000-0000-0000-00000000000
    clientSecret:my_client_secret
    scope:api://00000000-0000-0000-0000-00000000000
```

You can find the scope on the "Expose an API" tab in AAD.

## Client Certificate

To use a client certificate, you must generate the certificate using this code...

```c#
var bytes = System.IO.File.ReadAllBytes("/mypath/cert.pfx");
var certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(bytes, "my_pfx_password");
var signingCredentials = new Microsoft.IdentityModel.Tokens.X509SigningCredentials(certificate, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256);
var claims = new System.Collections.Generic.List<System.Security.Claims.Claim>();
claims.Add(new System.Security.Claims.Claim("sub", "client_id_for_service_account"));
claims.Add(new System.Security.Claims.Claim("jti", System.Guid.NewGuid().ToString()));
var tenant = "my_tenant_id";
var jwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
    issuer: "client_id_for_service_account",
    audience: $"https://login.microsoftonline.com/{tenant}/oauth2/token",
    claims: claims,
    notBefore: DateTime.UtcNow,
    expires: DateTime.UtcNow.AddMinutes(10),
    signingCredentials: signingCredentials);
var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
var token = handler.WriteToken(jwt);
```

Then to create a token from the client certificate...

```
URL:
    https://auth.plasne.com/api/auth/service

HEADERS:
    Content-Type:multipart/form-data

BODY:
    clientId:00000000-0000-0000-0000-00000000000
    token:token_generated_from_above_code
    scope:api://00000000-0000-0000-0000-00000000000
```

You must upload the certificate on the "Certificates & secrets" tab in AAD.

You can find the scope on the "Expose an API" tab in AAD.
