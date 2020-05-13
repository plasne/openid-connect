# Custom Claims

If you want to inject custom claims that may come from another service, database, or some computed logic, you can easily do that by providing a ClaimBuilderFunc when UseCasServerAuth is called in Startup.cs...

```c#
using ext = CasAuth.UseCasServerAuthMiddlewareExtensions;

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseRouting();
    app.UseCors();
    app.UseCasServerAuth(() =>
    {
        var opt = new ext.CasServerAuthOptions()
        {
            ClaimBuilderFunc = (inClaims, outClaims) =>
            {
                outClaims.Add(new System.Security.Claims.Claim("color", "yellow"));
            }
        };
        return opt;
    });
}
```

The above example shows adding a custom claim of "color = yellow".

-   inClaims - This is an IEnumerable of Claims that were found in the OIDC id_token.

-   outClaims - This is a List of Claims that will be encoded into the JWT payload. This will include the claims that were extracted or derived from the OIDC id_token. While generally you would add claims, it is possible to remove them as well.
