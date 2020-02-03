# AuthCode

If you want to collect access_tokens and refresh_tokens for Azure services (graph, storage, etc.) on behalf-of the logged in user, then you need to use the AuthCode flow. This project makes it easy to do with one major additional requirement... you should never return the access_token or refresh_token to the client, so you need to have a state management solution implemented so you can keep those tokens.

## Implementation

In Startup.cs, you can specify a lambda function for UseCasServerAuth to configure AuthCode flows.

```c#
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseRouting();
    app.UseCors();
    app.UseCasServerAuth(() =>
    {
        var opt = new ext.CasServerAuthOptions()
        {
            AuthCodeFunc = async (getAccessToken) =>
            {
                var token1 = await getAccessToken("offline_access https://graph.microsoft.com/user.read");
                var token2 = await getAccessToken("offline_access https://graph.microsoft.com/group.read");
            }
        };
        opt.Scopes.Add("https://graph.microsoft.com/user.read");
        opt.Scopes.Add("https://graph.microsoft.com/group.read");
        return opt;
    });
}
```

The above example shows adding a scope request for user.read and group.read (these will be delegate permissions in the Azure app), and then fetching those tokens (the return of getAccessToken includes an access_token and refresh_token). You would then need to store those tokens in your state management solution.

So you can understand the flow, the first call to getAccessToken uses the access_token that was obtained via the OIDC login process. The second call uses the refresh_token from the first. Subsequent calls would use previous refresh_tokens.
