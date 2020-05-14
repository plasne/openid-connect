# AuthCode

If you want to collect access_tokens and refresh_tokens for Azure services (graph, storage, etc.) on behalf-of the logged in user, then you need to use the AuthCode flow. This project makes it easy to do with one major additional requirement... you should never return the access_token or refresh_token to the client, so you need to have a state management solution implemented so you can keep those tokens. In addition, if needed for your solution, you will need to handle the expiration of access_tokens by fetching new ones using the refresh_token, there is nothing in this code base that assists with this operation.

## ICasAuthCodeReceiver

For implementing an AuthCode flow to capture access-tokens and refresh-tokens, you can create a class that inherits from ICasAuthCodeReceiver. You can then implement one of GetScopes() or GetScopesAsync() and one of Receive() or ReceiveAsync(). It is fine to leave the one you aren't using to throw a NotImplementedException. Both sync and async methods are called, so you should not implement both.

You define the extra scopes you want to receive in GetScopes() or GetScopesAsync(). You will then receive the access-tokens and refresh-tokens for those scopes whenever an authentication is successful via the Receive() or ReceiveAsync() method.

```c#
using System.Collections.Generic;
using System.Threading.Tasks;
using CasAuth;

public class MyAuthCodeReceiver : ICasAuthCodeReceiver
{
    public IEnumerable<string> GetScopes()
    {
        return new string[] { "https://graph.microsoft.com/user.read", "https://graph.microsoft.com/group.read" };
    }

    public Task<IEnumerable<string>> GetScopesAsync()
    {
        throw new System.NotImplementedException();
    }

    public void Receive(string scope, string accessToken, string refreshToken)
    {
        throw new System.NotImplementedException();
    }

    public Task ReceiveAsync(string scope, string accessToken, string refreshToken)
    {
        // store in a database
        return Task.CompletedTask;
    }
}
```

Make sure in the startup that you register the receiver...

```c#
public void ConfigureServices(IServiceCollection services)
{
    services.AddSingleton<ICasAuthCodeReceiver, MyAuthCodeReceiver>();
    services.AddCasServerAuth();
    services.AddControllers();
}
```

The above example shows adding a scope request for user.read and group.read (these will be delegate permissions in the Azure app) and then receiving those tokens. You would then need to store those tokens in your state management solution.