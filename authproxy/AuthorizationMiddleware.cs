using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

public class AuthorizationMiddleware
{

    public AuthorizationMiddleware(RequestDelegate next, string policyName)
    {
        Next = next;
        PolicyName = policyName;
    }

    private RequestDelegate Next { get; }
    private string PolicyName { get; }

    public async Task Invoke(HttpContext context, IAuthorizationService authorizationService)
    {

        // check for authentication (401 on failure)
        if (context?.User?.Identity?.IsAuthenticated != true)
        {
            context.Response.StatusCode = 401;
            await context.Response.CompleteAsync();
            return;
        }

        // check for authorization (403 on failure)
        AuthorizationResult authorizationResult =
            await authorizationService.AuthorizeAsync(context.User, null, PolicyName);
        if (!authorizationResult.Succeeded)
        {
            context.Response.StatusCode = 403;
            await context.Response.CompleteAsync();
            return;
        }

        // continue if both successful
        await Next(context);

    }
}