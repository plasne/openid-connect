# Internal Services

When deploying a microservices application it is common that only a few services are exposed to the outside world. One or more API or gateway services then make calls to the internal services and the internal services commonly talk to each other. Since those internal services are never exposed directly to outside traffic, they do not need to verify authentication. This pattern supports the creation of some simple headers based on the full authentication that can provide identity to the internal services.

Note: it is not required that you implement this pattern. You could simply pass the session_token to internal services and they could verify it (or not, since you are on a trusted network) and then extract the claims from the payload. However, doing so comes at the cost of larger headers.

## Implementation

When the exposed API service calls internal services or internal services call other internal services, we need to propogate some headers to those services for authentication and authorization. This can be done in the Startup.cs file as show below.

The below sample shows configuring the propogation of default headers (X-IDENTITY, X-EMAIL, X-ROLES, and X-CORRELATION)...

```c#
public void ConfigureServices(IServiceCollection services)
{

    // setup CasAuth
    services.AddCasClientAuth();

    // add an HttpClient for the api that supports propogating headers and the proxy settings
    services.AddTransient<CasIntPropogateHeaders>();
    services.AddHttpClient("api")
        .AddHttpMessageHandler<CasIntPropogateHeaders>()
        .ConfigurePrimaryHttpMessageHandler(() => new CasProxyHandler());

    // setup controllers
    services.AddControllers();

}
```

The below sample shows adding an additional header for propogation called "x-custom-header"...

```c#
public void ConfigureServices(IServiceCollection services)
{

    // setup CasAuth
    services.AddCasClientAuth();

    // add an HttpClient for the api that supports propogating headers and the proxy settings
    services.AddSingleton<CasIntPropogateHeadersOptions>(p =>
    {
        var options = new CasIntPropogateHeadersOptions();
        options.Headers.Add("x-custom-header");
        return options;
    });
    services.AddTransient<CasIntPropogateHeaders>();
    services.AddHttpClient("api")
        .AddHttpMessageHandler<CasIntPropogateHeaders>()
        .ConfigurePrimaryHttpMessageHandler(() => new CasProxyHandler());

    // setup controllers
    services.AddControllers();

}
```

To accept those headers and create a standard ClaimsPrincipal and Identity, the internal services can implement the AddCasIntAuth method in Startup.cs.

```c#
public void ConfigureServices(IServiceCollection services)
{

    // setup CasAuth
    services.AddCasIntAuth();

    // setup controllers
    services.AddControllers();

}
```

After doing so, the [Authorize] header will work as expected and the User object will include claims.

```c#
[ApiController]
[Route("[controller]")]
public class SampleController : ControllerBase
{

    [Authorize]
    [HttpGet, Route("name")]
    public ActionResult<string> GetName()
    {
        return User.Claims.Name();
    }
}
```

## Headers

The headers are implemented in the following way...

-   X-IDENTITY - All claims that are in the Identity of the fully authenticated User are packaged into X-IDENTITY as a serialized JSON Dictionary using non-URI-compliant names. If this header exists, it is deserialized to create the claims in the internal identity.

-   X-EMAIL - The X-IDENTITY will be used for the "real" traffic, but for testing your internal services, it is much harder to build that header. Instead you can simply provide this header and the email claim will be populated. Commonly this is enough to validate that a user is authenticated and may even inform authorization decisions.

-   X-ROLES - The X-IDENTITY will be used for the "real" traffic, but for testing your internal services, it is much harder to build that header. Instead you can simply provide this header and a series of role claims will be populated. This should be a comma-delimited list of roles (ex. "admin, service").

-   X-CORRELATION - If this header exists, it is passed from service to service so that you can track a single request. If the propogation does not find the header, it will create a new GUID to set this header.

## Extensions

There are some extensions available on IEnumerable\<Claim> that can be used...

-   .Name() - returns the name of the user or service.

-   .Email() - returns the email address of the user.

-   .EmailOrName() - first tries to return the .Email() but if not, it tries the .Name().

-   .Roles() - returns an IEnumerable\<string> of roles.

-   .HasRole("role_name") - returns true if the user or service has the specified role.

-   .IsAdmin() - returns true if the user or service contains the ROLE_FOR_ADMIN role.

-   .IsService() - returns true if the user or service contains the ROLE_FOR_SERVICE role.

There is also an extension available on List\<Claim>...

-   .Add("claim_key", "claim_value") - adds a specified key/value to the claims using the URI-claim-name instead of the provided name (where there is one), and only if the key/value pair does not already exist.

## Unit Testing

There are also some extention methods that can be used for unit testing as shown here...

```c#
// create a mock user with "user" role
var principal = ClaimsExtensions.CreateClaimsPrincipalForUser("me@email.com", "user");
var context = new Mock<HttpContext>();
context.Setup(c => c.User).Returns(principal);
controller.ControllerContext.HttpContext = context.Object;

// create a mock service account
var principal = ClaimsExtensions.CreateClaimsPrincipalForService("my-service");
var context = new Mock<HttpContext>();
context.Setup(c => c.User).Returns(principal);
controller.ControllerContext.HttpContext = context.Object;
```
