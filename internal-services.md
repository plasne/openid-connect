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

using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System;

namespace CasAuth
{

    public static class CasListOfClaimsExtensions
    {

        public static string Name(this IEnumerable<Claim> claims)
        {
            return claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")?.Value;
        }

        public static string Email(this IEnumerable<Claim> claims)
        {
            return claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")?.Value;
        }

        public static string EmailOrName(this IEnumerable<Claim> claims)
        {
            return claims.Email() ?? claims.Name();
        }

        public static IEnumerable<string> Roles(this IEnumerable<Claim> claims)
        {
            return claims.Where(c => c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role").Select(c => c.Value).Distinct();
        }

        public static bool HasRole(this IEnumerable<Claim> claims, string role)
        {
            return claims.Roles().FirstOrDefault(r => string.Compare(r, role, StringComparison.InvariantCultureIgnoreCase) == 0) != null;
        }

        public static bool IsAdmin(this IEnumerable<Claim> claims)
        {
            return claims.HasRole(CasEnv.RoleForAdmin);
        }

        public static bool IsService(this IEnumerable<Claim> claims)
        {
            return claims.HasRole(CasEnv.RoleForService);
        }

        public static Dictionary<string, string> ToDictionary(this IEnumerable<Claim> claims)
        {
            var dict = new Dictionary<string, string>();
            foreach (var claim in claims)
            {
                switch (claim.Type)
                {
                    case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":
                        dict.Add("name", claim.Value);
                        break;
                    case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
                        dict.Add("email", claim.Value);
                        break;
                    case "http://schemas.microsoft.com/ws/2008/06/identity/claims/role":
                        dict.Add("role", claim.Value);
                        break;
                    default:
                        dict.Add(claim.Type, claim.Value);
                        break;
                }
            }
            return dict;
        }

        public static void Add(this List<Claim> claims, string key, string value)
        {
            if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(value)) return;

            // normalize the key
            switch (key)
            {
                case "name":
                    key = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
                    break;
                case "email":
                    key = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
                    break;
                case "role":
                case "roles":
                    key = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
                    break;
            }

            // trim the value
            value = value.Trim();

            // add if not a duplicate
            var existing = claims.Find(c => string.Compare(c.Type, key, StringComparison.InvariantCultureIgnoreCase) == 0 &&
                string.Compare(c.Value, value, StringComparison.InvariantCultureIgnoreCase) == 0);
            if (existing == null) claims.Add(new Claim(key, value));

        }





    }

}

## Unit Testing

using System.Collections.Generic;
using System.Security.Claims;
using System.Linq;
using System;

namespace CasAuth
{

    public static class ClaimsPrincipalExtensions
    {

        /// <summary>
        /// CreateClaimsPrincipalForUser is mostly used by unit tests to easily create an identity.
        /// </summary>
        /// <code>
        /// var principal = ClaimsExtensions.CreateClaimsPrincipalForUser("me@email.com");
        /// var context = new Mock<HttpContext>();
        /// context.Setup(c => c.User).Returns(principal);
        /// controller.ControllerContext.HttpContext = context.Object;
        /// </code>
        public static ClaimsPrincipal CreateClaimsPrincipalForUser(string email, params string[] roles)
        {
            var claims = new List<Claim>() {
                new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", email)
            };
            if (roles != null)
            {
                foreach (string role in roles)
                {
                    new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", role);
                }
            }
            var identity = new ClaimsIdentity(claims);
            var principal = new ClaimsPrincipal(identity);
            return principal;
        }

        /// <summary>
        /// CreateClaimsPrincipalForUser is mostly used by unit tests to easily create an identity.
        /// </summary>
        /// <code>
        /// var principal = ClaimsExtensions.CreateClaimsPrincipalForService("my-service");
        /// var context = new Mock<HttpContext>();
        /// context.Setup(c => c.User).Returns(principal);
        /// controller.ControllerContext.HttpContext = context.Object;
        /// </code>
        public static ClaimsPrincipal CreateClaimsPrincipalForService()
        {
            var claims = new List<Claim>() {
                new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", CasEnv.RoleForService)
            };
            var identity = new ClaimsIdentity(claims);
            var principal = new ClaimsPrincipal(identity);
            return principal;
        }

    }

}
