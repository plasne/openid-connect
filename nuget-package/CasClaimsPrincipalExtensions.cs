using System.Collections.Generic;
using System.Security.Claims;
using System.Linq;
using System;

namespace CasAuth
{

    public static class ClaimsPrincipalExtensions
    {

        public static string Name(this ClaimsPrincipal principal)
        {
            return principal.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")?.Value;
        }

        public static string Email(this ClaimsPrincipal principal)
        {
            return principal.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")?.Value;
        }

        public static string EmailOrName(this ClaimsPrincipal principal)
        {
            return principal.Email() ?? principal.Name();
        }

        public static IEnumerable<string> Roles(this ClaimsPrincipal principal)
        {
            return principal.Claims.Where(c => c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role").Select(c => c.Value).Distinct();
        }

        public static bool HasRole(this ClaimsPrincipal principal, string role)
        {
            return principal.Roles().FirstOrDefault(r => string.Compare(r, role, StringComparison.InvariantCultureIgnoreCase) == 0) != null;
        }

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
                new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "service")
            };
            var identity = new ClaimsIdentity(claims);
            var principal = new ClaimsPrincipal(identity);
            return principal;
        }

    }

}