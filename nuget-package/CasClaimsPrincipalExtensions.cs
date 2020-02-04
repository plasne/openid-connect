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