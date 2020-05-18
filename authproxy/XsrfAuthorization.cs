using System;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace authproxy
{

    public class XsrfRequirement : IAuthorizationRequirement
    { }

    public class XsrfHandler : AuthorizationHandler<XsrfRequirement>
    {

        public XsrfHandler(ILogger<XsrfHandler> logger, IHttpContextAccessor contextAccessor)
        {
            this.Logger = logger;
            this.ContextAccessor = contextAccessor;
        }

        private ILogger Logger { get; }
        private IHttpContextAccessor ContextAccessor;

        private bool IsAuthorized(IIdentity iidentity)
        {
            try
            {
                Logger.LogDebug("IsAuthorized: start authorization check for XSRF...");
                var header = Program.XsrfHeader;
                var claim = Program.XsrfClaim;

                // if there is no requirement for XSRF, then don't check for it
                if (string.IsNullOrEmpty(header) && string.IsNullOrEmpty(claim))
                {
                    Logger.LogDebug("IsAuthorized: there is no header and claim defined for XSRF so the authorization check is a success.");
                    return true;
                }
                if (string.IsNullOrEmpty(header) || string.IsNullOrEmpty(claim))
                {
                    Logger.LogWarning("IsAuthorized: you must have a header and claim defined for XSRF authorization to work.");
                    throw new Exception("header/claim is not defined properly.");
                }

                // get the identity of the authenticated user
                var identity = iidentity as ClaimsIdentity;
                if (identity == null || !identity.IsAuthenticated)
                {
                    Logger.LogDebug("IsAuthorized: authentication failed, so the authorization check is a failure.");
                    throw new Exception("user is not authenticated");
                }

                // get the header
                string code = ContextAccessor.HttpContext.Request.Headers[header];
                if (string.IsNullOrEmpty(code))
                {
                    Logger.LogDebug($"IsAuthorized: the header \"{header}\" did not contain an XSRF code, so the authorization check is a failure.");
                    throw new Exception("XSRF code not found");
                }

                // verify that it matches the XSRF claim
                var xsrfclaim = identity.FindFirst(c => c.Type == claim);
                if (xsrfclaim == null)
                {
                    Logger.LogDebug("IsAuthorized: the identity did not contain an XSRF code, so the authorization check is a failure.");
                    throw new Exception("xsrf claim not found");
                }
                if (code != xsrfclaim.Value)
                {
                    Logger.LogDebug($"IsAuthorized: the XSRF code did not match, expected \"{xsrfclaim.Value}\", received \"{code}\", so the authorization check is a failure.");
                    throw new Exception("xsrf claim does not match code");
                }

                // success
                Logger.LogDebug("IsAuthorized: the codes matched, so the authorization check is a success.");
                return true;

            }
            catch (Exception e)
            {
                Logger.LogWarning(e, "authorization failure");
                return false;
            }
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, XsrfRequirement requirement)
        {
            var auth = IsAuthorized(context.User?.Identity);
            if (auth)
            {
                context.Succeed(requirement);
            }
            else
            {
                context.Fail();
            }
            return Task.CompletedTask;
        }





    }

}